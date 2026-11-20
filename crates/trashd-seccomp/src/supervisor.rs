//! Seccomp notification supervisor.
//!
//! Receives trapped syscall notifications, moves files to trash,
//! and responds to the kernel. On any error, responds with CONTINUE
//! to let the real syscall execute (fail-safe).

use crate::mem;
use crate::pin;
use std::io;
use trashd_common::{Config, TrashStore};

// ---------------------------------------------------------------------------
// seccomp notification structs (matching kernel uapi/linux/seccomp.h)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

// ioctl numbers: _IOWR('!', N, struct)
// Computed via: (3 << 30) | (sizeof(struct) << 16) | ('!' << 8) | N
//
// seccomp_notif = 80 bytes on x86_64 (8+4+4+64)
// seccomp_notif_resp = 24 bytes (8+8+4+4)
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = (3 << 30) | (80 << 16) | (0x21 << 8); // 0xC0502100
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = (3 << 30) | (24 << 16) | (0x21 << 8) | 1; // 0xC0182101
// NB: ID_VALID is _IOW (direction=1), not _IOWR (direction=3)
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = (1 << 30) | (8 << 16) | (0x21 << 8) | 2; // 0x40082102

// Compile-time verification that struct sizes match ioctl constants
const _: () = assert!(std::mem::size_of::<SeccompNotif>() == 80);
const _: () = assert!(std::mem::size_of::<SeccompNotifResp>() == 24);

/// Flag to tell kernel to execute the original syscall.
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

/// Receive a pending notification from the seccomp fd.
pub fn notif_recv(fd: i32) -> io::Result<SeccompNotif> {
    let mut notif = unsafe { std::mem::zeroed::<SeccompNotif>() };
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif as *mut _) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(notif)
    }
}

/// RECV failed: wait up to `timeout_ms` for listener news and report whether
/// none can ever come. Once every filtered task has exited, RECV fails at
/// once (ENOENT on current kernels) and poll reports POLLHUP, so retrying
/// RECV without this check spins at 100% CPU.
pub(crate) fn listener_done(fd: i32, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        if unsafe { libc::poll(&mut pfd, 1, timeout_ms) } >= 0 {
            return pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0;
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return true;
        }
    }
}

/// Send a response to a notification.
fn notif_send(fd: i32, resp: &SeccompNotifResp) -> io::Result<()> {
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp as *const _) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check if a notification ID is still valid (target is still blocked).
pub(crate) fn notif_id_valid(fd: i32, id: u64) -> bool {
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const _) };
    ret == 0
}

/// Respond with CONTINUE — tell kernel to execute the original syscall.
pub fn respond_continue(fd: i32, id: u64) {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let _ = notif_send(fd, &resp);
}

/// Respond with success (val=0, error=0) — syscall is "done", kernel skips it.
fn respond_success(fd: i32, id: u64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: 0,
    };
    notif_send(fd, &resp)
}

/// Respond with an errno — syscall "fails" with this error.
fn respond_errno(fd: i32, id: u64, errno: i32) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    notif_send(fd, &resp)
}

/// Run the supervisor notification loop.
///
/// This blocks forever, handling notifications until the fd is closed
/// or an unrecoverable error occurs.
pub fn run_supervisor(fd: i32, broker_fd: i32, ready_fd: i32) -> io::Result<()> {
    // The watchdog's death must also retire its supervisor on startup errors.
    // PR_SET_PDEATHSIG only covers deaths AFTER it takes effect, so capture
    // the parent BEFORE it and bail out if the parent vanished in the
    // fork→prctl window — otherwise this process would outlive the watchdog
    // holding the last copy of the notification fd (#93).
    let parent_at_spawn = unsafe { libc::getppid() };
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    if unsafe { libc::getppid() } != parent_at_spawn || parent_at_spawn == 1 {
        // Reparented already: the watchdog died before prctl took effect.
        std::process::exit(1);
    }
    if let Err(e) = crate::broker::connect(broker_fd) {
        signal_ready(ready_fd, false);
        return Err(e);
    }
    let mut session_state = match SessionState::open() {
        Ok(state) => state,
        Err(e) => {
            report!("trashd-exec: supervisor: failed to open trash store: {e}");
            signal_ready(ready_fd, false);
            if ready_fd >= 0 {
                return Err(io::Error::other(e));
            }
            report!("trashd-exec: supervisor: falling back to CONTINUE-only mode");
            return run_passthrough(fd);
        }
    };

    let mut own = OwnComponents::new();
    // Only a privileged supervisor can outrank its targets (#311). An
    // unreadable own status leaves nothing to compare with: protect nobody
    // rather than lend our credentials blindly.
    let labels = SecurityLabels::own();
    let credentials = match Credentials::of("self") {
        Some(own) if own.privileged() => CredentialGate::Compare(own, labels),
        Some(_) => CredentialGate::Unprivileged(labels),
        None => CredentialGate::Unknown,
    };
    let session = SessionAncestry::discover();
    signal_ready(ready_fd, true);

    loop {
        // Block until a notification arrives
        let notif = match notif_recv(fd) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => {
                // fd closed — supervisor is shutting down
                return Ok(());
            }
            Err(e) => {
                // ENOENT: a target died before we read its notification, or
                // every filtered task has exited.
                if e.raw_os_error() != Some(libc::ENOENT) {
                    report!("trashd-exec: supervisor: recv error: {e}");
                }
                if listener_done(fd, -1) {
                    return Ok(());
                }
                continue;
            }
        };

        // The config the session launched with must not outlive its file
        // forever: a wrapped login shell would keep trashing entries an
        // edited policy excludes, and vice versa (#437). Sampling is
        // cadence-limited inside refresh; the store reopens only on change.
        session_state.refresh();

        // Handle this notification (fail-safe: any error → CONTINUE). A
        // panic must still answer it: neither the watchdog nor a respawned
        // supervisor can receive a notification already read, so its thread
        // would stay blocked in the syscall (#350).
        let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_notification(
                fd,
                &notif,
                session_state.store(),
                session_state.store().config(),
                own.ids(),
                &credentials,
                session.as_ref(),
            )
        }));
        if handled.is_err() {
            decline(fd, &notif);
        }
        // Retention runs after the target has its answer, never while it
        // waits on its trapped syscall (#319).
        session_state.store().run_deferred_maintenance();
    }
}

/// The store one supervised session serves with. It is opened once with the
/// launch-time configuration, then reopened together with that configuration
/// whenever a config file's mtime changes — the same change detection the
/// preload applies inside its own process, for the same reason: a long-lived
/// trashd-exec session must follow config edits, or removed never_trash
/// entries keep permanently deleting (#437).
struct SessionState {
    /// `config_mtime()` observed before the last (re)load.
    mtime: i64,
    /// Last wall-clock moment `refresh` sampled the config files. The
    /// sample costs two stats; at bulk-delete rates that dominated the
    /// per-notification budget, so sampling is cadence-limited and a
    /// config edit lands within one cadence instead of instantly.
    last_check: std::time::Instant,
    store: TrashStore,
}

impl SessionState {
    fn open() -> Result<Self, trashd_common::store::TrashError> {
        // Sampled before the load, as `refresh` does: an edit landing while
        // the store opens is then a change, not the baseline (seccomp-sup-3).
        let mtime = config_mtime();
        Ok(Self {
            mtime,
            ..Self::from_parts(TrashStore::open()?)
        })
    }

    fn from_parts(store: TrashStore) -> Self {
        // Retention runs once the target has its answer (#319), from the
        // launch-time store on, not only after a reload (seccomp-sup-1).
        store.defer_maintenance();
        Self {
            mtime: config_mtime(),
            last_check: std::time::Instant::now(),
            store,
        }
    }

    fn store(&self) -> &TrashStore {
        &self.store
    }

    /// Re-load the config and reopen the store when a config file changed
    /// since the last load. A failed reload keeps the previous store serving
    /// — the old layer's behavior — and reports once per change.
    fn refresh(&mut self) {
        // At most one sample per cadence: two stats per notification made
        // config polling a visible share of bulk-delete cost.
        const CADENCE: std::time::Duration = std::time::Duration::from_millis(250);
        let now = std::time::Instant::now();
        if now.duration_since(self.last_check) < CADENCE {
            return;
        }
        self.last_check = now;
        self.refresh_with(config_mtime(), || {
            TrashStore::open_with_config(Config::load()).ok()
        });
    }

    /// `refresh` with the mtime sample and the loader injected, so a unit
    /// test can drive both without the ambient configuration.
    ///
    /// The reload runs after a notification was dequeued, outside the
    /// handler's guard: a panicking load keeps the previous store serving,
    /// so that notification is still answered (seccomp-sup-2).
    fn refresh_with(&mut self, now: i64, load: impl FnOnce() -> Option<TrashStore>) -> bool {
        if now == self.mtime {
            return false;
        }
        self.mtime = now;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(load)).unwrap_or(None) {
            Some(store) => {
                // Retention must keep waiting until the target is answered,
                // exactly as at startup (`from_parts`).
                store.defer_maintenance();
                self.store = store;
                true
            }
            None => {
                report!(
                    "trashd-exec: supervisor: config reload failed; keeping the previous configuration"
                );
                false
            }
        }
    }
}

/// The identity of the two files [`Config::load`] reads, combined in order
/// (a symmetric combination collides when the layers swap). A missing file
/// keys differently from any present one, so deleting a config is a change.
fn config_mtime() -> i64 {
    config_mtime_of(&Config::global_config_path(), &Config::user_config_path())
}

fn config_mtime_of(global: &std::path::Path, user: &std::path::Path) -> i64 {
    use std::hash::{Hash, Hasher};
    use std::os::unix::fs::MetadataExt;
    // Nanosecond resolution: a seconds-only key misses an edit made in the
    // same second as the load, leaving stale policy in force indefinitely.
    // The mtime alone is not enough either (seccomp-sup-3): Nix and
    // home-manager link every generation to a store file stamped at one
    // fixed time, and an edit can keep its timestamp tick. The link itself
    // (a retarget) and the followed file's inode, size and ctime, which
    // userspace cannot set, catch both.
    let layer = |path: &std::path::Path| {
        let link = std::fs::symlink_metadata(path)
            .ok()
            .map(|m| (m.dev(), m.ino(), m.mtime(), m.mtime_nsec()));
        let file = std::fs::metadata(path).ok().map(|m| {
            (
                (m.dev(), m.ino(), m.size()),
                (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()),
            )
        });
        (link, file)
    };
    // SipHash with fixed keys: the same files give the same key every time.
    let mut hasher = std::hash::DefaultHasher::new();
    (layer(global), layer(user)).hash(&mut hasher);
    hasher.finish() as i64
}

pub(crate) fn signal_ready(fd: i32, ready: bool) {
    if fd >= 0 {
        let byte = u8::from(ready);
        unsafe {
            libc::send(fd, (&byte as *const u8).cast(), 1, libc::MSG_NOSIGNAL);
            libc::close(fd);
        }
    }
}

/// Handle a single notification.
#[allow(clippy::too_many_arguments)]
fn handle_notification(
    fd: i32,
    notif: &SeccompNotif,
    store: &TrashStore,
    config: &Config,
    own: &[(u64, u64)],
    credentials: &CredentialGate,
    session: Option<&SessionAncestry>,
) {
    // Record security transitions before validation or any fallible work.
    // The same decline path serves watchdog recovery and passthrough modes.
    if notif.data.nr == SYS_LANDLOCK_RESTRICT_SELF {
        decline(fd, notif);
        return;
    }

    // Check if the notification is still valid BEFORE touching the target's
    // /proc state: if the target died and its PID was recycled, the reads
    // below must not inspect an unrelated process's memory or fds (#92).
    // try_pinned re-checks after each pidfd acquisition as well.
    if !notif_id_valid(fd, notif.id) {
        // Target likely gone. Send CONTINUE defensively — if the target is truly
        // dead, the response harmlessly fails with ENOENT. If the ioctl failed
        // spuriously, this prevents hanging the supervised process.
        respond_continue(fd, notif.id);
        return;
    }

    // A target we will not lend our credentials to deletes with its own:
    // a deferring preload trashes the entry itself, anything else is left to
    // the kernel (#311, #349). A Landlock domain the supervisor does not
    // share is the same refusal: our rename would bypass the target's own
    // policy, so the deletion stays with the target's credentials (#390).
    if !invalid_flags(notif) && (!credentials.lends_to(notif.pid) || crate::landlock::restricts()) {
        decline(fd, notif);
        return;
    }

    // Capture only after CONTINUE-only gates. Protected operations retain
    // one pathname capture and the same pinned mutation path (#286).
    let capture = capture_protected_path(notif, config, own, session, || {
        let raw = mem::read_arg_path(notif.pid, notif.data.nr, &notif.data.args)?;
        // Display only: mutation and policy use the pinned parent (#6, #226).
        let display = mem::resolve_syscall_path(notif.pid, notif.data.nr, &notif.data.args, &raw)?;
        Ok((raw, display))
    });
    let (raw, display) = match capture {
        Ok(Some(captured)) => captured,
        // Policy (bypass, store-internal, invalid flags): the kernel runs it.
        Ok(None) => {
            respond_continue(fd, notif.id);
            return;
        }
        // The path could not be read: the target's own layer decides (#355).
        Err(_) => {
            decline(fd, notif);
            return;
        }
    };

    // From this point, ALL code paths MUST send a response.
    // Failure to respond will hang the supervised process.

    #[cfg(target_arch = "x86_64")]
    let is_rmdir = notif.data.nr == 84; // SYS_rmdir
    #[cfg(target_arch = "aarch64")]
    let is_rmdir = false;
    let remove_dir = is_rmdir
        || (notif.data.nr == libc::SYS_unlinkat as i32
            && (notif.data.args[2] as i32 & libc::AT_REMOVEDIR) != 0);

    // Preferred path: race-free fd-pinned interception (#6). The kernel walks
    // prefixes against PINNED directory fds and the move is renameat() on the
    // same fds, so sibling renames between our stat and our move cannot divert
    // the operation.
    match crate::pin::try_pinned(
        notif.pid,
        notif.data.nr,
        &notif.data.args,
        raw.as_os_str(),
        &display,
        remove_dir,
        fd,
        notif.id,
        store,
    ) {
        Ok(pin::Decision::Trashed) => {
            if respond_success(fd, notif.id).is_err() {
                // Notification expired (target died) — no harm done
            }
        }
        Ok(pin::Decision::Continue) => respond_continue(fd, notif.id),
        Ok(pin::Decision::Decline) => decline(fd, notif),
        Ok(pin::Decision::Errno(e)) => {
            let _ = respond_errno(fd, notif.id, e);
        }
        // Kernel lacks pidfd_getfd/openat2, fds couldn't be pinned, or the
        // trash lives on another device: leave the original syscall to the
        // target's own layer (#355). A supervisor-side path fallback could
        // resolve the same string to an unrelated host inode.
        Err(_) => decline(fd, notif),
    }
}

/// An unlinkat with flags the kernel rejects: it answers EINVAL itself.
fn invalid_flags(notif: &SeccompNotif) -> bool {
    notif.data.nr == libc::SYS_unlinkat as i32
        && (notif.data.args[2] as i32 & !libc::AT_REMOVEDIR) != 0
}

/// A deletion the preload handed over (see `DEFER_MARK`).
fn deferred_by_preload(notif: &SeccompNotif) -> bool {
    let deletion = notif.data.nr == libc::SYS_unlinkat as i32;
    #[cfg(target_arch = "x86_64")]
    let deletion = deletion
        || notif.data.nr == libc::SYS_unlink as i32
        || notif.data.nr == libc::SYS_rmdir as i32;
    deletion && notif.data.args[3] == crate::seccomp_identity::DEFER_MARK
}

/// Leave a deletion to the target's own credentials: ENOSYS tells a
/// deferring preload to trash it in-process; anything else the kernel runs.
pub(crate) fn decline(fd: i32, notif: &SeccompNotif) {
    if notif.data.nr == SYS_LANDLOCK_RESTRICT_SELF {
        // Acknowledge the shared tracking update before the kernel may apply
        // the restriction. Missing state must never silently allow setup.
        match crate::landlock::note_restriction() {
            Ok(()) => respond_continue(fd, notif.id),
            Err(_) => {
                let _ = respond_errno(fd, notif.id, libc::EPERM);
            }
        }
        return;
    }
    if deferred_by_preload(notif) {
        let _ = respond_errno(fd, notif.id, libc::ENOSYS);
    } else {
        respond_continue(fd, notif.id);
    }
}

/// CONTINUE-only gates need no target pathname. In particular, package-tool
/// deletes must not pay a broker round trip before their bypass is known.
fn capture_protected_path(
    notif: &SeccompNotif,
    config: &Config,
    own: &[(u64, u64)],
    session: Option<&SessionAncestry>,
    capture: impl FnOnce() -> io::Result<(std::path::PathBuf, std::path::PathBuf)>,
) -> io::Result<Option<(std::path::PathBuf, std::path::PathBuf)>> {
    if invalid_flags(notif)
        // Store-internal deletes must never be intercepted (#195, #196).
        || is_own_component(notif.pid, own)
        || process_bypassed(
            notif.pid,
            &config.bypass_processes,
            &config.bypass_paths,
            session,
        )
        || target_bypassed(notif.pid)
    {
        return Ok(None);
    }
    capture().map(Some)
}

/// What the kernel checks for unlink/rmdir: filesystem UID and GID,
/// supplementary groups and effective capabilities.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Credentials {
    fsuid: u32,
    fsgid: u32,
    groups: Vec<u32>,
    cap_eff: u64,
    /// The user namespace the capabilities belong to. Status shows a
    /// sandbox's mapped root exactly like real root, but the kernel grants
    /// its capabilities only over IDs mapped into its namespace (#341).
    user_namespace: Option<(u64, u64)>,
}

impl Credentials {
    /// Credentials of `/proc/<task>`: "self", or a trapped thread's id.
    pub(crate) fn of(task: &str) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let mut credentials = Self::parse(&read_proc_text(&format!("/proc/{task}/status"))?)?;
        credentials.user_namespace = std::fs::metadata(format!("/proc/{task}/ns/user"))
            .ok()
            .map(|meta| (meta.dev(), meta.ino()));
        Some(credentials)
    }

    fn parse(status: &str) -> Option<Self> {
        let (mut fsuid, mut fsgid, mut groups, mut cap_eff) = (None, None, None, None);
        for line in status.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key {
                // real, effective, saved, filesystem
                "Uid" => fsuid = value.split_whitespace().nth(3)?.parse().ok(),
                "Gid" => fsgid = value.split_whitespace().nth(3)?.parse().ok(),
                "Groups" => {
                    let mut list = value
                        .split_whitespace()
                        .map(|group| group.parse().ok())
                        .collect::<Option<Vec<u32>>>()?;
                    list.sort_unstable();
                    list.dedup();
                    groups = Some(list);
                }
                "CapEff" => cap_eff = u64::from_str_radix(value.trim(), 16).ok(),
                _ => {}
            }
        }
        Some(Self {
            fsuid: fsuid?,
            fsgid: fsgid?,
            groups: groups?,
            cap_eff: cap_eff?,
            user_namespace: None,
        })
    }

    /// Whether these credentials can remove files others cannot.
    fn privileged(&self) -> bool {
        self.fsuid == 0 || self.cap_eff != 0
    }
}

/// The LSM labels (SELinux, AppArmor, Smack) the kernel reports for our own
/// task. The kernel checks a target's MAC policy only after seccomp trapped
/// its delete, so a move made under our label would carry out deletions the
/// target's policy denies (seccomp-sup-5). Credentials alone cannot tell:
/// `aa-exec`, path-attached profiles and SELinux domain transitions keep
/// every ID and capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecurityLabels(Vec<(&'static str, Vec<u8>)>);

impl SecurityLabels {
    /// Per-task label files under `/proc/<tid>`, as the LSMs expose them.
    const FILES: [&'static str; 3] = [
        "attr/current",
        "attr/apparmor/current",
        "attr/smack/current",
    ];

    /// Our labels: only the files this kernel answers for us, so a host with
    /// no LSM pays nothing per notification.
    fn own() -> Self {
        Self(
            Self::FILES
                .into_iter()
                .filter_map(|file| {
                    Some((file, read_proc_bytes(&format!("/proc/self/{file}"), 256)?))
                })
                .collect(),
        )
    }

    /// Whether task `tid` carries exactly our labels. A label we know but
    /// cannot read for the target fails closed.
    fn shared_by(&self, tid: u32) -> bool {
        self.0.iter().all(|(file, own)| {
            read_proc_bytes(&format!("/proc/{tid}/{file}"), 256).as_deref() == Some(own.as_slice())
        })
    }
}

/// The supervisor performs trapped deletes with its own credentials, and
/// seccomp traps them before the kernel's permission check. A filter set up
/// for a root session survives su/sudo, so a target switched to another
/// user, or one that dropped capabilities, would borrow root's (#311). A
/// target confined by another LSM label would borrow our label's access
/// (seccomp-sup-5).
pub(crate) enum CredentialGate {
    /// Privileged supervisor: only targets with identical credentials and
    /// security labels.
    Compare(Credentials, SecurityLabels),
    /// Unprivileged supervisor: no target can hold less than we do in a way
    /// that matters to unlink (setuid cannot elevate past NoNewPrivs), except
    /// through a security label of its own.
    Unprivileged(SecurityLabels),
    /// Our own credentials are unknown: lend them to nobody.
    Unknown,
}

impl CredentialGate {
    fn lends_to(&self, tid: u32) -> bool {
        match self {
            CredentialGate::Compare(own, labels) => {
                labels.shared_by(tid) && Credentials::of(&tid.to_string()).as_ref() == Some(own)
            }
            CredentialGate::Unprivileged(labels) => labels.shared_by(tid),
            CredentialGate::Unknown => false,
        }
    }
}

/// landlock_restrict_self on x86_64 and aarch64.
const SYS_LANDLOCK_RESTRICT_SELF: i32 = 446;

/// A small /proc text file, decoded lossily: status prints `Name:` as raw
/// bytes the kernel may cut mid-character, which failed a strict UTF-8 read
/// and refused the target outright (#350).
fn read_proc_text(path: &str) -> Option<String> {
    let bytes = read_proc_bytes(path, 4096)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A /proc file in one read into a buffer sized for typical contents. A
/// short read ends these files, so there is no EOF probe; fs::read grows
/// its buffer from 32 bytes for files that report size 0.
fn read_proc_bytes(path: &str, capacity: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(capacity);
    loop {
        let filled = bytes.len();
        if bytes.capacity() == filled {
            bytes.reserve(capacity);
        }
        let spare = bytes.capacity() - filled;
        bytes.resize(filled + spare, 0);
        match file.read(&mut bytes[filled..]) {
            Ok(n) => {
                bytes.truncate(filled + n);
                if n < spare {
                    return Some(bytes);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => bytes.truncate(filled),
            Err(_) => return None,
        }
    }
}

/// trashd's own installed binaries, re-identified every few seconds: an
/// update replaces them with new inodes mid-session, after which their store
/// deletes were intercepted again (#195, #196, #323).
struct OwnComponents {
    exe: Option<std::path::PathBuf>,
    ids: Vec<(u64, u64)>,
    at: std::time::Instant,
}

impl OwnComponents {
    const REFRESH: std::time::Duration = std::time::Duration::from_secs(5);

    fn new() -> Self {
        let exe = std::fs::read_link("/proc/self/exe").ok();
        let ids = exe.as_deref().map(own_component_ids).unwrap_or_default();
        Self {
            exe,
            ids,
            at: std::time::Instant::now(),
        }
    }

    fn ids(&mut self) -> &[(u64, u64)] {
        let now = std::time::Instant::now();
        if now.duration_since(self.at) > Self::REFRESH {
            if let Some(exe) = &self.exe {
                self.ids = own_component_ids(exe);
            }
            self.at = now;
        }
        &self.ids
    }
}

/// (device, inode) of trashd's own binaries installed beside this
/// supervisor: the `trash` CLI and the rm shim (a release prefix keeps the
/// shim in lib/trashd/bin; a build directory has both side by side).
pub(crate) fn own_component_ids(supervisor_exe: &std::path::Path) -> Vec<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let Some(dir) = supervisor_exe.parent() else {
        return Vec::new();
    };
    let mut candidates = vec![dir.join("trash"), dir.join("trashd-rm")];
    if let Some(prefix) = dir.parent() {
        candidates.push(prefix.join("lib/trashd/bin/rm"));
    }
    candidates
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .map(|meta| (meta.dev(), meta.ino()))
        .collect()
}

fn is_own_component(pid: u32, own: &[(u64, u64)]) -> bool {
    use std::os::unix::fs::MetadataExt;
    !own.is_empty()
        && std::fs::metadata(format!("/proc/{pid}/exe"))
            .is_ok_and(|meta| own.contains(&(meta.dev(), meta.ino())))
}

/// True when the TARGET process has TRASH_BYPASS=1 in its environment.
///
/// The shim and preload layers check TRASH_BYPASS directly, but this layer
/// runs OUTSIDE the target process — without reading its environ the variable
/// was silently ignored here, so e.g. self-update running install.sh with
/// TRASH_BYPASS=1 still had every old-binary unlink intercepted mid-upgrade
/// (#18). Reading /proc/<pid>/environ requires same-user or root, which the
/// supervisor necessarily is (it created the target).
fn target_bypassed(pid: u32) -> bool {
    // A buffer that fits a typical environment: fs::read grows from 32 bytes
    // for this size-0 proc file, ~13 syscalls for 5 KB, on every delete.
    read_proc_bytes(&format!("/proc/{pid}/environ"), 16 * 1024)
        .is_some_and(|data| data.split(|&b| b == 0).any(|e| e == b"TRASH_BYPASS=1"))
}

/// Ancestors examined above the deleting process, the same depth as the
/// preload and shim walks so every layer decides alike (#23).
const BYPASS_DEPTH: usize = 10;

/// The orchestrator and its ancestors are shared by every target: their
/// per-level bypass matches are computed once instead of walked again for
/// every trapped delete, and recomputed after a few seconds so a bypass
/// ancestor that exits stops applying (#249).
pub(crate) struct SessionAncestry {
    orchestrator: u32,
    /// Process names per level, the orchestrator first.
    cached: std::cell::RefCell<Option<(Vec<Vec<String>>, std::time::Instant)>>,
}

impl SessionAncestry {
    const REFRESH: std::time::Duration = std::time::Duration::from_secs(5);

    /// The supervisor's grandparent: supervisor <- watchdog <- orchestrator.
    fn discover() -> Option<Self> {
        let watchdog = unsafe { libc::getppid() } as u32;
        let (_, orchestrator) = trashd_common::proc_stat::comm_and_parent(watchdog)?;
        (orchestrator > 1).then(|| Self::new(orchestrator))
    }

    fn new(orchestrator: u32) -> Self {
        Self {
            orchestrator,
            cached: std::cell::RefCell::new(None),
        }
    }

    /// Whether a bypass name occurs among the first `levels` levels,
    /// starting at the orchestrator.
    fn bypassed_within(&self, levels: usize, bypass: &[String]) -> bool {
        let now = std::time::Instant::now();
        let fresh = self
            .cached
            .borrow()
            .as_ref()
            .is_some_and(|(_, at)| now.duration_since(*at) <= Self::REFRESH);
        if !fresh {
            let mut names = Vec::with_capacity(BYPASS_DEPTH + 1);
            let mut cur = Some(self.orchestrator);
            while let Some(pid) = cur.filter(|_| names.len() <= BYPASS_DEPTH) {
                let (level, parent) = level_names(pid);
                names.push(level);
                cur = parent;
            }
            *self.cached.borrow_mut() = Some((names, now));
        }
        self.cached.borrow().as_ref().is_some_and(|(names, _)| {
            names
                .iter()
                .take(levels)
                .flatten()
                .any(|name| bypass.contains(name))
        })
    }
}

/// Walk the target's process tree from `pid` upward; return true if any
/// process name is in the bypass list. Mirrors the preload layer's logic so a
/// given process makes the same trash/skip decision regardless of which
/// interception layer is active.
fn process_bypassed(
    pid: u32,
    bypass: &[String],
    bypass_paths: &[String],
    session: Option<&SessionAncestry>,
) -> bool {
    if bypass.is_empty() && bypass_paths.is_empty() {
        return false;
    }
    if !bypass_paths.is_empty()
        && std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| {
            bypass_paths
                .iter()
                .any(|prefix| exe.to_string_lossy().starts_with(prefix.as_str()))
        })
    {
        return true;
    }
    if bypass.is_empty() {
        return false;
    }
    let mut cur = pid;
    for depth in 0..=BYPASS_DEPTH {
        if depth > 0
            && let Some(session) = session
            && cur == session.orchestrator
        {
            return session.bypassed_within(BYPASS_DEPTH + 1 - depth, bypass);
        }
        let (names, parent) = level_names(cur);
        if names.iter().any(|name| bypass.contains(name)) {
            return true;
        }
        match parent {
            Some(parent) => cur = parent,
            None => break,
        }
    }
    false
}

/// `pid`'s executable basename and kernel comm, and the parent to examine
/// next (none at init or on a cycle). One stat read yields comm and parent
/// together (#302).
fn level_names(pid: u32) -> (Vec<String>, Option<u32>) {
    let mut names = Vec::with_capacity(2);
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe"))
        && let Some(name) = exe.file_name()
    {
        names.push(name.to_string_lossy().into_owned());
    }
    let parent = match trashd_common::proc_stat::comm_and_parent(pid) {
        Some((comm, parent)) => {
            names.push(comm);
            Some(parent).filter(|parent| *parent > 1 && *parent != pid)
        }
        // Preserve name matching if stat is unreadable or malformed.
        None => {
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                names.push(comm.trim().to_string());
            }
            None
        }
    };
    (names, parent)
}

/// Passthrough mode: respond CONTINUE to every notification.
/// Used when the trash store can't be opened.
fn run_passthrough(fd: i32) -> io::Result<()> {
    loop {
        match notif_recv(fd) {
            // Without a store, a deferring preload still trashes (#355).
            Ok(notif) => decline(fd, &notif),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => return Ok(()),
            Err(_) if listener_done(fd, -1) => return Ok(()),
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn credentials_parse_filesystem_ids_groups_and_capabilities() {
        let status = "Name:\tsh\nUid:\t1000\t1000\t1000\t1001\nGid:\t100\t100\t100\t102\n\
                      Groups:\t27 4 27 100 \nCapEff:\t0000000000000000\n";
        let parsed = Credentials::parse(status).unwrap();
        assert_eq!(
            parsed,
            Credentials {
                fsuid: 1001,
                fsgid: 102,
                groups: vec![4, 27, 100],
                cap_eff: 0,
                user_namespace: None,
            }
        );
        assert!(!parsed.privileged());
        let root = "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapEff:\t000001ffffffffff\n";
        assert!(Credentials::parse(root).unwrap().privileged());
        for broken in [
            "",
            "Uid:\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\nCapEff:\t0\n",
            "Uid:\t0\t0\t0\t0\n",
        ] {
            assert_eq!(Credentials::parse(broken), None, "{broken:?}");
        }
        assert!(Credentials::of("self").is_some());
        // #350: a comm cut mid-character leaves raw bytes in Name:.
        let cut = b"Name:\ta-\xe6\x97\nUid:\t5\t5\t5\t5\nGid:\t6\t6\t6\t6\nGroups:\t\nCapEff:\t0\n";
        let text = String::from_utf8_lossy(cut);
        assert_eq!(
            Credentials::parse(&text).map(|c| (c.fsuid, c.fsgid)),
            Some((5, 6))
        );
    }

    // #349: only a deletion carrying the preload's mark is answered ENOSYS
    // when declined; unmarked callers (static binaries) get CONTINUE.
    #[test]
    fn only_marked_deletions_are_preload_deferrals() {
        let notif = |nr: libc::c_long, flags: u64, mark: u64| SeccompNotif {
            id: 1,
            pid: 1,
            flags: 0,
            data: SeccompData {
                nr: nr as i32,
                arch: 0,
                instruction_pointer: 0,
                args: [libc::AT_FDCWD as u64, 0, flags, mark, 0, 0],
            },
        };
        let mark = crate::seccomp_identity::DEFER_MARK;
        assert!(deferred_by_preload(&notif(libc::SYS_unlinkat, 0, mark)));
        assert!(deferred_by_preload(&notif(
            libc::SYS_unlinkat,
            libc::AT_REMOVEDIR as u64,
            mark
        )));
        assert!(!deferred_by_preload(&notif(libc::SYS_unlinkat, 0, 0)));
        assert!(!deferred_by_preload(&notif(
            libc::SYS_unlinkat,
            0,
            mark ^ 1
        )));
        assert!(!deferred_by_preload(&notif(libc::SYS_getpid, 0, mark)));
        #[cfg(target_arch = "x86_64")]
        for syscall in [libc::SYS_unlink, libc::SYS_rmdir] {
            assert!(deferred_by_preload(&notif(syscall, 0, mark)));
            assert!(!deferred_by_preload(&notif(syscall, 0, 0)));
            assert!(!deferred_by_preload(&notif(syscall, 0, mark ^ 1)));
        }
        assert!(invalid_flags(&notif(libc::SYS_unlinkat, 1024, mark)));
        assert!(!invalid_flags(&notif(
            libc::SYS_unlinkat,
            libc::AT_REMOVEDIR as u64,
            0
        )));
    }

    // #311: a privileged supervisor lends its credentials only to targets
    // that hold the same ones.
    #[test]
    fn privileged_supervisor_protects_only_targets_with_its_credentials() {
        use std::os::unix::process::CommandExt;
        let own = Credentials::of("self").unwrap();
        if !own.privileged() || own.fsuid != 0 {
            return; // needs root to start a target as another user
        }
        let gate = CredentialGate::Compare(own, SecurityLabels::own());
        let mut same = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let mut dropped = std::process::Command::new("sleep")
            .arg("5")
            .uid(65534)
            .gid(65534)
            .spawn()
            .unwrap();
        assert!(gate.lends_to(same.id()));
        assert!(!gate.lends_to(dropped.id()));
        assert!(!CredentialGate::Unknown.lends_to(same.id()));
        assert!(CredentialGate::Unprivileged(SecurityLabels::own()).lends_to(dropped.id()));
        for child in [&mut same, &mut dropped] {
            let _ = child.kill();
            let _ = child.wait();
        }
        // A target that vanished is never lent anything.
        assert!(!gate.lends_to(same.id()));

        // #341: a sandbox's mapped root shows root's IDs and capabilities,
        // which hold only inside its own user namespace.
        let Ok(mut sandboxed) = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "sleep", "5"])
            .spawn()
        else {
            return;
        };
        use std::os::unix::fs::MetadataExt;
        let own_namespace = std::fs::metadata("/proc/self/ns/user").map(|meta| meta.ino());
        let entered = (0..200).any(|_| {
            let namespace = std::fs::metadata(format!("/proc/{}/ns/user", sandboxed.id()))
                .map(|meta| meta.ino());
            let entered =
                namespace.is_ok() && namespace.ok() != own_namespace.as_ref().ok().copied();
            if !entered {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            entered
        });
        if entered {
            let status = Credentials::of(&sandboxed.id().to_string()).unwrap();
            assert_eq!((status.fsuid, status.fsgid), (0, 0));
            assert!(!gate.lends_to(sandboxed.id()));
        }
        let _ = sandboxed.kill();
        let _ = sandboxed.wait();
    }

    // seccomp-sup-5: seccomp traps a delete before the kernel's LSM check.
    // A target confined by AppArmor, SELinux or Smack, with credentials equal
    // to ours (or under an unprivileged supervisor), must not have deletions
    // its policy denies carried out under our unconfined label.
    #[test]
    fn targets_with_other_security_labels_are_never_lent_credentials() {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        let own = SecurityLabels::own();
        assert!(own.shared_by(tid), "{own:?}");
        let confined = SecurityLabels(vec![("attr/current", b"confined (enforce)\n".to_vec())]);
        assert!(!confined.shared_by(tid));
        assert!(CredentialGate::Unprivileged(own.clone()).lends_to(tid));
        assert!(!CredentialGate::Unprivileged(confined.clone()).lends_to(tid));
        let credentials = Credentials::of("self").unwrap();
        assert!(!CredentialGate::Compare(credentials, confined).lends_to(tid));
        // A label we know but cannot read for the target fails closed.
        let unreadable = SecurityLabels(vec![("attr/no-such-label", b"ours".to_vec())]);
        assert!(!unreadable.shared_by(tid));
        // A target that is gone carries no label at all.
        assert!(!SecurityLabels(vec![("attr/current", Vec::new())]).shared_by(u32::MAX));
    }

    // #320: stopping at the orchestrator and using its cached ancestry must
    // decide exactly like the full walk, for every name along the chain.
    #[test]
    fn session_ancestry_cache_matches_the_full_walk() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let target = child.id();
        let session = SessionAncestry::new(std::process::id());
        let mut names = vec!["sleep".to_string(), "no-such-tool".to_string()];
        let mut cur = Some(std::process::id());
        while let Some(pid) = cur {
            match trashd_common::proc_stat::comm_and_parent(pid) {
                Some((comm, parent)) => {
                    names.push(comm);
                    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
                        names.push(exe.file_name().unwrap().to_string_lossy().into_owned());
                    }
                    cur = Some(parent).filter(|parent| *parent > 1);
                }
                None => break,
            }
        }
        for name in &names {
            let bypass = [name.clone()];
            assert_eq!(
                process_bypassed(target, &bypass, &[], Some(&session)),
                process_bypassed(target, &bypass, &[], None),
                "{name}"
            );
        }
        // The cached levels are reused within the refresh interval.
        let first = session.cached.borrow().as_ref().map(|(_, at)| *at);
        process_bypassed(target, &["no-such-tool".into()], &[], Some(&session));
        assert_eq!(session.cached.borrow().as_ref().map(|(_, at)| *at), first);
        let _ = child.kill();
        let _ = child.wait();
    }

    // #323: a reinstall replaces trashd's binaries with new inodes; the
    // exemption follows them after the refresh interval.
    #[test]
    fn own_components_follow_a_reinstall() {
        use std::os::unix::fs::MetadataExt;
        let fixture = tempfile::tempdir().unwrap();
        let exe = fixture.path().join("trashd-exec");
        let cli = fixture.path().join("trash");
        std::fs::write(&cli, b"old").unwrap();
        let identity = |path: &std::path::Path| {
            let meta = std::fs::metadata(path).unwrap();
            (meta.dev(), meta.ino())
        };
        let mut own = OwnComponents {
            exe: Some(exe),
            ids: Vec::new(),
            at: std::time::Instant::now() - 2 * OwnComponents::REFRESH,
        };
        assert_eq!(own.ids(), [identity(&cli)]);
        let staged = fixture.path().join("trash.new");
        std::fs::write(&staged, b"new").unwrap();
        std::fs::rename(&staged, &cli).unwrap();
        assert_ne!(own.ids(), [identity(&cli)], "fresh ids are reused");
        own.at -= 2 * OwnComponents::REFRESH;
        assert_eq!(own.ids(), [identity(&cli)]);
    }

    #[test]
    fn bypass_gates_do_not_capture_path_and_protected_capture_runs_once() {
        use std::path::PathBuf;
        let mut config = Config::default();
        config.bypass_processes.clear();
        config.bypass_paths.clear();
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
        notif.pid = u32::MAX;
        notif.data.nr = libc::SYS_unlinkat as i32;
        notif.data.args[2] = 0x4000;
        assert!(
            capture_protected_path(&notif, &config, &[], None, || panic!("unexpected capture"))
                .unwrap()
                .is_none()
        );
        notif.data.args[2] = 0;
        let captures = std::cell::Cell::new(0);
        let result = capture_protected_path(&notif, &config, &[], None, || {
            captures.set(captures.get() + 1);
            Ok((PathBuf::from("raw"), PathBuf::from("/display/raw")))
        })
        .unwrap();
        assert_eq!(captures.get(), 1);
        assert_eq!(result.unwrap().0, PathBuf::from("raw"));

        notif.pid = std::process::id();
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        config.bypass_processes = vec![exe.file_name().unwrap().to_string_lossy().into_owned()];
        assert!(
            capture_protected_path(&notif, &config, &[], None, || panic!("unexpected capture"))
                .unwrap()
                .is_none()
        );
        config.bypass_processes.clear();
        config.bypass_paths = vec![exe.to_string_lossy().into_owned()];
        assert!(
            capture_protected_path(&notif, &config, &[], None, || panic!("unexpected capture"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn process_policy_observes_comm_changes_without_caching() {
        if std::env::var_os("TRASHD_PROCESS_POLICY_CHILD").is_some() {
            // The test harness runs on a non-leader thread, like a seccomp
            // notification's triggering task. PR_SET_NAME changes this TID.
            let pid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NAME, c"before ) (".as_ptr()) },
                0
            );
            assert!(process_bypassed(pid, &["before ) (".into()], &[], None));
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NAME, c"after".as_ptr()) },
                0
            );
            assert!(!process_bypassed(pid, &["before ) (".into()], &[], None));
            assert!(process_bypassed(pid, &["after".into()], &[], None));
            let mut config = Config::default();
            config.bypass_processes.clear();
            let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
            notif.pid = pid;
            notif.data.nr = libc::SYS_unlinkat as i32;
            assert!(
                capture_protected_path(&notif, &config, &[], None, || panic!("unexpected capture"))
                    .unwrap()
                    .is_none()
            );
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supervisor::tests::process_policy_observes_comm_changes_without_caching",
            ])
            .env("TRASHD_PROCESS_POLICY_CHILD", "1")
            .env("TRASH_BYPASS", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Once every filtered task has exited, RECV fails at once (ENOENT on
    /// current kernels) and poll reports POLLHUP. A pipe without a writer
    /// reproduces both (RECV fails with ENOTTY) without a seccomp filter.
    pub(crate) fn finished_listener() -> i32 {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe { libc::close(fds[1]) };
        fds[0]
    }

    /// Run `case` in a child that a spin cannot outlive.
    pub(crate) fn exits_cleanly(case: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::alarm(5) };
            case();
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0, "loop kept running on a finished listener");
    }

    // Regression (#195, #196): trashd's own CLI and shim perform store-
    // internal deletes (cross-device source retirement, restore rollback);
    // intercepting them re-trashed data or deadlocked on the root lock.
    // They are recognized by inode, never by name.
    #[test]
    fn own_binaries_are_recognized_by_inode() {
        use std::path::PathBuf;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("own-binaries-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A hard link makes this test process "the installed trash CLI".
        std::fs::hard_link(std::env::current_exe().unwrap(), dir.join("trash")).unwrap();
        let installed = own_component_ids(&dir.join("trashd-exec"));
        let elsewhere = own_component_ids(&dir.join("other/trashd-exec"));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(is_own_component(std::process::id(), &installed));
        assert!(!is_own_component(std::process::id(), &elsewhere));
    }

    // Regression (#224): bypass names were compared with the executable's
    // basename only, so script tools (pip is python3.x, npm is node) never
    // matched their bypass_processes entries. The kernel's comm carries the
    // script's name.
    #[test]
    fn bypass_matches_script_names() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("pip");
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut child = std::process::Command::new(&script).spawn().unwrap();
        let pid = child.id();
        let comm_ready = (0..250).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim() == "pip")
        });
        let bypassed = process_bypassed(pid, &["pip".to_string()], &[], None);
        let _ = child.kill();
        let _ = child.wait();
        assert!(comm_ready, "script never started");
        assert!(bypassed, "a running `pip` script was not recognized");
    }

    #[test]
    fn only_a_finished_listener_is_done() {
        let mut idle = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(idle.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // Live tasks with nothing pending: keep supervising.
        assert!(!listener_done(idle[0], 0));
        let finished = finished_listener();
        assert!(listener_done(finished, 0));
        unsafe {
            libc::close(idle[0]);
            libc::close(idle[1]);
            libc::close(finished);
        }
    }

    /// The kernel contract the loops rely on, against a real listener.
    #[test]
    fn real_listener_reports_hangup_after_filtered_tasks_exit() {
        let (parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            let fd = crate::seccomp_identity::random()
                .and_then(crate::filter::install_filter)
                .unwrap_or(-1);
            crate::send_fd(std::os::fd::AsRawFd::as_raw_fd(&child), fd);
            unsafe { libc::_exit(0) };
        }
        let fd = crate::recv_fd(std::os::fd::AsRawFd::as_raw_fd(&parent)).unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        if fd < 0 {
            // e.g. WSL: an inherited listener makes installation fail EBUSY.
            eprintln!("SKIP: seccomp listener unavailable");
            return;
        }
        let start = std::time::Instant::now();
        assert!(notif_recv(fd).is_err());
        assert!(listener_done(fd, 1000));
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        unsafe { libc::close(fd) };
    }

    #[test]
    fn passthrough_ends_when_the_listener_is_finished() {
        exits_cleanly(|| run_passthrough(finished_listener()).unwrap());
    }

    // #437: the session keys on the same two files Config::load reads, in
    // either order (a swap must not collide), and a removed file is a change.
    #[test]
    fn config_mtime_tracks_both_layers() {
        let fixture = tempfile::tempdir().unwrap();
        let (global, user) = (
            fixture.path().join("global.toml"),
            fixture.path().join("user.toml"),
        );
        let stamp = |path: &std::path::Path, secs: u64| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
                )
                .unwrap();
        };
        let key = || config_mtime_of(&global, &user);
        let none = key();
        assert_eq!(key(), none, "the same files give the same key");
        std::fs::write(&global, "").unwrap();
        stamp(&global, 1_000);
        let with_global = key();
        assert_ne!(with_global, none);
        std::fs::write(&user, "").unwrap();
        stamp(&user, 2_000);
        let with_both = key();
        assert_ne!(with_both, with_global);
        // global=2000/user=1000 must differ from global=1000/user=2000, which
        // a symmetric sum would not catch (the preload's mtime key, #283).
        stamp(&global, 2_000);
        stamp(&user, 1_000);
        assert_ne!(key(), with_both);
        // A removed layer is a change, not the same key with a zero.
        std::fs::remove_file(&global).unwrap();
        assert_ne!(key(), with_both);
        assert_ne!(key(), none, "the surviving layer still counts");
        // Same-second edits must still register: the key is nanosecond
        // resolution, so two stamps one nanosecond apart differ.
        std::fs::File::options()
            .write(true)
            .open(&user)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::new(1_000, 1)),
            )
            .unwrap();
        let ns_one = key();
        std::fs::File::options()
            .write(true)
            .open(&user)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::new(1_000, 2)),
            )
            .unwrap();
        assert_ne!(key(), ns_one, "sub-second edit must change the key");

        // seccomp-sup-3: Nix and home-manager link every generation's config
        // to a store file with one normalized mtime. Retargeting the link
        // changes the policy, never the followed mtime.
        let stamp_ns = |path: &std::path::Path, time: std::time::SystemTime| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(time))
                .unwrap();
        };
        let normalized = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
        let generations = [fixture.path().join("a.toml"), fixture.path().join("b.toml")];
        for (generation, content) in generations
            .iter()
            .zip(["only_trash = []\n", "never_trash = []\n"])
        {
            std::fs::write(generation, content).unwrap();
            stamp_ns(generation, normalized);
        }
        std::os::unix::fs::symlink(&generations[0], &global).unwrap();
        let first = key();
        let staged = fixture.path().join("global.next");
        std::os::unix::fs::symlink(&generations[1], &staged).unwrap();
        std::fs::rename(&staged, &global).unwrap();
        assert_ne!(key(), first, "a retargeted config link must change the key");
        // A present file stamped at the epoch is not a missing file.
        std::fs::remove_file(&global).unwrap();
        let missing = key();
        std::fs::write(&global, "").unwrap();
        stamp_ns(&global, std::time::UNIX_EPOCH);
        assert_ne!(
            key(),
            missing,
            "an epoch-stamped file keys like a missing one"
        );
    }

    // #437: a changed mtime swaps in the reloaded store, a failed load keeps
    // the previous one serving, and an unchanged mtime never loads at all.
    #[test]
    fn session_refresh_swaps_stores_only_on_change() {
        let fixture = tempfile::tempdir().unwrap();
        let store = |name: &str| {
            TrashStore::open_isolated(&fixture.path().join(name), trashd_common::Config::default())
                .unwrap()
        };
        let mut session = SessionState::from_parts(store("one"));
        assert_eq!(session.store().home_dir(), fixture.path().join("one"));

        // `from_parts` sampled the ambient configuration's mtime; adopt a
        // fixed baseline by reloading the same store at a known sample.
        assert!(session.refresh_with(1_000, || Some(store("one"))));
        // The same sample never loads.
        assert!(!session.refresh_with(1_000, || panic!("unchanged mtime must not load")));
        assert_eq!(session.store().home_dir(), fixture.path().join("one"));

        // A change reloads config AND store, and the new store serves.
        let loads = std::cell::Cell::new(0usize);
        assert!(session.refresh_with(2_000, || {
            loads.set(loads.get() + 1);
            Some(store("two"))
        }));
        assert_eq!(loads.get(), 1);
        assert_eq!(session.store().home_dir(), fixture.path().join("two"));

        // A failed reload keeps the previous configuration serving.
        assert!(!session.refresh_with(3_000, || None));
        assert_eq!(session.store().home_dir(), fixture.path().join("two"));
        // And the failed sample became the baseline again.
        assert!(!session.refresh_with(3_000, || panic!("failed sample must be adopted")));

        // seccomp-sup-2: the reload runs after a notification was dequeued
        // and outside the handler's guard. A panicking load must keep the
        // previous store serving rather than end the supervisor with that
        // notification unanswered.
        let reloaded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            session.refresh_with(4_000, || panic!("reload panics"))
        }));
        assert_eq!(reloaded.ok(), Some(false), "a reload panic escaped");
        assert_eq!(session.store().home_dir(), fixture.path().join("two"));
        assert!(!session.refresh_with(4_000, || panic!("failed sample must be adopted")));
    }

    // seccomp-sup-1: the launch-time store ran retention inside the trapped
    // syscall, before the target had its answer (#319); only a reloaded
    // store deferred it.
    #[test]
    fn session_stores_defer_retention_until_the_target_is_answered() {
        use std::os::fd::AsRawFd;
        let fixture = tempfile::tempdir().unwrap();
        let work = fixture.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let store = |name: &str| {
            let config = trashd_common::Config {
                never_trash: Vec::new(),
                ..Default::default()
            };
            TrashStore::open_isolated(&fixture.path().join(name), config).unwrap()
        };
        let parent = std::fs::File::open(&work).unwrap();
        let trash = |session: &SessionState, name: &str| {
            let path = work.join(name);
            std::fs::write(&path, b"deferred").unwrap();
            let marker = session.store().home_dir().join(".trashd/last_purge");
            let _ = std::fs::remove_file(&marker);
            session
                .store()
                .trash_at_canonical(
                    parent.as_raw_fd(),
                    std::ffi::OsStr::new(name),
                    &path,
                    Some("seccomp"),
                    || true,
                )
                .unwrap();
            assert!(!marker.exists(), "retention ran before the answer");
            session.store().run_deferred_maintenance();
            assert!(marker.exists(), "deferred retention runs after it");
        };
        let mut session = SessionState::from_parts(store("launch"));
        trash(&session, "at-launch.txt");
        assert!(session.refresh_with(i64::MIN, || Some(store("reloaded"))));
        trash(&session, "after-reload.txt");
    }
}
