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
    let store = match TrashStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("trashd-exec: supervisor: failed to open trash store: {e}");
            signal_ready(ready_fd, false);
            if ready_fd >= 0 {
                return Err(io::Error::other(e));
            }
            eprintln!("trashd-exec: supervisor: falling back to CONTINUE-only mode");
            return run_passthrough(fd);
        }
    };

    let config = Config::load();
    let own = std::fs::read_link("/proc/self/exe")
        .map(|exe| own_component_ids(&exe))
        .unwrap_or_default();
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
                    eprintln!("trashd-exec: supervisor: recv error: {e}");
                }
                if listener_done(fd, -1) {
                    return Ok(());
                }
                continue;
            }
        };

        // Handle this notification (fail-safe: any error → CONTINUE)
        handle_notification(fd, &notif, &store, &config, &own);
    }
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
fn handle_notification(
    fd: i32,
    notif: &SeccompNotif,
    store: &TrashStore,
    config: &Config,
    own: &[(u64, u64)],
) {
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

    // trashd's own binaries remove only what their store logic decided to
    // remove; re-trashing that deadlocked or duplicated data (#195, #196).
    if is_own_component(notif.pid, own) {
        respond_continue(fd, notif.id);
        return;
    }

    // Raw pathname argument from the target's memory. The target is frozen in
    // its syscall, so this memory is stable against the TARGET; a sibling
    // sharing its memory could mutate it (documented residual micro-race —
    // every ptrace/seccomp supervisor has it).
    let raw = match mem::read_arg_path(notif.pid, notif.data.nr, &notif.data.args) {
        Ok(p) => p,
        Err(_) => {
            // Can't read path → let the real syscall run
            respond_continue(fd, notif.id);
            return;
        }
    };
    // Best-effort full path for logging and the .trashinfo Path= field when
    // the pinned parent cannot name itself. Never used to touch the inode
    // (#6), nor for never_trash: a spelling such as `/proc/self/cwd/x` says
    // nothing about where the file lives, so the store judges the path
    // derived from the pinned parent instead (#226).
    let display = match mem::resolve_syscall_path(notif.pid, notif.data.nr, &notif.data.args) {
        Ok(p) => p,
        Err(_) => {
            respond_continue(fd, notif.id);
            return;
        }
    };

    // From this point, ALL code paths MUST send a response.
    // Failure to respond will hang the supervised process.

    if notif.data.nr == libc::SYS_unlinkat as i32
        && (notif.data.args[2] as i32 & !libc::AT_REMOVEDIR) != 0
    {
        respond_continue(fd, notif.id);
        return;
    }

    // Honor bypass_processes: if the deleting process (or an ancestor) is in
    // the bypass list (git, cargo, apt, …), let the real delete happen — same
    // as the shim/preload layers do.
    if process_bypassed(notif.pid, &config.bypass_processes) {
        respond_continue(fd, notif.id);
        return;
    }

    // Honor TRASH_BYPASS=1 in the target's environment (#18).
    if target_bypassed(notif.pid) {
        respond_continue(fd, notif.id);
        return;
    }

    // Honor bypass_paths against the TRAPPING process's executable (#21).
    if !config.bypass_paths.is_empty()
        && let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", notif.pid))
    {
        let exe_str = exe.to_string_lossy();
        if config
            .bypass_paths
            .iter()
            .any(|p| exe_str.starts_with(p.as_str()))
        {
            respond_continue(fd, notif.id);
            return;
        }
    }

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
        Ok(pin::Decision::Errno(e)) => {
            let _ = respond_errno(fd, notif.id, e);
        }
        // Kernel lacks pidfd_getfd/openat2, fds couldn't be pinned, or the
        // trash lives on another device: execute the original syscall in the
        // target's namespace. A supervisor-side path fallback could resolve
        // the same string to an unrelated host inode.
        Err(_) => respond_continue(fd, notif.id),
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
    std::fs::metadata(format!("/proc/{pid}/exe"))
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
    match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(data) => data.split(|&b| b == 0).any(|e| e == b"TRASH_BYPASS=1"),
        Err(_) => false,
    }
}

/// Walk the target's process tree from `pid` upward; return true if any
/// process name is in the bypass list. Mirrors the preload layer's logic so a
/// given process makes the same trash/skip decision regardless of which
/// interception layer is active.
fn process_bypassed(pid: u32, bypass: &[String]) -> bool {
    if bypass.is_empty() {
        return false;
    }
    let mut cur = pid;
    for _ in 0..16 {
        if process_names(cur).iter().any(|name| bypass.contains(name)) {
            return true;
        }
        match parent_pid(cur) {
            Some(p) if p > 1 && p != cur => cur = p,
            _ => break,
        }
    }
    false
}

/// Parse the parent PID (field 4) from /proc/{pid}/stat, accounting for a comm
/// field that may itself contain spaces/parens.
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat.get(after_comm..)?.split_whitespace().collect();
    fields.get(1)?.parse().ok()
}

fn process_names(pid: u32) -> Vec<String> {
    // Both the executable's basename and the kernel's comm: for a script,
    // comm is the script's own name (pip, npm) while the executable is its
    // interpreter, so bypass entries for script tools never matched (#224).
    let mut names = Vec::with_capacity(2);
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe"))
        && let Some(name) = exe.file_name()
    {
        names.push(name.to_string_lossy().into_owned());
    }
    if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        let comm = comm.trim().to_string();
        if !names.contains(&comm) {
            names.push(comm);
        }
    }
    names
}

/// Passthrough mode: respond CONTINUE to every notification.
/// Used when the trash store can't be opened.
fn run_passthrough(fd: i32) -> io::Result<()> {
    loop {
        match notif_recv(fd) {
            Ok(notif) => respond_continue(fd, notif.id),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => return Ok(()),
            Err(_) if listener_done(fd, -1) => return Ok(()),
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
        let bypassed = process_bypassed(pid, &["pip".to_string()]);
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
}
