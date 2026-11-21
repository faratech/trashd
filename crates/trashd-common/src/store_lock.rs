//! Cross-process publication/retirement lock shared by every trash writer.
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long a writer waits for a trash root's lock before it reports the
/// trash busy (EBUSY). Holders keep it for one publication, sidecar write
/// or detach, never for a copy; a longer hold is a holder that was stopped
/// (Ctrl-Z, SIGSTOP) or hangs on its filesystem. Waiting without a bound
/// hung every delete of the user behind it, the preload's inside arbitrary
/// processes' unlink() included (store-metadata-6).
pub const ROOT_LOCK_WAIT: Duration = Duration::from_secs(10);

/// The wait once a lock has timed out in this process, until an
/// acquisition of it succeeds again or `STUCK_MEMORY` passes: long enough
/// for ordinary contention, short enough that a process deleting many
/// files behind a stuck holder does not wait the full bound for each.
const STUCK_LOCK_WAIT: Duration = Duration::from_millis(250);
const STUCK_MEMORY: Duration = Duration::from_secs(60);

/// The lock that last timed out here (device and inode folded into one
/// word, 0 for none) and until when that is remembered, in milliseconds on
/// `clock()`. Two words that are not updated together: a race only makes
/// one wait longer or shorter than intended.
static STUCK_LOCK: AtomicU64 = AtomicU64::new(0);
static STUCK_UNTIL: AtomicU64 = AtomicU64::new(0);

/// Milliseconds on the monotonic clock.
fn clock() -> u64 {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    (now.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(now.tv_nsec as u64 / 1_000_000)
}

fn lock_key(lock: &std::fs::Metadata) -> u64 {
    (lock.dev().rotate_left(32) ^ lock.ino()).max(1)
}

/// The error of a root lock that stayed held for the whole wait: EBUSY,
/// which unlink(2) and rmdir(2) document and every layer reports without
/// deleting anything.
fn busy() -> io::Error {
    io::Error::from_raw_os_error(libc::EBUSY)
}

/// A locked trash root and the descriptors it was validated through.
///
/// Every mutation of the root goes through `files()`, `info()` and
/// `state()`, never through a path below `root()`: a FUSE or NFS server
/// answers each lookup as it likes, so it could show the lock a private
/// `files/` and every later path walk a symlink to `/etc` (security-1,
/// security-2). The descriptors are those directories as validated: real
/// directories (no symlink followed), owned by the user, mode 0700, on the
/// root's own device.
pub struct RootMutationGuard {
    _lock: File,
    root: PathBuf,
    root_dir: File,
    files: File,
    info: File,
    state: File,
}

/// `fd` if it is a directory owned by `uid` with mode 0700, on `device`
/// when one is given (EXDEV otherwise).
fn private_directory(fd: File, uid: u32, device: Option<u64>) -> io::Result<File> {
    let m = fd.metadata()?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    if device.is_some_and(|device| m.dev() != device) {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(fd)
}

/// Open and validate a store directory of the pinned root `dir` (see
/// `private_directory`), following no symlink. A symlink reports ELOOP, as
/// it did when this was an fstatat: Linux checks O_DIRECTORY first and says
/// ENOTDIR.
fn private_child(dir: i32, name: &std::ffi::CStr, uid: u32, device: u64) -> io::Result<File> {
    let child = match open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(child) => child,
        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) }
                == 0
                && stat.st_mode & libc::S_IFMT == libc::S_IFLNK
            {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    private_directory(child, uid, Some(device))
}

fn open_at(dir: i32, name: &std::ffi::CStr, flags: i32, mode: u32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `.trashd/store.lock` under the pinned root, following no symlink in
/// either component: a filesystem whose server controls entry types (a
/// FUSE or NFS mount) could swap the checked `.trashd` for a symlink before
/// the open (#354). Opened in two steps with syscalls every seccomp
/// allowlist has: this runs inside every process the preload is loaded
/// into, and openat2 killed those under allowlists that predate it (#357).
/// Returns the state directory too.
fn open_lock(root: i32, uid: u32, device: Option<u64>) -> io::Result<(File, File)> {
    let state = private_directory(
        open_at(root, c".trashd", libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
        uid,
        device,
    )?;
    let lock = open_at(
        state.as_raw_fd(),
        c"store.lock",
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        0o600,
    )?;
    Ok((state, lock))
}

/// flock(LOCK_EX) on a root's lock file within `wait` (None: one attempt);
/// false when it stayed held. Polled, never blocking: flock(2) has no
/// timeout, and a blocking one waited for as long as its holder lived or
/// stayed stopped (store-metadata-6). The first pauses are short, so a
/// writer behind an ordinary holder loses microseconds, not a timer tick.
fn lock_within(lock: &File, key: u64, wait: Option<Duration>) -> io::Result<bool> {
    let remembered =
        STUCK_LOCK.load(Ordering::Relaxed) == key && clock() < STUCK_UNTIL.load(Ordering::Relaxed);
    let wait = wait.map(|wait| {
        if remembered {
            wait.min(STUCK_LOCK_WAIT)
        } else {
            wait
        }
    });
    let deadline = wait.map(|wait| Instant::now() + wait);
    let mut pause = Duration::from_micros(50);
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            if remembered {
                STUCK_UNTIL.store(0, Ordering::Relaxed);
            }
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {}
            _ => return Err(error),
        }
        let Some(deadline) = deadline else {
            return Ok(false);
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            STUCK_LOCK.store(key, Ordering::Relaxed);
            STUCK_UNTIL.store(
                clock().saturating_add(STUCK_MEMORY.as_millis() as u64),
                Ordering::Relaxed,
            );
            return Ok(false);
        }
        sleep(pause.min(left));
        pause = (pause * 2).min(Duration::from_millis(20));
    }
}

/// Sleep for about `duration`. Not `std::thread::sleep`, which asserts
/// that the call can only be interrupted: this runs inside arbitrary
/// processes (the preload), and one whose seccomp filter answers the sleep
/// with an errno must not be aborted by it. A sleep that ends early, or
/// does not happen, only makes the next attempt come sooner.
fn sleep(duration: Duration) {
    let request = libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    };
    unsafe { libc::nanosleep(&request, std::ptr::null_mut()) };
}

/// A hold on `.trashd/copy.lock`: shared by every writer with a copy staged
/// in the state directory, exclusive for the sweep that claims abandoned
/// stages. A copy is staged without the root lock (store-metadata-6), so
/// the root lock no longer says whether a stage's writer is alive; this
/// does, and it dies with the writer. Unlocked explicitly on drop, as the
/// root lock is: a forked child may hold a descriptor of it too.
pub struct StageLease(File);

impl Drop for StageLease {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl RootMutationGuard {
    pub fn acquire(root: &Path) -> io::Result<Self> {
        Self::acquire_as(root, unsafe { libc::geteuid() })
    }

    /// `acquire` for a caller that already knows its effective UID.
    pub fn acquire_as(root: &Path, uid: u32) -> io::Result<Self> {
        Self::acquire_within(root, uid, ROOT_LOCK_WAIT)
    }

    /// `acquire_as` that reports the root busy (EBUSY) once its lock stayed
    /// held for `wait`.
    pub fn acquire_within(root: &Path, uid: u32, wait: Duration) -> io::Result<Self> {
        Self::acquire_with(root, uid, Some(wait))?.ok_or_else(busy)
    }

    /// Try the same validated lock without waiting for an active writer.
    /// Maintenance uses this to leave live copy stages alone (#383).
    pub(crate) fn try_acquire_as(root: &Path, uid: u32) -> io::Result<Option<Self>> {
        Self::acquire_with(root, uid, None)
    }

    /// `wait` None: one attempt, Ok(None) when the lock is held. Some: until
    /// the wait is over, then Ok(None) as well.
    fn acquire_with(root: &Path, uid: u32, wait: Option<Duration>) -> io::Result<Option<Self>> {
        let name = CString::new(root.as_os_str().as_bytes())?;
        #[cfg(test)]
        validation_probe::run(root, false);
        let directory = private_directory(
            open_at(libc::AT_FDCWD, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
            uid,
            None,
        )?;
        let device = directory.metadata()?.dev();
        // The children are kept open and used for every mutation: checked
        // with one fstatat each and then resolved again by path, a FUSE or
        // NFS server answered the check with a directory and the mutation
        // with a symlink (security-1, security-2).
        let files = private_child(directory.as_raw_fd(), c"files", uid, device)?;
        let info = private_child(directory.as_raw_fd(), c"info", uid, device)?;
        // Create the state directory only when it is missing, not on every
        // acquisition.
        let (state, lock) = match open_lock(directory.as_raw_fd(), uid, Some(device)) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                if unsafe { libc::mkdirat(directory.as_raw_fd(), c".trashd".as_ptr(), 0o700) } < 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                {
                    return Err(io::Error::last_os_error());
                }
                open_lock(directory.as_raw_fd(), uid, Some(device))?
            }
            result => result?,
        };
        let m = lock.metadata()?;
        if !m.is_file() || m.uid() != uid || m.nlink() != 1 || m.mode() & 0o777 != 0o600 {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        if !lock_within(&lock, lock_key(&m), wait)? {
            return Ok(None);
        }
        #[cfg(test)]
        validation_probe::run(root, true);
        Ok(Some(Self {
            _lock: lock,
            root: root.to_path_buf(),
            root_dir: directory,
            files,
            info,
            state,
        }))
    }

    /// The root's path, as given: for messages and for matching entries,
    /// never for resolving anything below it again.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The validated root directory.
    pub fn root_dir(&self) -> &File {
        &self.root_dir
    }

    /// The validated `files/`.
    pub fn files(&self) -> &File {
        &self.files
    }

    /// The validated `info/`.
    pub fn info(&self) -> &File {
        &self.info
    }

    /// The validated private state directory, `.trashd/`.
    pub fn state(&self) -> &File {
        &self.state
    }

    /// `.trashd/copy.lock`, locked with `operation` without waiting; None
    /// when another holder excludes it.
    fn stage_lock(&self, operation: libc::c_int) -> io::Result<Option<StageLease>> {
        // Read-write: NFS takes a shared lock only on a readable descriptor
        // and an exclusive one only on a writable one.
        let lock = open_at(
            self.state.as_raw_fd(),
            c"copy.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        let m = lock.metadata()?;
        if !m.is_file() || m.uid() != self.state.metadata()?.uid() || m.nlink() != 1 {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        loop {
            if unsafe { libc::flock(lock.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
                return Ok(Some(StageLease(lock)));
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(None),
                _ => return Err(error),
            }
        }
    }

    /// Announce a copy this writer stages in the state directory and goes
    /// on with after releasing the root lock: until the lease is dropped no
    /// sweep takes a copy stage of this root for abandoned. Taken under the
    /// root lock, where only a sweep that also holds it could exclude it.
    pub fn lease_stages(&self) -> io::Result<StageLease> {
        self.stage_lock(libc::LOCK_SH)?.ok_or_else(busy)
    }

    /// The sweep's side: Some while no writer has a copy staged, and for as
    /// long as the result is held none can start one.
    pub fn claim_idle_stages(&self) -> io::Result<Option<StageLease>> {
        self.stage_lock(libc::LOCK_EX)
    }
}

impl Drop for RootMutationGuard {
    /// Unlock explicitly instead of leaving it to the close. The lock
    /// belongs to the open file description, and a child forked by another
    /// thread while the guard was held has a descriptor of it too: closing
    /// ours left that child (a fork pool worker that never execs) holding
    /// the store's lock, and every writer of that trash waiting, for as
    /// long as it lived (preload-4). Unlocking through any descriptor of
    /// the description releases it. Nothing relies on a forked child
    /// keeping the lock.
    fn drop(&mut self) {
        unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Test hook: runs with a root's path and `false` right before
/// `acquire_with` validates it, and with `true` once it holds the validated
/// descriptors. Tests show `files/` as a symlink to everything but the
/// validation, as a FUSE server can (security-1, security-2).
#[cfg(test)]
pub(crate) mod validation_probe {
    use std::path::{Path, PathBuf};

    type Hook = Box<dyn Fn(&Path, bool)>;

    thread_local! {
        static PROBE: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
    }

    /// Install (or with None, remove) this thread's probe.
    pub(crate) fn set(probe: Option<Hook>) {
        PROBE.with_borrow_mut(|slot| *slot = probe);
    }

    pub(crate) fn run(root: &Path, validated: bool) {
        PROBE.with_borrow(|probe| {
            if let Some(probe) = probe {
                probe(root, validated);
            }
        });
    }

    /// Where `serve_files_as_symlink` keeps the real `files/` of `root`.
    pub(crate) fn real_files(root: &Path) -> PathBuf {
        root.join("files.real")
    }

    fn swap_out(root: &Path, victim: &Path) {
        std::fs::rename(root.join("files"), real_files(root)).unwrap();
        std::os::unix::fs::symlink(victim, root.join("files")).unwrap();
    }

    /// Answer every lookup of `root/files` with a symlink to `victim`, but
    /// the lock's own validation with the real directory, as a FUSE server
    /// can. The real directory waits at `real_files(root)` meanwhile.
    pub(crate) fn serve_files_as_symlink(root: &Path, victim: &Path) {
        swap_out(root, victim);
        let (root, victim) = (root.to_path_buf(), victim.to_path_buf());
        set(Some(Box::new(move |locked, validated| {
            if locked != root {
                return;
            }
            if validated {
                swap_out(&root, &victim);
            } else {
                std::fs::remove_file(root.join("files")).unwrap();
                std::fs::rename(real_files(&root), root.join("files")).unwrap();
            }
        })));
    }
}

#[cfg(test)]
mod tests {
    // #354: the lock open itself refuses a symlinked state directory, not
    // only the check before it.
    #[test]
    fn lock_open_follows_no_symlink() {
        use std::os::fd::AsRawFd;
        let fixture = tempfile::tempdir().unwrap();
        let elsewhere = fixture.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, fixture.path().join(".trashd")).unwrap();
        let root = std::fs::File::open(fixture.path()).unwrap();
        let uid = unsafe { libc::geteuid() };
        let error = super::open_lock(root.as_raw_fd(), uid, None).unwrap_err();
        // O_NOFOLLOW|O_DIRECTORY on a symlink reports ENOTDIR.
        assert!(
            matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)),
            "{error}"
        );
        assert!(!elsewhere.join("store.lock").exists());
        std::fs::remove_file(fixture.path().join(".trashd")).unwrap();
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(fixture.path().join(".trashd"))
            .unwrap();
        assert!(super::open_lock(root.as_raw_fd(), uid, None).is_ok());
    }

    #[test]
    fn store_children_are_validated_with_open_errnos() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("Trash");
        let make =
            |path: &std::path::Path| std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        make(&root);
        let errno = || {
            super::RootMutationGuard::acquire(&root)
                .err()
                .and_then(|e| e.raw_os_error())
        };
        assert_eq!(errno(), Some(libc::ENOENT), "missing files/");
        std::fs::write(root.join("files"), b"").unwrap();
        assert_eq!(errno(), Some(libc::ENOTDIR), "regular files/");
        std::fs::remove_file(root.join("files")).unwrap();
        symlink(fixture.path(), root.join("files")).unwrap();
        assert_eq!(errno(), Some(libc::ELOOP), "symlinked files/");
        std::fs::remove_file(root.join("files")).unwrap();
        make(&root.join("files"));
        make(&root.join("info"));
        std::fs::set_permissions(root.join("info"), std::fs::Permissions::from_mode(0o750))
            .unwrap();
        assert_eq!(errno(), Some(libc::EACCES), "group-accessible info/");
        std::fs::set_permissions(root.join("info"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        // The state directory is created on demand, then reused.
        assert!(!root.join(".trashd").exists());
        drop(super::RootMutationGuard::acquire(&root).unwrap());
        assert!(root.join(".trashd/store.lock").is_file());
        drop(super::RootMutationGuard::acquire(&root).unwrap());
    }

    // security-1: the lock keeps descriptors of files/ and info/ only on
    // the root's own device; one mounted over (another filesystem a server
    // controls) is refused with EXDEV.
    #[test]
    fn store_directories_must_share_the_roots_device() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("Trash");
        for p in [&root, &root.join("files"), &root.join("info")] {
            std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
        }
        let verdict = crate::mounts::in_private_mounts(
            "store_lock::tests::store_directories_must_share_the_roots_device",
            || {
                let files =
                    std::ffi::CString::new(root.join("files").as_os_str().as_encoded_bytes())
                        .unwrap();
                if unsafe {
                    libc::mount(
                        c"none".as_ptr(),
                        files.as_ptr(),
                        c"tmpfs".as_ptr(),
                        0,
                        c"mode=0700".as_ptr().cast(),
                    )
                } != 0
                {
                    return false;
                }
                let _ = std::fs::set_permissions(
                    root.join("files"),
                    std::fs::Permissions::from_mode(0o700),
                );
                let refused = super::RootMutationGuard::acquire(&root)
                    .err()
                    .and_then(|e| e.raw_os_error())
                    == Some(libc::EXDEV);
                unsafe { libc::umount2(files.as_ptr(), libc::MNT_DETACH) };
                refused && super::RootMutationGuard::acquire(&root).is_ok()
            },
        );
        assert_ne!(verdict, Some(false));
    }

    // preload-4: an flock belongs to the open file description, which a
    // fork duplicates. A child forked by another thread while a guard was
    // held, and that never execs (a fork pool worker), kept the store locked
    // after the guard was dropped: every later writer of that trash waited
    // forever, in every layer.
    #[test]
    fn a_dropped_guard_unlocks_while_a_forked_child_still_holds_its_descriptor() {
        use std::os::unix::fs::DirBuilderExt;
        const CHILD: &str = "TRASHD_TEST_FORKED_LOCK";
        const TEST: &str = "store_lock::tests::a_dropped_guard_unlocks_while_a_forked_child_still_holds_its_descriptor";
        if !crate::mounts::is_rerun_child(TEST, CHILD) {
            assert_eq!(crate::mounts::rerun_test(TEST, CHILD), Some(true));
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("Trash");
        for p in [&root, &root.join("files"), &root.join("info")] {
            std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
        }
        let uid = unsafe { libc::geteuid() };
        let guard = super::RootMutationGuard::acquire_as(&root, uid).unwrap();
        let held = matches!(
            super::RootMutationGuard::try_acquire_as(&root, uid),
            Ok(None)
        );
        // The re-run child runs this one test: forking here is the scenario.
        let forked = unsafe { libc::fork() };
        assert!(forked >= 0);
        if forked == 0 {
            // Lives on with the inherited descriptor, and never execs.
            unsafe {
                libc::alarm(60);
                loop {
                    libc::pause();
                }
            }
        }
        drop(guard);
        let unlocked = matches!(
            super::RootMutationGuard::try_acquire_as(&root, uid),
            Ok(Some(_))
        );
        unsafe {
            libc::kill(forked, libc::SIGKILL);
            libc::waitpid(forked, std::ptr::null_mut(), 0);
        }
        eprintln!("held {held} unlocked {unlocked}");
        crate::mounts::report_test_verdict(Some(held && unlocked));
    }

    fn private_root(fixture: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let root = fixture.join("Trash");
        for p in [&root, &root.join("files"), &root.join("info")] {
            std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
        }
        root
    }

    // store-metadata-6: every writer waited for the root lock in a blocking
    // flock, for as long as its holder lived or stayed stopped. The wait
    // ends busy, and a process that has just waited it out for a lock waits
    // only briefly for the same one until it gets it again.
    #[test]
    fn a_held_lock_ends_the_wait_busy_and_is_remembered() {
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};
        const CHILD: &str = "TRASHD_TEST_STUCK_LOCK";
        const TEST: &str = "store_lock::tests::a_held_lock_ends_the_wait_busy_and_is_remembered";
        // The memory of a stuck lock is one per process: alone in a child.
        if !crate::mounts::is_rerun_child(TEST, CHILD) {
            assert_eq!(crate::mounts::rerun_test(TEST, CHILD), Some(true));
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let root = private_root(fixture.path());
        let uid = unsafe { libc::geteuid() };
        // Another open file description, as another process has.
        let holder = super::RootMutationGuard::acquire_as(&root, uid).unwrap();
        let started = Instant::now();
        let first =
            super::RootMutationGuard::acquire_within(&root, uid, Duration::from_millis(150))
                .err()
                .and_then(|error| error.raw_os_error());
        let first_wait = started.elapsed();
        // Asked to wait half a minute, it gives up after the short wait.
        let started = Instant::now();
        let second = super::RootMutationGuard::acquire_within(&root, uid, Duration::from_secs(30))
            .err()
            .and_then(|error| error.raw_os_error());
        let second_wait = started.elapsed();
        let try_lock = matches!(
            super::RootMutationGuard::try_acquire_as(&root, uid),
            Ok(None)
        );
        drop(holder);
        // Free again: taken at once, and nothing is remembered.
        let free = super::RootMutationGuard::acquire_within(&root, uid, Duration::from_secs(30));
        let forgotten = super::STUCK_UNTIL.load(Ordering::Relaxed) == 0;
        eprintln!(
            "first {first:?} after {first_wait:?}, second {second:?} after {second_wait:?}, \
             try_lock {try_lock}, free {}, forgotten {forgotten}",
            free.is_ok()
        );
        crate::mounts::report_test_verdict(Some(
            first == Some(libc::EBUSY)
                && first_wait >= Duration::from_millis(150)
                && first_wait < Duration::from_secs(5)
                && second == Some(libc::EBUSY)
                && second_wait < Duration::from_secs(5)
                && try_lock
                && free.is_ok()
                && forgotten,
        ));
    }

    // store-metadata-6: a copy is staged without the root lock, so the
    // sweep of abandoned stages asks the stage lock whether a writer is
    // still copying.
    #[test]
    fn a_leased_stage_excludes_the_sweep_until_it_is_dropped() {
        let fixture = tempfile::tempdir().unwrap();
        let root = private_root(fixture.path());
        let guard = super::RootMutationGuard::acquire(&root).unwrap();
        assert!(guard.claim_idle_stages().unwrap().is_some());
        // Leases are shared: every copier of the root holds one.
        let first = guard.lease_stages().unwrap();
        let second = guard.lease_stages().unwrap();
        assert!(guard.claim_idle_stages().unwrap().is_none());
        drop(first);
        assert!(guard.claim_idle_stages().unwrap().is_none());
        drop(second);
        // While a sweep claims the stages, no copy starts.
        let claim = guard.claim_idle_stages().unwrap();
        assert!(claim.is_some());
        assert_eq!(
            guard.lease_stages().err().and_then(|e| e.raw_os_error()),
            Some(libc::EBUSY)
        );
        drop(claim);
        drop(guard.lease_stages().unwrap());
        // The lock file is opened like store.lock: no symlink is followed.
        let victim = fixture.path().join("victim");
        std::fs::remove_file(root.join(".trashd/copy.lock")).unwrap();
        std::os::unix::fs::symlink(&victim, root.join(".trashd/copy.lock")).unwrap();
        assert!(guard.lease_stages().is_err());
        assert!(guard.claim_idle_stages().is_err());
        assert!(!victim.exists());
    }

    #[test]
    fn unsafe_lock_never_changes_the_victim() {
        use std::os::unix::fs::{DirBuilderExt, symlink};
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("Trash");
        for p in [
            &root,
            &root.join("files"),
            &root.join("info"),
            &root.join(".trashd"),
        ] {
            std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
        }
        let victim = fixture.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, root.join(".trashd/store.lock")).unwrap();
        assert!(super::RootMutationGuard::acquire(&root).is_err());
        assert_eq!(std::fs::read(victim).unwrap(), b"untouched");
    }
}
