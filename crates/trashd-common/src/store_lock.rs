//! Cross-process publication/retirement lock shared by every trash writer.
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

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

impl RootMutationGuard {
    pub fn acquire(root: &Path) -> io::Result<Self> {
        Self::acquire_as(root, unsafe { libc::geteuid() })
    }

    /// `acquire` for a caller that already knows its effective UID.
    pub fn acquire_as(root: &Path, uid: u32) -> io::Result<Self> {
        Self::acquire_with(root, uid, false)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }

    /// Try the same validated lock without waiting for an active writer.
    /// Maintenance uses this to leave live copy stages alone (#383).
    pub(crate) fn try_acquire_as(root: &Path, uid: u32) -> io::Result<Option<Self>> {
        Self::acquire_with(root, uid, true)
    }

    fn acquire_with(root: &Path, uid: u32, nonblocking: bool) -> io::Result<Option<Self>> {
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
        loop {
            let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
            if unsafe { libc::flock(lock.as_raw_fd(), flags) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if nonblocking && e.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
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
