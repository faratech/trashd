//! Cross-process publication/retirement lock shared by every trash writer.
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub struct RootMutationGuard {
    _lock: File,
    root: PathBuf,
}

fn private_directory(fd: File, uid: u32) -> io::Result<File> {
    let m = fd.metadata()?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(fd)
}

/// The same checks as `private_directory` for an entry of a pinned
/// directory, with the errors an `O_NOFOLLOW|O_DIRECTORY` open would give.
fn private_child(dir: i32, name: &std::ffi::CStr, uid: u32) -> io::Result<()> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        return Err(io::Error::last_os_error());
    }
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFDIR => {}
        libc::S_IFLNK => return Err(io::Error::from_raw_os_error(libc::ELOOP)),
        _ => return Err(io::Error::from_raw_os_error(libc::ENOTDIR)),
    }
    if stat.st_uid != uid || stat.st_mode & 0o777 != 0o700 {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(())
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
fn open_lock(root: i32, uid: u32) -> io::Result<File> {
    let state = private_directory(
        open_at(root, c".trashd", libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
        uid,
    )?;
    open_at(
        state.as_raw_fd(),
        c"store.lock",
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        0o600,
    )
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
        let directory = private_directory(
            open_at(libc::AT_FDCWD, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?,
            uid,
        )?;
        // A child of the pinned, private root needs no descriptor of its own:
        // one fstatat per child replaces open, fstat and close.
        for child in [c"files", c"info"] {
            private_child(directory.as_raw_fd(), child, uid)?;
        }
        // Create the state directory only when it is missing, not on every
        // acquisition.
        let lock = match open_lock(directory.as_raw_fd(), uid) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                if unsafe { libc::mkdirat(directory.as_raw_fd(), c".trashd".as_ptr(), 0o700) } < 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                {
                    return Err(io::Error::last_os_error());
                }
                open_lock(directory.as_raw_fd(), uid)?
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
        Ok(Some(Self {
            _lock: lock,
            root: root.to_path_buf(),
        }))
    }

    pub fn root(&self) -> &Path {
        &self.root
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
        let error = super::open_lock(root.as_raw_fd(), uid).unwrap_err();
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
        assert!(super::open_lock(root.as_raw_fd(), uid).is_ok());
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
