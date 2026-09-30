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

fn private_directory(fd: File) -> io::Result<File> {
    let m = fd.metadata()?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(fd)
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

impl RootMutationGuard {
    pub fn acquire(root: &Path) -> io::Result<Self> {
        let name = CString::new(root.as_os_str().as_bytes())?;
        let directory = private_directory(open_at(
            libc::AT_FDCWD,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?)?;
        for child in [c"files", c"info"] {
            private_directory(open_at(
                directory.as_raw_fd(),
                child,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?)?;
        }
        if unsafe { libc::mkdirat(directory.as_raw_fd(), c".trashd".as_ptr(), 0o700) } < 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err(io::Error::last_os_error());
        }
        let state = private_directory(open_at(
            directory.as_raw_fd(),
            c".trashd",
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?)?;
        let lock = open_at(
            state.as_raw_fd(),
            c"store.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        let m = lock.metadata()?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.nlink() != 1
            || m.mode() & 0o777 != 0o600
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        loop {
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        Ok(Self {
            _lock: lock,
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
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
