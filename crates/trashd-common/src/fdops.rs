//! Pinned-descriptor primitives: act on an object through a descriptor of
//! the inode a caller validated, never by resolving its path again.
//!
//! A path resolved again after validation can name something else by then.
//! A FUSE or network server answers every lookup as it likes, so it can
//! report a trash directory as a private directory for the check and as a
//! symlink to `/etc` for the next call (security-1, security-2, security-3).
//! A process that kept a descriptor inside a tree trashed later can still
//! swap entries in it (store-fs-2). Every helper here takes a directory
//! descriptor and one name, follows no symlink in that name, and either acts
//! on exactly the inode the caller validated or fails. None falls back to a
//! call that follows a symlink.
//!
//! Shared by trashd-common, the preload (through `#[path]`, so std and libc
//! only) and the seccomp supervisor. Removals and renames are raw syscalls:
//! the preload hooks libc's `unlink*` wrappers, and a store-internal call
//! through them would be trashed again (#104).

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

/// `openat(dir, name, flags | O_NOFOLLOW | O_CLOEXEC)` as a `File`.
fn open_nofollow_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open the directory `name` in `dir` for reading (and for `fchmod`,
/// `fsync`, getdents and every `*at` call relative to it), following no
/// symlink in `name`. A symlink fails: Linux checks `O_DIRECTORY` first and
/// reports ENOTDIR. `dir` may be `AT_FDCWD` with an absolute `name`; then
/// only the last component is protected, and the caller compares the
/// result's identity with what it validated.
pub fn open_dir_nofollow_at(dir: RawFd, name: &CStr) -> io::Result<File> {
    open_nofollow_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY)
}

/// Pin `name` in `dir` without opening it for I/O (`O_PATH`), following no
/// symlink: a FIFO is not waited on and a device is not opened. A symlink
/// pins the link itself.
pub fn open_path_nofollow_at(dir: RawFd, name: &CStr) -> io::Result<File> {
    open_nofollow_at(dir, name, libc::O_PATH)
}

/// fstat(2) of any descriptor, an `O_PATH` one included.
pub fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

/// lstat of `name` in `dir`: fstatat(2) with `AT_SYMLINK_NOFOLLOW`.
pub fn stat_nofollow_at(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

/// `std::fs::symlink_metadata` of `name` in `dir`, through an `O_PATH`
/// descriptor of the entry itself (see `open_path_nofollow_at`).
pub fn metadata_nofollow_at(dir: RawFd, name: &CStr) -> io::Result<std::fs::Metadata> {
    open_path_nofollow_at(dir, name)?.metadata()
}

/// The (device, inode) pair of a `stat`.
pub fn identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev, stat.st_ino)
}

/// Set the mode of the directory `name` in `dir` to `mode`, only if it still
/// is the inode `expected` (device, inode) that the caller validated.
///
/// The directory is pinned with `O_PATH|O_NOFOLLOW|O_DIRECTORY`, its
/// identity checked, and the mode changed through that pin. `fchmod`
/// refuses an `O_PATH` descriptor, so the pinned directory is reopened as
/// itself: through `.`, which the VFS resolves without asking the
/// filesystem, or, where its owner may not read it (a 0300 directory),
/// through its `/proc/self/fd` magic link. Both name the pinned inode and
/// never a path that can be swapped. A symlink in `name` (ENOTDIR), another
/// inode (ESTALE), or no way to reach the pin fails: nothing ever falls back
/// to chmod(2) of a path, which follows a symlink (security-3, store-fs-2).
pub fn fchmod_pinned_dir(
    dir: RawFd,
    name: &CStr,
    expected: (u64, u64),
    mode: libc::mode_t,
) -> io::Result<()> {
    let pinned = open_nofollow_at(dir, name, libc::O_PATH | libc::O_DIRECTORY)?;
    if identity(&stat_fd(pinned.as_raw_fd())?) != expected {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }
    match open_dir_nofollow_at(pinned.as_raw_fd(), c".") {
        Ok(directory) => {
            if identity(&stat_fd(directory.as_raw_fd())?) != expected {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
            if unsafe { libc::fchmod(directory.as_raw_fd(), mode) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            let link = std::ffi::CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
            if unsafe { libc::chmod(link.as_ptr(), mode) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// renameat2(2) with `RENAME_NOREPLACE` between two directories, as a raw
/// syscall: it fails with EEXIST instead of replacing anything that
/// appeared at the destination. EINVAL or ENOSYS mean the filesystem or
/// kernel lacks the flag.
pub fn rename_noreplace_at(
    src_dir: RawFd,
    src_name: &CStr,
    dst_dir: RawFd,
    dst_name: &CStr,
) -> io::Result<()> {
    const RENAME_NOREPLACE: libc::c_uint = 1;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            src_dir,
            src_name.as_ptr(),
            dst_dir,
            dst_name.as_ptr(),
            RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// unlinkat(2) of `name` in `dir` as a raw syscall (`flags` may hold
/// `AT_REMOVEDIR`). Never the libc wrapper, which the preload hooks.
pub fn unlink_at(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    if unsafe { libc::syscall(libc::SYS_unlinkat, dir, name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create the regular file `name` in `dir` exclusively, for writing, with
/// `mode`: `O_CREAT|O_EXCL` also refuses a symlink at `name`, dangling or
/// not, and `O_NOFOLLOW` is added for clarity.
pub fn create_excl_at(dir: RawFd, name: &CStr, mode: libc::mode_t) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Test hook: runs with the path of a trash directory whose mode is about to
/// be repaired, after its owner and type were checked and before the
/// repair. Tests swap the directory for a symlink there, as a FUSE server
/// could (security-3).
#[cfg(test)]
pub(crate) mod repair_probe {
    type Hook = Box<dyn Fn(&std::path::Path)>;
    type Probe = std::cell::RefCell<Option<Hook>>;

    thread_local! {
        static PROBE: Probe = const { std::cell::RefCell::new(None) };
    }

    /// Install (or with None, remove) this thread's probe.
    pub(crate) fn set(probe: Option<Hook>) {
        PROBE.with_borrow_mut(|slot| *slot = probe);
    }

    /// Install a probe that replaces the directory `dir` with a symlink to
    /// `victim` when `dir` is about to be repaired.
    pub(crate) fn swap_for_symlink(dir: &std::path::Path, victim: &std::path::Path) {
        let (dir, victim) = (dir.to_path_buf(), victim.to_path_buf());
        set(Some(Box::new(move |path| {
            if path == dir {
                let _ = std::fs::remove_dir(&dir);
                let _ = std::os::unix::fs::symlink(&victim, &dir);
            }
        })));
    }

    pub(crate) fn run(path: &std::path::Path) {
        PROBE.with_borrow(|probe| {
            if let Some(probe) = probe {
                probe(path);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn cpath(path: &std::path::Path) -> CString {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn open_dir_nofollow_refuses_a_symlink() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::create_dir(fixture.path().join("real")).unwrap();
        symlink(fixture.path().join("real"), fixture.path().join("link")).unwrap();
        let dir = File::open(fixture.path()).unwrap();
        assert!(open_dir_nofollow_at(dir.as_raw_fd(), c"real").is_ok());
        let error = open_dir_nofollow_at(dir.as_raw_fd(), c"link").unwrap_err();
        assert!(
            matches!(error.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)),
            "{error}"
        );
        // With AT_FDCWD only the last component is protected.
        assert!(
            open_dir_nofollow_at(libc::AT_FDCWD, &cpath(&fixture.path().join("link"))).is_err()
        );
    }

    #[test]
    fn metadata_nofollow_describes_the_link_itself() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("target"), b"x").unwrap();
        symlink("target", fixture.path().join("link")).unwrap();
        let dir = File::open(fixture.path()).unwrap();
        let link = metadata_nofollow_at(dir.as_raw_fd(), c"link").unwrap();
        assert!(link.file_type().is_symlink());
        let target = metadata_nofollow_at(dir.as_raw_fd(), c"target").unwrap();
        assert!(target.is_file());
        assert_eq!(
            identity(&stat_nofollow_at(dir.as_raw_fd(), c"target").unwrap()),
            (target.dev(), target.ino())
        );
        let missing = metadata_nofollow_at(dir.as_raw_fd(), c"missing").unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn fchmod_pinned_dir_changes_only_the_validated_directory() {
        let fixture = tempfile::tempdir().unwrap();
        let target = fixture.path().join("d");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let validated = std::fs::symlink_metadata(&target).unwrap();
        let dir = File::open(fixture.path()).unwrap();
        fchmod_pinned_dir(
            dir.as_raw_fd(),
            c"d",
            (validated.dev(), validated.ino()),
            0o700,
        )
        .unwrap();
        assert_eq!(mode_of(&target), 0o700);

        // Another inode at the name since validation: refused, untouched.
        std::fs::rename(&target, fixture.path().join("old")).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = fchmod_pinned_dir(
            dir.as_raw_fd(),
            c"d",
            (validated.dev(), validated.ino()),
            0o700,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESTALE));
        assert_eq!(mode_of(&target), 0o755);
    }

    // security-3, store-fs-2: a symlink where the validated directory was
    // is never followed, whatever it points at.
    #[test]
    fn fchmod_pinned_dir_never_follows_a_swapped_symlink() {
        let fixture = tempfile::tempdir().unwrap();
        let sentinel = fixture.path().join("sentinel");
        std::fs::write(&sentinel, b"keep").unwrap();
        std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o644)).unwrap();
        let sentinel_dir = fixture.path().join("sentinel-dir");
        std::fs::create_dir(&sentinel_dir).unwrap();
        std::fs::set_permissions(&sentinel_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let target = fixture.path().join("d");
        std::fs::create_dir(&target).unwrap();
        let validated = std::fs::symlink_metadata(&target).unwrap();
        std::fs::remove_dir(&target).unwrap();
        let dir = File::open(fixture.path()).unwrap();
        for victim in [&sentinel, &sentinel_dir] {
            symlink(victim, &target).unwrap();
            assert!(
                fchmod_pinned_dir(
                    dir.as_raw_fd(),
                    c"d",
                    (validated.dev(), validated.ino()),
                    0o700
                )
                .is_err()
            );
            std::fs::remove_file(&target).unwrap();
        }
        assert_eq!(mode_of(&sentinel), 0o644);
        assert_eq!(mode_of(&sentinel_dir), 0o755);
        // Even with the victim's own identity, a symlink is not a directory.
        symlink(&sentinel_dir, &target).unwrap();
        let victim = std::fs::metadata(&sentinel_dir).unwrap();
        assert!(
            fchmod_pinned_dir(dir.as_raw_fd(), c"d", (victim.dev(), victim.ino()), 0o700).is_err()
        );
        assert_eq!(mode_of(&sentinel_dir), 0o755);
    }

    // A directory its owner may not read (0300) or enter (0000) is still
    // repaired: through its pin's magic link where "." cannot be opened (for
    // root, which may read any directory, through ".").
    #[test]
    fn fchmod_pinned_dir_reaches_unreadable_directories() {
        let fixture = tempfile::tempdir().unwrap();
        let dir = File::open(fixture.path()).unwrap();
        for (name, mode) in [(c"wx", 0o300), (c"none", 0o000)] {
            let path = fixture
                .path()
                .join(std::ffi::OsStr::new(name.to_str().unwrap()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let validated = std::fs::symlink_metadata(&path).unwrap();
            fchmod_pinned_dir(
                dir.as_raw_fd(),
                name,
                (validated.dev(), validated.ino()),
                0o700,
            )
            .unwrap();
            assert_eq!(mode_of(&path), 0o700);
        }
    }

    #[test]
    fn rename_and_unlink_at_act_within_the_given_directories() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::create_dir(fixture.path().join("a")).unwrap();
        std::fs::create_dir(fixture.path().join("b")).unwrap();
        let a = File::open(fixture.path().join("a")).unwrap();
        let b = File::open(fixture.path().join("b")).unwrap();
        drop(create_excl_at(a.as_raw_fd(), c"x", 0o600).unwrap());
        assert_eq!(
            create_excl_at(a.as_raw_fd(), c"x", 0o600)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(create_excl_at(b.as_raw_fd(), c"x", 0o600).unwrap());
        let refused = rename_noreplace_at(a.as_raw_fd(), c"x", b.as_raw_fd(), c"x").unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EEXIST));
        rename_noreplace_at(a.as_raw_fd(), c"x", b.as_raw_fd(), c"y").unwrap();
        assert!(fixture.path().join("b/y").is_file());
        unlink_at(b.as_raw_fd(), c"y", 0).unwrap();
        std::fs::create_dir(fixture.path().join("b/z")).unwrap();
        unlink_at(b.as_raw_fd(), c"z", libc::AT_REMOVEDIR).unwrap();
        assert!(!fixture.path().join("b/y").exists());
        assert!(!fixture.path().join("b/z").exists());

        // A dangling symlink at the name is not created through.
        symlink(fixture.path().join("elsewhere"), fixture.path().join("a/l")).unwrap();
        assert!(create_excl_at(a.as_raw_fd(), c"l", 0o600).is_err());
        assert!(!fixture.path().join("elsewhere").exists());
    }
}
