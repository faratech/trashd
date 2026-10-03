//! Safe reading of a per-directory `.trashd.toml`.
//!
//! Shared verbatim by trashd-common and the standalone preload (`#[path]`
//! include), so it depends on std and libc only.
//!
//! A local policy decides whether deletes become permanent, and it is read by
//! root processes (the shim, the preload inside root programs, the seccomp
//! supervisor). It therefore only counts when it is a regular file owned by
//! the deleting user or root that nobody else can write (#198, #207). The file
//! is opened without following symlinks and without blocking, then validated
//! and read through that one descriptor: a symlink cannot point a root reader
//! at /etc/shadow or /proc/kmsg, and a swap after the checks changes nothing.

use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Larger files are not policies; reading them would only cost memory.
pub(crate) const MAX_LOCAL_CONFIG_BYTES: u64 = 64 * 1024;

pub(crate) enum LocalConfigFile {
    /// No `.trashd.toml` in this directory: keep walking up.
    Absent,
    /// Present but not usable as policy. Like a broken file this stops the
    /// walk: an ancestor's narrower whitelist must not apply instead (#136).
    Ignored(&'static str),
    /// Trusted contents, still to be parsed.
    Content(String),
}

/// Read `dir/.trashd.toml` if it is a policy this process may trust.
pub(crate) fn read_local_config(dir: &Path) -> LocalConfigFile {
    let candidate = dir.join(".trashd.toml");
    let Ok(name) = std::ffi::CString::new(candidate.as_os_str().as_bytes()) else {
        return LocalConfigFile::Ignored("has an invalid path");
    };
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ENOTDIR) => LocalConfigFile::Absent,
            Some(libc::ELOOP) => LocalConfigFile::Ignored("is a symbolic link"),
            _ => LocalConfigFile::Ignored("cannot be opened"),
        };
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let Ok(meta) = file.metadata() else {
        return LocalConfigFile::Ignored("cannot be inspected");
    };
    if !meta.file_type().is_file() {
        return LocalConfigFile::Ignored("is not a regular file");
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid && meta.uid() != 0 {
        return LocalConfigFile::Ignored("is owned by another user");
    }
    if meta.mode() & 0o022 != 0 {
        return LocalConfigFile::Ignored("is writable by other users");
    }
    let mut content = String::new();
    match file
        .take(MAX_LOCAL_CONFIG_BYTES + 1)
        .read_to_string(&mut content)
    {
        Ok(read) if read as u64 > MAX_LOCAL_CONFIG_BYTES => {
            LocalConfigFile::Ignored("is too large")
        }
        Ok(_) => LocalConfigFile::Content(content),
        Err(_) => LocalConfigFile::Ignored("is not readable UTF-8 text"),
    }
}
