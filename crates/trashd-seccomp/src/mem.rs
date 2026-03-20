//! Read path arguments from a target process's memory via process_vm_readv.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// Read a NUL-terminated string from the target process's address space.
pub fn read_path_from_process(pid: u32, addr: u64) -> io::Result<PathBuf> {
    if addr == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "null pointer"));
    }

    // Read up to PATH_MAX bytes
    let mut buf = vec![0u8; libc::PATH_MAX as usize];

    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local_iov, 1, &remote_iov, 1, 0) };

    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let bytes_read = n as usize;

    // Find NUL terminator — if missing, the path was truncated (partial read)
    let len = match buf[..bytes_read].iter().position(|&b| b == 0) {
        Some(pos) => pos,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "path string has no NUL terminator (truncated read)",
            ));
        }
    };

    buf.truncate(len);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Resolve the path for a given syscall notification.
///
/// - unlink(pathname):        args[0] = pathname pointer
/// - rmdir(pathname):         args[0] = pathname pointer
/// - unlinkat(dirfd, path, flags): args[0] = dirfd, args[1] = pathname pointer
pub fn resolve_syscall_path(pid: u32, syscall_nr: i32, args: &[u64; 6]) -> io::Result<PathBuf> {
    #[cfg(target_arch = "x86_64")]
    const NR_UNLINKAT: i32 = 263;
    #[cfg(target_arch = "aarch64")]
    const NR_UNLINKAT: i32 = 35;

    let (dirfd, path_addr) = if syscall_nr == NR_UNLINKAT {
        (Some(args[0] as i32), args[1])
    } else {
        // unlink or rmdir: pathname is args[0]
        (None, args[0])
    };

    let path = read_path_from_process(pid, path_addr)?;

    // If the path is absolute, return it directly
    if path.is_absolute() {
        return Ok(path);
    }

    // Relative path — resolve against dirfd or cwd
    let base = match dirfd {
        Some(fd) if fd == libc::AT_FDCWD => {
            // Resolve against target's cwd
            read_proc_link(pid, "cwd")?
        }
        Some(fd) => {
            // Resolve against the directory referred to by dirfd
            read_proc_fd(pid, fd)?
        }
        None => {
            // unlink/rmdir with relative path — resolve against target's cwd
            read_proc_link(pid, "cwd")?
        }
    };

    Ok(base.join(&path))
}

/// Read a /proc/{pid}/{name} symlink.
fn read_proc_link(pid: u32, name: &str) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/{name}"))
}

/// Read /proc/{pid}/fd/{fd} symlink to get the path a file descriptor points to.
fn read_proc_fd(pid: u32, fd: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
}
