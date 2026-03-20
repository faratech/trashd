//! trashd-daemon — system-wide deletion monitor using fanotify.
//!
//! Watches all real filesystems for FAN_DELETE events and logs them.
//! Detection only — cannot intercept or prevent deletions.
//!
//! Requires CAP_SYS_ADMIN (or root) and Linux 5.9+.
//!
//! Usage: trashd-daemon [--foreground]

mod logger;

use logger::{process_name, DeletionEvent};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use trashd_common::mounts;
use trashd_common::Config;

// fanotify constants (from linux/fanotify.h)
const FAN_CLASS_NOTIF: libc::c_uint = 0;
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_NONBLOCK: libc::c_uint = 0x0000_0002;
const FAN_REPORT_FID: libc::c_uint = 0x0000_0200;
const FAN_REPORT_DFID_NAME: libc::c_uint = 0x0000_0C00;

const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_MARK_FILESYSTEM: libc::c_uint = 0x0000_0100;

const FAN_DELETE: u64 = 0x0000_0200;
const FAN_DELETE_SELF: u64 = 0x0000_0400;
const FAN_MOVED_FROM: u64 = 0x0000_0040;

const FAN_NOFD: i32 = -1;

const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;

/// fanotify event metadata (struct fanotify_event_metadata).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// Extended info header (struct fanotify_event_info_header).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FanotifyEventInfoHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

/// FID info (struct fanotify_event_info_fid) — header only, followed by fsid + file_handle.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FanotifyEventInfoFid {
    hdr: FanotifyEventInfoHeader,
    fsid_val0: i32,
    fsid_val1: i32,
    // Followed by: struct file_handle { handle_bytes, handle_type, f_handle[] }
}

const FANOTIFY_METADATA_VERSION: u8 = 3;
const META_SIZE: usize = std::mem::size_of::<FanotifyEventMetadata>();

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("Usage: trashd-daemon [--foreground]");
        eprintln!();
        eprintln!("Monitor filesystem deletions using fanotify.");
        eprintln!("Requires CAP_SYS_ADMIN or root, and Linux 5.9+.");
        eprintln!("Logs detected deletions to stderr/journald.");
        std::process::exit(0);
    }

    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("trashd-daemon: fatal: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> io::Result<()> {
    let config = Config::load();

    // Initialize fanotify with FAN_REPORT_FID | FAN_REPORT_DFID_NAME
    // so FAN_DELETE events include the directory + filename (Linux 5.9+)
    let init_flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_DFID_NAME;
    let fan_fd = match fanotify_init(init_flags) {
        Ok(fd) => fd,
        Err(e) => {
            if e.raw_os_error() == Some(libc::EINVAL) {
                eprintln!("trashd-daemon: fanotify_init failed (kernel too old? need 5.9+)");
            }
            return Err(e);
        }
    };
    eprintln!("trashd-daemon: fanotify initialized (fd {})", fan_fd);

    // Mark all real mount points
    let mount_list = mounts::list_mounts();
    let mut marked = 0;
    for mount in &mount_list {
        if matches!(
            mount.fstype.as_str(),
            "tmpfs" | "ramfs" | "devtmpfs" | "overlay" | "squashfs"
        ) {
            continue;
        }

        match fanotify_mark(
            fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            FAN_DELETE | FAN_DELETE_SELF | FAN_MOVED_FROM,
            &mount.path,
        ) {
            Ok(()) => {
                eprintln!(
                    "trashd-daemon: watching {} ({})",
                    mount.path.display(),
                    mount.fstype,
                );
                marked += 1;
            }
            Err(e) => {
                eprintln!(
                    "trashd-daemon: failed to mark {}: {e}",
                    mount.path.display(),
                );
            }
        }
    }

    if marked == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no filesystems could be monitored — check permissions (need CAP_SYS_ADMIN)",
        ));
    }

    // Open O_PATH fds to each watched mount point for open_by_handle_at.
    // open_by_handle_at requires a mount fd on the same filesystem as the handle.
    let mut mount_fds: Vec<RawFd> = Vec::new();
    for mount in &mount_list {
        if matches!(
            mount.fstype.as_str(),
            "tmpfs" | "ramfs" | "devtmpfs" | "overlay" | "squashfs"
        ) {
            continue;
        }
        let c_path = match std::ffi::CString::new(mount.path.to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_PATH) };
        if fd >= 0 {
            mount_fds.push(fd);
        }
    }

    eprintln!("trashd-daemon: monitoring {} filesystem(s) for deletions", marked);

    // Event loop
    let mut buf = vec![0u8; 8192];

    loop {
        let n = unsafe {
            libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                let mut pfd = libc::pollfd {
                    fd: fan_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, 1000) };
                continue;
            }
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }

        let n = n as usize;
        let mut offset = 0;

        while offset + META_SIZE <= n {
            let event = unsafe {
                &*(buf.as_ptr().add(offset) as *const FanotifyEventMetadata)
            };

            if event.vers != FANOTIFY_METADATA_VERSION {
                eprintln!("trashd-daemon: unexpected fanotify version {}", event.vers);
                break;
            }

            let event_len = event.event_len as usize;
            if event_len < META_SIZE {
                eprintln!("trashd-daemon: corrupt event (event_len={})", event_len);
                break;
            }

            // Process event
            if event.mask & (FAN_DELETE | FAN_DELETE_SELF | FAN_MOVED_FROM) != 0 {
                let path = resolve_event_path(&buf[offset..offset + event_len], event, &mount_fds);
                let pid = event.pid as u32;
                let proc_name = process_name(pid);
                if let Some(ref p) = path {
                    let skipped = config.should_skip(p);
                    let ev = DeletionEvent {
                        path: p.clone(),
                        pid,
                        process: proc_name,
                    };
                    ev.log(skipped);
                } else {
                    // Could not resolve path — log with what we have
                    eprintln!(
                        "[trashd-daemon] DELETE pid={} proc={} path=(unresolved)",
                        pid, proc_name,
                    );
                }
            }

            // Always close the fd if one was provided (even for unmatched events)
            if event.fd >= 0 {
                unsafe { libc::close(event.fd) };
            }

            offset += event_len;
        }
    }
}

/// Resolve the full path from a fanotify event.
///
/// With FAN_REPORT_DFID_NAME, FAN_DELETE events include extended info
/// containing the parent directory's file handle and the deleted filename.
/// We resolve the parent via open_by_handle_at and join with the filename.
///
/// Falls back to reading /proc/self/fd/{event.fd} for FAN_DELETE_SELF.
fn resolve_event_path(event_buf: &[u8], event: &FanotifyEventMetadata, mount_fds: &[RawFd]) -> Option<PathBuf> {
    // Try to extract path from extended FID info (for FAN_DELETE)
    if let Some(path) = extract_dfid_name_path(event_buf, mount_fds) {
        return Some(path);
    }

    // Fallback: use the event fd (works for FAN_DELETE_SELF)
    if event.fd >= 0 && event.fd != FAN_NOFD {
        return std::fs::read_link(format!("/proc/self/fd/{}", event.fd)).ok();
    }

    None
}

/// Parse the DFID_NAME extended info to get parent_dir + filename.
fn extract_dfid_name_path(event_buf: &[u8], mount_fds: &[RawFd]) -> Option<PathBuf> {
    let info_hdr_size = std::mem::size_of::<FanotifyEventInfoHeader>();
    let mut offset = META_SIZE;

    while offset + info_hdr_size <= event_buf.len() {
        let hdr = unsafe {
            &*(event_buf.as_ptr().add(offset) as *const FanotifyEventInfoHeader)
        };

        let info_len = hdr.len as usize;
        if info_len < info_hdr_size || offset + info_len > event_buf.len() {
            break;
        }

        if hdr.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME {
            // Layout: FanotifyEventInfoFid header (hdr + fsid) + file_handle + name
            let fid_hdr_size = std::mem::size_of::<FanotifyEventInfoFid>();
            if info_len < fid_hdr_size + 8 {
                // Too small for file_handle + name
                break;
            }

            let fh_offset = offset + fid_hdr_size;

            // struct file_handle { handle_bytes(u32), handle_type(i32), f_handle[] }
            if fh_offset + 8 > event_buf.len() {
                break;
            }
            let handle_bytes = u32::from_ne_bytes([
                event_buf[fh_offset],
                event_buf[fh_offset + 1],
                event_buf[fh_offset + 2],
                event_buf[fh_offset + 3],
            ]) as usize;

            // The name follows the file_handle
            let name_offset = fh_offset + 8 + handle_bytes;
            if name_offset >= offset + info_len {
                break;
            }

            let name_bytes = &event_buf[name_offset..offset + info_len];
            // Name is NUL-terminated
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            if name_len == 0 {
                break;
            }
            let filename = OsStr::from_bytes(&name_bytes[..name_len]);

            // Try to resolve the parent directory via open_by_handle_at
            let file_handle_ptr = event_buf[fh_offset..].as_ptr();
            let parent_dir = resolve_handle_to_path(
                file_handle_ptr,
                handle_bytes,
                mount_fds,
            );

            if let Some(dir) = parent_dir {
                return Some(dir.join(filename));
            }

            // Fallback: return just the filename
            return Some(PathBuf::from(filename));
        }

        offset += info_len;
    }

    None
}

/// Try to resolve a file_handle to a path via open_by_handle_at + /proc/self/fd.
///
/// `mount_fd_hint` is an O_PATH fd to a file on the same filesystem as the handle,
/// or -1 to try all known mount points.
fn resolve_handle_to_path(
    file_handle_ptr: *const u8,
    _handle_bytes: usize,
    mount_fds: &[RawFd],
) -> Option<PathBuf> {
    // open_by_handle_at requires a mount fd on the same filesystem as the handle.
    // Try each cached mount fd until one succeeds.
    for &mount_fd in mount_fds {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_open_by_handle_at,
                mount_fd as libc::c_long,
                file_handle_ptr as libc::c_long,
                libc::O_RDONLY as libc::c_long | libc::O_PATH as libc::c_long,
            )
        };

        if fd >= 0 {
            let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
            unsafe { libc::close(fd as i32) };
            return path;
        }
    }

    None
}

fn fanotify_init(flags: libc::c_uint) -> io::Result<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_fanotify_init, flags as libc::c_long, 0i64) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}

fn fanotify_mark(
    fan_fd: RawFd,
    flags: libc::c_uint,
    mask: u64,
    path: &std::path::Path,
) -> io::Result<()> {
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fan_fd as libc::c_long,
            flags as libc::c_long,
            mask as libc::c_long,
            libc::AT_FDCWD as libc::c_long,
            c_path.as_ptr() as libc::c_long,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
