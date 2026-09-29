//! trashd — system-wide deletion monitor using fanotify.
//!
//! Watches all real filesystems for FAN_DELETE events and logs them.
//! Detection only — cannot intercept or prevent deletions.
//!
//! Requires CAP_SYS_ADMIN (or root) and Linux 5.9+.
//!
//! Usage: trashd [--foreground]

mod logger;

use logger::{DeletionEvent, escape_path, process_name};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use trashd_common::Config;
use trashd_common::mounts;

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
// Delete events carry fd = FAN_NOFD (-1) with FAN_REPORT_FID groups — there
// is no fd to close for them.
// FAN_MOVED_FROM deliberately NOT watched: without pairing logic every
// rename logged a bogus DELETE record (#31). This is an audit log — false
// entries are worse than missing rename coverage.
const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

const FAN_EVENT_INFO_TYPE_DFID: u8 = 1;
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

/// statfs/fanotify filesystem identity: statfs's f_fsid as a comparable pair.
type Fsid = Option<(i32, i32)>;

/// Cached handle-resolution mount: path, O_PATH fd, and that fd's fsid (#97).
type MountFd = (PathBuf, RawFd, Fsid);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("trashd {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("Usage: trashd [--foreground]");
        eprintln!();
        eprintln!("Monitor filesystem deletions using fanotify.");
        eprintln!("Requires CAP_SYS_ADMIN or root, and Linux 5.9+.");
        eprintln!("Logs detected deletions to stderr/journald.");
        std::process::exit(0);
    }

    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("trashd: fatal: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> io::Result<()> {
    let config = Config::load();

    // Initialize fanotify with FAN_REPORT_FID | FAN_REPORT_DFID_NAME
    // so FAN_DELETE events include the directory + filename (Linux 5.9+)
    let init_flags =
        FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_DFID_NAME;
    let fan_fd = match fanotify_init(init_flags) {
        Ok(fd) => fd,
        Err(e) => {
            if e.raw_os_error() == Some(libc::EINVAL) {
                eprintln!("trashd: fanotify_init failed (kernel too old? need 5.9+)");
            }
            return Err(e);
        }
    };
    eprintln!("trashd: fanotify initialized (fd {})", fan_fd);

    // Mark all real mount points
    let mount_list = mounts::list_mounts();
    let mut marked = 0;
    // Each entry carries the filesystem identity (statfs f_fsid) it was
    // marked for: a remount at the same path is a NEW superblock whose old
    // fanotify mark died with the unmount (#98).
    let mut marked_paths: Vec<(PathBuf, Fsid)> = Vec::new();
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
            FAN_DELETE | FAN_DELETE_SELF,
            &mount.path,
        ) {
            Ok(()) => {
                eprintln!(
                    "trashd: watching \"{}\" ({})",
                    escape_path(&mount.path),
                    mount.fstype,
                );
                marked += 1;
                marked_paths.push((mount.path.clone(), fsid_of_path(&mount.path)));
            }
            Err(e) => {
                eprintln!(
                    "trashd: failed to mark \"{}\": {e}",
                    escape_path(&mount.path),
                );
            }
        }
    }

    if marked == 0 {
        return Err(io::Error::other(
            "no filesystems could be monitored — check permissions (need CAP_SYS_ADMIN)",
        ));
    }

    // Open O_PATH fds to each watched mount point for open_by_handle_at.
    // open_by_handle_at requires a mount fd on the same filesystem as the
    // handle; the fsid recorded beside each fd is what events are matched
    // against so a handle is never decoded against the WRONG filesystem (#97).
    let mut mount_fds: Vec<MountFd> = Vec::new();
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
            mount_fds.push((mount.path.clone(), fd, fsid_of_path(&mount.path)));
        }
    }

    eprintln!("trashd: monitoring {} filesystem(s) for deletions", marked);

    // Event loop
    let mut buf = vec![0u8; 8192];

    loop {
        let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                let mut pfd = libc::pollfd {
                    fd: fan_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, 1000) };
                // Idle tick: pick up mounts that appeared after startup
                // (USB sticks, network shares) — the startup snapshot never
                // watched them (#37).
                refresh_mounts(fan_fd, &mut marked_paths, &mut mount_fds);
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
            let event = unsafe { &*(buf.as_ptr().add(offset) as *const FanotifyEventMetadata) };

            if event.vers != FANOTIFY_METADATA_VERSION {
                eprintln!("trashd: unexpected fanotify version {}", event.vers);
                break;
            }

            let event_len = event.event_len as usize;
            if event_len < META_SIZE {
                eprintln!("trashd: corrupt event (event_len={})", event_len);
                break;
            }

            // Queue overflow: events were DROPPED by the kernel — say so
            // loudly instead of silently producing an incomplete audit log
            // (#32).
            if event.mask & FAN_Q_OVERFLOW != 0 {
                eprintln!("[trashd] WARNING: fanotify queue overflow — deletion events were lost");
            }

            // Process event
            if event.mask & (FAN_DELETE | FAN_DELETE_SELF) != 0 {
                let path = resolve_event_path(&buf[offset..offset + event_len], event, &mount_fds);
                let pid = event.pid as u32;
                let proc_name = process_name(pid);
                if let Some(ref p) = path {
                    let skipped = config.should_skip(p);
                    let ev = DeletionEvent {
                        path: Some(p.clone()),
                        pid,
                        process: proc_name,
                    };
                    ev.log(skipped);
                } else {
                    // Could not resolve path — log with what we have through
                    // the same byte-safe, single-line formatter.
                    DeletionEvent {
                        path: None,
                        pid,
                        process: proc_name,
                    }
                    .log(false);
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
fn resolve_event_path(
    event_buf: &[u8],
    _event: &FanotifyEventMetadata,
    mount_fds: &[MountFd],
) -> Option<PathBuf> {
    // Try to extract path from extended FID info (DFID_NAME for FAN_DELETE,
    // DFID for FAN_DELETE_SELF). No fd-based fallback: with FAN_REPORT_FID
    // groups delete events always carry fd=FAN_NOFD, so it was dead code (#29).
    extract_dfid_name_path(event_buf, mount_fds)
}

/// statfs f_fsid of the filesystem at `path` — the identity fanotify events
/// carry, used to decode file handles against the RIGHT mount (#97).
fn fsid_of_path(path: &std::path::Path) -> Fsid {
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut st) } != 0 {
        return None;
    }
    // libc keeps fsid_t.__val private; the type is repr(C) [c_int; 2].
    const _: () = assert!(std::mem::size_of::<libc::fsid_t>() == std::mem::size_of::<[i32; 2]>());
    let fsid: [i32; 2] = unsafe { std::mem::transmute(st.f_fsid) };
    Some((fsid[0], fsid[1]))
}

/// Read the event's fsid (two native-endian i32 words that sit between the
/// info header and the file_handle).
fn event_fsid(event_buf: &[u8], fh_offset: usize) -> Fsid {
    if fh_offset < 8 {
        return None;
    }
    let b = event_buf.get(fh_offset - 8..fh_offset)?;
    if b.len() != 8 {
        return None;
    }
    Some((
        i32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
        i32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
    ))
}

/// Parse extended FID info to get a path.
///
/// - DFID_NAME (type 2): parent dir handle + deleted filename → full path.
/// - DFID (type 1): the inode's OWN handle (FAN_DELETE_SELF) → resolved
///   directly via open_by_handle_at. Type-1 records were never parsed before,
///   and with FAN_REPORT_FID groups delete events carry fd=FAN_NOFD, so the
///   old /proc/self/fd fallback could never fire either (#29).
fn extract_dfid_name_path(
    event_buf: &[u8],
    mount_fds: &[MountFd],
) -> Option<PathBuf> {
    let info_hdr_size = std::mem::size_of::<FanotifyEventInfoHeader>();
    let mut offset = META_SIZE;

    while offset + info_hdr_size <= event_buf.len() {
        let hdr = unsafe { &*(event_buf.as_ptr().add(offset) as *const FanotifyEventInfoHeader) };

        let info_len = hdr.len as usize;
        if info_len < info_hdr_size || offset + info_len > event_buf.len() {
            break;
        }

        if hdr.info_type == FAN_EVENT_INFO_TYPE_DFID {
            let fid_hdr_size = std::mem::size_of::<FanotifyEventInfoFid>();
            if info_len < fid_hdr_size + 8 {
                break;
            }
            let fh_offset = offset + fid_hdr_size;
            if fh_offset + 8 > event_buf.len() {
                break;
            }
            // handle_bytes is not needed here: the kernel-returned handle is
            // passed to open_by_handle_at by pointer, length-validated above.
            let fsid = event_fsid(event_buf, fh_offset);
            let file_handle_ptr = event_buf[fh_offset..].as_ptr();
            return resolve_handle_to_path(file_handle_ptr, fsid, mount_fds);
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
            let fsid = event_fsid(event_buf, fh_offset);

            // The name follows the file_handle
            let name_offset = fh_offset + 8 + handle_bytes;
            if name_offset >= offset + info_len {
                break;
            }

            let name_bytes = &event_buf[name_offset..offset + info_len];
            // Name is NUL-terminated
            let name_len = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            if name_len == 0 {
                break;
            }
            let filename = OsStr::from_bytes(&name_bytes[..name_len]);

            // Try to resolve the parent directory via open_by_handle_at
            let file_handle_ptr = event_buf[fh_offset..].as_ptr();
            let parent_dir = resolve_handle_to_path(file_handle_ptr, fsid, mount_fds);

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
/// `expected_fsid` is the filesystem identity the event was emitted for. When
/// known, ONLY a cached mount fd with a matching statfs f_fsid is used: the
/// kernel does not verify that a handle originated on the given mount, so
/// trial-decoding against every mount could resolve identical
/// inode/generation pairs on the wrong filesystem (#97). When unknown, fall
/// back to the historical trial order.
fn resolve_handle_to_path(
    file_handle_ptr: *const u8,
    expected_fsid: Fsid,
    mount_fds: &[MountFd],
) -> Option<PathBuf> {
    let candidates: Vec<RawFd> = match expected_fsid {
        Some(fsid) => mount_fds
            .iter()
            .filter(|(_, _, f)| *f == Some(fsid))
            .map(|(_, fd, _)| *fd)
            .collect(),
        None => mount_fds.iter().map(|(_, fd, _)| *fd).collect(),
    };

    // open_by_handle_at requires a mount fd on the same filesystem as the handle.
    for mount_fd in candidates {
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

/// Diff a fresh /proc/mounts scan against the marked set; mark and open
/// handle-resolution fds for anything new (#37), and RE-mark anything whose
/// filesystem identity changed: a remount at the same path is a new
/// superblock whose old mark and old cached fd died with the unmount (#98).
fn refresh_mounts(
    fan_fd: RawFd,
    marked: &mut Vec<(PathBuf, Fsid)>,
    fds: &mut Vec<MountFd>,
) {
    let fresh = mounts::list_mounts();
    let live_paths: Vec<PathBuf> = fresh.iter().map(|m| m.path.clone()).collect();

    // Drop state for mounts that vanished entirely (fd close; the fanotify
    // mark died with the superblock).
    marked.retain(|(p, _)| live_paths.contains(p));
    fds.retain(|(p, fd, _)| {
        if live_paths.contains(p) {
            true
        } else {
            unsafe { libc::close(*fd) };
            false
        }
    });

    for mount in &fresh {
        if matches!(
            mount.fstype.as_str(),
            "tmpfs" | "ramfs" | "devtmpfs" | "overlay" | "squashfs"
        ) {
            continue;
        }
        let fsid = fsid_of_path(&mount.path);

        let known = marked.iter().find(|(p, _)| p == &mount.path);
        let identity_changed = match (known, &fsid) {
            (Some((_, Some(old))), Some(new)) => old != new,
            _ => false,
        };
        if known.is_none() || identity_changed {
            match fanotify_mark(
                fan_fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                FAN_DELETE | FAN_DELETE_SELF,
                &mount.path,
            ) {
                Ok(()) => {
                    if identity_changed {
                        eprintln!(
                            "trashd: re-marking \"{}\" ({}) [remounted]",
                            escape_path(&mount.path),
                            mount.fstype
                        );
                        if let Some(entry) = marked.iter_mut().find(|(p, _)| p == &mount.path) {
                            entry.1 = fsid;
                        }
                    } else {
                        eprintln!(
                            "trashd: watching \"{}\" ({}) [new mount]",
                            escape_path(&mount.path),
                            mount.fstype
                        );
                        marked.push((mount.path.clone(), fsid));
                    }
                }
                Err(_) => continue,
            }
        }

        let fd_known = fds.iter().find(|(p, _, _)| p == &mount.path).is_some();
        let fd_stale = match (fds.iter().find(|(p, _, _)| p == &mount.path), &fsid) {
            (Some((_, _, Some(old))), Some(new)) => old != new,
            _ => false,
        };
        if (!fd_known || fd_stale)
            && let Ok(c) = std::ffi::CString::new(mount.path.to_string_lossy().as_bytes())
        {
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_PATH) };
            if fd >= 0 {
                match fds.iter_mut().find(|(p, _, _)| p == &mount.path) {
                    Some(entry) => {
                        unsafe { libc::close(entry.1) };
                        entry.1 = fd;
                        entry.2 = fsid;
                    }
                    None => fds.push((mount.path.clone(), fd, fsid)),
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Regression (#97): the fsid recorded in a fanotify FID record must be
    // extracted from the bytes between the info header and the file_handle,
    // so handle decoding can be pinned to the originating filesystem.
    #[test]
    fn event_fsid_is_read_from_the_record() {
        // header (4 bytes) + fsid (8 bytes) + file_handle prefix (8 bytes)
        let mut buf = Vec::new();
        buf.push(2u8); // FAN_EVENT_INFO_TYPE_DFID_NAME
        buf.push(0); // pad
        buf.extend_from_slice(&32u16.to_ne_bytes()); // len
        buf.extend_from_slice(&0x1111_2222i32.to_ne_bytes());
        buf.extend_from_slice(&0x3333_4444i32.to_ne_bytes());
        buf.extend_from_slice(&8u32.to_ne_bytes()); // handle_bytes
        buf.extend_from_slice(&1i32.to_ne_bytes()); // handle_type

        assert_eq!(event_fsid(&buf, 12), Some((0x1111_2222, 0x3333_4444)));
        assert_eq!(event_fsid(&buf[..8], 12), None, "truncated record");
        assert_eq!(event_fsid(&buf, 4), None, "offset before the fsid");
    }
}
