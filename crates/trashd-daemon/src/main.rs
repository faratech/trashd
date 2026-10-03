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
// Without FAN_ONDIR in the mark mask the kernel drops every event carrying
// FS_ISDIR — including on FAN_MARK_FILESYSTEM marks — so directory deletions
// (rmdir, rm -rf of a dir-only tree) would never reach the audit log.
const FAN_ONDIR: u64 = 0x4000_0000;
// Delete events carry fd = FAN_NOFD (-1) with FAN_REPORT_FID groups — there
// is no fd to close for them.
// FAN_MOVED_FROM deliberately NOT watched: without pairing logic every
// rename logged a bogus DELETE record (#31). This is an audit log — false
// entries are worse than missing rename coverage.
const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

// FAN_DELETE_SELF deliberately NOT watched: FAN_DELETE already records each
// removed name, and the extra event carried only the dead inode's own handle,
// which no longer resolves, plus whichever pid dropped the last reference
// (#228).

/// The object's own handle. On a delete it names the removed inode, which
/// cannot be opened once gone, so only DFID_NAME records are resolved.
const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
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

/// A mount that file handles can be resolved against: its path and fsid (#97).
/// No descriptor is kept: an open fd pins the mount, so `umount` would fail
/// with EBUSY for as long as trashd runs (#197).
type WatchedMount = (PathBuf, Fsid);

fn main() {
    // Die quietly on a closed stderr/journal pipe instead of panicking on a
    // broken pipe (Rust ignores SIGPIPE by default) (#129).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("trashd {}", env!("TRASHD_VERSION"));
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
            FAN_DELETE | FAN_ONDIR,
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

    // Exiting here made Restart=always relaunch the daemon forever (#228).
    // Idle instead: the mount refresh below marks filesystems that become
    // markable later.
    if marked == 0 {
        eprintln!(
            "trashd: no filesystem could be monitored (need CAP_SYS_ADMIN); waiting for a filesystem to mark"
        );
    }

    // Open O_PATH fds to each watched mount point for open_by_handle_at.
    // open_by_handle_at requires a mount fd on the same filesystem as the
    // handle; the fsid recorded beside each fd is what events are matched
    // against so a handle is never decoded against the WRONG filesystem (#97).
    let mut mount_fds: Vec<WatchedMount> = Vec::new();
    for mount in &mount_list {
        if matches!(
            mount.fstype.as_str(),
            "tmpfs" | "ramfs" | "devtmpfs" | "overlay" | "squashfs"
        ) {
            continue;
        }
        mount_fds.push((mount.path.clone(), fsid_of_path(&mount.path)));
    }

    eprintln!("trashd: monitoring {} filesystem(s) for deletions", marked);

    // Event loop
    let mut buf = vec![0u8; 8192];
    let mut last_refresh = std::time::Instant::now();

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
                // Pick up mounts that appeared after startup (USB sticks,
                // network shares) — the startup snapshot never watched them
                // (#37). The queue also drains after every busy batch, so
                // throttle the full re-scan instead of running it per batch.
                let now = std::time::Instant::now();
                if mount_refresh_due(last_refresh, now) {
                    refresh_mounts(fan_fd, &mut marked_paths, &mut mount_fds);
                    last_refresh = now;
                }
                continue;
            }
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }

        for (event, record) in parse_events(&buf[..n as usize]) {
            // Queue overflow: events were DROPPED by the kernel — say so
            // loudly instead of silently producing an incomplete audit log
            // (#32).
            if event.mask & FAN_Q_OVERFLOW != 0 {
                eprintln!("[trashd] WARNING: fanotify queue overflow — deletion events were lost");
            }

            // Process event
            if event.mask & FAN_DELETE != 0 {
                let path = resolve_event_path(record, &event, &mount_fds);
                let pid = event.pid as u32;
                let proc_name = process_name(pid);
                if let Some(ref p) = path {
                    let skipped = audit_skipped(&config, p);
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
        }
    }
}

/// Split one read() of the fanotify fd into (header, record) pairs. Headers
/// are copied out with read_unaligned, since a byte buffer promises no
/// alignment, and a record that claims more bytes than were read ends the
/// batch instead of being sliced out of bounds (#228).
fn parse_events(buf: &[u8]) -> Vec<(FanotifyEventMetadata, &[u8])> {
    let mut events = Vec::new();
    let mut offset = 0;
    while offset + META_SIZE <= buf.len() {
        let event = unsafe {
            std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FanotifyEventMetadata)
        };
        if event.vers != FANOTIFY_METADATA_VERSION {
            eprintln!("trashd: unexpected fanotify version {}", event.vers);
            break;
        }
        let event_len = event.event_len as usize;
        if event_len < META_SIZE || event_len > buf.len() - offset {
            eprintln!("trashd: corrupt event (event_len={event_len})");
            break;
        }
        events.push((event, &buf[offset..offset + event_len]));
        offset += event_len;
    }
    events
}

/// Whether an audited delete is annotated "(skipped)". Only configured policy
/// counts: the daemon runs as root for every user's deletes, and a
/// `.trashd.toml` beside a deleted file is untrusted input it must never read
/// (a symlink to /etc/shadow leaked through parse errors, #198).
fn audit_skipped(config: &Config, path: &std::path::Path) -> bool {
    config.should_skip_configured(path)
}

/// Mounts that appear after startup are picked up at most this often.
const MOUNT_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

fn mount_refresh_due(last: std::time::Instant, now: std::time::Instant) -> bool {
    now.saturating_duration_since(last) >= MOUNT_REFRESH_INTERVAL
}

/// Resolve the full path from a fanotify event.
///
/// With FAN_REPORT_DFID_NAME, FAN_DELETE events include extended info
/// containing the parent directory's file handle and the deleted filename.
/// We resolve the parent via open_by_handle_at and join with the filename.
fn resolve_event_path(
    event_buf: &[u8],
    _event: &FanotifyEventMetadata,
    mount_fds: &[WatchedMount],
) -> Option<PathBuf> {
    // No fd-based fallback: with FAN_REPORT_FID groups delete events always
    // carry fd=FAN_NOFD, so it was dead code (#29).
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

/// Parse extended FID info to get a path from the DFID_NAME record: the parent
/// directory's handle plus the deleted filename. Other records, such as the
/// removed inode's own FID, are skipped (#228).
fn extract_dfid_name_path(event_buf: &[u8], mount_fds: &[WatchedMount]) -> Option<PathBuf> {
    let info_hdr_size = std::mem::size_of::<FanotifyEventInfoHeader>();
    let mut offset = META_SIZE;

    while offset + info_hdr_size <= event_buf.len() {
        let hdr = unsafe {
            std::ptr::read_unaligned(
                event_buf.as_ptr().add(offset) as *const FanotifyEventInfoHeader
            )
        };

        let info_len = hdr.len as usize;
        if info_len < info_hdr_size || offset + info_len > event_buf.len() {
            break;
        }

        if hdr.info_type == FAN_EVENT_INFO_TYPE_FID {
            offset += info_len;
            continue;
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
    mounts: &[WatchedMount],
) -> Option<PathBuf> {
    let candidates = mounts
        .iter()
        .filter(|(_, fsid)| expected_fsid.is_none() || *fsid == expected_fsid);

    // open_by_handle_at requires a mount fd on the same filesystem as the
    // handle. Open it for this lookup only and re-check its fsid: the path
    // may have been remounted since the last refresh. Not O_PATH: current
    // kernels reject O_PATH mount descriptors here with EBADF, which left
    // every audited path unresolved (#240).
    for (path, fsid) in candidates {
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            continue;
        };
        let mount_fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if mount_fd < 0 {
            continue;
        }
        let fd = if fsid.is_none() || fsid_of_fd(mount_fd) == *fsid {
            unsafe {
                libc::syscall(
                    libc::SYS_open_by_handle_at,
                    mount_fd as libc::c_long,
                    file_handle_ptr as libc::c_long,
                    libc::O_RDONLY as libc::c_long | libc::O_PATH as libc::c_long,
                )
            }
        } else {
            -1
        };
        unsafe { libc::close(mount_fd) };

        if fd >= 0 {
            let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
            unsafe { libc::close(fd as i32) };
            return path;
        }
    }

    None
}

/// fstatfs f_fsid of an open descriptor (see `fsid_of_path`).
fn fsid_of_fd(fd: RawFd) -> Fsid {
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &mut st) } != 0 {
        return None;
    }
    let fsid: [i32; 2] = unsafe { std::mem::transmute(st.f_fsid) };
    Some((fsid[0], fsid[1]))
}

/// Diff a fresh /proc/mounts scan against the marked set; mark anything new
/// (#37) and record it for handle resolution, and RE-mark anything whose
/// filesystem identity changed: a remount at the same path is a new
/// superblock whose old mark died with the unmount (#98).
fn refresh_mounts(
    fan_fd: RawFd,
    marked: &mut Vec<(PathBuf, Fsid)>,
    watched: &mut Vec<WatchedMount>,
) {
    let fresh = mounts::list_mounts();
    let live_paths: Vec<PathBuf> = fresh.iter().map(|m| m.path.clone()).collect();

    // Drop state for mounts that vanished entirely (the fanotify mark died
    // with the superblock).
    marked.retain(|(p, _)| live_paths.contains(p));
    watched.retain(|(p, _)| live_paths.contains(p));

    for mount in &fresh {
        if matches!(
            mount.fstype.as_str(),
            "tmpfs" | "ramfs" | "devtmpfs" | "overlay" | "squashfs"
        ) {
            continue;
        }
        let fsid = fsid_of_path(&mount.path);

        // Re-mark EVERY live mount on every refresh tick: f_fsid is stable
        // across unmount/remount of the SAME filesystem, so an identity
        // comparison cannot see a same-fs umount+mount cycle at one path —
        // yet the old fanotify mark died with the old superblock (#122).
        // FAN_MARK_ADD is idempotent for an already-marked superblock, so the
        // unconditional re-mark is cheap and re-arms the current one.
        match fanotify_mark(
            fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            FAN_DELETE | FAN_ONDIR,
            &mount.path,
        ) {
            Ok(()) => match marked.iter_mut().find(|(p, _)| p == &mount.path) {
                Some(entry) => {
                    if entry.1 != fsid && fsid.is_some() {
                        eprintln!(
                            "trashd: re-marking \"{}\" ({}) [filesystem changed]",
                            escape_path(&mount.path),
                            mount.fstype
                        );
                        entry.1 = fsid;
                    }
                }
                None => {
                    eprintln!(
                        "trashd: watching \"{}\" ({}) [new mount]",
                        escape_path(&mount.path),
                        mount.fstype
                    );
                    marked.push((mount.path.clone(), fsid));
                }
            },
            Err(_) => continue,
        }

        // Record the current identity for handle resolution; descriptors are
        // opened per lookup, so a remount needs nothing else.
        match watched.iter_mut().find(|(p, _)| p == &mount.path) {
            Some(entry) => entry.1 = fsid,
            None => watched.push((mount.path.clone(), fsid)),
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

    // Regression (#197): holding an O_PATH descriptor per watched mount kept
    // every mount busy, so `umount` failed with EBUSY while trashd ran.
    // Handles resolve through a descriptor opened for that one lookup.
    #[test]
    fn handles_resolve_without_held_mount_descriptors() {
        use std::os::unix::ffi::OsStrExt;
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: open_by_handle_at needs CAP_DAC_READ_SEARCH");
            return;
        }
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("handle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("victim");
        std::fs::write(&file, b"x").unwrap();
        let mut handle = vec![0u8; 8 + 128];
        handle[..4].copy_from_slice(&128u32.to_ne_bytes());
        let mut mount_id: libc::c_int = 0;
        let name = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
        let encoded = unsafe {
            libc::syscall(
                libc::SYS_name_to_handle_at,
                libc::AT_FDCWD,
                name.as_ptr(),
                handle.as_mut_ptr(),
                &mut mount_id,
                0,
            )
        };
        assert_eq!(encoded, 0, "{}", io::Error::last_os_error());
        let canonical = std::fs::canonicalize(&file).unwrap();
        let mount = mounts::list_mounts()
            .into_iter()
            .map(|m| m.path)
            .filter(|path| canonical.starts_with(path))
            .max_by_key(|path| path.as_os_str().len())
            .unwrap();
        let fsid = fsid_of_path(&mount);
        let watched: Vec<WatchedMount> = vec![(mount, fsid)];
        let resolved = resolve_handle_to_path(handle.as_ptr(), fsid, &watched);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(resolved, Some(canonical));
    }

    // Regression (#198): the daemon runs as root for every user's deletes; a
    // .trashd.toml beside a deleted file is attacker-controlled input and must
    // never be read (a symlink to /etc/shadow leaked through parse errors).
    #[test]
    fn audit_annotation_ignores_local_policies() {
        let dir = std::env::temp_dir().join(format!("trashd-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".trashd.toml"), "never_trash = [\"*\"]\n").unwrap();
        let mut config = Config::default();
        config.never_trash.clear();
        let skipped = audit_skipped(&config, &dir.join("deleted"));
        std::fs::remove_file(dir.join(".trashd.toml")).unwrap();
        assert!(!skipped);
    }

    // The queue drains after every batch of events, not only when idle: a
    // full mount re-scan per batch multiplied CPU under steady deletes.
    #[test]
    fn mount_refresh_runs_at_most_once_per_interval() {
        let last = std::time::Instant::now();
        assert!(!mount_refresh_due(last, last));
        assert!(!mount_refresh_due(
            last,
            last + std::time::Duration::from_millis(999)
        ));
        assert!(mount_refresh_due(
            last,
            last + std::time::Duration::from_secs(1)
        ));
    }

    fn event_header(event_len: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&event_len.to_ne_bytes());
        buf.push(FANOTIFY_METADATA_VERSION);
        buf.push(0);
        buf.extend_from_slice(&(META_SIZE as u16).to_ne_bytes());
        buf.extend_from_slice(&FAN_DELETE.to_ne_bytes());
        buf.extend_from_slice(&(-1i32).to_ne_bytes());
        buf.extend_from_slice(&42i32.to_ne_bytes());
        buf
    }

    fn info_record(info_type: u8, name: &[u8]) -> Vec<u8> {
        let mut record = vec![info_type, 0, 0, 0];
        record.extend_from_slice(&[0; 8]); // fsid
        record.extend_from_slice(&8u32.to_ne_bytes()); // handle_bytes
        record.extend_from_slice(&1i32.to_ne_bytes()); // handle_type
        record.extend_from_slice(&[0; 8]); // f_handle
        record.extend_from_slice(name);
        record.push(0);
        while record.len() % 4 != 0 {
            record.push(0);
        }
        let len = record.len() as u16;
        record[2..4].copy_from_slice(&len.to_ne_bytes());
        record
    }

    // A record whose event_len runs past the bytes read must end the batch,
    // not slice out of bounds (#228).
    #[test]
    fn event_records_never_overrun_the_read() {
        let mut buf = event_header(META_SIZE as u32);
        buf.extend(event_header(META_SIZE as u32 + 64));
        let events = parse_events(&buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0.pid, 42);
        assert_eq!(events[0].1.len(), META_SIZE);
    }

    // Headers are copied out of a byte buffer, which promises no alignment.
    #[test]
    fn event_headers_parse_at_any_alignment() {
        let mut storage = vec![0u8];
        storage.extend(event_header(META_SIZE as u32));
        let events = parse_events(&storage[1..]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0.mask, FAN_DELETE);
    }

    // Type 1 is the deleted inode's own FID (named DFID before), which cannot
    // be opened once it is gone; it must not hide the DFID_NAME record that
    // names the deleted entry (#228).
    #[test]
    fn fid_records_do_not_hide_the_name_record() {
        let mut buf = event_header(0);
        buf.extend(info_record(FAN_EVENT_INFO_TYPE_FID, b""));
        buf.extend(info_record(FAN_EVENT_INFO_TYPE_DFID_NAME, b"victim"));
        let len = buf.len() as u32;
        buf[..4].copy_from_slice(&len.to_ne_bytes());
        assert_eq!(
            extract_dfid_name_path(&buf, &[]),
            Some(PathBuf::from("victim"))
        );
    }

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
