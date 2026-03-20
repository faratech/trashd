//! trashd-daemon — system-wide deletion monitor using fanotify.
//!
//! Watches all real filesystems for FAN_DELETE events and logs them.
//! Detection only — cannot intercept or prevent deletions.
//!
//! Requires CAP_SYS_ADMIN (or root).
//!
//! Usage: trashd-daemon [--foreground]

mod logger;

use logger::{DeletionEvent, path_from_fd, process_name};
use std::io;
use std::os::unix::io::RawFd;
use trashd_common::mounts;
use trashd_common::Config;

// fanotify constants (from linux/fanotify.h)
const FAN_CLASS_NOTIF: libc::c_uint = 0;
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_NONBLOCK: libc::c_uint = 0x0000_0002;

const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_MARK_FILESYSTEM: libc::c_uint = 0x0000_0100;

const FAN_DELETE: u64 = 0x0000_0200;
const FAN_DELETE_SELF: u64 = 0x0000_0400;
const FAN_MOVED_FROM: u64 = 0x0000_0040;

const FAN_NOFD: i32 = -1;

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

const FANOTIFY_METADATA_VERSION: u8 = 3;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("Usage: trashd-daemon [--foreground]");
        eprintln!();
        eprintln!("Monitor filesystem deletions using fanotify.");
        eprintln!("Requires CAP_SYS_ADMIN or root.");
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

    // Initialize fanotify
    let fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK)?;
    eprintln!("trashd-daemon: fanotify initialized (fd {})", fan_fd);

    // Mark all real mount points
    let mount_list = mounts::list_mounts();
    let mut marked = 0;
    for mount in &mount_list {
        // Skip virtual and network filesystems for fanotify
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

    eprintln!("trashd-daemon: monitoring {} filesystem(s) for deletions", marked);

    // Event loop
    let mut buf = vec![0u8; 4096];
    let meta_size = std::mem::size_of::<FanotifyEventMetadata>();

    loop {
        let n = unsafe {
            libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                // No events — poll/sleep
                let mut pfd = libc::pollfd {
                    fd: fan_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, 1000) }; // 1s timeout
                continue;
            }
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }

        let n = n as usize;
        let mut offset = 0;

        while offset + meta_size <= n {
            let event = unsafe {
                &*(buf.as_ptr().add(offset) as *const FanotifyEventMetadata)
            };

            // Validate
            if event.vers != FANOTIFY_METADATA_VERSION {
                eprintln!("trashd-daemon: unexpected fanotify version {}", event.vers);
                break;
            }

            // Process event
            if event.mask & (FAN_DELETE | FAN_DELETE_SELF | FAN_MOVED_FROM) != 0 {
                let path = if event.fd != FAN_NOFD {
                    path_from_fd(event.fd)
                } else {
                    None
                };

                let pid = event.pid as u32;
                let proc_name = process_name(pid);
                let now = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();

                if let Some(ref p) = path {
                    let skipped = config.should_skip(p);
                    let ev = DeletionEvent {
                        path: p.clone(),
                        pid,
                        process: proc_name,
                        timestamp: now,
                    };
                    ev.log(skipped);
                }

                // Close the fd provided by fanotify
                if event.fd >= 0 {
                    unsafe { libc::close(event.fd) };
                }
            }

            offset += event.event_len as usize;
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
