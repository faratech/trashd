//! Seccomp notification supervisor.
//!
//! Receives trapped syscall notifications, moves files to trash,
//! and responds to the kernel. On any error, responds with CONTINUE
//! to let the real syscall execute (fail-safe).

use crate::mem;
use std::io;
use trashd_common::store::TrashError;
use trashd_common::{Config, TrashStore};

// ---------------------------------------------------------------------------
// seccomp notification structs (matching kernel uapi/linux/seccomp.h)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

// ioctl numbers: _IOWR('!', N, struct)
// Computed via: (3 << 30) | (sizeof(struct) << 16) | ('!' << 8) | N
//
// seccomp_notif = 80 bytes on x86_64 (8+4+4+64)
// seccomp_notif_resp = 24 bytes (8+8+4+4)
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = (3 << 30) | (80 << 16) | (0x21 << 8); // 0xC0502100
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = (3 << 30) | (24 << 16) | (0x21 << 8) | 1; // 0xC0182101
                                                                                          // NB: ID_VALID is _IOW (direction=1), not _IOWR (direction=3)
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = (1 << 30) | (8 << 16) | (0x21 << 8) | 2; // 0x40082102

// Compile-time verification that struct sizes match ioctl constants
const _: () = assert!(std::mem::size_of::<SeccompNotif>() == 80);
const _: () = assert!(std::mem::size_of::<SeccompNotifResp>() == 24);

/// Flag to tell kernel to execute the original syscall.
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

/// Receive a pending notification from the seccomp fd.
pub fn notif_recv(fd: i32) -> io::Result<SeccompNotif> {
    let mut notif = unsafe { std::mem::zeroed::<SeccompNotif>() };
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif as *mut _) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(notif)
    }
}

/// Send a response to a notification.
fn notif_send(fd: i32, resp: &SeccompNotifResp) -> io::Result<()> {
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp as *const _) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check if a notification ID is still valid (target is still blocked).
fn notif_id_valid(fd: i32, id: u64) -> bool {
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const _) };
    ret == 0
}

/// Respond with CONTINUE — tell kernel to execute the original syscall.
pub fn respond_continue(fd: i32, id: u64) {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let _ = notif_send(fd, &resp);
}

/// Respond with success (val=0, error=0) — syscall is "done", kernel skips it.
fn respond_success(fd: i32, id: u64) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: 0,
    };
    notif_send(fd, &resp)
}

/// Respond with an errno — syscall "fails" with this error.
fn respond_errno(fd: i32, id: u64, errno: i32) -> io::Result<()> {
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: -errno,
        flags: 0,
    };
    notif_send(fd, &resp)
}

/// Run the supervisor notification loop.
///
/// This blocks forever, handling notifications until the fd is closed
/// or an unrecoverable error occurs.
pub fn run_supervisor(fd: i32) -> io::Result<()> {
    let store = match TrashStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("trashd-exec: supervisor: failed to open trash store: {e}");
            eprintln!("trashd-exec: supervisor: falling back to CONTINUE-only mode");
            return run_passthrough(fd);
        }
    };

    let config = Config::load();

    loop {
        // Block until a notification arrives
        let notif = match notif_recv(fd) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                // Target process died before we read the notification
                continue;
            }
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => {
                // fd closed — supervisor is shutting down
                return Ok(());
            }
            Err(e) => {
                eprintln!("trashd-exec: supervisor: recv error: {e}");
                continue;
            }
        };

        // Handle this notification (fail-safe: any error → CONTINUE)
        handle_notification(fd, &notif, &store, &config);
    }
}

/// Handle a single notification.
fn handle_notification(fd: i32, notif: &SeccompNotif, store: &TrashStore, config: &Config) {
    // Read the path from target's memory
    let path = match mem::resolve_syscall_path(notif.pid, notif.data.nr, &notif.data.args) {
        Ok(p) => p,
        Err(_) => {
            // Can't read path → let the real syscall run
            respond_continue(fd, notif.id);
            return;
        }
    };

    // Check if the notification is still valid (TOCTOU mitigation).
    // If invalid, the target already died or was handled by the watchdog —
    // any response we send will just get ENOENT, which is harmless.
    if !notif_id_valid(fd, notif.id) {
        // Target likely gone. Send CONTINUE defensively — if the target is truly
        // dead, the response harmlessly fails with ENOENT. If the ioctl failed
        // spuriously, this prevents hanging the supervised process.
        respond_continue(fd, notif.id);
        return;
    }

    // From this point, ALL code paths MUST send a response.
    // Failure to respond will hang the supervised process.

    // Check TRASH_BYPASS env var in the target process
    // (We can't easily read env vars from another process, so we rely on
    // the config's skip/bypass lists instead. TRASH_BYPASS is checked in
    // the shim and preload layers.)

    // Check never-trash list
    if config.should_skip(&path) {
        respond_continue(fd, notif.id);
        return;
    }

    // Check if the file exists and is appropriate to trash
    // (For rmdir/unlinkat with AT_REMOVEDIR, the path is a directory)
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(_) => {
            // File doesn't exist or not accessible → let syscall handle the error
            respond_continue(fd, notif.id);
            return;
        }
    };

    // For unlinkat with AT_REMOVEDIR flag or rmdir: only trash empty directories
    #[cfg(target_arch = "x86_64")]
    let is_rmdir = notif.data.nr == 84; // SYS_rmdir
    #[cfg(target_arch = "aarch64")]
    let is_rmdir = false;

    let is_unlinkat_rmdir = notif.data.nr == libc::SYS_unlinkat as i32
        && (notif.data.args[2] as i32 & libc::AT_REMOVEDIR) != 0;

    if is_rmdir || is_unlinkat_rmdir {
        if !meta.is_dir() {
            let _ = respond_errno(fd, notif.id, libc::ENOTDIR);
            return;
        }
        // Only trash empty directories (matching rmdir semantics)
        if let Ok(mut entries) = std::fs::read_dir(&path) {
            if entries.next().is_some() {
                let _ = respond_errno(fd, notif.id, libc::ENOTEMPTY);
                return;
            }
        }
    } else if meta.is_dir() {
        // unlink on a directory → EISDIR
        let _ = respond_errno(fd, notif.id, libc::EISDIR);
        return;
    }

    // Attempt to trash the file
    match store.trash(&path, Some("seccomp")) {
        Ok(_id) => {
            // File moved to trash — tell kernel the syscall "succeeded"
            if respond_success(fd, notif.id).is_err() {
                // Notification expired (target died) — no harm done
            }
        }
        Err(TrashError::Excluded(_)) => {
            // In never-trash list — let real syscall run
            respond_continue(fd, notif.id);
        }
        Err(_) => {
            // Trash failed — fall back to real delete
            respond_continue(fd, notif.id);
        }
    }
}

/// Passthrough mode: respond CONTINUE to every notification.
/// Used when the trash store can't be opened.
fn run_passthrough(fd: i32) -> io::Result<()> {
    loop {
        match notif_recv(fd) {
            Ok(notif) => respond_continue(fd, notif.id),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => return Ok(()),
            Err(_) => continue,
        }
    }
}
