//! trashd-exec — launch a command under seccomp trash protection.
//!
//! Usage: trashd-exec <command> [args...]
//!
//! All child processes (and their descendants) have unlink/unlinkat/rmdir
//! trapped by a seccomp filter. A supervisor process moves files to trash
//! instead of deleting them. A watchdog process ensures crash recovery.
//!
//! Architecture:
//!   trashd-exec (orchestrator)
//!     ├── child: installs seccomp filter, exec's command
//!     ├── supervisor: handles notifications, trashes files
//!     └── watchdog: monitors supervisor, failover with CONTINUE

mod filter;
mod mem;
mod supervisor;
mod watchdog;

use std::ffi::CString;
use std::io;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("Usage: trashd-exec <command> [args...]");
        eprintln!();
        eprintln!("Launch a command with seccomp-based trash protection.");
        eprintln!("All unlink/rmdir syscalls are intercepted and files are");
        eprintln!("moved to trash instead of deleted.");
        eprintln!();
        eprintln!("Set TRASH_BYPASS=1 to disable (checked by shim/preload layers).");
        eprintln!("Requires Linux 5.5+ kernel.");
        return ExitCode::from(1);
    }

    match run(&args[1..]) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("trashd-exec: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(command_args: &[String]) -> io::Result<ExitCode> {
    // Create a socketpair for passing the notification fd from child to parent.
    let mut sv = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    // Fork the child process (will install seccomp filter + exec).
    let child_pid = unsafe { libc::fork() };
    match child_pid {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            // --- CHILD PROCESS ---
            unsafe { libc::close(sv[0]) }; // Close parent's end

            // Required before seccomp
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
                let e = io::Error::last_os_error();
                eprintln!("trashd-exec: prctl(NO_NEW_PRIVS) failed: {e}");
                unsafe { libc::_exit(126) };
            }

            // Install seccomp filter — returns notification fd
            let notif_fd = match filter::install_filter() {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("trashd-exec: seccomp filter install failed: {e}");
                    eprintln!("trashd-exec: running command without protection");
                    // Send -1 to signal failure, then exec without protection
                    send_fd(sv[1], -1);
                    unsafe { libc::close(sv[1]) };
                    exec_command(command_args);
                }
            };

            // Send notification fd to parent
            send_fd(sv[1], notif_fd);
            unsafe {
                libc::close(notif_fd);
                libc::close(sv[1]);
            }

            // Exec the command
            exec_command(command_args);
        }
        _ => {}
    }

    // --- PARENT (ORCHESTRATOR) PROCESS ---
    unsafe { libc::close(sv[1]) }; // Close child's end

    // Receive notification fd from child
    let notif_fd = recv_fd(sv[0])?;
    unsafe { libc::close(sv[0]) };

    if notif_fd < 0 {
        // Child couldn't install seccomp — just wait for it
        eprintln!("trashd-exec: running without seccomp protection");
        return wait_for_child(child_pid);
    }

    // Dup the fd for the watchdog
    let watchdog_fd = unsafe { libc::dup(notif_fd) };
    if watchdog_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Fork the supervisor
    let supervisor_pid = unsafe { libc::fork() };
    match supervisor_pid {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            // --- SUPERVISOR PROCESS ---
            unsafe { libc::close(watchdog_fd) };
            if let Err(e) = supervisor::run_supervisor(notif_fd) {
                eprintln!("trashd-exec: supervisor error: {e}");
            }
            unsafe { libc::_exit(0) };
        }
        _ => {}
    }

    // Fork the watchdog
    let watchdog_pid = unsafe { libc::fork() };
    match watchdog_pid {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            // --- WATCHDOG PROCESS ---
            unsafe { libc::close(notif_fd) };
            watchdog::run_watchdog(watchdog_fd, supervisor_pid);
            // run_watchdog never returns (it's a ! function)
        }
        _ => {}
    }

    // Orchestrator: close fds we don't need, wait for the child
    unsafe {
        libc::close(notif_fd);
        libc::close(watchdog_fd);
    }

    // Forward SIGINT and SIGTERM to the child process so Ctrl-C works
    install_signal_forwarder(child_pid);

    let result = wait_for_child(child_pid);

    // Child is done — clean up supervisor and watchdog
    unsafe {
        libc::kill(supervisor_pid, libc::SIGTERM);
        libc::kill(watchdog_pid, libc::SIGTERM);
        let mut s = 0;
        libc::waitpid(supervisor_pid, &mut s, 0);
        libc::waitpid(watchdog_pid, &mut s, 0);
    }

    result
}

/// Global child PID for signal forwarding (signal handlers can't capture closures).
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

fn install_signal_forwarder(child_pid: libc::pid_t) {
    CHILD_PID.store(child_pid, Ordering::Relaxed);
    unsafe {
        libc::signal(
            libc::SIGINT,
            forward_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            forward_signal as *const () as libc::sighandler_t,
        );
    }
}

/// Wait for the child process and return its exit code.
fn wait_for_child(pid: libc::pid_t) -> io::Result<ExitCode> {
    let mut status: libc::c_int = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        break;
    }

    if libc::WIFEXITED(status) {
        Ok(ExitCode::from(libc::WEXITSTATUS(status) as u8))
    } else if libc::WIFSIGNALED(status) {
        // Killed by signal — convention is 128 + signal number
        Ok(ExitCode::from((128 + libc::WTERMSIG(status)) as u8))
    } else {
        Ok(ExitCode::from(1))
    }
}

/// exec the command (never returns on success).
fn exec_command(args: &[String]) -> ! {
    let c_args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect();
    let c_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execvp(c_ptrs[0], c_ptrs.as_ptr());
    }

    // execvp only returns on error
    let e = io::Error::last_os_error();
    eprintln!("trashd-exec: exec '{}': {e}", args[0]);
    unsafe { libc::_exit(127) };
}

// ---------------------------------------------------------------------------
// fd passing over unix socket (SCM_RIGHTS)
// ---------------------------------------------------------------------------

fn send_fd(sock: i32, fd: i32) {
    let fd_bytes = fd.to_ne_bytes();

    // cmsg buffer: must be aligned and large enough for one fd
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let dummy = [0u8; 1];
    let iov = libc::iovec {
        iov_base: dummy.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    if fd >= 0 {
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
            std::ptr::copy_nonoverlapping(fd_bytes.as_ptr(), libc::CMSG_DATA(cmsg), fd_bytes.len());
        }
    } else {
        // No fd to send — just send the dummy byte
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
    }

    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    if ret < 0 {
        eprintln!(
            "trashd-exec: send_fd failed: {}",
            io::Error::last_os_error()
        );
    }
}

fn recv_fd(sock: i32) -> io::Result<i32> {
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Ok(-1); // Child closed without sending
    }

    // Extract fd from cmsg
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Ok(-1); // No ancillary data — child signaled failure
        }
        if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
            let mut fd: i32 = 0;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                &mut fd as *mut i32 as *mut u8,
                std::mem::size_of::<i32>(),
            );
            Ok(fd)
        } else {
            Ok(-1)
        }
    }
}
