//! Watchdog process for the seccomp supervisor.
//!
//! Holds a dup'd copy of the notification fd. If the supervisor crashes,
//! the watchdog immediately starts draining notifications with CONTINUE
//! (allowing real syscalls) and spawns a new supervisor.

use crate::supervisor;
use std::io;

/// Run the watchdog loop. This never returns under normal operation.
///
/// - `notif_fd`: a dup'd copy of the seccomp notification fd
/// - `supervisor_pid`: PID of the initial supervisor process
///
/// On supervisor death:
///   1. Start draining notifications with CONTINUE (fail-safe)
///   2. Fork a new supervisor
///   3. Stop draining, let new supervisor take over
pub fn run_watchdog(notif_fd: i32, mut supervisor_pid: libc::pid_t) -> ! {
    loop {
        // Wait for the supervisor to exit
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(supervisor_pid, &mut status, 0) };

        let exit_info = if waited <= 0 {
            // waitpid error — status is uninitialized, don't read it
            format!("waitpid error: {}", io::Error::last_os_error())
        } else if libc::WIFEXITED(status) {
            format!("exited with code {}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("killed by signal {}", libc::WTERMSIG(status))
        } else {
            "unknown status".to_string()
        };

        eprintln!(
            "trashd-exec: watchdog: supervisor (pid {}) died ({}), failing over",
            supervisor_pid, exit_info,
        );

        // Phase 1: Drain pending notifications with CONTINUE.
        // We do this in a non-blocking fashion while we set up the new supervisor.
        // Set the fd to non-blocking for draining.
        set_nonblocking(notif_fd, true);
        drain_with_continue(notif_fd);

        // Phase 2: Fork a new supervisor.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                eprintln!(
                    "trashd-exec: watchdog: fork failed: {}",
                    io::Error::last_os_error()
                );
                // Keep draining in passthrough mode — better than nothing
                set_nonblocking(notif_fd, false);
                passthrough_loop(notif_fd);
            }
            0 => {
                // New supervisor child process
                set_nonblocking(notif_fd, false);
                eprintln!(
                    "trashd-exec: watchdog: new supervisor started (pid {})",
                    unsafe { libc::getpid() }
                );
                if let Err(e) = supervisor::run_supervisor(notif_fd) {
                    eprintln!("trashd-exec: supervisor error: {e}");
                }
                unsafe { libc::_exit(1) };
            }
            child_pid => {
                // Watchdog continues — restore blocking mode and loop
                set_nonblocking(notif_fd, false);
                supervisor_pid = child_pid;
                eprintln!(
                    "trashd-exec: watchdog: new supervisor spawned (pid {})",
                    child_pid
                );
            }
        }
    }
}

/// Drain all pending notifications by responding CONTINUE.
fn drain_with_continue(fd: i32) {
    loop {
        match supervisor::notif_recv(fd) {
            Ok(notif) => {
                supervisor::respond_continue(fd, notif.id);
            }
            Err(e)
                if e.raw_os_error() == Some(libc::EAGAIN)
                    || e.raw_os_error() == Some(libc::EWOULDBLOCK) =>
            {
                // No more pending notifications
                break;
            }
            Err(_) => break,
        }
    }
}

/// Emergency passthrough: respond CONTINUE to everything forever.
fn passthrough_loop(fd: i32) -> ! {
    eprintln!("trashd-exec: watchdog: entering emergency passthrough mode");
    loop {
        match supervisor::notif_recv(fd) {
            Ok(notif) => supervisor::respond_continue(fd, notif.id),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => {
                // fd closed — we're done
                unsafe { libc::_exit(0) };
            }
            Err(e)
                if e.raw_os_error() == Some(libc::EAGAIN)
                    || e.raw_os_error() == Some(libc::EWOULDBLOCK) =>
            {
                // fd is non-blocking and no notifications pending — poll until ready
                unsafe {
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    libc::poll(&mut pfd, 1, 1000);
                }
            }
            Err(_) => continue,
        }
    }
}

fn set_nonblocking(fd: i32, nonblock: bool) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            let new_flags = if nonblock {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            libc::fcntl(fd, libc::F_SETFL, new_flags);
        }
    }
}
