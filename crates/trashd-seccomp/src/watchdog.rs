//! Watchdog process for the seccomp supervisor.
//!
//! The watchdog FORKS the supervisor itself, so `waitpid()` always targets a
//! real child. (Previously the orchestrator forked the supervisor as the
//! watchdog's SIBLING; the watchdog's waitpid got ECHILD immediately, causing
//! a fake failover and two supervisors racing on one notification fd.)
//!
//! If the supervisor dies:
//!   1. Start draining notifications with CONTINUE (fail-safe)
//!   2. Fork a new supervisor
//!   3. Stop draining, let the new supervisor take over

use crate::supervisor;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

static SUPERVISOR_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_term_and_exit(sig: libc::c_int) {
    let pid = SUPERVISOR_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
    unsafe { libc::_exit(0) };
}

/// Run the watchdog loop. This never returns under normal operation.
///
/// - `notif_fd`: a dup'd copy of the seccomp notification fd
pub fn run_watchdog(notif_fd: i32) -> ! {
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        libc::signal(
            libc::SIGINT,
            forward_term_and_exit as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            forward_term_and_exit as *const () as libc::sighandler_t,
        );
    }

    // Spawn OUR OWN supervisor so waitpid below targets a real child (#5).
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            eprintln!(
                "trashd-exec: watchdog: initial supervisor fork failed: {}",
                io::Error::last_os_error()
            );
            // No supervisor at all — drain forever so the wrapped command
            // can still make progress (permanent deletes, fail-open).
            set_nonblocking(notif_fd, true);
            passthrough_loop(notif_fd)
        }
        0 => {
            // Supervisor child
            if let Err(e) = supervisor::run_supervisor(notif_fd) {
                eprintln!("trashd-exec: supervisor error: {e}");
            }
            unsafe { libc::_exit(1) }
        }
        supervisor_pid => {
            SUPERVISOR_PID.store(supervisor_pid, Ordering::Relaxed);
            eprintln!("trashd-exec: watchdog: supervisor spawned (pid {supervisor_pid})");
            supervise_loop(supervisor_pid, notif_fd)
        }
    }
}

/// Wait for our supervisor child; on death, fail over to a fresh one.
fn supervise_loop(mut supervisor_pid: libc::pid_t, notif_fd: i32) -> ! {
    loop {
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

        // Our child was reaped — clear the global before any fork so a
        // SIGTERM landing between here and the new spawn can't hit a
        // recycled PID.
        SUPERVISOR_PID.store(0, Ordering::Relaxed);

        eprintln!(
            "trashd-exec: watchdog: supervisor died ({}), failing over",
            exit_info
        );

        // Phase 1: Drain pending notifications with CONTINUE.
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
                passthrough_loop(notif_fd)
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
                SUPERVISOR_PID.store(child_pid, Ordering::Relaxed);
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
