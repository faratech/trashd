//! Watchdog process for the seccomp supervisor.
//!
//! The watchdog FORKS the supervisor itself, so `waitpid()` always targets a
//! real child. (Previously the orchestrator forked the supervisor as the
//! watchdog's SIBLING; the watchdog's waitpid got ECHILD immediately, causing
//! a fake failover and two supervisors racing on one notification fd.)
//!
//! If the supervisor dies, a new one is forked at once and receives the
//! notifications still queued. A crash loop backs off, and once several
//! replacements in a row die at once, the queue is declined (CONTINUE, or
//! ENOSYS for a deferring preload) before each further attempt.

use crate::supervisor;
use std::io;

/// The start time (clock ticks since boot) of `pid` from /proc, or None.
/// Distinguishes a process from a later process reusing its PID.
pub fn proc_start_time(pid: i32) -> Option<u64> {
    parse_start_time(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Parse field 22 (starttime) out of a /proc/<pid>/stat line. The comm field
/// may contain spaces and parens, so fields are counted from the last ')'.
pub fn parse_start_time(stat: &str) -> Option<u64> {
    let after_comm = stat.rfind(')')? + 2;
    // after_comm starts at field 3 (state), so starttime is index 19.
    stat.get(after_comm..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Run the watchdog loop. This never returns under normal operation.
///
/// - `notif_fd`: a dup'd copy of the seccomp notification fd
/// - `orchestrator_start`: the orchestrator's /proc start time, captured by
///   the orchestrator before forking, so its identity survives PID reuse
pub fn run_watchdog(
    notif_fd: i32,
    broker_fd: i32,
    ready_fd: i32,
    orchestrator_start: Option<u64>,
) -> ! {
    // Same fork→prctl race #93 fixed for the supervisor: PR_SET_PDEATHSIG
    // only covers orchestrator deaths AFTER it takes effect, so bail out if
    // the orchestrator vanished in the window — an orphaned watchdog would
    // otherwise respawn a supervisor that holds the notification fd forever.
    // The parent is identified by PID + start time, not PID alone: when the
    // orchestrator legitimately IS PID 1 (container init), PPID 1 is the
    // live orchestrator, not proof of reparenting (#252).
    let parent_at_spawn = unsafe { libc::getppid() };
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
    }
    if unsafe { libc::getppid() } != parent_at_spawn
        || orchestrator_start.is_some_and(|start| proc_start_time(parent_at_spawn) != Some(start))
    {
        // Already reparented: the orchestrator died before prctl took effect.
        unsafe {
            libc::close(notif_fd);
            libc::close(broker_fd);
            libc::close(ready_fd);
        }
        std::process::exit(1);
    }
    // Workers never use the launch directory; holding it as their cwd kept
    // its filesystem busy for the whole session (#323).
    unsafe { libc::chdir(c"/".as_ptr()) };
    // Terminal and job signals, SIGTERM included, are ignored
    // (SignalWait::reset_for_worker): Ctrl-C, and later a process-group
    // SIGTERM (seccomp-orch-1), ended both workers while the command kept
    // running, so its cleanup deletes failed with ENOSYS. The orchestrator
    // tears this process down with SIGKILL once the command exits; the
    // supervisor follows through PR_SET_PDEATHSIG.

    // Spawn OUR OWN supervisor so waitpid below targets a real child (#5).
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            supervisor::signal_ready(ready_fd, false);
            report!(
                "trashd-exec: watchdog: initial supervisor fork failed: {}",
                io::Error::last_os_error()
            );
            // No supervisor at all — drain forever so the wrapped command
            // can still make progress (permanent deletes, fail-open).
            set_nonblocking(notif_fd, true);
            passthrough_loop(notif_fd)
        }
        0 => {
            // Supervisor child. A panic must not unwind into the frames this
            // fork shares with the watchdog and orchestrator (#323).
            let _ = std::panic::catch_unwind(|| {
                if let Err(e) = supervisor::run_supervisor(notif_fd, broker_fd, ready_fd) {
                    report!("trashd-exec: supervisor error: {e}");
                }
            });
            unsafe { libc::_exit(1) }
        }
        supervisor_pid => {
            unsafe { libc::close(ready_fd) };
            report!("trashd-exec: watchdog: supervisor spawned (pid {supervisor_pid})");
            supervise_loop(supervisor_pid, notif_fd, broker_fd)
        }
    }
}

/// How a dead supervisor is replaced. The replacement inherits the listener
/// and receives every notification still queued, so failover forks it at
/// once: declining the queue first answered CONTINUE, a permanent delete for
/// a raw-syscall caller, moments before a replacement could have trashed it
/// (seccomp-orch-5). Only a crash loop backs off, and only one that keeps
/// dying declines the queue, so no delete waits forever.
#[derive(Default)]
struct Failover {
    /// Consecutive supervisors that died before serving `HEALTHY`.
    rapid_deaths: u32,
}

impl Failover {
    /// A supervisor that lived this long was not part of a crash loop.
    const HEALTHY: std::time::Duration = std::time::Duration::from_secs(1);
    /// Rapid deaths in a row after which the queue is declined.
    const DECLINE_AFTER: u32 = 3;
    /// Bounded backoff (#121): a persistent startup error (e.g. socketpair
    /// failure under fd pressure) would otherwise produce a tight
    /// fork/respawn loop with stderr spam. 250 ms keeps failover snappy
    /// while bounding the loop rate.
    const BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

    /// After a supervisor that ran for `lifetime` died: whether to decline
    /// the queued notifications first, and how long to wait before forking
    /// the replacement.
    fn after_death(&mut self, lifetime: std::time::Duration) -> (bool, std::time::Duration) {
        if lifetime >= Self::HEALTHY {
            self.rapid_deaths = 0;
            return (false, std::time::Duration::ZERO);
        }
        self.rapid_deaths = self.rapid_deaths.saturating_add(1);
        (self.rapid_deaths >= Self::DECLINE_AFTER, Self::BACKOFF)
    }
}

/// Wait for our supervisor child; on death, fail over to a fresh one.
fn supervise_loop(mut supervisor_pid: libc::pid_t, notif_fd: i32, broker_fd: i32) -> ! {
    let mut failover = Failover::default();
    let mut started = std::time::Instant::now();
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

        // Every filtered task has exited: there is nothing left to
        // supervise, and a replacement would only exit again every 250 ms.
        if supervisor::listener_done(notif_fd, 0) {
            unsafe { libc::_exit(0) };
        }

        report!(
            "trashd-exec: watchdog: supervisor died ({}), failing over",
            exit_info
        );

        let (decline, delay) = failover.after_death(started.elapsed());
        if decline {
            // Replacements keep dying: answer what is queued (CONTINUE, or
            // ENOSYS for a deferring preload) rather than let it wait.
            set_nonblocking(notif_fd, true);
            drain_declining(notif_fd);
        }
        std::thread::sleep(delay);

        // Phase 2: Fork a new supervisor.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                report!(
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
                report!(
                    "trashd-exec: watchdog: new supervisor started (pid {})",
                    unsafe { libc::getpid() }
                );
                let _ = std::panic::catch_unwind(|| {
                    if let Err(e) = supervisor::run_supervisor(notif_fd, broker_fd, -1) {
                        report!("trashd-exec: supervisor error: {e}");
                    }
                });
                unsafe { libc::_exit(1) };
            }
            child_pid => {
                // Watchdog continues — restore blocking mode and loop
                set_nonblocking(notif_fd, false);
                supervisor_pid = child_pid;
                started = std::time::Instant::now();
                report!(
                    "trashd-exec: watchdog: new supervisor spawned (pid {})",
                    child_pid
                );
            }
        }
    }
}

/// Drain all pending notifications by responding CONTINUE.
///
/// KNOWN LIMIT: a notification the DEAD supervisor had already dequeued but
/// not answered cannot be re-received (NOTIF_RECV dequeues); the kernel only
/// flushes waiters with ENOSYS when the LAST listener fd closes, and this
/// process deliberately holds one open to stay useful. Such a delete would
/// hang until the target dies. Accepted: requires a supervisor crash mid-
/// handle, which is exactly the failure this watchdog exists to bound.
fn drain_declining(fd: i32) {
    loop {
        // Older notification ioctls ignore O_NONBLOCK. Check readiness before
        // RECV so an idle listener cannot prevent supervisor replacement.
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut ready, 1, 0) } <= 0 || ready.revents & libc::POLLIN == 0 {
            break;
        }
        match supervisor::notif_recv(fd) {
            // A deferring preload still trashes in-process (#349).
            Ok(notif) => supervisor::decline(fd, &notif),
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

/// Emergency passthrough: decline everything forever (CONTINUE, or ENOSYS
/// for a deferring preload).
fn passthrough_loop(fd: i32) -> ! {
    report!("trashd-exec: watchdog: entering emergency passthrough mode");
    loop {
        match supervisor::notif_recv(fd) {
            Ok(notif) => supervisor::decline(fd, &notif),
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => {
                // fd closed — we're done
                unsafe { libc::_exit(0) };
            }
            // RECV ignores O_NONBLOCK and fails at once after every filtered
            // task exits: block in poll, never retry blindly.
            Err(_) if supervisor::listener_done(fd, -1) => unsafe { libc::_exit(0) },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::tests::{exits_cleanly, finished_listener};

    // Regression (#252): PID + start time identifies the orchestrator, so a
    // legitimate PID 1 parent is not mistaken for reparenting to init.
    #[test]
    fn start_time_parses_despite_a_spaced_comm() {
        // Fields after ')' start at field 3; starttime (field 22) is the
        // 20th token. comm contains spaces and a paren here on purpose.
        let stat = "1 (weird ) name) S 0 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 98765 1234";
        assert_eq!(parse_start_time(stat), Some(98765));
        assert!(proc_start_time(unsafe { libc::getpid() }).is_some());
    }

    // seccomp-orch-5: failover declined every queued notification, which is
    // CONTINUE, a permanent delete for a raw-syscall caller, although the
    // replacement forked moments later can receive them. Only a crash loop
    // backs off, and only one that keeps dying declines the queue, so no
    // delete waits forever.
    #[test]
    fn failover_hands_queued_deletes_to_the_replacement() {
        use std::time::Duration;
        let mut failover = Failover::default();
        // A supervisor that served a while is replaced at once.
        assert_eq!(
            failover.after_death(Duration::from_secs(60)),
            (false, Duration::ZERO)
        );
        // Replacements dying at once back off, then decline the queue.
        let rapid = Duration::from_millis(10);
        assert_eq!(failover.after_death(rapid), (false, Failover::BACKOFF));
        assert_eq!(failover.after_death(rapid), (false, Failover::BACKOFF));
        assert_eq!(failover.after_death(rapid), (true, Failover::BACKOFF));
        assert_eq!(failover.after_death(rapid), (true, Failover::BACKOFF));
        // One that lasts ends the crash loop.
        assert_eq!(
            failover.after_death(Duration::from_secs(5)),
            (false, Duration::ZERO)
        );
        assert_eq!(failover.after_death(rapid), (false, Failover::BACKOFF));
    }

    #[test]
    fn emergency_passthrough_ends_when_the_listener_is_finished() {
        exits_cleanly(|| passthrough_loop(finished_listener()));
    }
}
