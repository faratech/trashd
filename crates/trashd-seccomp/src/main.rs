//! trashd-exec — launch a command under seccomp trash protection.
//!
//! Usage: trashd-exec [--preserve-privileges] [--] <command> [args...]
//!
//! All child processes (and their descendants) have unlink/unlinkat/rmdir
//! trapped by a seccomp filter. A supervisor process moves files to trash
//! instead of deleting them. A watchdog process ensures crash recovery.
//!
//! Architecture:
//!   trashd-exec (orchestrator)
//!     ├── child: installs seccomp filter, exec's command
//!     └── watchdog: monitors supervisor, failover with CONTINUE
//!          └── supervisor: handles notifications, trashes files
//! The orchestrator brokers memory/fd access as the stable target ancestor.

mod broker;
mod filter;
mod mem;
mod pin;
#[path = "../../trashd-common/src/seccomp_identity.rs"]
mod seccomp_identity;
mod supervisor;
mod watchdog;

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::process::ExitCode;

static STARTUP_PROBE: &[u8] = b"trashd-startup-probe\0";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("Usage: trashd-exec [--preserve-privileges] [--] <command> [args...]");
        eprintln!();
        eprintln!("Launch a command with seccomp-based trash protection.");
        eprintln!("All unlink/rmdir syscalls are intercepted and files are");
        eprintln!("moved to trash instead of deleted.");
        eprintln!();
        eprintln!("Set TRASH_BYPASS=1 to disable (checked by shim/preload layers).");
        eprintln!("Requires Linux 5.6+ kernel.");
        eprintln!(
            "Explicit wrapping sets NoNewPrivs (setuid and file capabilities cannot elevate)."
        );
        eprintln!("--preserve-privileges requires CAP_SYS_ADMIN; otherwise it uses fallback.");
        return ExitCode::from(1);
    }

    let preserve_privileges = args[1] == "--preserve-privileges";
    let mut start = if preserve_privileges { 2 } else { 1 };
    if args.get(start).is_some_and(|a| a == "--") {
        start += 1;
    }
    if start == args.len() {
        return ExitCode::from(1);
    }
    if std::env::var("TRASH_BYPASS")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        exec_command(&args[start..]);
    }

    match run(&args[start..], preserve_privileges) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("trashd-exec: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(command_args: &[String], preserve_privileges: bool) -> io::Result<ExitCode> {
    // Keep orphaned target descendants in our ancestry: Yama authorizes the
    // stable ancestor broker even when a target forks and its parent exits.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let signals = SignalWait::new()?;
    let cookie = seccomp_identity::random()?;
    // This descriptor exists in the waiting child and exercises dirfd pinning.
    let directory = std::fs::File::open(".")?;
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
            signals.restore_mask();
            unsafe { libc::close(sv[0]) }; // Close parent's end

            // Required before seccomp
            if !preserve_privileges
                && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
            {
                let e = io::Error::last_os_error();
                eprintln!("trashd-exec: prctl(NO_NEW_PRIVS) failed: {e}");
                send_fd(sv[1], -1);
                unsafe { libc::_exit(126) };
            }

            // Install seccomp filter — returns notification fd
            let notif_fd = match filter::install_filter(cookie) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("trashd-exec: seccomp filter install failed: {e}");
                    if e.raw_os_error() == Some(libc::EBUSY) {
                        eprintln!(
                            "trashd-exec: an inherited notification listener prevents another listener"
                        );
                    }
                    eprintln!("trashd-exec: continuing with preload/shim fallback, if available");
                    // Only an established listener may disable preload. A
                    // stale inherited marker must never survive fallback.
                    unsafe { std::env::remove_var("TRASHD_SECCOMP_ACTIVE") };
                    // Send -1 to signal failure, then exec without protection
                    send_fd(sv[1], -1);
                    unsafe { libc::close(sv[1]) };
                    unsafe { libc::_exit(126) };
                }
            };

            // Send notification fd to parent. If delivery fails, the parent
            // can never drain notifications — running on would hang the very
            // first delete. Abort loudly instead (#13).
            if !send_fd(sv[1], notif_fd) {
                eprintln!("trashd-exec: child: could not pass notification fd — aborting");
                unsafe { libc::_exit(126) };
            }
            unsafe {
                libc::close(notif_fd);
            }

            // Do not announce protection or start deleting until the parent
            // has verified memory access and started the supervisor tree.
            let mut ready = 0u8;
            if unsafe { libc::read(sv[1], (&mut ready as *mut u8).cast(), 1) } != 1 || ready != 1 {
                eprintln!("trashd-exec: supervisor startup failed — aborting");
                unsafe { libc::_exit(126) };
            }
            unsafe {
                libc::close(sv[1]);
                std::env::set_var("TRASHD_SECCOMP_ACTIVE", "1");
                std::env::set_var(
                    seccomp_identity::COOKIE_ENV,
                    seccomp_identity::encode(cookie),
                );
            }

            // Exec the command
            exec_command(command_args);
        }
        _ => {}
    }

    // --- PARENT (ORCHESTRATOR) PROCESS ---
    unsafe { libc::close(sv[1]) }; // Close child's end
    let startup = unsafe { OwnedFd::from_raw_fd(sv[0]) };
    let mut child = ChildProcess(child_pid);
    if let Some(exit) = wait_for_startup(startup.as_raw_fd(), &mut child, &signals)? {
        return Ok(exit);
    }

    // Receive notification fd from child. On error, the child may already
    // have installed its filter: leaving it running with no listener would
    // hang every delete, so kill + reap it before bailing (#13).
    let notif_fd = recv_fd(startup.as_raw_fd())?;
    if notif_fd < 0 {
        child.wait(None, &signals)?;
        return fallback(command_args, &signals);
    }
    let listener = unsafe { OwnedFd::from_raw_fd(notif_fd) };

    // Verify actual ptrace permission before releasing the filtered child.
    if let Err(e) = mem::read_path_locally(child_pid as u32, STARTUP_PROBE.as_ptr() as u64)
        .map_err(|e| io::Error::other(format!("memory access: {e}")))
        .and_then(|_| {
            pin::startup_probe(child_pid as u32, directory.as_raw_fd())
                .map_err(|e| io::Error::other(format!("filesystem access: {e}")))
        })
    {
        child.terminate(libc::SIGKILL);
        drop(listener);
        drop(startup);
        eprintln!("trashd-exec: cannot inspect protected child: {e}");
        eprintln!("trashd-exec: continuing with preload/shim fallback, if available");
        // A filter cannot be removed. Replace the waiting filtered child
        // with one forked from this unfiltered parent before fallback exec.
        return fallback(command_args, &signals);
    }
    let (broker_server, broker_client) = UnixDatagram::pair()?;
    let (ready_server, ready_client) = UnixDatagram::pair()?;
    ready_server.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    // fork duplicates the listener reference; the parent drops its copy
    // once the watchdog has started the supervisor.

    // Fork the WATCHDOG first; IT forks (and owns) the supervisor so that
    // its waitpid() targets a real child. The previous layout made the
    // supervisor a SIBLING of the watchdog — waitpid always returned ECHILD,
    // triggering an instant fake failover with two supervisors racing on one
    // notification fd (#5).
    let watchdog_pid = unsafe { libc::fork() };
    match watchdog_pid {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            // --- WATCHDOG PROCESS ---
            signals.restore_mask();
            drop(startup);
            drop(broker_server);
            drop(ready_server);
            watchdog::run_watchdog(
                notif_fd,
                broker_client.as_raw_fd(),
                ready_client.as_raw_fd(),
            );
            // run_watchdog never returns (it's a ! function)
        }
        _ => {}
    }
    let mut watchdog = ChildProcess(watchdog_pid);
    drop(ready_client);
    if let Some(exit) = wait_for_startup(ready_server.as_raw_fd(), &mut child, &signals)? {
        return Ok(exit);
    }
    let mut ready = [0u8];
    if ready_server.recv(&mut ready)? != 1 || ready[0] != 1 {
        return Err(io::Error::other(
            "supervisor could not establish protection",
        ));
    }

    // Orchestrator: close fds we don't need, wait for the child
    if unsafe {
        libc::send(
            startup.as_raw_fd(),
            ready.as_ptr().cast(),
            1,
            libc::MSG_NOSIGNAL,
        )
    } != 1
    {
        return Err(io::Error::last_os_error());
    }
    drop(startup);
    drop(listener);
    drop(broker_client);

    let result = wait_for_children(
        &mut child,
        Some(broker_server.as_raw_fd()),
        &signals,
        Some(watchdog_pid),
    );

    // Child is done — tear down the protection tree. The watchdog forwards
    // SIGTERM to its supervisor child before exiting (#5), so one TERM here
    // retires both.
    watchdog.terminate(libc::SIGTERM);

    result
}

fn fallback(command_args: &[String], signals: &SignalWait) -> io::Result<ExitCode> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        signals.restore_mask();
        unsafe {
            std::env::remove_var("TRASHD_SECCOMP_ACTIVE");
            std::env::remove_var(seccomp_identity::COOKIE_ENV);
        }
        exec_command(command_args);
    }
    ChildProcess(pid).wait(None, signals)
}

/// Own a child until it is reaped. Startup failures must never strand a
/// filtered child waiting forever for a listener or a readiness message.
struct ChildProcess(libc::pid_t);

impl ChildProcess {
    fn wait(&mut self, broker: Option<i32>, signals: &SignalWait) -> io::Result<ExitCode> {
        wait_for_children(self, broker, signals, None)
    }

    fn terminate(&mut self, signal: i32) {
        if self.0 <= 0 {
            return;
        }
        unsafe { libc::kill(self.0, signal) };
        while unsafe { libc::waitpid(self.0, std::ptr::null_mut(), 0) } < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
        self.0 = 0;
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        self.terminate(libc::SIGKILL);
    }
}

/// Consume termination signals synchronously while servicing broker requests.
/// Signals target a pidfd, never a potentially recycled numeric PID.
struct SignalWait {
    fd: OwnedFd,
    old: libc::sigset_t,
}

impl SignalWait {
    fn new() -> io::Result<Self> {
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            let mut old = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGCHLD] {
                libc::sigaddset(&mut mask, sig);
            }
            let result = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut old);
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            let fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                let e = io::Error::last_os_error();
                libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
                return Err(e);
            }
            Ok(Self {
                fd: OwnedFd::from_raw_fd(fd),
                old,
            })
        }
    }

    fn restore_mask(&self) {
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) };
    }

    fn next(&self) -> Option<u32> {
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of_val(&info),
            )
        };
        (n == std::mem::size_of_val(&info) as isize).then_some(info.ssi_signo)
    }
}

impl Drop for SignalWait {
    fn drop(&mut self) {
        while self.next().is_some() {}
        self.restore_mask();
    }
}

fn open_pidfd(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
    }
}

fn signal_pidfd(fd: i32, signal: u32) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
}

/// Wait for either startup message while remaining responsive to cancellation.
/// A stopped startup child cannot handle TERM yet, so abort and reap it after
/// forwarding the requested signal, preserving the requested exit status.
fn wait_for_startup(
    fd: i32,
    child: &mut ChildProcess,
    signals: &SignalWait,
) -> io::Result<Option<ExitCode>> {
    let pidfd = open_pidfd(child.0)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
        if result < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        while let Some(sig) = signals.next() {
            if sig != libc::SIGCHLD as u32 {
                signal_pidfd(pidfd.as_raw_fd(), sig);
                child.terminate(libc::SIGKILL);
                return Ok(Some(ExitCode::from((128 + sig) as u8)));
            }
        }
        if fds[0].revents != 0 {
            return Ok(None);
        }
        if fds[2].revents != 0 {
            let mut status = 0;
            if unsafe { libc::waitpid(child.0, &mut status, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            child.0 = 0;
            return Ok(Some(exit_status(status)));
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "supervisor startup timed out",
            ));
        }
    }
}

/// Wait for the original command and all protected descendants. Subreaper
/// adoption keeps them in the broker's ancestry even after their parents exit.
///
/// A pidfd stays bound to the original process after exit and reap (#42).
/// Polling signalfd keeps HUP/INT/TERM responsive for both protected and
/// fallback execution, instead of blocking them throughout waitpid (#64).
fn wait_for_children(
    child: &mut ChildProcess,
    broker_fd: Option<i32>,
    signals: &SignalWait,
    watchdog_pid: Option<i32>,
) -> io::Result<ExitCode> {
    let original = child.0;
    let mut original_status = None;
    let mut targets = std::collections::BTreeMap::<i32, OwnedFd>::new();
    let mut refresh = true;
    let mut pending_signals = Vec::new();
    // A dead broker peer must not abort the wait loop: the wrapped command is
    // still running and its real exit status has to survive (#120).
    let mut broker_fd = broker_fd;
    loop {
        if refresh {
            let mut reaped = false;
            let children =
                std::fs::read_to_string(format!("/proc/self/task/{}/children", unsafe {
                    libc::getpid()
                }))?;
            for pid in children
                .split_whitespace()
                .filter_map(|p| p.parse::<i32>().ok())
            {
                if Some(pid) == watchdog_pid {
                    continue;
                }
                let mut status = 0;
                let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if waited == pid {
                    reaped = true;
                    targets.remove(&pid);
                    if pid == original {
                        child.0 = 0; // disarm cleanup immediately after reap
                        original_status = Some(exit_status(status));
                    }
                } else if waited == 0 && !targets.contains_key(&pid) {
                    targets.insert(pid, open_pidfd(pid)?);
                } else if waited < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // Reparenting may have happened after this /proc snapshot but
            // before waitpid. Rescan after every reap before declaring the
            // protected tree empty, including newly adopted descendants.
            if reaped {
                continue;
            }
            if targets.is_empty()
                && let Some(status) = original_status
            {
                return Ok(status);
            }
            refresh = false;
        }
        for sig in pending_signals.drain(..) {
            if let Some(fd) = targets.get(&original) {
                signal_pidfd(fd.as_raw_fd(), sig);
            } else {
                for fd in targets.values() {
                    signal_pidfd(fd.as_raw_fd(), sig);
                }
            }
        }
        let mut fds = vec![
            libc::pollfd {
                fd: signals.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: broker_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        fds.extend(targets.values().map(|fd| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }));
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        while let Some(sig) = signals.next() {
            refresh = true;
            if sig != libc::SIGCHLD as u32 {
                // Refresh before forwarding: the original may have just
                // exited, in which case its adopted roots receive the signal.
                pending_signals.push(sig);
            }
        }
        refresh |= fds.iter().skip(2).any(|fd| fd.revents != 0);
        if fds[1].revents & libc::POLLIN != 0 {
            match broker::serve(fds[1].fd) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Peer closed: drop it from the poll set instead of
                    // spinning on EOF or tearing down live children (#120).
                    eprintln!("trashd-exec: broker peer closed; continuing without it");
                    broker_fd = None;
                }
                Err(e) => {
                    // One malformed/failed request must not kill the wrapped
                    // command; log and keep serving.
                    eprintln!("trashd-exec: broker request failed: {e}");
                }
            }
        }
    }
}

fn exit_status(status: i32) -> ExitCode {
    if libc::WIFEXITED(status) {
        ExitCode::from(libc::WEXITSTATUS(status) as u8)
    } else if libc::WIFSIGNALED(status) {
        // Killed by signal — convention is 128 + signal number
        ExitCode::from((128 + libc::WTERMSIG(status)) as u8)
    } else {
        ExitCode::from(1)
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

/// Send `fd` over the socket. Returns false when delivery failed — callers
/// in the child MUST abort (a filter without a listener hangs deletes, #13).
fn send_fd(sock: i32, fd: i32) -> bool {
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
        return false;
    }
    true
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

    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_case(case: impl FnOnce() + std::panic::UnwindSafe) {
        let helper = unsafe { libc::fork() };
        assert!(helper >= 0);
        if helper == 0 {
            unsafe { libc::alarm(10) };
            let result = std::panic::catch_unwind(case);
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(helper, &mut status, 0) }, helper);
        assert_eq!(status, 0);
    }

    #[test]
    fn adopted_children_finish_before_original_status_is_returned() {
        isolated_case(|| {
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
                0
            );
            let signals = SignalWait::new().unwrap();
            let (report, writer) = UnixDatagram::pair().unwrap();
            report.set_nonblocking(true).unwrap();
            let original = unsafe { libc::fork() };
            assert!(original >= 0);
            if original == 0 {
                let descendant = unsafe { libc::fork() };
                assert!(descendant >= 0);
                if descendant == 0 {
                    // Guarantee adoption happens while the original is being
                    // reaped, and that the descendant outlives the original.
                    unsafe { libc::usleep(150_000) };
                    writer.send(b"finished").unwrap();
                    unsafe { libc::_exit(0) };
                }
                unsafe { libc::_exit(37) };
            }
            let mut child = ChildProcess(original);
            assert_eq!(child.wait(None, &signals).unwrap(), ExitCode::from(37));
            assert_eq!(child.0, 0);
            let mut bytes = [0u8; 8];
            assert_eq!(report.recv(&mut bytes).unwrap(), 8);
            assert_eq!(&bytes, b"finished");
            assert_eq!(
                unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        });
    }

    #[test]
    fn startup_cancellation_reaps_even_a_stopped_child() {
        isolated_case(|| {
            let signals = SignalWait::new().unwrap();
            let (server, _client) = UnixDatagram::pair().unwrap();
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                unsafe {
                    libc::raise(libc::SIGSTOP);
                    libc::_exit(0)
                };
            }
            let wrapper = unsafe { libc::getpid() };
            let sender = unsafe { libc::fork() };
            assert!(sender >= 0);
            if sender == 0 {
                unsafe {
                    libc::usleep(20_000);
                    libc::kill(wrapper, libc::SIGTERM);
                    libc::_exit(0)
                };
            }
            let mut child = ChildProcess(pid);
            let start = std::time::Instant::now();
            assert_eq!(
                wait_for_startup(server.as_raw_fd(), &mut child, &signals).unwrap(),
                Some(ExitCode::from(143))
            );
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
            assert_eq!(child.0, 0);
            unsafe { libc::waitpid(sender, std::ptr::null_mut(), 0) };
        });
    }

    #[test]
    fn forwards_hup_int_term_without_recycled_pids() {
        const CHILD: &str = "TRASHD_TEST_SIGNAL_CHILD";
        if let Ok(signal) = std::env::var(CHILD) {
            // The Rust test harness has an unblocked main thread. Run the
            // event loop in a fresh single-threaded process, like the binary.
            let harness_child = unsafe { libc::fork() };
            assert!(harness_child >= 0);
            if harness_child > 0 {
                let mut status = 0;
                assert_eq!(
                    unsafe { libc::waitpid(harness_child, &mut status, 0) },
                    harness_child
                );
                assert_eq!(status, 0);
                return;
            }
            let signal: i32 = signal.parse().unwrap();
            let signals = SignalWait::new().unwrap();
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
                    unsafe { libc::signal(sig, libc::SIG_DFL) };
                }
                signals.restore_mask();
                loop {
                    unsafe { libc::pause() };
                }
            }
            let wrapper = unsafe { libc::getpid() };
            let sender = unsafe { libc::fork() };
            assert!(sender >= 0);
            if sender == 0 {
                unsafe {
                    libc::usleep(20_000);
                    libc::kill(wrapper, signal);
                    libc::_exit(0);
                }
            }
            assert_eq!(
                ChildProcess(child).wait(None, &signals).unwrap(),
                ExitCode::from((128 + signal) as u8)
            );
            unsafe { libc::waitpid(sender, std::ptr::null_mut(), 0) };
            unsafe { libc::_exit(0) };
        }
        for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::forwards_hup_int_term_without_recycled_pids",
                    "--nocapture",
                ])
                .env(CHILD, signal.to_string())
                .status()
                .unwrap();
            assert!(status.success(), "signal {signal}");
        }
    }
}
