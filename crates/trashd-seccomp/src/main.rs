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

/// `eprintln!` that never panics. The orchestrator and its workers outlive
/// their terminal; a panic on a closed stderr unwound into guards that kill
/// the command, or ended protection while the command kept deleting (#323).
macro_rules! report {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

mod broker;
mod filter;
mod landlock;
mod mem;
mod pin;
#[path = "../../trashd-common/src/seccomp_identity.rs"]
mod seccomp_identity;
mod supervisor;
mod watchdog;

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::process::ExitCode;

static STARTUP_PROBE: &[u8] = b"trashd-startup-probe\0";

fn main() -> ExitCode {
    // Arguments are raw bytes: std::env::args() panicked on non-UTF-8 ones
    // before the command could run (#314).
    let args: Vec<OsString> = std::env::args_os().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        report!("Usage: trashd-exec [--preserve-privileges] [--] <command> [args...]");
        report!();
        report!("Launch a command with seccomp-based trash protection.");
        report!("All unlink/rmdir syscalls are intercepted and files are");
        report!("moved to trash instead of deleted.");
        report!();
        report!("Set TRASH_BYPASS=1 to disable (checked by shim/preload layers).");
        report!("Requires Linux 5.6+ kernel.");
        report!("Explicit wrapping sets NoNewPrivs (setuid and file capabilities cannot elevate).");
        report!("--preserve-privileges requires CAP_SYS_ADMIN; otherwise it uses fallback.");
        return ExitCode::from(1);
    }

    // Answer --version instead of wrapping a command named "--version" (#234);
    // the profile hook runs it to check that the wrapper can start at all.
    if args[1] == "--version" || args[1] == "-V" {
        println!("trashd-exec {}", env!("TRASHD_VERSION"));
        return ExitCode::SUCCESS;
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

    let command = &args[start..];
    let signals = match SignalWait::new() {
        Ok(signals) => signals,
        Err(e) => {
            report!("trashd-exec: {e}; continuing with preload/shim fallback, if available");
            unprotected_exec(command)
        }
    };
    wrap(command, preserve_privileges, &signals)
}

/// Run `command` protected, or unprotected when protection cannot start.
fn wrap(command: &[OsString], preserve_privileges: bool, signals: &SignalWait) -> ExitCode {
    match run(command, preserve_privileges, signals) {
        Ok(status) => status.finish(),
        // Nothing has run yet: become the unprotected command rather than
        // fail a login whose shell this wrapper was asked to start (#313).
        Err(Failure::Startup(e)) => {
            report!("trashd-exec: {e}");
            report!("trashd-exec: continuing with preload/shim fallback, if available");
            fallback(command, signals)
        }
        Err(Failure::Running(e)) => {
            report!("trashd-exec: {e}");
            ExitCode::from(1)
        }
    }
}

/// Why `run` returned without the command's own exit status.
enum Failure {
    /// Before the filtered child was released to exec the command; its
    /// tree is torn down when `run` returns.
    Startup(io::Error),
    /// While the command ran or after it exited.
    Running(io::Error),
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Failure::Startup(error)
    }
}

fn run(
    command_args: &[OsString],
    preserve_privileges: bool,
    signals: &SignalWait,
) -> Result<CommandStatus, Failure> {
    // Keep orphaned target descendants in our ancestry: Yama authorizes the
    // stable ancestor broker even when a target forks and its parent exits.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let cookie = seccomp_identity::random()?;
    // This descriptor exists in the waiting child and exercises dirfd
    // pinning. O_PATH needs no read permission on the cwd (#313).
    let directory = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(".")?
    };
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
        return Err(io::Error::last_os_error().into());
    }

    // Fork the child process (will install seccomp filter + exec).
    let child_pid = unsafe { libc::fork() };
    match child_pid {
        -1 => return Err(io::Error::last_os_error().into()),
        0 => {
            // --- CHILD PROCESS ---
            signals.restore_for_exec();
            unsafe { libc::close(sv[0]) }; // Close parent's end

            // Required before seccomp
            if !preserve_privileges
                && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
            {
                let e = io::Error::last_os_error();
                report!("trashd-exec: prctl(NO_NEW_PRIVS) failed: {e}");
                send_fd(sv[1], -1);
                unsafe { libc::_exit(126) };
            }

            // Install seccomp filter — returns notification fd
            let notif_fd = match filter::install_filter(cookie) {
                Ok(fd) => fd,
                Err(e) => {
                    // One line: every root login on WSL lands here (#235).
                    let cause = if e.raw_os_error() == Some(libc::EBUSY) {
                        "an inherited notification listener prevents another".to_string()
                    } else {
                        e.to_string()
                    };
                    report!(
                        "trashd-exec: seccomp filter install failed ({cause}); continuing with preload/shim fallback"
                    );
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
                report!("trashd-exec: child: could not pass notification fd — aborting");
                unsafe { libc::_exit(126) };
            }
            unsafe {
                libc::close(notif_fd);
            }

            // Do not announce protection or start deleting until the parent
            // has verified memory access and started the supervisor tree.
            let mut ready = 0u8;
            if unsafe { libc::read(sv[1], (&mut ready as *mut u8).cast(), 1) } != 1 || ready != 1 {
                report!("trashd-exec: supervisor startup failed — aborting");
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
    if let Some(exit) = wait_for_startup(startup.as_raw_fd(), &mut child, signals)? {
        return Ok(exit);
    }

    // Receive notification fd from child. On error, the child may already
    // have installed its filter: leaving it running with no listener would
    // hang every delete, so kill + reap it before bailing (#13).
    let notif_fd = recv_fd(startup.as_raw_fd())?;
    if notif_fd < 0 {
        // The failed child is exiting on its own; reap it before replacing
        // this process so it never lingers as the command's zombie.
        child.terminate(libc::SIGKILL);
        fallback(command_args, signals);
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
        report!("trashd-exec: cannot inspect protected child: {e}");
        report!("trashd-exec: continuing with preload/shim fallback, if available");
        // A filter cannot be removed. Replace the waiting filtered child
        // with this unfiltered process.
        fallback(command_args, signals);
    }
    // The waiting child holds its own copy for the command.
    drop(directory);
    let (broker_server, broker_client) = UnixDatagram::pair()?;
    let (ready_server, ready_client) = UnixDatagram::pair()?;
    ready_server.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    // Keep permission tracking outside the target address space, shared by
    // every worker generation before the target can start restricting itself.
    landlock::initialize()?;

    // fork duplicates the listener reference; the parent drops its copy
    // once the watchdog has started the supervisor.

    // Fork the WATCHDOG first; IT forks (and owns) the supervisor so that
    // its waitpid() targets a real child. The previous layout made the
    // supervisor a SIBLING of the watchdog — waitpid always returned ECHILD,
    // triggering an instant fake failover with two supervisors racing on one
    // notification fd (#5).
    // Captured before the fork so the watchdog can tell this process from
    // a different process later reusing its PID — including PID 1 (#252).
    let orchestrator_start = watchdog::proc_start_time(unsafe { libc::getpid() });
    let watchdog_pid = unsafe { libc::fork() };
    match watchdog_pid {
        -1 => return Err(io::Error::last_os_error().into()),
        0 => {
            // --- WATCHDOG PROCESS ---
            signals.reset_for_worker();
            drop(startup);
            drop(broker_server);
            drop(ready_server);
            // This fork shares the orchestrator's stack: a panic must never
            // unwind into its guards, whose drop SIGKILLs the command (#323).
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                watchdog::run_watchdog(
                    notif_fd,
                    broker_client.as_raw_fd(),
                    ready_client.as_raw_fd(),
                    orchestrator_start,
                );
            }));
            unsafe { libc::_exit(1) }
        }
        _ => {}
    }
    let mut watchdog = ChildProcess(watchdog_pid);
    drop(ready_client);
    // A startup failure from here on retires the watchdog (and with it the
    // supervisor) before the command runs unprotected.
    let startup_failed = |watchdog: &mut ChildProcess, error: io::Error| {
        watchdog.terminate(libc::SIGTERM);
        Failure::Startup(error)
    };
    match wait_for_startup(ready_server.as_raw_fd(), &mut child, signals) {
        Ok(Some(exit)) => return Ok(exit),
        Ok(None) => {}
        Err(e) => return Err(startup_failed(&mut watchdog, e)),
    }
    let mut ready = [0u8];
    match ready_server.recv(&mut ready) {
        Ok(1) if ready[0] == 1 => {}
        Ok(_) => {
            return Err(startup_failed(
                &mut watchdog,
                io::Error::other("supervisor could not establish protection"),
            ));
        }
        Err(e) => return Err(startup_failed(&mut watchdog, e)),
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
        // The child sees EOF instead of the readiness byte and exits without
        // running the command.
        return Err(startup_failed(&mut watchdog, io::Error::last_os_error()));
    }
    // The command runs now, so no fallback can need the launch directory:
    // release it, or the session pins its filesystem against umount (#323).
    // Nor can a fallback exec inherit this process's descriptor limit.
    unsafe { libc::chdir(c"/".as_ptr()) };
    raise_descriptor_limit();
    drop(startup);
    drop(listener);
    drop(broker_client);

    let result = wait_for_children(
        &mut child,
        Some(broker_server.as_raw_fd()),
        signals,
        Some(watchdog_pid),
    );

    // Child is done — tear down the protection tree. The watchdog forwards
    // SIGTERM to its supervisor child before exiting (#5), so one TERM here
    // retires both.
    watchdog.terminate(libc::SIGTERM);

    result.map_err(Failure::Running)
}

/// The orchestrator holds a pidfd for every adopted descendant; at the
/// default soft limit (often 1024) a shell leaving many background jobs ran
/// it out of descriptors. Raise the soft limit to the hard one for this
/// process only, once the command was released with the inherited one (#325).
fn raise_descriptor_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < limit.rlim_max
        {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

/// Become the unprotected command. With no supervisor there is nothing for a
/// resident wrapper to do: exec in place leaves no wait loop to spin, keeps
/// signals and exit status native, and lets `exit` close a terminal while
/// daemons the shell started keep running. The failed child must already be
/// reaped.
fn fallback(command_args: &[OsString], signals: &SignalWait) -> ! {
    signals.restore_for_exec();
    unprotected_exec(command_args)
}

/// Exec the command without protection, after any signal state was restored.
fn unprotected_exec(command_args: &[OsString]) -> ! {
    unsafe {
        // Survives execve; the command must not start adopting orphans.
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0);
        std::env::remove_var("TRASHD_SECCOMP_ACTIVE");
        std::env::remove_var(seccomp_identity::COOKIE_ENV);
    }
    exec_command(command_args)
}

/// Own a child until it is reaped. Startup failures must never strand a
/// filtered child waiting forever for a listener or a readiness message.
struct ChildProcess(libc::pid_t);

impl ChildProcess {
    #[cfg(test)]
    fn wait(&mut self, broker: Option<i32>, signals: &SignalWait) -> io::Result<CommandStatus> {
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

/// Signals whose default action ends a process, which the orchestrator
/// waits for and forwards instead. QUIT, USR1 and USR2, and later ALRM (GNU
/// `timeout -s ALRM` signals the whole group), the timer, resource-limit
/// and real-time signals, used to take that default action on the
/// orchestrator, ending protection while the command kept running (#350).
const JOB_SIGNALS: [libc::c_int; 12] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGALRM,
    libc::SIGVTALRM,
    libc::SIGPROF,
    libc::SIGPWR,
    libc::SIGXCPU,
    libc::SIGXFSZ,
];

/// Job signals that report the orchestrator's own resource limits and
/// timers: waited for, so they cannot end it, but never forwarded, which
/// would kill the command (with a core dump) for the wrapper's limits.
const OWN_SIGNALS: [libc::c_int; 4] =
    [libc::SIGVTALRM, libc::SIGPROF, libc::SIGXCPU, libc::SIGXFSZ];

/// One of `OWN_SIGNALS` raised by the wrapper's own limit or timer:
/// kernel-generated, or self-sent like SIGXFSZ (#355). A user's kill still
/// reaches the command (#357).
fn own_signal(sig: u32, from_kernel: bool, sender: u32) -> bool {
    OWN_SIGNALS.contains(&(sig as libc::c_int))
        && (from_kernel || sender == unsafe { libc::getpid() } as u32)
}

/// What the orchestrator waits for: the job signals, the real-time range
/// and SIGCHLD.
fn waited_signals() -> impl Iterator<Item = libc::c_int> {
    JOB_SIGNALS
        .into_iter()
        .chain(libc::SIGRTMIN()..=libc::SIGRTMAX())
        .chain([libc::SIGCHLD])
}

/// What the watchdog and supervisor ignore: every job signal but TERM (their
/// teardown), the real-time range, and terminal stops.
fn worker_ignored_signals() -> impl Iterator<Item = libc::c_int> {
    JOB_SIGNALS
        .into_iter()
        .filter(|&sig| sig != libc::SIGTERM)
        .chain(libc::SIGRTMIN()..=libc::SIGRTMAX())
        .chain([libc::SIGTSTP, libc::SIGTTOU])
}

/// Consume termination signals synchronously while servicing broker requests.
/// Signals target a pidfd, never a potentially recycled numeric PID.
///
/// An inherited SIGCHLD=SIG_IGN (WSL's login passes one to every shell) or
/// SA_NOCLDWAIT makes the kernel reap our children itself: no zombie, no
/// status, and a pidfd that stays readable forever, a 100% CPU spin. Waiting
/// therefore runs with the default disposition; the wrapped command gets the
/// inherited one back.
struct SignalWait {
    fd: OwnedFd,
    old: libc::sigset_t,
    old_sigchld: libc::sigaction,
}

impl SignalWait {
    fn new() -> io::Result<Self> {
        unsafe {
            let mut default_sigchld: libc::sigaction = std::mem::zeroed();
            default_sigchld.sa_sigaction = libc::SIG_DFL;
            let mut old_sigchld = std::mem::zeroed();
            if libc::sigaction(libc::SIGCHLD, &default_sigchld, &mut old_sigchld) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut mask: libc::sigset_t = std::mem::zeroed();
            let mut old = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            for sig in waited_signals() {
                libc::sigaddset(&mut mask, sig);
            }
            let result = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut old);
            if result != 0 {
                libc::sigaction(libc::SIGCHLD, &old_sigchld, std::ptr::null_mut());
                return Err(io::Error::from_raw_os_error(result));
            }
            let fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                let e = io::Error::last_os_error();
                libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
                libc::sigaction(libc::SIGCHLD, &old_sigchld, std::ptr::null_mut());
                return Err(e);
            }
            Ok(Self {
                fd: OwnedFd::from_raw_fd(fd),
                old,
                old_sigchld,
            })
        }
    }

    /// Hand the wrapped command the signal state it would have had without
    /// the wrapper. Call last before exec: pending signals are delivered here.
    fn restore_for_exec(&self) {
        unsafe {
            libc::sigaction(libc::SIGCHLD, &self.old_sigchld, std::ptr::null_mut());
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
        }
    }

    /// Internal workers (watchdog, supervisor) never inherit the wrapper's
    /// mask: teardown relies on SIGTERM reaching them, and SIGCHLD stays at
    /// the default so their waitpid() observes real exits.
    fn reset_for_worker(&self) {
        unsafe {
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            // Workers live until the orchestrator tears them down after the
            // command exits. Signals aimed at the job (Ctrl-C/Ctrl-\, a
            // hangup, `kill -USR1 %1`, Ctrl-Z, tostop output) must not end or
            // stop them while the command still deletes.
            for sig in worker_ignored_signals() {
                libc::signal(sig, libc::SIG_IGN);
            }
        }
    }

    /// The next pending signal, whether the kernel generated it (the
    /// terminal, a timer, a resource limit), and its sender.
    fn next(&self) -> Option<(u32, bool, u32)> {
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of_val(&info),
            )
        };
        (n == std::mem::size_of_val(&info) as isize).then_some((
            info.ssi_signo,
            info.ssi_code == libc::SI_KERNEL,
            info.ssi_pid,
        ))
    }
}

impl Drop for SignalWait {
    fn drop(&mut self) {
        while self.next().is_some() {}
        self.restore_for_exec();
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
) -> io::Result<Option<CommandStatus>> {
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
        while let Some((sig, from_kernel, sender)) = signals.next() {
            if own_signal(sig, from_kernel, sender) {
                continue;
            }
            if sig != libc::SIGCHLD as u32 {
                signal_pidfd(pidfd.as_raw_fd(), sig);
                child.terminate(libc::SIGKILL);
                return Ok(Some(CommandStatus::Signaled(sig as libc::c_int)));
            }
        }
        if fds[0].revents != 0 {
            return Ok(None);
        }
        if fds[2].revents != 0 {
            let mut status = 0;
            while unsafe { libc::waitpid(child.0, &mut status, 0) } < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    // Already reaped: never let Drop SIGKILL a reused PID.
                    if e.raw_os_error() == Some(libc::ECHILD) {
                        child.0 = 0;
                    }
                    return Err(e);
                }
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

/// The pids of `parent`'s children. The task `children` file needs
/// CONFIG_PROC_CHILDREN, which some kernels lack; without it the parent field
/// of every /proc/<pid>/stat is scanned instead (#232).
/// Our children, from `/proc/self/task/<pid>/children` opened once: a
/// re-read needs no descriptor, so a full descriptor table no longer ends
/// the wait and kills the command (#350). Without the file, /proc is
/// scanned; a scan that fails leaves only the known candidates.
struct ChildList {
    file: Option<std::fs::File>,
    parent: i32,
    buffer: Vec<u8>,
}

impl ChildList {
    fn open(parent: i32) -> Self {
        Self {
            file: std::fs::File::open(format!("/proc/self/task/{parent}/children")).ok(),
            parent,
            buffer: Vec::with_capacity(4096),
        }
    }

    fn read(&mut self) -> Vec<i32> {
        use std::os::unix::fs::FileExt;
        let Some(file) = &self.file else {
            return scan_children(self.parent).unwrap_or_default();
        };
        self.buffer.clear();
        loop {
            let filled = self.buffer.len();
            if self.buffer.capacity() - filled < 4096 {
                self.buffer.reserve(4096);
            }
            let spare = self.buffer.capacity() - filled;
            self.buffer.resize(filled + spare, 0);
            match file.read_at(&mut self.buffer[filled..], filled as u64) {
                // A seq file hands out a page per read: only an empty read
                // ends it (#354).
                Ok(0) => {
                    self.buffer.truncate(filled);
                    break;
                }
                Ok(n) => self.buffer.truncate(filled + n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => self.buffer.truncate(filled),
                Err(_) => {
                    self.buffer.truncate(filled);
                    break;
                }
            }
        }
        self.buffer
            .split(|b| b.is_ascii_whitespace())
            .filter_map(|pid| std::str::from_utf8(pid).ok()?.parse().ok())
            .collect()
    }
}

fn scan_children(parent: i32) -> io::Result<Vec<i32>> {
    Ok(std::fs::read_dir("/proc")?
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter(|&pid| {
            u32::try_from(pid)
                .ok()
                .and_then(trashd_common::proc_stat::comm_and_parent)
                .is_some_and(|(_, ppid)| ppid as i32 == parent)
        })
        .collect())
}

/// Who receives a forwarded HUP/INT/TERM: the original command while it
/// lives, else every adopted descendant still in our session. One that called
/// setsid() (a daemon) left the terminal's session on purpose and would never
/// see its hangup without this wrapper (#231). Every pid here is an unreaped
/// child, so it cannot have been recycled.
fn signal_recipients(
    targets: &std::collections::BTreeMap<i32, OwnedFd>,
    untracked: &std::collections::BTreeSet<i32>,
    original: i32,
) -> Vec<i32> {
    if targets.contains_key(&original) || untracked.contains(&original) {
        return vec![original];
    }
    let session = unsafe { libc::getsid(0) };
    targets
        .keys()
        .chain(untracked)
        .copied()
        .filter(|&pid| unsafe { libc::getsid(pid) } == session)
        .collect()
}

/// Wait for the original command and all protected descendants. Subreaper
/// adoption keeps them in the broker's ancestry even after their parents exit.
///
/// A pidfd stays bound to the original process after exit and reap (#42).
/// Polling signalfd keeps HUP/INT/TERM responsive for both protected and
/// fallback execution, instead of blocking them throughout waitpid (#64).
///
/// Every polled descriptor that reports an event is drained or dropped in the
/// same iteration: a pidfd whose process can no longer be reaped here (the
/// kernel reaped it under an ignored SIGCHLD) is readable forever and used to
/// spin this loop at 100% CPU.
fn wait_for_children(
    child: &mut ChildProcess,
    broker_fd: Option<i32>,
    signals: &SignalWait,
    watchdog_pid: Option<i32>,
) -> io::Result<CommandStatus> {
    let original = child.0;
    let mut original_status = None;
    let mut targets = std::collections::BTreeMap::<i32, OwnedFd>::new();
    // Live children without a pidfd (descriptor limit reached). They are
    // our unreaped children, so SIGCHLD announces their exit and their PIDs
    // cannot be reused while we watch them.
    let mut untracked = std::collections::BTreeSet::<i32>::new();
    let mut children = ChildList::open(unsafe { libc::getpid() });
    // Exited but not yet waitable (a tracer holds the zombie): poll again
    // only after the SIGCHLD that announces its release.
    let mut parked = std::collections::BTreeSet::<i32>::new();
    let mut fired = Vec::new();
    let mut refresh = true;
    let mut pending_signals = Vec::new();
    // A dead broker peer must not abort the wait loop: the wrapped command is
    // still running and its real exit status has to survive (#120).
    let mut broker_fd = broker_fd;
    loop {
        if refresh {
            let mut reaped = false;
            let mut candidates: std::collections::BTreeSet<i32> = children
                .read()
                .into_iter()
                .filter(|&pid| Some(pid) != watchdog_pid)
                .collect();
            // A process the kernel already reaped is never listed, and a
            // snapshot can miss a live child: check known pids directly.
            candidates.extend(targets.keys().copied());
            candidates.extend(untracked.iter().copied());
            if original_status.is_none() {
                candidates.insert(original);
            }
            for pid in candidates {
                let mut status = 0;
                let waited = loop {
                    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                    if waited >= 0
                        || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        break waited;
                    }
                };
                if waited == pid {
                    reaped = true;
                    targets.remove(&pid);
                    untracked.remove(&pid);
                    if pid == original && original_status.is_none() {
                        child.0 = 0; // disarm cleanup immediately after reap
                        original_status = Some(exit_status(status));
                    }
                } else if waited == 0 && !targets.contains_key(&pid) {
                    match open_pidfd(pid) {
                        Ok(fd) => {
                            untracked.remove(&pid);
                            targets.insert(pid, fd);
                        }
                        // Reaped by the kernel since waitpid: rescan.
                        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => reaped = true,
                        // Out of descriptors (many adopted orphans): keep
                        // waiting for it by SIGCHLD instead of aborting,
                        // which tore down protection and killed the command.
                        Err(_) => {
                            untracked.insert(pid);
                        }
                    }
                } else if waited < 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::ECHILD) {
                        return Err(e);
                    }
                    // No longer ours to reap: stop watching it.
                    targets.remove(&pid);
                    untracked.remove(&pid);
                    parked.remove(&pid);
                    if pid == original && original_status.is_none() {
                        child.0 = 0;
                        report!(
                            "trashd-exec: exit status of pid {pid} was lost (SIGCHLD ignored?)"
                        );
                        original_status = Some(CommandStatus::Exited(1));
                    }
                }
            }
            parked.extend(fired.drain(..).filter(|pid| targets.contains_key(pid)));
            // Reparenting may have happened after this /proc snapshot but
            // before waitpid. Rescan after every reap before declaring the
            // protected tree empty, including newly adopted descendants.
            if reaped {
                continue;
            }
            if targets.is_empty()
                && untracked.is_empty()
                && let Some(status) = original_status
            {
                return Ok(status);
            }
            refresh = false;
        }
        for sig in pending_signals.drain(..) {
            for pid in signal_recipients(&targets, &untracked, original) {
                match targets.get(&pid) {
                    Some(fd) => signal_pidfd(fd.as_raw_fd(), sig),
                    None => unsafe {
                        libc::kill(pid, sig as libc::c_int);
                    },
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
        let polled: Vec<i32> = targets
            .keys()
            .copied()
            .filter(|pid| !parked.contains(pid))
            .collect();
        fds.extend(polled.iter().map(|pid| libc::pollfd {
            fd: targets[pid].as_raw_fd(),
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
        // Read the signalfd only when it is ready: every broker request woke
        // this loop and paid a read that found nothing.
        while fds[0].revents != 0
            && let Some((sig, from_terminal, sender)) = signals.next()
        {
            refresh = true;
            if sig == libc::SIGCHLD as u32 {
                parked.clear();
            } else if own_signal(sig, from_terminal, sender) {
            } else if from_terminal
                && matches!(sig as libc::c_int, libc::SIGINT | libc::SIGQUIT)
                && original_status.is_none()
                && unsafe { libc::getpgid(original) == libc::getpgid(0) }
            {
                // The terminal signalled our whole process group, the
                // command included: forwarding would deliver it twice.
            } else {
                // Refresh before forwarding: the original may have just
                // exited, in which case its adopted roots receive the signal.
                pending_signals.push(sig);
            }
        }
        fired.extend(
            polled
                .iter()
                .zip(fds.iter().skip(2))
                .filter(|(_, fd)| fd.revents != 0)
                .map(|(&pid, _)| pid),
        );
        refresh |= !fired.is_empty();
        let broker_events = fds[1].revents;
        if broker_events & libc::POLLIN != 0 {
            match broker::serve(fds[1].fd) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Peer closed: drop it from the poll set instead of
                    // spinning on EOF or tearing down live children (#120).
                    report!("trashd-exec: broker peer closed; continuing without it");
                    broker_fd = None;
                }
                Err(e) => {
                    // One malformed/failed request must not kill the wrapped
                    // command; log and keep serving.
                    report!("trashd-exec: broker request failed: {e}");
                }
            }
        } else if broker_events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            // Nothing to read will ever clear this state: stop polling it.
            report!("trashd-exec: broker socket failed; continuing without it");
            broker_fd = None;
        }
    }
}

fn exit_status(status: i32) -> CommandStatus {
    if libc::WIFEXITED(status) {
        CommandStatus::Exited(libc::WEXITSTATUS(status) as u8)
    } else if libc::WIFSIGNALED(status) {
        CommandStatus::Signaled(libc::WTERMSIG(status))
    } else {
        CommandStatus::Exited(1)
    }
}

/// How the wrapped command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandStatus {
    Exited(u8),
    Signaled(libc::c_int),
}

impl CommandStatus {
    /// End the wrapper the way the command ended. Exiting with 128+n for a
    /// command killed by signal n hid the death from the parent: a shell
    /// only stops a loop on Ctrl-C when its child died of SIGINT. The signal
    /// is re-raised with core dumps disabled (the core would be ours).
    fn finish(self) -> ExitCode {
        match self {
            CommandStatus::Exited(code) => ExitCode::from(code),
            CommandStatus::Signaled(signal) => {
                unsafe {
                    let no_core = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    libc::setrlimit(libc::RLIMIT_CORE, &no_core);
                    // A piped core_pattern (systemd-coredump, apport)
                    // ignores RLIMIT_CORE; only a non-dumpable process is
                    // never captured, whatever the host handler is.
                    libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                    libc::signal(signal, libc::SIG_DFL);
                    let mut only: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut only);
                    libc::sigaddset(&mut only, signal);
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &only, std::ptr::null_mut());
                    libc::raise(signal);
                }
                // Signals whose default action is to continue or be ignored.
                ExitCode::from((128 + signal) as u8)
            }
        }
    }
}

/// exec the command (never returns on success).
fn exec_command(args: &[OsString]) -> ! {
    let c_args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect();
    // Rust's runtime ignores SIGPIPE; an ignored disposition survives exec,
    // so pipelines would stop terminating their writers (#312). Commands
    // start with the default, as std::process::Command arranges.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
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
    report!("trashd-exec: exec '{}': {e}", args[0].to_string_lossy());
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
        report!(
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
        // Serialize forked cases: forking a multithreaded harness while a
        // sibling thread holds the environment or allocator lock leaves the
        // child blocked on a lock that will never be released in it, and a
        // watchdog alarm set in the child survives execve into the exec'd
        // harness (#251). The parent therefore owns the deadline instead.
        static ISOLATED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = ISOLATED_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let helper = unsafe { libc::fork() };
        assert!(helper >= 0);
        if helper == 0 {
            let result = std::panic::catch_unwind(case);
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(helper, &mut status, libc::WNOHANG) };
            if waited == helper {
                assert_eq!(status, 0, "isolated case helper failed");
                return;
            }
            assert!(waited == 0, "waitpid for isolated case helper failed");
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::kill(helper, libc::SIGKILL);
                    libc::waitpid(helper, &mut status, 0);
                }
                panic!("isolated case helper timed out after 20s");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
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
            assert_eq!(
                child.wait(None, &signals).unwrap(),
                CommandStatus::Exited(37)
            );
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
    fn inherited_sigchld_ignore_still_returns_status() {
        isolated_case(|| {
            // WSL's login hands shells SIGCHLD=SIG_IGN. The kernel then reaps
            // children itself, so a wrapper that keeps the inherited
            // disposition never observes the exit and spins on its pidfd.
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
            let signals = SignalWait::new().unwrap();
            let original = unsafe { libc::fork() };
            assert!(original >= 0);
            if original == 0 {
                unsafe {
                    libc::usleep(50_000);
                    libc::_exit(37)
                };
            }
            let mut child = ChildProcess(original);
            assert_eq!(
                child.wait(None, &signals).unwrap(),
                CommandStatus::Exited(37)
            );
            assert_eq!(child.0, 0);
        });
    }

    #[test]
    fn target_reaped_elsewhere_is_dropped_instead_of_polled_forever() {
        isolated_case(|| {
            let signals = SignalWait::new().unwrap();
            // Defeat SignalWait's normalization: the kernel reaps this child,
            // so its status is lost, but its pidfd must not keep the wait
            // loop awake (or asleep) forever.
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
            let original = unsafe { libc::fork() };
            assert!(original >= 0);
            if original == 0 {
                unsafe {
                    libc::usleep(50_000);
                    libc::_exit(37)
                };
            }
            let start = std::time::Instant::now();
            let mut child = ChildProcess(original);
            assert_eq!(
                child.wait(None, &signals).unwrap(),
                CommandStatus::Exited(1)
            );
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
            assert_eq!(child.0, 0);
        });
    }

    #[test]
    fn fallback_replaces_the_wrapper_with_the_command() {
        const PROBE: &str = "TRASHD_TEST_FALLBACK_PROBE";
        if let Ok(wrapper) = std::env::var(PROBE) {
            // Running as the fallback command. Nothing protects it, so no
            // wrapper may stay resident: it IS the wrapper process, with the
            // wrapper's subreaper, signal and marker state undone.
            assert_eq!(unsafe { libc::getpid() }.to_string(), wrapper);
            let mut subreaper: libc::c_int = -1;
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper) },
                0
            );
            assert_eq!(subreaper, 0);
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) };
            assert_eq!(action.sa_sigaction, libc::SIG_IGN, "inherited disposition");
            let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask) };
            for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGCHLD] {
                assert_eq!(unsafe { libc::sigismember(&mask, sig) }, 0, "signal {sig}");
            }
            assert!(std::env::var_os("TRASHD_SECCOMP_ACTIVE").is_none());
            assert!(std::env::var_os(seccomp_identity::COOKIE_ENV).is_none());
            let children =
                std::fs::read_to_string(format!("/proc/self/task/{wrapper}/children")).unwrap();
            assert_eq!(
                children.trim(),
                "",
                "a forked fallback child is left behind"
            );
            return;
        }
        isolated_case(|| {
            unsafe {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), 0);
                std::env::set_var("TRASHD_SECCOMP_ACTIVE", "1");
                std::env::set_var(seccomp_identity::COOKIE_ENV, "stale");
                std::env::set_var(PROBE, libc::getpid().to_string());
            }
            let signals = SignalWait::new().unwrap();
            let args: [OsString; 5] = [
                std::env::current_exe().unwrap().into_os_string(),
                "--exact".into(),
                "tests::fallback_replaces_the_wrapper_with_the_command".into(),
                "--test-threads=1".into(),
                "--nocapture".into(),
            ];
            fallback(&args, &signals);
        });
    }

    // #312: Rust's runtime ignores SIGPIPE in this harness, exactly as in
    // trashd-exec; the exec'd command must still start with the default.
    #[test]
    fn commands_start_with_default_sigpipe() {
        isolated_case(|| {
            let check = "ignored=$(sed -n 's/^SigIgn:[[:space:]]*//p' /proc/self/status); \
                         [ $((0x$ignored & 0x1000)) -eq 0 ]";
            exec_command(&["/bin/sh".into(), "-c".into(), check.into()]);
        });
    }

    // #314: arguments are passed through as raw bytes.
    #[test]
    fn commands_receive_non_utf8_arguments_verbatim() {
        use std::os::unix::ffi::OsStringExt;
        isolated_case(|| {
            exec_command(&[
                "/bin/sh".into(),
                "-c".into(),
                r#"[ "$1" = "$(printf 'caf\351')" ]"#.into(),
                "sh".into(),
                OsString::from_vec(b"caf\xe9".to_vec()),
            ]);
        });
    }

    // #313: protection that cannot start (here: a cwd the user cannot read,
    // which the startup probe used to open for reading, plus a home trash it
    // cannot reach) still runs the command, unprotected.
    #[test]
    fn startup_failure_still_runs_the_command() {
        if unsafe { libc::geteuid() } != 0 {
            return; // needs to switch to an unprivileged user
        }
        let fixture = tempfile::tempdir().unwrap();
        let blind = fixture.path().join("blind");
        std::fs::create_dir(&blind).unwrap();
        std::fs::set_permissions(&blind, std::os::unix::fs::PermissionsExt::from_mode(0o311))
            .unwrap();
        std::fs::set_permissions(
            fixture.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let blind = CString::new(blind.as_os_str().as_bytes()).unwrap();
        isolated_case(move || {
            unsafe {
                assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
                assert_eq!(libc::setresgid(65534, 65534, 65534), 0);
                assert_eq!(libc::setresuid(65534, 65534, 65534), 0);
                assert_eq!(libc::chdir(blind.as_ptr()), 0);
            }
            let signals = SignalWait::new().unwrap();
            let code = wrap(
                &["/bin/sh".into(), "-c".into(), "exit 0".into()],
                false,
                &signals,
            );
            assert_eq!(code, ExitCode::SUCCESS);
        });
    }

    #[test]
    fn internal_workers_start_with_default_signal_state() {
        isolated_case(|| {
            // A blocked SIGTERM inherited by trashd-exec would make the
            // watchdog immune to teardown, and an ignored SIGCHLD would hide
            // its supervisor's exit status.
            unsafe {
                let mut term: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut term);
                libc::sigaddset(&mut term, libc::SIGTERM);
                libc::pthread_sigmask(libc::SIG_BLOCK, &term, std::ptr::null_mut());
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            }
            let signals = SignalWait::new().unwrap();
            signals.reset_for_worker();
            let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask) };
            for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGCHLD] {
                assert_eq!(unsafe { libc::sigismember(&mask, sig) }, 0, "signal {sig}");
            }
            let disposition = |sig| {
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                unsafe { libc::sigaction(sig, std::ptr::null(), &mut action) };
                action.sa_sigaction
            };
            assert_eq!(disposition(libc::SIGCHLD), libc::SIG_DFL);
            // Teardown stays possible; job and terminal signals are ignored.
            assert_eq!(disposition(libc::SIGTERM), libc::SIG_DFL);
            for sig in worker_ignored_signals() {
                assert_eq!(disposition(sig), libc::SIG_IGN, "signal {sig}");
            }
            std::mem::forget(signals); // a worker never restores the wrapper's state
        });
    }

    // A command killed by a signal ends the wrapper by the same signal,
    // without a core file of the wrapper.
    #[test]
    fn signal_deaths_are_reraised_without_core() {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGSEGV] {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let _ = CommandStatus::Signaled(signal).finish();
                unsafe { libc::_exit(99) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(
                libc::WIFSIGNALED(status),
                "signal {signal}: status {status:#x}"
            );
            assert_eq!(libc::WTERMSIG(status), signal);
            assert!(!libc::WCOREDUMP(status), "signal {signal} dumped core");
        }
        assert_eq!(CommandStatus::Exited(7).finish(), ExitCode::from(7));
    }

    // A terminal signal already reached every process of our group, the
    // command included; only signals sent to the wrapper itself are passed on.
    #[test]
    fn terminal_interrupts_are_not_forwarded_twice() {
        for from_terminal in [true, false] {
            isolated_case(move || {
                let signals = SignalWait::new().unwrap();
                let child = unsafe { libc::fork() };
                assert!(child >= 0);
                if child == 0 {
                    extern "C" fn interrupted(_: libc::c_int) {
                        unsafe { libc::_exit(3) };
                    }
                    signals.restore_for_exec();
                    unsafe {
                        libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t);
                        libc::usleep(300_000);
                        libc::_exit(0);
                    }
                }
                unsafe { libc::usleep(20_000) };
                let us = unsafe { libc::getpid() };
                if from_terminal {
                    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                    info.si_signo = libc::SIGINT;
                    info.si_code = libc::SI_KERNEL;
                    let queued = unsafe {
                        libc::syscall(libc::SYS_rt_sigqueueinfo, us, libc::SIGINT, &mut info)
                    };
                    assert_eq!(queued, 0, "{}", io::Error::last_os_error());
                } else {
                    unsafe { libc::kill(us, libc::SIGINT) };
                }
                let status = ChildProcess(child).wait(None, &signals).unwrap();
                let expected = if from_terminal { 0 } else { 3 };
                assert_eq!(status, CommandStatus::Exited(expected));
            });
        }
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
                Some(CommandStatus::Signaled(libc::SIGTERM))
            );
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
            assert_eq!(child.0, 0);
            unsafe { libc::waitpid(sender, std::ptr::null_mut(), 0) };
        });
    }

    // Regression (#231): once the original command exited, HUP/INT/TERM went
    // to every adopted descendant, including daemons that called setsid()
    // and would never receive the terminal's hangup without this wrapper.
    #[test]
    fn hangups_skip_descendants_that_left_the_session() {
        use std::os::unix::process::CommandExt;
        let mut plain = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut daemon = unsafe {
            std::process::Command::new("sleep")
                .arg("30")
                .pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                })
                .spawn()
                .unwrap()
        };
        let mut targets = std::collections::BTreeMap::new();
        for child in [&plain, &daemon] {
            let pid = child.id() as i32;
            targets.insert(pid, open_pidfd(pid).unwrap());
        }
        // The original (pid 0 here: already reaped) is gone.
        let recipients = signal_recipients(&targets, &std::collections::BTreeSet::new(), 0);
        for child in [&mut plain, &mut daemon] {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert_eq!(recipients, vec![plain.id() as i32]);
    }

    // #357: only the wrapper's own limits and timers are kept from the
    // command; a user's kill of the same signal is forwarded.
    #[test]
    fn own_signals_are_only_the_wrappers_own() {
        let us = unsafe { libc::getpid() } as u32;
        for sig in OWN_SIGNALS {
            let sig = sig as u32;
            assert!(own_signal(sig, true, 0), "{sig} from the kernel");
            assert!(own_signal(sig, false, us), "{sig} self-sent");
            assert!(!own_signal(sig, false, us + 1), "{sig} from a user");
        }
        assert!(!own_signal(libc::SIGTERM as u32, true, 0));
        assert!(!own_signal(libc::SIGALRM as u32, false, us));
    }

    // Regression (#232): without CONFIG_PROC_CHILDREN the children file is
    // missing and the wait failed outright; the /proc ppid scan finds them.
    #[test]
    fn children_are_found_without_the_children_file() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let us = unsafe { libc::getpid() };
        let mut without_file = ChildList {
            file: None,
            parent: us,
            buffer: Vec::new(),
        };
        let scanned = without_file.read();
        // #350: the list re-reads one open file, with no new descriptor. The
        // file lists one task's children: this test runs on a harness thread.
        let mut listed = ChildList::open(us);
        listed.file = std::fs::File::open(format!("/proc/self/task/{}/children", unsafe {
            libc::gettid()
        }))
        .ok();
        let first = listed.read();
        let again = listed.read();
        let _ = child.kill();
        let _ = child.wait();
        let id = child.id() as i32;
        assert!(scanned.contains(&id));
        if listed.file.is_some() {
            assert!(first.contains(&id) && again.contains(&id));
        }
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
                unsafe { libc::signal(signal, libc::SIG_DFL) };
                signals.restore_for_exec();
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
                CommandStatus::Signaled(signal)
            );
            unsafe { libc::waitpid(sender, std::ptr::null_mut(), 0) };
            unsafe { libc::_exit(0) };
        }
        // #350: ALRM (GNU `timeout -s ALRM`), timer and real-time signals too.
        for signal in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGALRM,
            libc::SIGRTMIN() + 1,
        ] {
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
