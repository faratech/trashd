//! Perform ptrace-restricted operations in the stable target ancestor.
//!
//! Yama permissions do not follow supervisor restarts or PR_SET_PTRACER across
//! a target fork. The orchestrator remains an ancestor (and subreaper), while
//! supervisors send requests on a private socket never inherited by targets.
//!
//! Replies come back on the same socket, tagged with their request's id, so
//! a request carries no descriptor: one per request (its private reply
//! socket) could not be received at the orchestrator's descriptor limit,
//! which left the supervisor nowhere to be answered (seccomp-orch-2). A
//! supervisor waits a bounded time and skips any reply that is not its own,
//! so a crashed or timed-out predecessor's late answer never stands in for
//! another request's.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

struct Client {
    socket: OwnedFd,
    next: AtomicU32,
}

static CLIENT: OnceLock<Client> = OnceLock::new();

/// How long a supervisor waits for an answer before declining the trapped
/// syscall: a lost reply used to hang it, and every later delete, forever.
const REPLY_TIMEOUT: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(500)
} else {
    std::time::Duration::from_secs(5)
};

/// kind, pid, value, request id.
const REQUEST_LEN: usize = 4 + 4 + 8 + 8;

pub fn connect(request: RawFd) -> io::Result<()> {
    CLIENT
        .set(Client {
            // The supervisor owns this inherited descriptor.
            socket: unsafe { OwnedFd::from_raw_fd(request) },
            next: AtomicU32::new(0),
        })
        .map_err(|_| io::Error::other("broker already connected"))
}

pub fn is_connected() -> bool {
    CLIENT.get().is_some()
}

fn request(kind: u32, pid: u32, value: u64) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let client = CLIENT.get().expect("broker connected");
    let socket = client.socket.as_raw_fd();
    // Unique across supervisor generations, which share the socket.
    let id = (u64::from(std::process::id()) << 32)
        | u64::from(client.next.fetch_add(1, Ordering::Relaxed));
    let mut data = Vec::with_capacity(REQUEST_LEN);
    data.extend_from_slice(&kind.to_ne_bytes());
    data.extend_from_slice(&pid.to_ne_bytes());
    data.extend_from_slice(&value.to_ne_bytes());
    data.extend_from_slice(&id.to_ne_bytes());
    // A broker that stopped serving fills its queue: fail, never block.
    send_packet(socket, &data, None, libc::MSG_DONTWAIT)?;
    let deadline = std::time::Instant::now() + REPLY_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let mut ready = libc::pollfd {
            fd: socket,
            events: libc::POLLIN,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut ready, 1, remaining.as_millis().max(1) as i32) };
        if polled < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if polled == 0 {
            continue;
        }
        let packet = match recv_packet(socket, libc::MSG_DONTWAIT) {
            Ok(packet) => packet,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };
        if packet.bytes.len() < 12 {
            // Our socket's peer is gone: no answer can come.
            return Err(io::Error::other("invalid broker response"));
        }
        if u64::from_ne_bytes(packet.bytes[..8].try_into().unwrap()) != id {
            // A late answer to an abandoned request; its descriptor drops.
            continue;
        }
        let errno = i32::from_ne_bytes(packet.bytes[8..12].try_into().unwrap());
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if packet.control_truncated {
            // Our own descriptor table is full: the descriptor was lost.
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        return Ok((packet.bytes[12..].to_vec(), packet.descriptor));
    }
}

pub fn read_path(pid: u32, addr: u64) -> io::Result<PathBuf> {
    let (data, _) = request(1, pid, addr)?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(data)))
}

pub fn duplicate_fd(pid: u32, fd: i32) -> io::Result<RawFd> {
    use std::os::fd::IntoRawFd;
    let (_, received) = request(2, pid, fd as u64)?;
    received
        .map(IntoRawFd::into_raw_fd)
        .ok_or_else(|| io::Error::other("broker did not return a descriptor"))
}

/// Handle one datagram, answering on the same socket. A dead supervisor's
/// answer is harmless: its replacement skips any reply not tagged with one
/// of its own requests.
pub fn serve(fd: RawFd) -> io::Result<()> {
    // No request carries a descriptor, so a truncated control message (the
    // descriptor table is full) loses nothing: the request is still answered.
    let packet = recv_packet(fd, 0)?;
    drop(packet.descriptor);
    let data = packet.bytes;
    // A zero-length datagram means the peer (the watchdog's broker half) is
    // GONE: further polls would spin forever on our socketpair half. Report
    // it distinctly so the orchestrator can stop polling instead of failing
    // the whole wait loop (#120).
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "broker peer closed",
        ));
    }
    if data.len() != REQUEST_LEN {
        // Without its id, nobody can be answered: the requester times out.
        return Err(io::Error::other("invalid broker request"));
    }
    let kind = u32::from_ne_bytes(data[..4].try_into().unwrap());
    let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
    let value = u64::from_ne_bytes(data[8..16].try_into().unwrap());
    let result = match kind {
        1 => crate::mem::read_path_locally(pid, value)
            .map(|p| (p.as_os_str().as_bytes().to_vec(), None)),
        2 => duplicate_locally(pid, value as i32).map(|fd| (Vec::new(), Some(fd))),
        _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
    };
    let mut bytes = data[16..].to_vec(); // the request's id
    let descriptor = match result {
        Ok((data, descriptor)) => {
            bytes.extend_from_slice(&0i32.to_ne_bytes());
            bytes.extend_from_slice(&data);
            descriptor
        }
        Err(e) => {
            bytes.extend_from_slice(&e.raw_os_error().unwrap_or(libc::EIO).to_ne_bytes());
            None
        }
    };
    // Never block the orchestrator on a supervisor that stopped reading; an
    // unsent answer times out on its side.
    let _ = send_packet(
        fd,
        &bytes,
        descriptor.as_ref().map(AsRawFd::as_raw_fd),
        libc::MSG_DONTWAIT,
    );
    Ok(())
}

pub(crate) fn duplicate_locally(pid: u32, fd: i32) -> io::Result<OwnedFd> {
    use std::sync::atomic::{AtomicBool, Ordering};
    // Kernels before 6.9 reject PIDFD_THREAD with EINVAL; remember that
    // instead of failing one syscall per duplication (#320).
    static THREAD_PIDFDS_UNSUPPORTED: AtomicBool = AtomicBool::new(false);
    // PIDFD_THREAD (O_EXCL) addresses the task's own descriptor table.
    let pidfd = if THREAD_PIDFDS_UNSUPPORTED.load(Ordering::Relaxed) {
        -1
    } else {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, libc::O_EXCL) };
        if pidfd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            THREAD_PIDFDS_UNSUPPORTED.store(true, Ordering::Relaxed);
        }
        pidfd
    };
    if pidfd >= 0 {
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
        let result = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
        if result >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) });
        }
    }
    let task = std::ffi::CString::new(format!("/proc/{pid}"))?;
    let procfd = unsafe {
        libc::open(
            task.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if procfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let procfd = unsafe { OwnedFd::from_raw_fd(procfd) };
    let name = std::ffi::CString::new(format!("fd/{fd}"))?;
    let result = unsafe {
        libc::openat(
            procfd.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(result) })
    }
}

fn send_packet(sock: RawFd, bytes: &[u8], fd: Option<RawFd>, flags: i32) -> io::Result<()> {
    let mut control = [0usize; 4]; // aligned ancillary buffer
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(4) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<i32>(), fd);
        }
    }
    loop {
        if unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL | flags) } >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// One received datagram.
struct Packet {
    bytes: Vec<u8>,
    descriptor: Option<OwnedFd>,
    /// A passed descriptor could not be installed (descriptor table full).
    control_truncated: bool,
}

fn recv_packet(sock: RawFd, flags: i32) -> io::Result<Packet> {
    let mut bytes = vec![0u8; libc::PATH_MAX as usize + 12];
    let mut control = [0usize; 4];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control);
    let count = loop {
        let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC | flags) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    let mut descriptor = None;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        {
            descriptor = Some(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                libc::CMSG_DATA(cmsg).cast::<i32>(),
            )));
        }
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(io::Error::other("truncated broker packet"));
    }
    bytes.truncate(count);
    Ok(Packet {
        bytes,
        descriptor,
        control_truncated: msg.msg_flags & libc::MSG_CTRUNC != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    /// Run `test` in a re-executed child, failing if it does not finish:
    /// a broker request that never returns must fail, not hang the suite.
    fn rerun_with_deadline(test: &str, variable: &str) {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(variable, "1")
            .env("TRASH_BYPASS", "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{status}");
                return;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("a broker request hung");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Fork a worker that connects a broker client to `client` and runs
    /// `case`, exiting 0 only when it returns true.
    fn worker(client: &UnixDatagram, case: impl FnOnce() -> bool) -> libc::pid_t {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // A hung worker must not outlive the case.
            unsafe { libc::alarm(10) };
            let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                connect(unsafe { libc::dup(client.as_raw_fd()) }).unwrap();
                case()
            }));
            unsafe { libc::_exit(i32::from(!matches!(passed, Ok(true)))) };
        }
        pid
    }

    fn reaped(pid: libc::pid_t) -> i32 {
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        status
    }

    // seccomp-orch-2: the supervisor waited for a reply forever, with no
    // timeout, so one lost reply hung the trapped target and every later
    // delete. A timeout alone is not enough: the late reply must never be
    // taken as the answer to the next request.
    #[test]
    fn lost_and_late_replies_never_hang_or_answer_another_request() {
        const CHILD: &str = "TRASHD_TEST_BROKER_LOST_REPLY";
        const TEST: &str =
            "broker::tests::lost_and_late_replies_never_hang_or_answer_another_request";
        if std::env::var_os(CHILD).is_none() {
            return rerun_with_deadline(TEST, CHILD);
        }
        let (first, second) = (b"/first\0", b"/second\0");
        let us = unsafe { libc::getpid() } as u32;
        let (server, client) = UnixDatagram::pair().unwrap();
        let (report, worker_report) = UnixDatagram::pair().unwrap();
        let pid = worker(&client, || {
            let start = std::time::Instant::now();
            let lost = read_path(us, first.as_ptr() as u64).unwrap_err();
            let timed_out = lost.raw_os_error() == Some(libc::ETIMEDOUT)
                && start.elapsed() < std::time::Duration::from_secs(5);
            worker_report.send(&[u8::from(timed_out)]).unwrap();
            let answer = read_path(us, second.as_ptr() as u64).unwrap();
            timed_out && answer.as_os_str().as_bytes() == b"/second"
        });
        // Hold the first request until the worker has given up on it.
        let mut timed_out = [0u8];
        report.recv(&mut timed_out).unwrap();
        assert_eq!(timed_out, [1], "a lost reply did not time out");
        serve(server.as_raw_fd()).unwrap(); // the late reply to the first
        serve(server.as_raw_fd()).unwrap(); // the second
        assert_eq!(reaped(pid), 0, "the late reply answered the next request");
    }

    // seccomp-orch-2: each request carried its reply socket as a descriptor.
    // At its descriptor limit the orchestrator could not receive it, so it
    // had nowhere to answer and the supervisor hung.
    #[test]
    fn a_broker_at_its_descriptor_limit_still_answers() {
        const CHILD: &str = "TRASHD_TEST_BROKER_EMFILE";
        const TEST: &str = "broker::tests::a_broker_at_its_descriptor_limit_still_answers";
        if std::env::var_os(CHILD).is_none() {
            return rerun_with_deadline(TEST, CHILD);
        }
        let path = b"/at/the/limit\0";
        let us = unsafe { libc::getpid() } as u32;
        let (server, client) = UnixDatagram::pair().unwrap();
        let pid = worker(&client, || {
            read_path(us, path.as_ptr() as u64)
                .unwrap()
                .as_os_str()
                .as_bytes()
                == b"/at/the/limit"
        });
        // Fill every free descriptor slot below a lowered limit.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let saved = limit.rlim_cur;
        limit.rlim_cur = 256;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let mut fillers = Vec::new();
        loop {
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                break;
            }
            fillers.push(fd);
        }
        let served = serve(server.as_raw_fd());
        for fd in fillers {
            unsafe { libc::close(fd) };
        }
        limit.rlim_cur = saved;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        served.unwrap();
        assert_eq!(reaped(pid), 0, "the worker got no answer");
    }

    /// Isolate forks, credential changes and the per-process broker client
    /// from the test harness. No permission changes escape this subprocess.
    #[test]
    fn unprivileged_ancestor_reads_descendants_after_worker_restart() {
        const CHILD: &str = "TRASHD_TEST_BROKER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "broker::tests::unprivileged_ancestor_reads_descendants_after_worker_restart",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(result.success());
            return;
        }
        unsafe {
            if libc::geteuid() == 0 {
                assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
                assert_eq!(libc::setgid(65534), 0);
                assert_eq!(libc::setuid(65534), 0);
            }
            assert_eq!(libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0), 0);
            assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), 0);
        }
        let fixture = tempfile::tempdir().unwrap();
        let directory = std::fs::File::open(fixture.path()).unwrap();
        let directory_fd = directory.as_raw_fd();
        let expected = b"/broker/non-utf8-\xff";
        let mut path = expected.to_vec();
        path.push(0);
        let address = path.as_ptr() as u64;
        let (report, target_report) = UnixDatagram::pair().unwrap();
        let target = unsafe { libc::fork() };
        assert!(target >= 0);
        if target == 0 {
            let grandchild = unsafe { libc::fork() };
            assert!(grandchild >= 0);
            if grandchild == 0 {
                loop {
                    unsafe { libc::pause() };
                }
            }
            target_report.send(&grandchild.to_ne_bytes()).unwrap();
            loop {
                unsafe { libc::pause() };
            }
        }
        let mut report_bytes = [0u8; 4];
        report.recv(&mut report_bytes).unwrap();
        let grandchild = i32::from_ne_bytes(report_bytes);
        let (server, client) = UnixDatagram::pair().unwrap();
        // The same broker serves replacement workers. Each sees both the
        // initial target and its forked child, without PR_SET_PTRACER_ANY.
        for restart in 0..2 {
            let worker = unsafe { libc::fork() };
            assert!(worker >= 0);
            if worker == 0 {
                if std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
                    .is_ok_and(|s| s.trim() == "1")
                {
                    assert_eq!(
                        crate::mem::read_path_locally(target as u32, address)
                            .unwrap_err()
                            .raw_os_error(),
                        Some(libc::EPERM)
                    );
                }
                connect(unsafe { libc::dup(client.as_raw_fd()) }).unwrap();
                for pid in [target, grandchild] {
                    assert_eq!(
                        read_path(pid as u32, address)
                            .unwrap()
                            .as_os_str()
                            .as_bytes(),
                        expected
                    );
                }
                let received = duplicate_fd(grandchild as u32, directory_fd).unwrap();
                let mut before: libc::stat = unsafe { std::mem::zeroed() };
                let mut after: libc::stat = unsafe { std::mem::zeroed() };
                assert_eq!(unsafe { libc::fstat(directory_fd, &mut before) }, 0);
                assert_eq!(unsafe { libc::fstat(received, &mut after) }, 0);
                assert_eq!(before.st_ino, after.st_ino);
                unsafe { libc::_exit(0) };
            }
            for _ in 0..3 {
                serve(server.as_raw_fd()).unwrap();
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(worker, &mut status, 0) }, worker);
            assert_eq!(status, 0, "replacement {restart}");
        }
        unsafe {
            libc::kill(target, libc::SIGKILL);
            libc::waitpid(target, std::ptr::null_mut(), 0);
            // After orphaning, the subreaper remains a valid ancestor.
        }
        assert_eq!(
            crate::mem::read_path_locally(grandchild as u32, address)
                .unwrap()
                .as_os_str()
                .as_bytes(),
            expected
        );
        unsafe {
            libc::kill(grandchild, libc::SIGKILL);
            libc::waitpid(grandchild, std::ptr::null_mut(), 0);
        }
    }
}
