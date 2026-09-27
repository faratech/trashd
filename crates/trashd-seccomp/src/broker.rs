//! Perform ptrace-restricted operations in the stable target ancestor.
//!
//! Yama permissions do not follow supervisor restarts or PR_SET_PTRACER across
//! a target fork. The orchestrator remains an ancestor (and subreaper), while
//! supervisors send requests on a private socket never inherited by targets.
//! Each supervisor has its own reply socket, so a crash cannot leave a stale
//! response or descriptor for its replacement.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::OnceLock;

struct Client {
    request: OwnedFd,
    reply: UnixDatagram,
    destination: UnixDatagram,
}

static CLIENT: OnceLock<Client> = OnceLock::new();

pub fn connect(request: RawFd) -> io::Result<()> {
    let (reply, destination) = UnixDatagram::pair()?;
    CLIENT
        .set(Client {
            // The supervisor owns this inherited descriptor.
            request: unsafe { OwnedFd::from_raw_fd(request) },
            reply,
            destination,
        })
        .map_err(|_| io::Error::other("broker already connected"))
}

pub fn is_connected() -> bool {
    CLIENT.get().is_some()
}

fn request(kind: u32, pid: u32, value: u64) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let client = CLIENT.get().expect("broker connected");
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&kind.to_ne_bytes());
    data.extend_from_slice(&pid.to_ne_bytes());
    data.extend_from_slice(&value.to_ne_bytes());
    send_packet(
        client.request.as_raw_fd(),
        &data,
        Some(client.destination.as_raw_fd()),
    )?;
    let (response, fd) = recv_packet(client.reply.as_raw_fd())?;
    if response.len() < 4 {
        return Err(io::Error::other("invalid broker response"));
    }
    let errno = i32::from_ne_bytes(response[..4].try_into().unwrap());
    if errno != 0 {
        return Err(io::Error::from_raw_os_error(errno));
    }
    Ok((response[4..].to_vec(), fd))
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

/// Handle one datagram. A dead supervisor's reply socket is harmless: its
/// replacement has a different socket and never consumes the old response.
pub fn serve(fd: RawFd) -> io::Result<()> {
    let (data, reply) = recv_packet(fd)?;
    let reply = reply.ok_or_else(|| io::Error::other("missing broker reply socket"))?;
    if data.len() != 16 {
        return Err(io::Error::other("invalid broker request"));
    }
    let kind = u32::from_ne_bytes(data[..4].try_into().unwrap());
    let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
    let value = u64::from_ne_bytes(data[8..].try_into().unwrap());
    let result = match kind {
        1 => crate::mem::read_path_locally(pid, value)
            .map(|p| (p.as_os_str().as_bytes().to_vec(), None)),
        2 => duplicate_locally(pid, value as i32).map(|fd| (Vec::new(), Some(fd))),
        _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
    };
    let (bytes, descriptor) = match result {
        Ok((data, descriptor)) => {
            let mut bytes = 0i32.to_ne_bytes().to_vec();
            bytes.extend_from_slice(&data);
            (bytes, descriptor)
        }
        Err(e) => (
            e.raw_os_error().unwrap_or(libc::EIO).to_ne_bytes().to_vec(),
            None,
        ),
    };
    // ECONNREFUSED means the worker died while its request was in flight.
    let _ = send_packet(
        reply.as_raw_fd(),
        &bytes,
        descriptor.as_ref().map(AsRawFd::as_raw_fd),
    );
    Ok(())
}

fn duplicate_locally(pid: u32, fd: i32) -> io::Result<OwnedFd> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
    let result = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) })
    }
}

fn send_packet(sock: RawFd, bytes: &[u8], fd: Option<RawFd>) -> io::Result<()> {
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
        if unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) } >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn recv_packet(sock: RawFd) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut bytes = vec![0u8; libc::PATH_MAX as usize + 4];
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
        let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
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
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::other("truncated broker packet"));
    }
    bytes.truncate(count);
    Ok((bytes, descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

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
