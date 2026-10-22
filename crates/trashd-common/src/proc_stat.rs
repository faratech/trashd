//! Kernel process name and parent PID from one `/proc/<pid>/stat` read.
//!
//! Shared verbatim by trashd-common and the standalone preload (`#[path]`
//! include), so it depends on std and libc only. Bypass checks walk a whole
//! process tree; reading `comm` and `stat` separately through
//! `fs::read_to_string` cost 15 syscalls per ancestor (#302).

use std::ffi::CStr;

/// The stat line starts `pid (comm) state ppid ...`. comm is at most 64
/// bytes (kernel worker names), so this prefix always fits even though
/// later fields may be cut off.
const STAT_PREFIX_BYTES: usize = 512;

/// `comm` and parent PID of `pid`.
pub fn comm_and_parent(pid: u32) -> Option<(String, u32)> {
    let path = std::ffi::CString::new(format!("/proc/{pid}/stat")).ok()?;
    read_stat(&path)
}

/// `comm` and parent PID of the calling process, resolved by the kernel in
/// the PID namespace of the mounted /proc, like every `/proc/<pid>` path
/// the walk visits afterwards.
pub fn own_comm_and_parent() -> Option<(String, u32)> {
    read_stat(c"/proc/self/stat")
}

/// One open, one bounded read, one close: no metadata query, no growth
/// loop and no EOF probe.
fn read_stat(path: &CStr) -> Option<(String, u32)> {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; STAT_PREFIX_BYTES];
    let read = loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break n;
    };
    unsafe { libc::close(fd) };
    let len = usize::try_from(read).ok()?;
    parse_stat_prefix(&buf[..len], len == buf.len())
}

/// Parse `pid (comm) state ppid`. The last `)` ends comm, which may itself
/// contain parentheses, spaces or newlines; no later field contains `)`.
/// A PPID touching the end of a filled buffer may be cut off: reject it.
fn parse_stat_prefix(stat: &[u8], filled: bool) -> Option<(String, u32)> {
    let start = stat.iter().position(|&b| b == b'(')? + 1;
    let end = stat.iter().rposition(|&b| b == b')')?;
    let comm = stat.get(start..end)?;
    let rest = stat.get(end + 1..)?;
    let mut fields = rest
        .split(|b| b.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let _state = fields.next()?;
    let ppid = fields.next()?;
    let ppid_end = ppid.as_ptr() as usize - rest.as_ptr() as usize + ppid.len();
    if filled && ppid_end == rest.len() {
        return None;
    }
    let ppid = std::str::from_utf8(ppid).ok()?.parse().ok()?;
    Some((String::from_utf8_lossy(comm).trim().to_string(), ppid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comm_with_parentheses_spaces_and_newlines() {
        let stat = b"42 (a) (b c\n)) S 7 42 42 0 -1 4194560";
        assert_eq!(
            parse_stat_prefix(stat, false),
            Some(("a) (b c\n)".to_string(), 7))
        );
        assert_eq!(
            parse_stat_prefix(b"9 (git) R 1 9 9", false),
            Some(("git".to_string(), 1))
        );
        // Surrounding whitespace is trimmed, as for the comm file's newline.
        assert_eq!(
            parse_stat_prefix(b"12 ( \nodd ) ( name\n ) S 34 5 6", false),
            Some(("odd ) ( name".to_string(), 34))
        );
    }

    #[test]
    fn rejects_malformed_and_cut_off_prefixes() {
        for stat in [
            &b""[..],
            b"42 git S 7",
            b"42 (git S 7",
            b"42 (git)",
            b"42 (git) S",
            b"42 (git) S x 1",
        ] {
            assert_eq!(parse_stat_prefix(stat, false), None, "{stat:?}");
        }
        // A filled buffer ending inside the PPID is incomplete.
        assert_eq!(parse_stat_prefix(b"42 (git) S 71", true), None);
        assert_eq!(
            parse_stat_prefix(b"42 (git) S 71 ", true),
            Some(("git".to_string(), 71))
        );
    }

    #[test]
    fn reads_own_and_parent_stat() {
        let (comm, parent) = own_comm_and_parent().expect("own stat is readable");
        assert_eq!(parent, unsafe { libc::getppid() } as u32);
        let expected = std::fs::read_to_string("/proc/self/comm").unwrap();
        assert_eq!(comm, expected.trim());
        assert_eq!(
            comm_and_parent(std::process::id()).map(|(_, p)| p),
            Some(parent)
        );
        assert_eq!(comm_and_parent(u32::MAX), None);
    }
}
