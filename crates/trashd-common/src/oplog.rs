//! Append-only operation log for trash operations.
//!
//! Logs every trash, restore, purge, and empty operation to
//! `~/.local/share/Trash/.trashd/operations.log`.
//!
//! Format: `TIMESTAMP OP [details]`

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Log a trash operation.
pub fn log_trash(original_path: &Path, trash_id: &str, command: Option<&str>) {
    log_trash_in(
        &crate::TrashStore::home_trash_dir(),
        original_path,
        trash_id,
        command,
    );
}

pub(crate) fn log_trash_in(
    home: &Path,
    original_path: &Path,
    trash_id: &str,
    command: Option<&str>,
) {
    let cmd = command.unwrap_or("-");
    write_log(
        home,
        &format!(
            "TRASH id={} path={} cmd={}",
            escape_field_bytes(trash_id.as_bytes()),
            escape_field(original_path.as_os_str()),
            escape_field_bytes(cmd.as_bytes()),
        ),
    );
}

/// Log a restore operation.
pub fn log_restore(trash_id: &str, restored_to: &Path) {
    log_restore_in(&crate::TrashStore::home_trash_dir(), trash_id, restored_to);
}

pub(crate) fn log_restore_in(home: &Path, trash_id: &str, restored_to: &Path) {
    write_log(
        home,
        &format!(
            "RESTORE id={} to={}",
            escape_field_bytes(trash_id.as_bytes()),
            escape_field(restored_to.as_os_str()),
        ),
    );
}

/// Log a purge operation.
pub fn log_purge(trash_id: &str) {
    log_purge_in(&crate::TrashStore::home_trash_dir(), trash_id);
}

pub(crate) fn log_purge_in(home: &Path, trash_id: &str) {
    // The ID is attacker-influenced (it derives from a filename): escape it
    // like every other field or a newline in it forges the next record (#254).
    write_log(
        home,
        &format!("PURGE id={}", escape_field_bytes(trash_id.as_bytes())),
    );
}

/// Log an empty operation.
pub fn log_empty(count: u64, filter: Option<&str>) {
    log_empty_in(&crate::TrashStore::home_trash_dir(), count, filter);
}

pub(crate) fn log_empty_in(home: &Path, count: u64, filter: Option<&str>) {
    let filter_str = filter.unwrap_or("all");
    write_log(
        home,
        &format!(
            "EMPTY count={count} filter={}",
            escape_field_bytes(filter_str.as_bytes()),
        ),
    );
}

/// Read the last N lines of the operation log.
pub fn read_log(max_lines: usize) -> Vec<String> {
    read_log_file(&log_path(), max_lines)
}

fn read_log_file(path: &Path, max_lines: usize) -> Vec<String> {
    if max_lines == 0 {
        return Vec::new();
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .and_then(|file| {
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "operation log is not a regular file",
                ));
            }
            read_log_tail(metadata.len(), max_lines, |position, chunk| {
                file.read_exact_at(chunk, position)
            })
        })
        .unwrap_or_default()
}

fn read_log_tail(
    end: u64,
    max_lines: usize,
    mut read_chunk: impl FnMut(u64, &mut [u8]) -> io::Result<()>,
) -> io::Result<Vec<String>> {
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let mut position = end;
    let mut remaining = max_lines;
    let mut reversed = Vec::new();
    let mut chunk = [0u8; 8192];
    'chunks: while position > 0 {
        let length = position.min(chunk.len() as u64) as usize;
        position -= length as u64;
        read_chunk(position, &mut chunk[..length])?;
        for index in (0..length).rev() {
            let byte = chunk[index];
            // A terminating newline belongs to the last record; every
            // earlier newline separates two records, including empty ones.
            if byte == b'\n' && position + index as u64 != end - 1 {
                remaining -= 1;
                if remaining == 0 {
                    break 'chunks;
                }
            }
            reversed.push(byte);
        }
    }
    reversed.reverse();
    let content = String::from_utf8(reversed)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(content.lines().map(str::to_owned).collect())
}

/// Get the path to the operation log file.
pub fn log_path() -> PathBuf {
    let trash_dir = crate::TrashStore::home_trash_dir();
    trash_dir.join(".trashd").join("operations.log")
}

/// Send a desktop notification if notify-send is available and DISPLAY/WAYLAND is set.
/// Only called from the shim (not preload) to avoid spamming from LD_PRELOAD hooks.
pub fn notify_desktop(summary: &str, body: &str) {
    // Only notify in GUI sessions
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return;
    }
    let mut command = std::process::Command::new("notify-send");
    command
        .args([
            "--app-name=trashd",
            "--icon=user-trash",
            "-t",
            "3000",
            summary,
            body,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let _ = spawn_reaped(command);
}

/// Start `command` without waiting for it, and reap it on a detached thread:
/// a long-lived caller (the seccomp supervisor) otherwise kept one zombie per
/// notification (#233). Returns the child's pid.
fn spawn_reaped(mut command: std::process::Command) -> std::io::Result<u32> {
    let mut child = command.spawn()?;
    let pid = child.id();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

/// Encode a log field so one `write_log` call is always exactly one line:
/// backslash is escaped, and every byte outside printable ASCII (including
/// newline, which would forge the next record) becomes `\xNN`. Same
/// discipline as the daemon logger's escape_field (#82); the result can never
/// contain a physical newline.
fn escape_field(value: &std::ffi::OsStr) -> String {
    escape_field_bytes(value.as_bytes())
}

fn escape_field_bytes(value: &[u8]) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value {
        match byte {
            b'\\' => escaped.push_str("\\\\"),
            0x20..=0x7e => escaped.push(char::from(*byte)),
            _ => {
                use std::fmt::Write;
                write!(&mut escaped, "\\x{byte:02x}").expect("writing to String cannot fail");
            }
        }
    }
    escaped
}

fn write_log(home: &Path, message: &str) {
    let path = home.join(".trashd/operations.log");

    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
    let pid = std::process::id();
    let line = format!("{timestamp} pid={pid} {message}\n");

    let result = open_log_for_append(&path).and_then(|mut f| {
        let metadata = f.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operation log is not a regular file",
            ));
        }
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(line.as_bytes())
    });

    if let Err(e) = result {
        eprintln!("trashd: failed to write operation log: {e}");
    }
}

fn open_log_for_append(path: &Path) -> io::Result<fs::File> {
    let open = || {
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
    };
    match open() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            open()
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        escape_field_bytes, log_purge_in, log_restore_in, log_trash_in, read_log_file,
        read_log_tail, spawn_reaped,
    };
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    #[test]
    fn append_creates_repairs_and_reopens_the_current_log() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let log = home.path().join(".trashd/operations.log");
        log_purge_in(home.path(), "first");
        assert_eq!(log.metadata().unwrap().permissions().mode() & 0o7777, 0o600);
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o640)).unwrap();
        log_purge_in(home.path(), "second");
        assert_eq!(log.metadata().unwrap().permissions().mode() & 0o7777, 0o600);
        let retired = home.path().join("retired.log");
        std::fs::rename(&log, &retired).unwrap();
        log_purge_in(home.path(), "third");
        let original = std::fs::read_to_string(retired).unwrap();
        assert!(original.contains("id=first\n"));
        assert!(original.contains("id=second\n"));
        assert!(!original.contains("id=third\n"));
        let current = std::fs::read_to_string(&log).unwrap();
        assert!(current.contains("id=third\n"));
        assert!(!current.contains("id=first\n"));
    }

    #[test]
    fn special_logs_cannot_block_or_modify_an_external_target() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
        let home = tempfile::tempdir().unwrap();
        let log = home.path().join(".trashd/operations.log");
        std::fs::create_dir(log.parent().unwrap()).unwrap();
        let name = std::ffi::CString::new(log.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_log_file(&log, 1).is_empty());
        log_purge_in(home.path(), "fifo");
        assert!(log.symlink_metadata().unwrap().file_type().is_fifo());
        std::fs::remove_file(&log).unwrap();

        let target = home.path().join("external");
        std::fs::write(&target, "unchanged\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &log).unwrap();
        assert!(read_log_file(&log, 1).is_empty());
        log_purge_in(home.path(), "link");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "unchanged\n");
        assert_eq!(
            target.metadata().unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn log_tail_preserves_line_semantics_and_chunk_boundaries() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("operations.log");
        // The first backwards chunk starts inside the two-byte character.
        let boundary = format!("old\né{}\n", "x".repeat(8190));
        for content in [
            "",
            "\n",
            "\n\n",
            "a",
            "a\n",
            "a\r\n",
            "a\r",
            "a\n\nb",
            "a\n\n",
            "a\r\nb\nc\r\n",
            &boundary,
        ] {
            std::fs::write(&path, content).unwrap();
            let lines: Vec<_> = content.lines().map(str::to_owned).collect();
            for count in [0, 1, 2, 3, usize::MAX] {
                let expected = &lines[lines.len().saturating_sub(count)..];
                let actual = read_log_file(&path, count);
                assert_eq!(
                    actual,
                    expected,
                    "content length={}, count={count}",
                    content.len()
                );
            }
        }
        std::fs::write(&path, b"invalid\xff\n").unwrap();
        assert!(read_log_file(&path, 1).is_empty());
    }

    #[test]
    fn log_tail_reads_only_requested_history() {
        // A sparse historical prefix proves the amount of I/O is bounded
        // without creating a large fixture or relying on timing/RSS.
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(1024 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(b"\nold\nlatest\n").unwrap();
        let bytes_read = std::cell::Cell::new(0);
        let mut read_chunk = |position, chunk: &mut [u8]| {
            file.read_exact_at(chunk, position)?;
            bytes_read.set(bytes_read.get() + chunk.len());
            Ok(())
        };
        let end = file.metadata().unwrap().len();
        assert!(read_log_tail(end, 0, &mut read_chunk).unwrap().is_empty());
        assert_eq!(bytes_read.get(), 0);
        assert_eq!(read_log_tail(end, 1, &mut read_chunk).unwrap(), ["latest"]);
        assert!(
            bytes_read.get() <= 8192,
            "read {} historical bytes",
            bytes_read.get()
        );
        file.set_len(1).unwrap();
        assert_eq!(
            read_log_tail(end, 1, &mut read_chunk).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    // Regression (#254): the trash ID was interpolated unescaped, so an ID
    // containing a newline forged a second operations.log record.
    #[test]
    fn log_writers_escape_the_trash_id() {
        let home = tempfile::tempdir().unwrap();
        let evil = "evil\n2099-01-01 pid=1 PURGE id=forged";
        log_purge_in(home.path(), evil);
        log_restore_in(home.path(), evil, std::path::Path::new("/tmp/x"));
        log_trash_in(home.path(), std::path::Path::new("/tmp/x"), evil, None);
        let log = std::fs::read_to_string(home.path().join(".trashd/operations.log")).unwrap();
        assert_eq!(log.lines().count(), 3, "forged extra line in: {log}");
        assert!(log.contains("evil\\x0a2099"), "ID not escaped in: {log}");
    }

    // Regression (#233): notify-send was spawned and never waited for, so a
    // long-lived caller (the seccomp supervisor) kept one zombie per delete.
    #[test]
    fn notification_helpers_are_reaped() {
        let pid = spawn_reaped(std::process::Command::new("true")).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::path::Path::new(&format!("/proc/{pid}")).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "pid {pid} was never reaped"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    // A field that could contain a physical newline would forge the next
    // record in the operation log (#137) — the escape must guarantee one
    // write_log call maps to exactly one line.
    #[test]
    fn escape_field_never_emits_newlines_or_raw_control_bytes() {
        assert_eq!(escape_field_bytes(b"a\nb"), "a\\x0ab");
        assert_eq!(escape_field_bytes(b"a\rb"), "a\\x0db");
        assert_eq!(escape_field_bytes(b"back\\slash"), "back\\\\slash");
        assert_eq!(escape_field_bytes(b"plain text"), "plain text");
        assert_eq!(escape_field_bytes(&[0xff, b'x']), "\\xffx");
        for byte in 0u8..0x20 {
            let escaped = escape_field_bytes(&[byte]);
            assert!(!escaped.contains('\n') && !escaped.contains('\r'));
        }
    }
}
