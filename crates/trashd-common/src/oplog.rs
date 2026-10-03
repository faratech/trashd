//! Append-only operation log for trash operations.
//!
//! Logs every trash, restore, purge, and empty operation to
//! `~/.local/share/Trash/.trashd/operations.log`.
//!
//! Format: `TIMESTAMP OP [details]`

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
            "TRASH id={trash_id} path={} cmd={}",
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
            "RESTORE id={trash_id} to={}",
            escape_field(restored_to.as_os_str()),
        ),
    );
}

/// Log a purge operation.
pub fn log_purge(trash_id: &str) {
    log_purge_in(&crate::TrashStore::home_trash_dir(), trash_id);
}

pub(crate) fn log_purge_in(home: &Path, trash_id: &str) {
    write_log(home, &format!("PURGE id={trash_id}"));
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
    let path = log_path();
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

    if lines.len() <= max_lines {
        lines
    } else {
        lines[lines.len() - max_lines..].to_vec()
    }
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

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
    let pid = std::process::id();
    let line = format!("{timestamp} pid={pid} {message}\n");

    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(line.as_bytes())
        });

    if let Err(e) = result {
        eprintln!("trashd: failed to write operation log: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::{escape_field_bytes, spawn_reaped};

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
