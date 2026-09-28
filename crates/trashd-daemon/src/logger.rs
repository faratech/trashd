//! Structured logging for deletion events.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// A detected deletion event.
pub struct DeletionEvent {
    pub path: Option<PathBuf>,
    pub pid: u32,
    pub process: OsString,
}

impl DeletionEvent {
    /// Format as a structured log line.
    pub fn log(&self, skipped: bool) {
        eprintln!("{}", self.format(skipped));
    }

    fn format(&self, skipped: bool) -> String {
        let process = escape_field(self.process.as_os_str());
        let path = match self.path.as_deref() {
            Some(path) => format!("\"{}\"", escape_path(path)),
            None => "(unresolved)".to_string(),
        };
        let suffix = if skipped { " (skipped)" } else { "" };
        format!(
            "[trashd] DELETE pid={} proc=\"{}\" path={}{}",
            self.pid, process, path, suffix
        )
    }
}

pub(crate) fn escape_path(path: &Path) -> String {
    escape_field(path.as_os_str())
}

/// Encode an arbitrary Unix string into a quoted log field. Backslash and
/// quote are escaped, and every byte outside printable ASCII is represented as
/// `\xNN`. The result is reversible and can never contain a physical newline.
fn escape_field(value: &OsStr) -> String {
    let mut escaped = String::with_capacity(value.as_bytes().len());
    for byte in value.as_bytes() {
        match byte {
            b'\\' => escaped.push_str("\\\\"),
            b'\"' => escaped.push_str("\\\""),
            0x20..=0x7e => escaped.push(char::from(*byte)),
            _ => {
                use std::fmt::Write;
                write!(&mut escaped, "\\x{byte:02x}").expect("writing to String cannot fail");
            }
        }
    }
    escaped
}

/// Resolve a process name from its PID.
pub fn process_name(pid: u32) -> OsString {
    if pid == 0 {
        return "(kernel)".into();
    }
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(OsStr::to_os_string))
        .or_else(|| {
            fs::read(format!("/proc/{pid}/comm")).ok().map(|mut bytes| {
                while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                    bytes.pop();
                }
                OsString::from_vec(bytes)
            })
        })
        .unwrap_or_else(|| format!("(pid {pid})").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_bytes_are_reversibly_escaped_on_one_line() {
        let event = DeletionEvent {
            path: Some(PathBuf::from(OsString::from_vec(
                b"/tmp/file\n\t\\\"\xff".to_vec(),
            ))),
            pid: 42,
            process: OsString::from_vec(b"bad\nproc\t\\\"\xfe".to_vec()),
        };

        let line = event.format(false);
        assert_eq!(
            line,
            "[trashd] DELETE pid=42 proc=\"bad\\x0aproc\\x09\\\\\\\"\\xfe\" path=\"/tmp/file\\x0a\\x09\\\\\\\"\\xff\""
        );
        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
    }

    #[test]
    fn unresolved_events_use_the_same_safe_formatter() {
        let event = DeletionEvent {
            path: None,
            pid: 7,
            process: OsString::from("worker\nspoof"),
        };

        assert_eq!(
            event.format(true),
            "[trashd] DELETE pid=7 proc=\"worker\\x0aspoof\" path=(unresolved) (skipped)"
        );
    }

    #[test]
    fn mount_diagnostic_path_is_single_line() {
        let path = PathBuf::from(OsString::from_vec(
            b"/mnt/hostile\n[trashd] forged".to_vec(),
        ));
        let escaped = escape_path(&path);
        assert_eq!(escaped, "/mnt/hostile\\x0a[trashd] forged");
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
    }
}
