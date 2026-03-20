//! Structured logging for deletion events.

use std::fs;
use std::path::PathBuf;

/// A detected deletion event.
pub struct DeletionEvent {
    pub path: PathBuf,
    pub pid: u32,
    pub process: String,
}

impl DeletionEvent {
    /// Format as a structured log line.
    pub fn log(&self, skipped: bool) {
        if skipped {
            eprintln!(
                "[trashd-daemon] DELETE pid={} proc={} path={} (skipped)",
                self.pid,
                self.process,
                self.path.display(),
            );
        } else {
            eprintln!(
                "[trashd-daemon] DELETE pid={} proc={} path={}",
                self.pid,
                self.process,
                self.path.display(),
            );
        }
    }
}

/// Resolve a process name from its PID.
pub fn process_name(pid: u32) -> String {
    if pid == 0 {
        return "(kernel)".into();
    }
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .or_else(|| {
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| format!("(pid {pid})"))
}
