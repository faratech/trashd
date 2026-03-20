//! Append-only operation log for trash operations.
//!
//! Logs every trash, restore, purge, and empty operation to
//! `~/.local/share/Trash/.trashd/operations.log`.
//!
//! Format: `TIMESTAMP OP [details]`

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Log a trash operation.
pub fn log_trash(original_path: &Path, trash_id: &str, command: Option<&str>) {
    let cmd = command.unwrap_or("-");
    write_log(&format!(
        "TRASH id={trash_id} path={} cmd={cmd}",
        original_path.display(),
    ));
}

/// Log a restore operation.
pub fn log_restore(trash_id: &str, restored_to: &Path) {
    write_log(&format!(
        "RESTORE id={trash_id} to={}",
        restored_to.display(),
    ));
}

/// Log a purge operation.
pub fn log_purge(trash_id: &str) {
    write_log(&format!("PURGE id={trash_id}"));
}

/// Log an empty operation.
pub fn log_empty(count: u64, filter: Option<&str>) {
    let filter_str = filter.unwrap_or("all");
    write_log(&format!("EMPTY count={count} filter={filter_str}"));
}

/// Read the last N lines of the operation log.
pub fn read_log(max_lines: usize) -> Vec<String> {
    let path = log_path();
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let lines: Vec<String> = content
        .lines()
        .map(|l| l.to_string())
        .collect();

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

fn write_log(message: &str) {
    let path = log_path();

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
        .open(&path)
        .and_then(|mut f| f.write_all(line.as_bytes()));

    if let Err(e) = result {
        eprintln!("trashd: failed to write operation log: {e}");
    }
}
