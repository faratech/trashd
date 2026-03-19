use chrono::{DateTime, Local, NaiveDateTime};
use std::path::{Path, PathBuf};
use url::Url;

/// Represents a .trashinfo metadata file per FreeDesktop.org Trash spec.
#[derive(Debug, Clone)]
pub struct TrashInfo {
    pub original_path: PathBuf,
    pub deletion_date: DateTime<Local>,
    /// trashd extension: the command that caused deletion
    pub command: Option<String>,
    /// trashd extension: PID of the deleting process
    pub pid: Option<u32>,
    /// trashd extension: file size in bytes
    pub size: Option<u64>,
    /// trashd extension: SHA-256 of file contents (files only, not dirs)
    pub sha256: Option<String>,
}

impl TrashInfo {
    pub fn new(original_path: PathBuf) -> Self {
        Self {
            original_path,
            deletion_date: Local::now(),
            command: None,
            pid: None,
            size: None,
            sha256: None,
        }
    }

    /// Serialize to .trashinfo format (FreeDesktop.org Trash spec).
    pub fn to_trashinfo_string(&self) -> String {
        let encoded_path = encode_path(&self.original_path);
        let date_str = self.deletion_date.format("%Y-%m-%dT%H:%M:%S").to_string();

        let mut s = format!(
            "[Trash Info]\nPath={encoded_path}\nDeletionDate={date_str}\n"
        );

        if let Some(ref cmd) = self.command {
            s.push_str(&format!("X-Trashd-Command={cmd}\n"));
        }
        if let Some(pid) = self.pid {
            s.push_str(&format!("X-Trashd-PID={pid}\n"));
        }
        if let Some(size) = self.size {
            s.push_str(&format!("X-Trashd-Size={size}\n"));
        }
        if let Some(ref hash) = self.sha256 {
            s.push_str(&format!("X-Trashd-SHA256={hash}\n"));
        }

        s
    }

    /// Parse a .trashinfo file.
    pub fn from_trashinfo(content: &str) -> Option<Self> {
        let mut path: Option<PathBuf> = None;
        let mut date: Option<DateTime<Local>> = None;
        let mut command = None;
        let mut pid = None;
        let mut size = None;
        let mut sha256 = None;

        for line in content.lines() {
            let line = line.trim();
            if line == "[Trash Info]" || line.is_empty() {
                continue;
            }
            // split_once on '=' — the value is everything after the first '='
            // (handles '=' in filenames since Path values are percent-encoded)
            if let Some((key, value)) = line.split_once('=') {
                match key.trim() {
                    "Path" => path = Some(decode_path(value.trim())),
                    "DeletionDate" => {
                        if let Ok(naive) =
                            NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%dT%H:%M:%S")
                        {
                            // Use latest() instead of single() to handle DST
                            // ambiguity (fall-back transitions where one wall-clock
                            // time maps to two UTC instants).
                            date = match naive.and_local_timezone(Local) {
                                chrono::LocalResult::Single(dt) => Some(dt),
                                chrono::LocalResult::Ambiguous(_, latest) => Some(latest),
                                chrono::LocalResult::None => {
                                    // DST gap — shift forward by an hour
                                    let shifted = naive + chrono::Duration::hours(1);
                                    shifted.and_local_timezone(Local).earliest()
                                }
                            };
                        }
                    }
                    "X-Trashd-Command" => command = Some(value.trim().to_string()),
                    "X-Trashd-PID" => pid = value.trim().parse().ok(),
                    "X-Trashd-Size" => size = value.trim().parse().ok(),
                    "X-Trashd-SHA256" => sha256 = Some(value.trim().to_string()),
                    _ => {}
                }
            }
        }

        Some(TrashInfo {
            original_path: path?,
            deletion_date: date?,
            command,
            pid,
            size,
            sha256,
        })
    }
}

/// Percent-encode a path for .trashinfo (spec requirement).
fn encode_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    // Encode non-ASCII and special chars per the trash spec
    let mut encoded = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match *byte {
            // Safe chars: unreserved + /
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(*byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

/// Decode a percent-encoded path from .trashinfo.
fn decode_path(s: &str) -> PathBuf {
    if let Ok(url) = Url::parse(&format!("file://{s}")) {
        if let Ok(path) = url.to_file_path() {
            return path;
        }
    }
    // Fallback: manual decode
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let hex = [hi, lo];
            if let Ok(val) = u8::from_str_radix(std::str::from_utf8(&hex).unwrap_or("00"), 16) {
                bytes.push(val);
            }
        } else {
            bytes.push(b);
        }
    }
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}
