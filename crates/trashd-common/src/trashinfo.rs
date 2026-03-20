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
            // Use X-Trashd-Hash for new entries (algorithm-agnostic).
            // X-Trashd-SHA256 is still read for backward compatibility.
            s.push_str(&format!("X-Trashd-Hash={hash}\n"));
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
                    "X-Trashd-Hash" | "X-Trashd-SHA256" => sha256 = Some(value.trim().to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple_path() {
        let info = TrashInfo {
            original_path: PathBuf::from("/home/user/Documents/report.pdf"),
            deletion_date: Local::now(),
            command: Some("rm report.pdf".into()),
            pid: Some(1234),
            size: Some(4096),
            sha256: Some("abcdef1234567890".into()),
        };

        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).expect("should parse");

        assert_eq!(parsed.original_path, info.original_path);
        assert_eq!(parsed.command, info.command);
        assert_eq!(parsed.pid, info.pid);
        assert_eq!(parsed.size, info.size);
        assert_eq!(parsed.sha256, info.sha256);
    }

    #[test]
    fn round_trip_path_with_spaces() {
        let info = TrashInfo::new(PathBuf::from("/home/user/My Documents/file name.txt"));
        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn round_trip_path_with_unicode() {
        let info = TrashInfo::new(PathBuf::from("/home/user/文档/日本語ファイル.txt"));
        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn round_trip_path_with_equals() {
        let info = TrashInfo::new(PathBuf::from("/home/user/key=value.conf"));
        let serialized = info.to_trashinfo_string();

        // '=' should be percent-encoded so it doesn't break the key=value parser
        assert!(!serialized.contains("Path=/home/user/key=value"));
        assert!(serialized.contains("%3D"));

        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn round_trip_path_with_percent() {
        let info = TrashInfo::new(PathBuf::from("/home/user/100%done.txt"));
        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn parse_minimal_trashinfo() {
        let content = "[Trash Info]\nPath=/tmp/test.txt\nDeletionDate=2026-03-20T14:30:00\n";
        let info = TrashInfo::from_trashinfo(content).unwrap();
        assert_eq!(info.original_path, PathBuf::from("/tmp/test.txt"));
        assert!(info.command.is_none());
        assert!(info.pid.is_none());
        assert!(info.size.is_none());
        assert!(info.sha256.is_none());
    }

    #[test]
    fn parse_with_extensions() {
        let content = "\
[Trash Info]
Path=/home/user/file.txt
DeletionDate=2026-03-20T14:30:00
X-Trashd-Command=rm -rf file.txt
X-Trashd-PID=42
X-Trashd-Size=1024
X-Trashd-SHA256=deadbeef
";
        let info = TrashInfo::from_trashinfo(content).unwrap();
        assert_eq!(info.command.as_deref(), Some("rm -rf file.txt"));
        assert_eq!(info.pid, Some(42));
        assert_eq!(info.size, Some(1024));
        assert_eq!(info.sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn parse_missing_path_returns_none() {
        let content = "[Trash Info]\nDeletionDate=2026-03-20T14:30:00\n";
        assert!(TrashInfo::from_trashinfo(content).is_none());
    }

    #[test]
    fn parse_missing_date_returns_none() {
        let content = "[Trash Info]\nPath=/tmp/test.txt\n";
        assert!(TrashInfo::from_trashinfo(content).is_none());
    }

    #[test]
    fn encode_decode_path_preserves_special_chars() {
        let original = PathBuf::from("/path/to/file with spaces & symbols=yes!.txt");
        let encoded = encode_path(&original);
        let decoded = decode_path(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn trashinfo_format_matches_spec() {
        let info = TrashInfo::new(PathBuf::from("/home/user/test.txt"));
        let s = info.to_trashinfo_string();

        assert!(s.starts_with("[Trash Info]\n"));
        assert!(s.contains("Path="));
        assert!(s.contains("DeletionDate="));
        // Date format: YYYY-MM-DDTHH:MM:SS (no timezone per spec)
        let date_line = s.lines().find(|l| l.starts_with("DeletionDate=")).unwrap();
        let date_val = date_line.strip_prefix("DeletionDate=").unwrap();
        assert_eq!(date_val.len(), 19); // "2026-03-20T14:30:00"
    }
}
