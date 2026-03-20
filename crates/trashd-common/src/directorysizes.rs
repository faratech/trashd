//! `$trash/directorysizes` cache per FreeDesktop.org Trash spec v1.0.
//!
//! Format: `[size] [mtime] [percent-encoded-directory-name]\n`
//! - size: bytes (like `du -B1`)
//! - mtime: seconds since epoch of the .trashinfo file (not the directory)
//! - name: percent-encoded, no `/` allowed
//!
//! Updated via temp file + atomic rename per spec.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// A cached directory size entry.
#[derive(Debug)]
pub struct DirSizeEntry {
    pub size: u64,
    pub mtime: i64,
    pub name: String,
}

/// Read the directorysizes cache for a trash directory.
pub fn read_cache(trash_dir: &Path) -> HashMap<String, DirSizeEntry> {
    let cache_path = trash_dir.join("directorysizes");
    let mut entries = HashMap::new();

    let content = match fs::read_to_string(&cache_path) {
        Ok(c) => c,
        Err(_) => return entries,
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() != 3 {
            continue;
        }
        let size: u64 = match parts[0].parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mtime: i64 = match parts[1].parse() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let name = decode_name(parts[2]);
        entries.insert(name.clone(), DirSizeEntry { size, mtime, name });
    }

    entries
}

/// Write/update the directorysizes cache for a trash directory.
/// Uses temp file + atomic rename per spec.
pub fn write_cache(trash_dir: &Path) -> io::Result<()> {
    let info_dir = trash_dir.join("info");
    let files_dir = trash_dir.join("files");
    let cache_path = trash_dir.join("directorysizes");
    let tmp_path = trash_dir.join(".directorysizes.tmp");

    let mut lines = Vec::new();

    if let Ok(entries) = fs::read_dir(&info_dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name().to_string_lossy().into_owned();
            if !filename.ends_with(".trashinfo") {
                continue;
            }
            let id = match filename.strip_suffix(".trashinfo") {
                Some(id) => id,
                None => continue,
            };

            // Only cache directories
            let file_path = files_dir.join(id);
            if !file_path.is_dir() {
                continue;
            }

            // mtime of the .trashinfo file per spec (NOT the directory)
            let info_meta = match fs::metadata(entry.path()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = info_meta.mtime();

            // Size: recursive directory size
            let size = dir_size_bytes(&file_path);

            lines.push(format!("{} {} {}", size, mtime, encode_name(id)));
        }
    }

    // Write to temp file, then atomic rename
    fs::write(&tmp_path, lines.join("\n") + "\n")?;
    fs::rename(&tmp_path, &cache_path)?;

    Ok(())
}

/// Compute directory size recursively (bytes, like `du -B1`).
fn dir_size_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    total += dir_size_bytes(&entry.path());
                }
                // Count blocks * 512 for actual disk usage (like du)
                total += meta.blocks() * 512;
            }
        }
    }
    total
}

/// Percent-encode a directory name for the cache.
/// Spec: no `/` allowed (even as %2F). Encode control chars, `%`, and newlines.
fn encode_name(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len());
    for byte in name.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'.' | b'_' | b'~' | b' ' | b'(' | b')' | b'!' | b'@' | b'+'
            | b',' | b';' | b'=' | b'&' | b'\'' => {
                encoded.push(*byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

/// Decode a percent-encoded directory name from the cache.
fn decode_name(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            if let Ok(val) = u8::from_str_radix(
                std::str::from_utf8(&[hi, lo]).unwrap_or("00"),
                16,
            ) {
                bytes.push(val);
            }
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}
