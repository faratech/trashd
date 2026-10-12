//! `$trash/directorysizes` cache per FreeDesktop.org Trash spec v1.0.
//!
//! Format: `[size] [mtime] [percent-encoded-directory-name]\n`
//! - size: bytes (like `du -B1`)
//! - mtime: seconds since epoch of the .trashinfo file (not the directory)
//! - name: percent-encoded, no `/` allowed
//!
//! Updated via temp file + atomic rename per spec.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// A cached directory size entry. Names are raw filename bytes: entry IDs
/// are not guaranteed to be UTF-8 (#258).
#[derive(Debug)]
pub struct DirSizeEntry {
    pub size: u64,
    pub mtime: i64,
    pub name: Vec<u8>,
}

/// Read the directorysizes cache for a trash directory.
pub fn read_cache(trash_dir: &Path) -> HashMap<Vec<u8>, DirSizeEntry> {
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
/// Uses a unique temp file + atomic rename per spec.
pub fn write_cache(trash_dir: &Path) -> io::Result<()> {
    write_cache_with(trash_dir, dir_size_bytes)
}

fn write_cache_with(trash_dir: &Path, mut measure: impl FnMut(&Path) -> u64) -> io::Result<()> {
    let previous = read_cache(trash_dir);
    let info_dir = trash_dir.join("info");
    let files_dir = trash_dir.join("files");
    let cache_path = trash_dir.join("directorysizes");
    let mut lines = Vec::new();

    if let Ok(entries) = fs::read_dir(&info_dir) {
        for entry in entries.flatten() {
            // Raw bytes end-to-end: a lossy ID joined nowhere near its real
            // files/ path, silently dropping non-UTF-8 directories (#258).
            let filename = entry.file_name();
            let id: &[u8] = match filename.as_bytes().strip_suffix(b".trashinfo") {
                Some(id) => id,
                None => continue,
            };

            // Only cache directories — symlink_metadata so a trashed SYMLINK
            // to an external directory is never walked through or cached as
            // a directory.
            let file_path = files_dir.join(OsStr::from_bytes(id));
            let is_real_dir = match fs::symlink_metadata(&file_path) {
                Ok(m) => m.is_dir(),
                Err(_) => continue,
            };
            if !is_real_dir {
                continue;
            }

            // mtime of the .trashinfo file per spec (NOT the directory)
            let mtime = match entry.metadata() {
                Ok(m) => m.mtime(),
                Err(_) => continue,
            };

            // Size: recursive directory size
            let size = match previous.get(id) {
                Some(cached) if cached.mtime == mtime => cached.size,
                _ => measure(&file_path),
            };

            lines.push(format!("{} {} {}", size, mtime, encode_name(id)));
        }
    }

    // Exclusive staging remains safe even for concurrent threads in one PID.
    let data = lines.join("\n") + "\n";
    let mut staging = tempfile::NamedTempFile::new_in(trash_dir)?;
    std::io::Write::write_all(&mut staging, data.as_bytes())?;
    staging.persist(&cache_path).map_err(|e| e.error)?;

    Ok(())
}

/// Compute directory size recursively (bytes, like `du -B1`).
fn dir_size_bytes(path: &Path) -> u64 {
    dir_size_bytes_inner(path, 0)
}

/// Depth cap mirrors `copy_tree`'s, so a pathological deep tree can't exhaust
/// the stack (returns a partial total once the cap is hit).
const DIR_SIZE_MAX_DEPTH: u32 = 100;

fn dir_size_bytes_inner(path: &Path, depth: u32) -> u64 {
    if depth > DIR_SIZE_MAX_DEPTH {
        return 0;
    }
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            // symlink_metadata / file_type(): never follow symlinks —
            // following made the walk escape into external (possibly huge or
            // cyclic) trees and count foreign data.
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                total = total.saturating_add(dir_size_bytes_inner(&entry.path(), depth + 1));
            } else if !ft.is_symlink() {
                // Count blocks * 512 for actual disk usage (like du)
                if let Ok(meta) = entry.metadata() {
                    total = total.saturating_add(meta.blocks().saturating_mul(512));
                }
            }
        }
    }
    total
}

/// Percent-encode a directory name for the cache.
/// Spec: no `/` allowed (even as %2F). Encode control chars, `%`, and newlines.
fn encode_name(name: &[u8]) -> String {
    let mut encoded = String::with_capacity(name.len());
    // Keep only the unreserved set safe. The directorysizes line is a
    // space-separated triple `size SP mtime SP name`, so a space (or other
    // separator) in the name MUST be percent-encoded or strict third-party
    // parsers split the field wrong. decode_name round-trips %20 back to space.
    for byte in name {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
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
fn decode_name(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            match (chars.next(), chars.next()) {
                (Some(hi), Some(lo)) => {
                    if let Ok(val) =
                        u8::from_str_radix(std::str::from_utf8(&[hi, lo]).unwrap_or(""), 16)
                    {
                        bytes.push(val);
                    } else {
                        bytes.push(b'%');
                        bytes.push(hi);
                        bytes.push(lo);
                    }
                }
                (Some(hi), None) => {
                    bytes.push(b'%');
                    bytes.push(hi);
                }
                _ => {
                    bytes.push(b'%');
                }
            }
        } else {
            bytes.push(b);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn cache_reuses_unchanged_trees_and_refreshes_only_invalid_entries() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::create_dir(root.join("info")).unwrap();
        for name in ["first", "second"] {
            fs::create_dir_all(root.join("files").join(name)).unwrap();
            fs::write(root.join("files").join(name).join("payload"), b"data").unwrap();
            fs::write(
                root.join("info").join(format!("{name}.trashinfo")),
                b"metadata",
            )
            .unwrap();
        }
        let mut measured = Vec::new();
        write_cache_with(root, |p| {
            measured.push(p.to_path_buf());
            dir_size_bytes(p)
        })
        .unwrap();
        assert_eq!(measured.len(), 2);
        measured.clear();
        write_cache_with(root, |p| {
            measured.push(p.to_path_buf());
            dir_size_bytes(p)
        })
        .unwrap();
        assert!(
            measured.is_empty(),
            "unchanged cache must not walk any tree"
        );
        let original = read_cache(root)[b"first".as_slice()].size;
        fs::write(root.join("files/first/extra"), vec![1u8; 8192]).unwrap();
        let sidecar = fs::File::open(root.join("info/first.trashinfo")).unwrap();
        sidecar
            .set_times(
                fs::FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(2)),
            )
            .unwrap();
        write_cache_with(root, |p| {
            measured.push(p.to_path_buf());
            dir_size_bytes(p)
        })
        .unwrap();
        assert_eq!(measured, [root.join("files/first")]);
        assert!(read_cache(root)[b"first".as_slice()].size > original);
        fs::remove_file(root.join("info/second.trashinfo")).unwrap();
        measured.clear();
        write_cache_with(root, |p| {
            measured.push(p.to_path_buf());
            dir_size_bytes(p)
        })
        .unwrap();
        assert!(measured.is_empty());
        assert!(!read_cache(root).contains_key(b"second".as_slice()));
        fs::create_dir(root.join("files/third")).unwrap();
        fs::write(root.join("info/third.trashinfo"), b"metadata").unwrap();
        write_cache_with(root, |p| {
            measured.push(p.to_path_buf());
            dir_size_bytes(p)
        })
        .unwrap();
        assert_eq!(measured, [root.join("files/third")]);
    }

    // Regression (#258): a non-UTF-8 directory ID was lossy-converted, so
    // its files/ path never matched and the entry vanished from the cache.
    #[test]
    fn cache_keeps_non_utf8_directory_entries() {
        use std::os::unix::ffi::OsStrExt;
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::create_dir(root.join("info")).unwrap();
        let raw_id: &[u8] = b"dir-\xff";
        let dir_path = root.join("files").join(OsStr::from_bytes(raw_id));
        fs::create_dir_all(&dir_path).unwrap();
        fs::write(dir_path.join("payload"), b"data").unwrap();
        let mut sidecar = std::ffi::OsString::from(OsStr::from_bytes(raw_id));
        sidecar.push(".trashinfo");
        fs::write(root.join("info").join(sidecar), b"metadata").unwrap();
        write_cache(root).unwrap();
        let cache = read_cache(root);
        assert!(
            cache.contains_key(raw_id),
            "non-UTF-8 entry dropped from cache: {cache:?}"
        );
    }
}
