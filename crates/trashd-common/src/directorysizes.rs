//! `$trash/directorysizes` cache per FreeDesktop.org Trash spec v1.0.
//!
//! Format: `[size] [mtime] [percent-encoded-directory-name]\n`
//! - size: bytes (like `du -B1`)
//! - mtime: seconds since epoch of the .trashinfo file (not the directory)
//! - name: percent-encoded, no `/` allowed
//!
//! Updated via temp file + atomic rename per spec.

use crate::store_lock::RootMutationGuard;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
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

/// Largest directorysizes cache read (a few hundred bytes per directory);
/// anything larger is treated as malformed and rebuilt.
const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;

/// Read the directorysizes cache for a trash directory.
pub fn read_cache(trash_dir: &Path) -> HashMap<Vec<u8>, DirSizeEntry> {
    let cache_path = trash_dir.join("directorysizes");
    let content = match crate::trashinfo::read_regular_text_file(&cache_path, MAX_CACHE_BYTES) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };
    parse_cache(&content).0
}

/// Names the cache lists; an absent cache lists none. None when it is
/// malformed or unreadable and needs the full repair.
pub(crate) fn cached_names(trash_dir: &Path) -> Option<std::collections::HashSet<Vec<u8>>> {
    match crate::trashinfo::read_regular_text_file(
        &trash_dir.join("directorysizes"),
        MAX_CACHE_BYTES,
    ) {
        Ok(content) => {
            // Only the requested names are retained: no DirSizeEntry map and
            // no second cloned key per row (#400).
            let mut names = std::collections::HashSet::new();
            let malformed = scan_cache(&content, |name| {
                names.insert(name.to_vec());
            });
            (!malformed).then_some(names)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Some(Default::default()),
        Err(_) => None,
    }
}

/// Check a removed raw name without traversing the trash. A malformed or
/// unreadable cache needs the same best-effort rebuild as before; callers may
/// skip maintenance only after a successful parse (or an absent cache).
pub(crate) fn cache_contains_name(trash_dir: &Path, name: &OsStr) -> io::Result<bool> {
    let content = crate::trashinfo::read_regular_text_file(
        &trash_dir.join("directorysizes"),
        MAX_CACHE_BYTES,
    )?;
    // Validate every row before answering: a malformed row after the match
    // still means the cache needs repair, not a successful verdict (#400).
    let mut found = false;
    let malformed = scan_cache(&content, |row_name| {
        found |= row_name == name.as_bytes();
    });
    if malformed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed directorysizes cache",
        ));
    }
    Ok(found)
}

enum CacheRow {
    Empty,
    /// A row that cannot be parsed at all; it contributes no entry.
    Malformed,
    Row {
        size: u64,
        mtime: i64,
        name: Vec<u8>,
        malformed: bool,
    },
}

fn parse_cache_row(line: &str) -> CacheRow {
    if line.is_empty() {
        return CacheRow::Empty;
    }
    let mut parts = line.splitn(3, ' ');
    let (Some(size), Some(mtime), Some(encoded_name)) = (parts.next(), parts.next(), parts.next())
    else {
        return CacheRow::Malformed;
    };
    let Ok(size) = size.parse() else {
        return CacheRow::Malformed;
    };
    let Ok(mtime) = mtime.parse() else {
        return CacheRow::Malformed;
    };
    // Keep the public reader's permissive decoding, but a checked read
    // must request repair for invalid/incomplete escapes instead of
    // treating the resulting literal percent bytes as a valid cache.
    let mut malformed = false;
    let mut encoded = encoded_name.bytes();
    while let Some(byte) = encoded.next() {
        if byte == b'%'
            && !matches!(
                (encoded.next(), encoded.next()),
                (Some(hi), Some(lo)) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit()
            )
        {
            malformed = true;
            break;
        }
    }
    let name = decode_name(encoded_name);
    if name.is_empty() || name.contains(&b'/') || name.contains(&0) || name == b"." || name == b".."
    {
        malformed = true;
    }
    CacheRow::Row {
        size,
        mtime,
        name,
        malformed,
    }
}

/// Visit each parsed row's decoded name one at a time, retaining nothing.
/// True when any row was malformed.
fn scan_cache(content: &str, mut visit: impl FnMut(&[u8])) -> bool {
    let mut malformed = false;
    for line in content.lines() {
        match parse_cache_row(line) {
            CacheRow::Empty => {}
            CacheRow::Malformed => malformed = true,
            CacheRow::Row {
                name,
                malformed: row_malformed,
                ..
            } => {
                malformed |= row_malformed;
                visit(&name);
            }
        }
    }
    malformed
}

fn cache_is_malformed(content: &str) -> bool {
    scan_cache(content, |_| {})
}

fn parse_cache(content: &str) -> (HashMap<Vec<u8>, DirSizeEntry>, bool) {
    let mut entries = HashMap::new();
    let mut malformed = false;

    for line in content.lines() {
        match parse_cache_row(line) {
            CacheRow::Empty => {}
            CacheRow::Malformed => malformed = true,
            CacheRow::Row {
                size,
                mtime,
                name,
                malformed: row_malformed,
            } => {
                malformed |= row_malformed;
                entries.insert(name.clone(), DirSizeEntry { size, mtime, name });
            }
        }
    }

    (entries, malformed)
}

/// A trash root, its files/ and its info/, held open: every lookup below
/// them starts at the directory itself, never at a path a FUSE or NFS
/// server could answer again with a symlink once it was checked (security-1
/// follow-up). The cache used to be staged and renamed by path, and landed
/// wherever such a symlink pointed.
struct Pinned<'a> {
    root: &'a fs::File,
    /// May be search-only (`O_PATH`) when the directory cannot be read.
    files: Option<&'a fs::File>,
    /// None when info/ is missing or cannot be read: no rows then.
    info: Option<&'a fs::File>,
}

/// Open `trash_dir` and its files/ and info/ following no symlink, the
/// children on the root's own device. An unreadable files/ is held for
/// search only, as a path walk through it worked before.
fn open_pinned(trash_dir: &Path) -> io::Result<(fs::File, Option<fs::File>, Option<fs::File>)> {
    let root = crate::fdops::open_dir_nofollow_at(
        libc::AT_FDCWD,
        &CString::new(trash_dir.as_os_str().as_bytes())?,
    )?;
    let device = crate::fdops::stat_fd(root.as_raw_fd())?.st_dev;
    let on_device = |dir: fs::File| -> io::Result<fs::File> {
        let stat = crate::fdops::stat_fd(dir.as_raw_fd())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        if stat.st_dev != device {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
        Ok(dir)
    };
    let child = |name: &CStr, search_only: bool| -> io::Result<Option<fs::File>> {
        match crate::fdops::open_dir_nofollow_at(root.as_raw_fd(), name) {
            Ok(dir) => on_device(dir).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::EACCES) => {
                if search_only {
                    on_device(crate::fdops::open_path_nofollow_at(root.as_raw_fd(), name)?)
                        .map(Some)
                } else {
                    Ok(None)
                }
            }
            Err(error) => Err(error),
        }
    };
    let files = child(c"files", true)?;
    let info = child(c"info", false)?;
    Ok((root, files, info))
}

/// Write/update the directorysizes cache for a trash directory.
/// Uses a unique temp file + atomic rename per spec, through descriptors
/// opened following no symlink.
pub fn write_cache(trash_dir: &Path) -> io::Result<()> {
    let (root, files, info) = open_pinned(trash_dir)?;
    let pinned = Pinned {
        root: &root,
        files: files.as_ref(),
        info: info.as_ref(),
    };
    rebuild(&pinned, trash_dir, |files, name, _| {
        crate::store::tree_allocated_bytes_at(files, name)
    })
}

/// `write_cache` measuring each directory with `measure`, given its path.
#[cfg(test)]
fn write_cache_with(trash_dir: &Path, mut measure: impl FnMut(&Path) -> u64) -> io::Result<()> {
    let (root, files, info) = open_pinned(trash_dir)?;
    let pinned = Pinned {
        root: &root,
        files: files.as_ref(),
        info: info.as_ref(),
    };
    rebuild(&pinned, trash_dir, |_, _, path| measure(path))
}

/// The names in the open directory `dir`, read through a fresh descriptor
/// of it (a held one may have been read to its end before).
fn for_each_name(dir: &fs::File, mut each: impl FnMut(&CStr, u8)) -> io::Result<()> {
    let listing = crate::fdops::open_dir_nofollow_at(dir.as_raw_fd(), c".")?;
    crate::store::for_each_entry(listing.as_raw_fd(), |name, kind| {
        each(name, kind);
        std::ops::ControlFlow::Continue(())
    })
}

/// Directory-entry types let a rebuild skip unrelated regular files and
/// symlinks without statting each one (#377). Entries of unknown type are
/// statted. Keep only potential directories: each still gets a fresh
/// nofollow check before use, because a directory can be replaced after
/// this scan. An incomplete scan (an unreadable files/) falls back to that
/// check alone.
fn directory_candidates(files: &fs::File) -> io::Result<HashSet<Vec<u8>>> {
    let mut directories = HashSet::new();
    for_each_name(files, |name, kind| {
        let is_dir = match kind {
            libc::DT_DIR => true,
            libc::DT_UNKNOWN => crate::fdops::stat_nofollow_at(files.as_raw_fd(), name)
                .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFDIR),
            _ => false,
        };
        if is_dir {
            directories.insert(name.to_bytes().to_vec());
        }
    })?;
    Ok(directories)
}

fn is_directory_at(dir: RawFd, name: &CStr) -> bool {
    crate::fdops::stat_nofollow_at(dir, name)
        .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// Rebuild the cache of `pinned`, measuring a directory whose row is
/// missing or stale with `measure(files, name, path)`; `trash_dir` only
/// names paths for it.
fn rebuild(
    pinned: &Pinned<'_>,
    trash_dir: &Path,
    mut measure: impl FnMut(RawFd, &CStr, &Path) -> u64,
) -> io::Result<()> {
    let previous = read_cache_at(pinned.root);
    let mut lines = Vec::new();
    if let (Some(files), Some(info)) = (pinned.files, pinned.info) {
        let directories = directory_candidates(files).ok();
        let mut sidecars = Vec::new();
        // Raw bytes end-to-end: a lossy ID joined nowhere near its real
        // files/ entry, silently dropping non-UTF-8 directories (#258).
        let _ = for_each_name(info, |name, _| {
            if name.to_bytes().ends_with(b".trashinfo") {
                sidecars.push(name.to_owned());
            }
        });
        for sidecar in sidecars {
            let id = &sidecar.to_bytes()[..sidecar.to_bytes().len() - b".trashinfo".len()];
            if directories
                .as_ref()
                .is_some_and(|names| !names.contains(id))
            {
                continue;
            }
            let Ok(name) = CString::new(id) else {
                continue;
            };
            // Only real directories: a trashed SYMLINK to an external
            // directory is never walked through or cached as one.
            if !is_directory_at(files.as_raw_fd(), &name) {
                continue;
            }
            // mtime of the .trashinfo file per spec (NOT the directory)
            let mtime = match crate::fdops::metadata_nofollow_at(info.as_raw_fd(), &sidecar) {
                Ok(metadata) => metadata.mtime(),
                Err(_) => continue,
            };
            let size = match previous.get(id) {
                Some(cached) if cached.mtime == mtime => cached.size,
                _ => measure(
                    files.as_raw_fd(),
                    &name,
                    &trash_dir.join("files").join(OsStr::from_bytes(id)),
                ),
            };
            lines.push(format!("{} {} {}", size, mtime, encode_name(id)));
        }
    }
    replace_cache_at(pinned.root, (lines.join("\n") + "\n").as_bytes())
}

/// The cache of the open trash root `root`, as `read_cache` reads it.
fn read_cache_at(root: &fs::File) -> HashMap<Vec<u8>, DirSizeEntry> {
    match crate::trashinfo::read_regular_text_file_at(
        root.as_raw_fd(),
        c"directorysizes",
        MAX_CACHE_BYTES,
    ) {
        Ok(content) => parse_cache(&content).0,
        Err(_) => HashMap::new(),
    }
}

/// Atomically replace `directorysizes` in the open trash root `root`:
/// staged exclusively beside it and renamed over it, both relative to the
/// root's descriptor.
fn replace_cache_at(root: &fs::File, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    static STAGES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    for _ in 0..64 {
        let staged = CString::new(format!(
            ".directorysizes-{}-{}.tmp",
            std::process::id(),
            STAGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))?;
        let mut file = match crate::fdops::create_excl_at(root.as_raw_fd(), &staged, 0o600) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            created => created?,
        };
        let published = file.write_all(data).and_then(|()| {
            if unsafe {
                libc::renameat(
                    root.as_raw_fd(),
                    staged.as_ptr(),
                    root.as_raw_fd(),
                    c"directorysizes".as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
        if published.is_err() {
            let _ = crate::fdops::unlink_at(root.as_raw_fd(), &staged, 0);
        }
        return published;
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

/// Add or refresh the row of one newly trashed directory, in the root
/// `locked` holds, through the descriptors it validated. A full rebuild
/// stats every entry of the trash for each trashed directory; rows are keyed
/// by name and validated by sidecar mtime, so every other row stays valid
/// (#322). A malformed or unreadable cache gets the full repair instead.
///
/// `size` is the tree's allocated bytes, measured by the caller while it
/// sized the entry (one walk serves both).
pub(crate) fn record_directory(
    locked: &RootMutationGuard,
    name: &OsStr,
    size: u64,
) -> io::Result<()> {
    let pinned = Pinned {
        root: locked.root_dir(),
        files: Some(locked.files()),
        info: Some(locked.info()),
    };
    let content = match crate::trashinfo::read_regular_text_file_at(
        locked.root_dir().as_raw_fd(),
        c"directorysizes",
        MAX_CACHE_BYTES,
    ) {
        Ok(content) => content,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(_) => return rebuild_locked(&pinned, locked.root()),
    };
    if cache_is_malformed(&content) {
        return rebuild_locked(&pinned, locked.root());
    }
    let directory = CString::new(name.as_bytes())?;
    if !is_directory_at(locked.files().as_raw_fd(), &directory) {
        return Ok(());
    }
    let mut sidecar = name.as_bytes().to_vec();
    sidecar.extend_from_slice(b".trashinfo");
    let mtime =
        crate::fdops::metadata_nofollow_at(locked.info().as_raw_fd(), &CString::new(sidecar)?)?
            .mtime();
    let mut data = String::with_capacity(content.len() + 64);
    for line in content.lines().filter(|line| !line.is_empty()) {
        // parse_cache accepted every line, so each has three fields.
        if line.splitn(3, ' ').nth(2).map(decode_name).as_deref() != Some(name.as_bytes()) {
            data.push_str(line);
            data.push('\n');
        }
    }
    data.push_str(&format!(
        "{size} {mtime} {}\n",
        encode_name(name.as_bytes())
    ));
    replace_cache_at(locked.root_dir(), data.as_bytes())
}

fn rebuild_locked(pinned: &Pinned<'_>, trash_dir: &Path) -> io::Result<()> {
    rebuild(pinned, trash_dir, |files, name, _| {
        crate::store::tree_allocated_bytes_at(files, name)
    })
}

/// Compute directory size recursively (bytes, like `du -B1`): the walk that
/// sizes a directory when it is trashed, so a rebuilt row equals the one
/// `record_directory` got (store-metadata-9). Symlinks are never followed.
#[cfg(test)]
fn dir_size_bytes(path: &Path) -> u64 {
    crate::store::tree_allocated_bytes(path)
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
    use std::ffi::OsString;
    use std::time::{Duration, SystemTime};

    /// Lock `root` as a writer does (its directories made private first).
    fn lock(root: &Path) -> RootMutationGuard {
        use std::os::unix::fs::PermissionsExt;
        for dir in [root.to_path_buf(), root.join("files"), root.join("info")] {
            fs::create_dir_all(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        RootMutationGuard::acquire(root).unwrap()
    }

    #[test]
    fn checked_cache_names_reject_malformed_encoding_without_changing_public_reads() {
        let fixture = tempfile::tempdir().unwrap();
        let cases: &[(&str, &[u8], bool)] = &[
            ("bad%GG", b"bad%GG", false),
            ("bad%G0", b"bad%G0", false),
            ("bad%0G", b"bad%0G", false),
            ("trailing%", b"trailing%", false),
            ("short%A", b"short%A", false),
            ("nul%00name", b"nul\0name", false),
            ("", b"", false),
            ("%2F", b"/", false),
            ("%2f", b"/", false),
            (".", b".", false),
            ("%2e%2E", b"..", false),
            ("plain", b"plain", true),
            ("literal%25GG", b"literal%GG", true),
            ("literal%252F", b"literal%2F", true),
            ("raw%FF", b"raw\xff", true),
            ("encoded%20space", b"encoded space", true),
        ];
        for &(encoded, decoded, valid) in cases {
            fs::write(
                fixture.path().join("directorysizes"),
                format!("7 9 kept\n123 456 {encoded}\n"),
            )
            .unwrap();
            // The legacy public map retains even permissively decoded bad
            // names. Only the checked helper uses the malformed flag.
            let public = read_cache(fixture.path());
            assert_eq!(public.len(), 2, "{encoded}");
            let entry = public.get(decoded).unwrap();
            assert_eq!((entry.size, entry.mtime), (123, 456), "{encoded}");
            assert_eq!(entry.name, decoded, "{encoded}");
            let checked = cache_contains_name(fixture.path(), OsStr::from_bytes(decoded));
            if valid {
                assert!(checked.unwrap(), "{encoded}");
                assert!(!cache_contains_name(fixture.path(), OsStr::new("absent")).unwrap());
            } else {
                assert_eq!(
                    checked.unwrap_err().kind(),
                    io::ErrorKind::InvalidData,
                    "{encoded}"
                );
            }
        }
    }

    // #400: maintenance helpers must validate every row before a
    // successful verdict, without retaining a full entry map.
    #[test]
    fn checked_helpers_validate_rows_after_the_match() {
        let fixture = tempfile::tempdir().unwrap();
        // Match first, malformed row last: an early-exit membership check
        // would wrongly report success (or a usable name set).
        fs::write(
            fixture.path().join("directorysizes"),
            "1 2 wanted\n3 4 other\ngarbage\n",
        )
        .unwrap();
        assert_eq!(
            cache_contains_name(fixture.path(), OsStr::new("wanted"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(cached_names(fixture.path()), None);
        assert!(cache_is_malformed("1 2 wanted\ngarbage\n"));
        assert!(!cache_is_malformed("1 2 wanted\n3 4 other\n"));

        // Duplicate rows: the public map keeps the last row, the name set
        // keeps one name, and membership still succeeds.
        fs::write(
            fixture.path().join("directorysizes"),
            "1 2 dup\n9 8 dup\n3 4 other\n",
        )
        .unwrap();
        let public = read_cache(fixture.path());
        assert_eq!(public.len(), 2);
        assert_eq!(
            (
                public[b"dup".as_slice()].size,
                public[b"dup".as_slice()].mtime
            ),
            (9, 8)
        );
        assert_eq!(cached_names(fixture.path()).unwrap().len(), 2);
        assert!(cache_contains_name(fixture.path(), OsStr::new("dup")).unwrap());
        assert!(!cache_contains_name(fixture.path(), OsStr::new("absent")).unwrap());
    }

    #[test]
    fn checked_helpers_scan_a_large_cache_row_by_row() {
        let fixture = tempfile::tempdir().unwrap();
        let mut content = String::new();
        for i in 0..20_000u32 {
            content.push_str(&format!("{i} {i} dir{i}\n"));
        }
        content.push_str("42 43 target\n");
        fs::write(fixture.path().join("directorysizes"), content).unwrap();
        assert!(cache_contains_name(fixture.path(), OsStr::new("target")).unwrap());
        assert!(!cache_contains_name(fixture.path(), OsStr::new("missing")).unwrap());
        assert_eq!(cached_names(fixture.path()).unwrap().len(), 20_001);
    }

    #[test]
    fn fifo_cache_is_ignored_and_replaced_without_blocking() {
        use std::ffi::CString;
        let fixture = tempfile::tempdir().unwrap();
        let cache = fixture.path().join("directorysizes");
        let name = CString::new(cache.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_cache(fixture.path()).is_empty());
        write_cache(fixture.path()).unwrap();
        assert!(cache.symlink_metadata().unwrap().is_file());
    }

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

    #[test]
    fn rebuilding_mixed_entries_keeps_full_repair_and_sidecar_metadata() {
        use std::ffi::CString;
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::create_dir(root.join("files")).unwrap();
        fs::create_dir(root.join("info")).unwrap();
        let target = root.join("sidecar-target");
        fs::write(&target, b"external metadata").unwrap();
        fs::File::open(&target)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        let names: &[&[u8]] = &[
            b"cached",
            b"uncached",
            b"raw \xff%",
            b"linked",
            b"dangling",
            b"fifo",
            b"directory",
        ];
        let mut expected_mtimes = HashMap::new();
        for &name in names {
            fs::create_dir(root.join("files").join(OsStr::from_bytes(name))).unwrap();
            let mut info_name = OsString::from(OsStr::from_bytes(name));
            info_name.push(".trashinfo");
            let sidecar = root.join("info").join(info_name);
            match name {
                b"linked" => symlink(&target, &sidecar).unwrap(),
                b"dangling" => symlink(root.join("absent"), &sidecar).unwrap(),
                b"fifo" => {
                    let name = CString::new(sidecar.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                b"directory" => fs::create_dir(&sidecar).unwrap(),
                // A cache rebuild uses metadata, not a sidecar parse.
                _ => fs::write(&sidecar, b"unparsed metadata").unwrap(),
            }
            expected_mtimes.insert(
                name.to_vec(),
                fs::symlink_metadata(sidecar).unwrap().mtime(),
            );
        }
        for i in 0..128 {
            fs::write(root.join(format!("files/plain-{i}")), b"file").unwrap();
            fs::write(root.join(format!("info/plain-{i}.trashinfo")), b"metadata").unwrap();
        }
        fs::create_dir(root.join("orphan-target")).unwrap();
        fs::write(root.join("orphan-target/KEEP"), b"external data").unwrap();
        symlink(root.join("orphan-target"), root.join("files/link")).unwrap();
        fs::write(root.join("info/link.trashinfo"), b"metadata").unwrap();
        fs::create_dir(root.join("files/orphan")).unwrap();
        fs::write(root.join("info/missing.trashinfo"), b"metadata").unwrap();
        fs::write(
            root.join("directorysizes"),
            format!(
                "123 {} cached\n456 0 missing\n789 0 plain-0\nmalformed\n",
                expected_mtimes[b"cached".as_slice()]
            ),
        )
        .unwrap();
        let mut measured = HashSet::new();
        write_cache_with(root, |path| {
            measured.insert(path.file_name().unwrap().as_bytes().to_vec());
            17
        })
        .unwrap();
        let rebuilt = read_cache(root);
        assert_eq!(rebuilt.len(), names.len());
        for &name in names {
            let entry = &rebuilt[name];
            assert_eq!(entry.mtime, expected_mtimes[name], "{name:?}");
            assert_eq!(entry.size, if name == b"cached" { 123 } else { 17 });
            assert_eq!(measured.contains(name), name != b"cached");
        }
        assert_ne!(
            rebuilt[b"linked".as_slice()].mtime,
            fs::metadata(&target).unwrap().mtime()
        );
        assert!(!parse_cache(&fs::read_to_string(root.join("directorysizes")).unwrap()).1);
        assert_eq!(
            fs::read(root.join("orphan-target/KEEP")).unwrap(),
            b"external data"
        );

        fs::File::open(root.join("info/cached.trashinfo"))
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(2))
            .unwrap();
        measured.clear();
        write_cache_with(root, |path| {
            measured.insert(path.file_name().unwrap().as_bytes().to_vec());
            23
        })
        .unwrap();
        assert_eq!(measured, HashSet::from([b"cached".to_vec()]));
        assert_eq!(read_cache(root)[b"cached".as_slice()].size, 23);
    }

    #[test]
    fn rebuild_rechecks_a_directory_replaced_after_the_type_scan() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::create_dir(root.join("info")).unwrap();
        for name in ["first", "second"] {
            fs::create_dir_all(root.join("files").join(name)).unwrap();
            fs::write(
                root.join("info").join(format!("{name}.trashinfo")),
                b"metadata",
            )
            .unwrap();
        }
        let external = root.join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("KEEP"), b"external data").unwrap();
        let mut measured = Vec::new();
        write_cache_with(root, |path| {
            measured.push(path.file_name().unwrap().as_bytes().to_vec());
            if measured.len() == 1 {
                // Both names were directories during the files/ scan. Swap
                // the other one before its sidecar is visited, regardless
                // of the filesystem's directory iteration order.
                let other = if path.file_name().unwrap() == "first" {
                    "second"
                } else {
                    "first"
                };
                fs::rename(root.join("files").join(other), root.join("held")).unwrap();
                symlink(&external, root.join("files").join(other)).unwrap();
            }
            17
        })
        .unwrap();
        assert_eq!(
            measured.len(),
            1,
            "a stale directory type followed the replacement"
        );
        let rebuilt = read_cache(root);
        assert_eq!(rebuilt.len(), 1);
        assert!(rebuilt.contains_key(&measured[0]));
        assert_eq!(fs::read(external.join("KEEP")).unwrap(), b"external data");
    }

    #[test]
    fn rebuild_preserves_unreadable_directory_behavior() {
        use std::os::unix::fs::PermissionsExt;

        const TEST: &str = "directorysizes::tests::rebuild_preserves_unreadable_directory_behavior";
        const CHILD: &str = "TRASHD_TEST_DIRECTORYSIZES_PERMISSIONS";
        if unsafe { libc::geteuid() } == 0 {
            if !crate::mounts::is_rerun_child(TEST, CHILD) {
                assert_ne!(crate::mounts::rerun_test(TEST, CHILD), Some(false));
                return;
            }
            assert!(unsafe {
                libc::setgroups(0, std::ptr::null()) == 0
                    && libc::setgid(65534) == 0
                    && libc::setuid(65534) == 0
            });
        }
        for unreadable in ["files", "info"] {
            let fixture = tempfile::tempdir().unwrap();
            let root = fixture.path();
            fs::create_dir_all(root.join("files/tree")).unwrap();
            fs::create_dir(root.join("info")).unwrap();
            fs::write(root.join("info/tree.trashinfo"), b"metadata").unwrap();
            let directory = root.join(unreadable);
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o111)).unwrap();
            let result = write_cache_with(root, |_| 17);
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            result.unwrap();
            let rebuilt = read_cache(root);
            if unreadable == "files" {
                assert_eq!(rebuilt[b"tree".as_slice()].size, 17);
            } else {
                assert!(rebuilt.is_empty());
            }
        }
        if crate::mounts::is_rerun_child(TEST, CHILD) {
            crate::mounts::report_test_verdict(Some(true));
        }
    }

    // #322: recording one directory yields the rows a full rebuild would,
    // without touching any other entry, and repairs a malformed cache.
    #[test]
    fn recording_one_directory_matches_a_full_rebuild() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        fs::create_dir(root.join("info")).unwrap();
        let add = |name: &[u8], payload: usize| {
            let name = OsStr::from_bytes(name);
            fs::create_dir_all(root.join("files").join(name)).unwrap();
            fs::write(
                root.join("files").join(name).join("payload"),
                vec![7u8; payload],
            )
            .unwrap();
            let mut sidecar = name.to_os_string();
            sidecar.push(".trashinfo");
            fs::write(root.join("info").join(sidecar), b"metadata").unwrap();
        };
        add(b"first", 10);
        add(b"second", 9000);
        write_cache(root).unwrap();
        add(b"third \xff%", 20000);
        record_directory(
            &lock(root),
            OsStr::from_bytes(b"third \xff%"),
            dir_size_bytes(&root.join("files").join(OsStr::from_bytes(b"third \xff%"))),
        )
        .unwrap();
        let recorded = read_cache(root);
        write_cache(root).unwrap();
        let rebuilt = read_cache(root);
        assert_eq!(recorded.len(), 3);
        for (name, entry) in &rebuilt {
            let other = &recorded[name];
            assert_eq!(
                (other.size, other.mtime),
                (entry.size, entry.mtime),
                "{name:?}"
            );
        }
        // A reused name replaces its row instead of duplicating it.
        fs::write(root.join("files/first/more"), vec![1u8; 50000]).unwrap();
        record_directory(
            &lock(root),
            OsStr::new("first"),
            dir_size_bytes(&root.join("files/first")),
        )
        .unwrap();
        let content = fs::read_to_string(root.join("directorysizes")).unwrap();
        assert_eq!(content.lines().filter(|l| l.ends_with(" first")).count(), 1);
        assert!(read_cache(root)[b"first".as_slice()].size > rebuilt[b"first".as_slice()].size);
        // Non-directories are not cached.
        fs::write(root.join("files/plain"), b"x").unwrap();
        fs::write(root.join("info/plain.trashinfo"), b"metadata").unwrap();
        record_directory(&lock(root), OsStr::new("plain"), 0).unwrap();
        assert!(!read_cache(root).contains_key(b"plain".as_slice()));
        // A malformed cache is rebuilt completely.
        fs::write(root.join("directorysizes"), "garbage\n").unwrap();
        record_directory(
            &lock(root),
            OsStr::new("first"),
            dir_size_bytes(&root.join("files/first")),
        )
        .unwrap();
        assert_eq!(read_cache(root).len(), 3);
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
