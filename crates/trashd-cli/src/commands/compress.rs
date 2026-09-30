use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, older: &str, dry_run: bool) {
    let days = match parse_duration_days(older) {
        Some(d) => d,
        None => fatal(format!("invalid duration '{older}'")),
    };

    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => fatal(e),
    };

    let now = chrono::Local::now();
    let mut compressed = 0usize;
    let mut saved = 0u64;

    for entry in &entries {
        if entry.orphaned {
            continue;
        }
        // symlink_metadata: a trashed SYMLINK must never be compressed —
        // reading through it would slurp its target and renaming the
        // compressed data over it would replace the link with a regular
        // file (#45).
        let stored_meta = match std::fs::symlink_metadata(&entry.trashed_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !stored_meta.is_file() {
            continue;
        }
        let age = now.signed_duration_since(entry.info.deletion_date);
        if age.num_days() < days as i64 {
            continue;
        }
        let size_before = stored_meta.len();
        if size_before < 1024 {
            continue;
        }
        // Keep the invariant "anything compress accepts is restorable":
        // restore refuses to decompress beyond min(max_file_size_mb, 4 GiB),
        // so a larger entry would be permanently stuck if swapped here.
        let configured = store.config().max_file_size_mb.saturating_mul(1024 * 1024);
        const HARD_DECOMPRESS_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
        let restore_limit = if configured == 0 {
            HARD_DECOMPRESS_LIMIT
        } else {
            configured.min(HARD_DECOMPRESS_LIMIT)
        };
        if size_before > restore_limit {
            continue;
        }
        // Check zstd magic — skip already compressed
        if is_zstd(&entry.trashed_path) {
            continue;
        }

        if dry_run {
            println!(
                "  {} {} ({})",
                entry.trashed_path.display(),
                entry.id.dimmed(),
                format_size(size_before),
            );
            compressed += 1;
            continue;
        }

        match compress_file_zstd(store, entry, size_before) {
            Ok(Some(size_after)) => {
                saved += size_before.saturating_sub(size_after);
                compressed += 1;
            }
            Ok(None) => {} // not worth compressing; original untouched
            Err(e) => {
                eprintln!(
                    "  {} {}: {e}",
                    "warn:".yellow(),
                    entry.trashed_path.display(),
                );
            }
        }
    }

    if dry_run {
        if compressed == 0 {
            println!("{}", "Nothing to compress.".dimmed());
        } else {
            println!(
                "\n{} {} items would be compressed (zstd)",
                "Dry run:".yellow().bold(),
                compressed,
            );
        }
    } else if compressed == 0 {
        println!("{}", "Nothing to compress.".dimmed());
    } else {
        println!(
            "{} compressed {} items, saved {}",
            "Done:".green().bold(),
            compressed,
            format_size(saved),
        );
    }
}

/// Sniff only the first 4 bytes for the zstd magic (0x28 B5 2F FD
/// little-endian) — never slurp a whole file just to test its header.
fn is_zstd(path: &std::path::Path) -> bool {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut magic = [0u8; 4];
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && u32::from_le_bytes(magic) == 0xFD2FB528
}

/// Compress a trashed entry's data in-place with zstd (streaming, bounded
/// memory). Returns `Some(new_size)` when swapped, `None` when compression
/// wasn't worthwhile.
///
/// Crash-safe ordering (#23): the `X-Trashd-Compressed` marker is recorded
/// BEFORE the compressed data is renamed over the original. A crash in the
// window then leaves plain data with a stale marker — which restore detects
/// from the missing zstd magic and recovers from — instead of zstd bytes with NO marker,
/// which restore would silently serve as "original content". If the final
/// swap fails, the marker is reverted so the entry stays consistent.
fn compress_file_zstd(
    store: &TrashStore,
    entry: &trashd_common::store::TrashEntry,
    size_before: u64,
) -> std::io::Result<Option<u64>> {
    use trashd_common::store::write_trashinfo_atomic;

    use std::io::{Read, Seek};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let path = &entry.trashed_path;
    let info_path = &entry.info_path;
    let info = &entry.info;
    // Open without following a replacement symlink, and don't block if the
    // entry was replaced with a FIFO after the caller inspected it.
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Ok(None);
    }
    // Serialize compressors that opened the same inode. The second one may
    // have waited on a file that has since been replaced; don't swap it back.
    input.lock()?;
    let current = std::fs::symlink_metadata(path)?;
    if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
        return Ok(None);
    }
    let mut magic = [0u8; 4];
    if input.read_exact(&mut magic).is_ok() && u32::from_le_bytes(magic) == 0xFD2FB528 {
        return Ok(None);
    }
    input.rewind()?;

    // Exclusive, unpredictable sibling names cannot overwrite another trash
    // entry or follow a planted symlink. RAII removes abandoned attempts.
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "entry has no parent")
    })?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".trashd-compress-")
        .tempfile_in(parent)?;
    {
        let mut enc = zstd::stream::Encoder::new(tmp.as_file_mut(), 3)?;
        std::io::copy(&mut input, &mut enc)?;
        enc.finish()?;
    }
    let compressed_len = tmp.as_file().metadata()?.len();
    if compressed_len >= size_before {
        // Incompressible content — discard the attempt, keep the original.
        return Ok(None);
    }
    // Preserve ownership before restoring modes, so set-ID permissions keep
    // their original meaning. Refuse the swap if ownership cannot be kept.
    let temporary_metadata = tmp.as_file().metadata()?;
    if (temporary_metadata.uid(), temporary_metadata.gid()) != (metadata.uid(), metadata.gid())
        && unsafe { libc::fchown(tmp.as_file().as_raw_fd(), metadata.uid(), metadata.gid()) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // chmod after writing/chown, since those operations can clear set-ID bits.
    // Preserve private/executable permissions through compression and restore.
    tmp.as_file().set_permissions(metadata.permissions())?;
    tmp.as_file().sync_all()?;

    let guard = store
        .lock_trash_root(&entry.trash_root)
        .map_err(std::io::Error::other)?;
    store
        .validate_entry_locked(entry, &guard)
        .map_err(std::io::Error::other)?;
    // 1) Marker first.
    let mut marked = info.clone();
    marked.compressed = Some("zstd".into());
    write_trashinfo_atomic(info_path, &marked)?;

    // 2) Then the atomic data swap.
    if let Err(e) = tmp.persist(path) {
        // Revert the marker: data is still plaintext.
        let _ = write_trashinfo_atomic(info_path, info);
        return Err(e.error);
    }
    Ok(Some(compressed_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use trashd_common::trashinfo::TrashInfo;

    fn fixture(dir: &Path, name: &str) -> (TrashStore, trashd_common::store::TrashEntry) {
        let store = TrashStore::open_isolated(&dir.join("Trash"), trashd_common::Config::default())
            .unwrap();
        let path = store.home_dir().join("files").join(name);
        fs::write(&path, vec![b'x'; 8192]).unwrap();
        let info = TrashInfo::new(dir.join(name));
        fs::write(
            store
                .home_dir()
                .join("info")
                .join(format!("{name}.trashinfo")),
            info.to_trashinfo_string(),
        )
        .unwrap();
        let entry = store.find_entry(name).unwrap();
        (store, entry)
    }

    fn compress_fixture(dir: &Path, name: &str, mode: u32) {
        let (store, entry) = fixture(dir, name);
        let path = entry.trashed_path.clone();
        let info_path = entry.info_path.clone();
        let content = vec![b'x'; 8192];
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

        assert!(
            compress_file_zstd(&store, &entry, content.len() as u64)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            zstd::decode_all(fs::File::open(&path).unwrap()).unwrap(),
            content
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            mode
        );
        let marked = TrashInfo::from_trashinfo(&fs::read_to_string(info_path).unwrap()).unwrap();
        assert_eq!(marked.compressed.as_deref(), Some("zstd"));
    }

    #[test]
    fn compression_preserves_colliding_trash_entry_and_modes() {
        let dir = tempfile::tempdir().unwrap();
        let collision = dir.path().join("a.zst.tmp");
        fs::write(&collision, b"other trashed data").unwrap();
        compress_fixture(dir.path(), "a.txt", 0o700);
        compress_fixture(dir.path(), "private.txt", 0o600);
        assert_eq!(fs::read(collision).unwrap(), b"other trashed data");
    }

    #[test]
    fn compression_does_not_follow_old_temporary_path_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"precious").unwrap();
        symlink(&victim, dir.path().join("a.zst.tmp")).unwrap();
        compress_fixture(dir.path(), "a.txt", 0o640);
        assert_eq!(fs::read(victim).unwrap(), b"precious");
        assert!(
            fs::symlink_metadata(dir.path().join("a.zst.tmp"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn compression_preserves_foreign_ownership_when_permitted() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;

        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (store, entry) = fixture(dir.path(), "data");
        let path = entry.trashed_path.clone();
        let input = fs::File::open(&path).unwrap();
        assert_eq!(unsafe { libc::fchown(input.as_raw_fd(), 65534, 65534) }, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4700)).unwrap();
        assert!(compress_file_zstd(&store, &entry, 8192).unwrap().is_some());
        let metadata = fs::metadata(path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (65534, 65534));
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o4700);
    }

    #[test]
    fn concurrent_compression_of_shared_stems_is_independent() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for name in ["same.a", "same.b", "same.c", "same.d"] {
                let path = dir.path();
                scope.spawn(move || compress_fixture(path, name, 0o600));
            }
        });
        assert_eq!(
            fs::read_dir(dir.path().join("Trash/files"))
                .unwrap()
                .count(),
            4
        );
    }

    #[test]
    fn concurrent_compression_of_same_entry_does_not_compress_twice() {
        let dir = tempfile::tempdir().unwrap();
        let (store, entry) = fixture(dir.path(), "data");
        let path = entry.trashed_path.clone();
        let content = vec![b'x'; 8192];
        let root = store.home_dir().to_path_buf();
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    barrier.wait();
                    let store =
                        TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
                    let _ = compress_file_zstd(&store, &entry, 8192);
                });
            }
        });
        assert_eq!(
            zstd::decode_all(fs::File::open(path).unwrap()).unwrap(),
            content
        );
        assert_eq!(fs::read_dir(root.join("files")).unwrap().count(), 1);
    }

    #[test]
    fn failed_marker_write_preserves_original_and_removes_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut entry) = fixture(dir.path(), "data");
        let path = entry.trashed_path.clone();
        let content = vec![b'x'; 8192];
        entry.info_path = dir.path().join("missing/info");
        let result = compress_file_zstd(&store, &entry, 8192);
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), content);
        assert_eq!(
            fs::read_dir(store.home_dir().join("files"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn compression_refuses_symlink_as_source() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let (store, entry) = fixture(dir.path(), "link");
        let path = entry.trashed_path.clone();
        let content = vec![b'x'; 8192];
        fs::write(&target, &content).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert!(compress_file_zstd(&store, &entry, 8192).is_err());
        assert_eq!(fs::read(target).unwrap(), content);
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }
    #[test]
    fn stale_snapshot_cannot_compress_reused_id_or_changed_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let (store, entry) = fixture(dir.path(), "data");
        // Keep the original inode alive so immediate recreation cannot reuse
        // it: this case tests a different data identity with an unchanged sidecar.
        let _original = fs::File::open(&entry.trashed_path).unwrap();
        fs::remove_file(&entry.trashed_path).unwrap();
        fs::write(&entry.trashed_path, vec![b'y'; 8192]).unwrap();
        let replacement = fs::read(&entry.info_path).unwrap();
        assert!(compress_file_zstd(&store, &entry, 8192).is_err());
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), vec![b'y'; 8192]);
        assert_eq!(fs::read(&entry.info_path).unwrap(), replacement);
        let fresh = store.find_entry("data").unwrap();
        fs::write(&fresh.info_path, b"changed metadata").unwrap();
        assert!(compress_file_zstd(&store, &fresh, 8192).is_err());
        assert_eq!(fs::read(&fresh.info_path).unwrap(), b"changed metadata");
    }
}
