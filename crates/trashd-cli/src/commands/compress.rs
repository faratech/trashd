use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;
use trashd_common::store::compression_source_matches;

pub fn run(store: &TrashStore, older: &str, dry_run: bool) {
    let days = match parse_duration_days(older) {
        Some(d) => d,
        None => fatal(format!("invalid duration '{older}'")),
    };

    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => fatal_untrusted(e),
    };

    let now = chrono::Local::now();
    let mut compressed = 0usize;
    let mut failed = 0usize;
    let mut saved = 0u64;
    if !dry_run {
        sweep_interrupted_attempts(&entries);
    }

    for entry in &entries {
        // Most entries are recent; their data and xattrs need no inspection.
        let age = now.signed_duration_since(entry.info.deletion_date);
        if age.num_days() < days as i64 {
            continue;
        }
        // symlink_metadata: a trashed SYMLINK must never be compressed —
        // reading through it would slurp its target and renaming the
        // compressed data over it would replace the link with a regular
        // file (#45). Hard links, extended attributes and other tools'
        // entries are left alone as well (#327).
        let stored_meta = match std::fs::symlink_metadata(&entry.trashed_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !trashd_common::store::compression_candidate(entry, &stored_meta) {
            continue;
        }
        let size_before = stored_meta.len();
        if size_before < 1024 {
            continue;
        }
        // Keep the invariant "anything compress accepts is restorable":
        // restore decompresses up to the entry's recorded size (at most
        // 4 GiB), so larger data would be stuck if swapped here. Not up to
        // max_file_size_mb as it is today: once lowered, every larger entry
        // compressed before stayed unrestorable (cli-4).
        if size_before > trashd_common::store::decompress_limit(entry.info.size) {
            continue;
        }
        // --dry-run performs the real compression, counting its output, so
        // "would be compressed" means exactly what the real run would keep:
        // one keep/discard decision, one code path (#415). The
        // shared path also skips already-zstd data the way the real run does,
        // by checking the magic under the entry's lock.
        let mode = if dry_run {
            CommitMode::ReportOnly
        } else {
            CommitMode::Publish
        };
        match compress_file_zstd(store, entry, size_before, mode) {
            Ok(Some(size_after)) => {
                compressed += 1;
                if dry_run {
                    println!(
                        "  {} {} ({})",
                        printable_path(&entry.trashed_path),
                        printable(&entry.id).dimmed(),
                        format_size(size_before),
                    );
                } else {
                    saved += size_before.saturating_sub(size_after);
                }
            }
            Ok(None) => {} // not worth compressing; original untouched
            Err(e) => {
                eprintln!(
                    "  {} {}: {}",
                    "warn:".yellow(),
                    printable_path(&entry.trashed_path),
                    printable(&e.to_string()),
                );
                failed += 1;
            }
        }
    }

    if compressed == 0 && failed == 0 {
        println!("{}", "Nothing to compress.".dimmed());
    } else if compressed == 0 {
        // Every attempt failed (an unwritable state directory, a full disk):
        // scripts and timers read the exit status, as for empty and fsck
        // (#409, #156) (cli-3).
        fatal(format!("{failed} item(s) could not be compressed"));
    } else if dry_run {
        println!(
            "\n{} {} items would be compressed (zstd)",
            "Dry run:".yellow().bold(),
            compressed,
        );
    } else {
        println!(
            "{} compressed {} items, saved {}",
            "Done:".green().bold(),
            compressed,
            format_size(saved),
        );
    }
    if failed > 0 {
        eprintln!(
            "{} {failed} item(s) could not be compressed",
            "warn:".yellow()
        );
    }
}

const COMPRESS_PREFIX: &str = ".trashd-compress-";

/// Remove attempts a killed run left behind: in the state directory, and in
/// files/ from versions that staged there (only names without a sidecar).
/// An hour's grace keeps a concurrent run's attempt in place.
fn sweep_interrupted_attempts(entries: &[trashd_common::store::TrashEntry]) {
    let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    sweep_attempts_changed_before(entries, stale);
}

/// Staleness is judged by the status-change time: a live attempt is given
/// the original's old mtime just before it is published, and a concurrent
/// sweep judging by mtime removed it (#348). ctime cannot be set back.
fn sweep_attempts_changed_before(
    entries: &[trashd_common::store::TrashEntry],
    stale: std::time::SystemTime,
) {
    use std::os::unix::fs::MetadataExt;
    let mut roots: Vec<&std::path::Path> = entries.iter().map(|e| e.trash_root.as_path()).collect();
    roots.sort();
    roots.dedup();
    let uid = unsafe { libc::geteuid() };
    for root in roots {
        for dir in [root.join(".trashd"), root.join("files")] {
            let Ok(listing) = std::fs::read_dir(&dir) else {
                continue;
            };
            for item in listing.flatten() {
                let name = item.file_name();
                if !name
                    .as_encoded_bytes()
                    .starts_with(COMPRESS_PREFIX.as_bytes())
                {
                    continue;
                }
                let mut sidecar = name.clone();
                sidecar.push(".trashinfo");
                if root.join("info").join(sidecar).exists() {
                    continue;
                }
                if let Ok(meta) = std::fs::symlink_metadata(item.path())
                    && meta.is_file()
                    && meta.uid() == uid
                    && std::time::UNIX_EPOCH
                        .checked_add(std::time::Duration::new(
                            meta.ctime().max(0) as u64,
                            meta.ctime_nsec().clamp(0, 999_999_999) as u32,
                        ))
                        .is_some_and(|changed| changed < stale)
                {
                    let _ = std::fs::remove_file(item.path());
                }
            }
        }
    }
}

/// Sniff only the first 4 bytes for the zstd magic (0x28 B5 2F FD
/// little-endian) — never slurp a whole file just to test its header.
/// Production skips zstd data through the checked magic read under the
/// entry lock; the standalone probe is a test assertion aid.
#[cfg(test)]
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

/// What happens to a staged compression that passed the keep/discard
/// decision: the compressed copy is smaller than the source.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitMode {
    /// The real run: publish the stage (marker, then rename) via the hooks.
    Publish,
    /// `--dry-run`: report the verdict from the compressed length alone, so
    /// the estimate can never claim a file the real run would discard
    /// (#415), and nothing is written to the trash (recent-changes-6).
    ReportOnly,
}

/// Compress a trashed entry's data in-place with zstd (streaming, bounded
/// memory). Returns `Some(new_size)` when swapped (or, in `ReportOnly`, when
/// the compressed size qualified), `None` when compression wasn't worthwhile.
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
    mode: CommitMode,
) -> std::io::Result<Option<u64>> {
    compress_before_publish(store, entry, size_before, mode, || {}, || {})
}

/// Encode exactly `size` bytes of `input` into `output`; false when the
/// source no longer has that size.
fn encode_zstd(
    input: &mut std::fs::File,
    size: u64,
    output: impl std::io::Write,
) -> std::io::Result<bool> {
    use std::io::Read;
    let mut enc = zstd::stream::Encoder::new(output, 3)?;
    // A writer with an existing descriptor need not honor our flock.
    // Bound work even if it keeps extending the same inode (#386).
    let copied = std::io::copy(
        &mut Read::by_ref(input).take(size.saturating_add(1)),
        &mut enc,
    )?;
    if copied != size {
        return Ok(false);
    }
    enc.finish()?;
    Ok(true)
}

/// Stands in for the stage file in a dry run, which needs only the
/// compressed length (recent-changes-6).
struct ByteCount(u64);

impl std::io::Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn compress_before_publish(
    store: &TrashStore,
    entry: &trashd_common::store::TrashEntry,
    size_before: u64,
    mode: CommitMode,
    before_commit: impl FnOnce(),
    before_persist: impl FnOnce(),
) -> std::io::Result<Option<u64>> {
    use trashd_common::store::{publish_data_stage, set_compression_marker_locked};

    use std::io::{Read, Seek};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let path = &entry.trashed_path;
    // Open without following a replacement symlink, and don't block if the
    // entry was replaced with a FIFO after the caller inspected it.
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() != size_before {
        return Ok(None);
    }
    // Serialize compressors that opened the same inode. The second one may
    // have waited on a file that has since been replaced; don't swap it back.
    // A process that locked the file before it was trashed still holds the
    // lock: give up after a bounded wait and report the entry busy (cli-8).
    trashd_common::store::lock_entry_data_until(
        &input,
        std::time::Instant::now() + trashd_common::store::ENTRY_LOCK_WAIT,
    )?;
    let current = std::fs::symlink_metadata(path)?;
    if !compression_source_matches(&metadata, &current) {
        return Ok(None);
    }
    let mut magic = [0u8; 4];
    if input.read_exact(&mut magic).is_ok() && u32::from_le_bytes(magic) == 0xFD2FB528 {
        return Ok(None);
    }
    input.rewind()?;

    // Exclusive, unpredictable names cannot overwrite another trash entry or
    // follow a planted symlink. RAII removes abandoned attempts; a run killed
    // by a signal skips RAII, so attempts are staged in the root's private
    // state directory (same filesystem) rather than files/, where a leftover
    // listed as an orphaned entry forever (#327). A dry run needs only the
    // compressed length: it counts the encoder's output instead, so it never
    // takes space in the trash or strands a stage when interrupted
    // (recent-changes-6).
    let mut tmp = match mode {
        CommitMode::Publish => Some(trashd_common::store::create_data_stage(&entry.trash_root)?),
        CommitMode::ReportOnly => None,
    };
    let compressed_len = match tmp.as_mut() {
        Some(stage) => {
            if !encode_zstd(&mut input, size_before, stage.as_file_mut())? {
                return Ok(None);
            }
            stage.as_file().metadata()?.len()
        }
        None => {
            let mut counted = ByteCount(0);
            if !encode_zstd(&mut input, size_before, &mut counted)? {
                return Ok(None);
            }
            counted.0
        }
    };
    if compressed_len >= size_before {
        // Incompressible content — discard the attempt, keep the original.
        // This is the single keep/discard verdict: --dry-run reports exactly
        // what passes it, so the estimate cannot drift from the real run.
        return Ok(None);
    }
    let Some(tmp) = tmp else {
        // The verdict is in and the trash is still untouched: no stage, no
        // marker, no swap, no timestamps (#415).
        return Ok(Some(compressed_len));
    };
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

    before_commit();
    let guard = store
        .lock_trash_root(&entry.trash_root)
        .map_err(std::io::Error::other)?;
    store
        .validate_entry_locked(entry, &guard)
        .map_err(std::io::Error::other)?;
    if !compression_source_matches(&metadata, &input.metadata()?) {
        return Ok(None);
    }
    // The replacement keeps the original timestamps (#202).
    tmp.as_file().set_times(
        std::fs::FileTimes::new()
            .set_accessed(metadata.accessed()?)
            .set_modified(metadata.modified()?),
    )?;

    // 1) Marker first, touching only that line of the on-disk sidecar (#218).
    // Marker and data go through the directories the lock validated: by
    // path, a FUSE or NFS server could answer files/ or info/ with a symlink
    // once the lock had checked them (security-1 follow-up).
    set_compression_marker_locked(&guard, entry, Some("zstd"))?;

    before_persist();
    // The marker write syncs its temporary file, so a writer can change the
    // source while it blocks. Recheck immediately before the data swap.
    let result = (|| -> std::io::Result<bool> {
        if !compression_source_matches(&metadata, &input.metadata()?) {
            return Ok(false);
        }
        publish_data_stage(&guard, entry, tmp)?;
        Ok(true)
    })();
    match result {
        Ok(true) => Ok(Some(compressed_len)),
        Ok(false) => {
            set_compression_marker_locked(&guard, entry, None)?;
            Ok(None)
        }
        Err(error) => {
            // Revert the marker: data is still plaintext.
            let _ = set_compression_marker_locked(&guard, entry, None);
            Err(error)
        }
    }
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

    // #386: an open writer can edit the trashed inode without taking its
    // flock. Neither its inode identity nor the sidecar version changes.
    #[test]
    fn compression_preserves_newer_same_inode_data_and_metadata() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        for action in ["append", "rewrite", "mode", "link"] {
            let dir = tempfile::tempdir().unwrap();
            let (store, entry) = fixture(dir.path(), "data");
            let sidecar = fs::read(&entry.info_path).unwrap();
            let inode = fs::metadata(&entry.trashed_path).unwrap().ino();
            let result = compress_before_publish(
                &store,
                &entry,
                8192,
                CommitMode::Publish,
                || match action {
                    "append" => fs::OpenOptions::new()
                        .append(true)
                        .open(&entry.trashed_path)
                        .unwrap()
                        .write_all(b"newer content")
                        .unwrap(),
                    "rewrite" => fs::write(&entry.trashed_path, b"updated data").unwrap(),
                    "mode" => fs::set_permissions(
                        &entry.trashed_path,
                        fs::Permissions::from_mode(
                            fs::metadata(&entry.trashed_path).unwrap().mode() ^ 0o100,
                        ),
                    )
                    .unwrap(),
                    "link" => {
                        fs::hard_link(&entry.trashed_path, dir.path().join("another-link")).unwrap()
                    }
                    _ => unreachable!(),
                },
                || {},
            )
            .unwrap();
            assert!(result.is_none(), "{action}: changed source was published");
            assert_eq!(fs::metadata(&entry.trashed_path).unwrap().ino(), inode);
            assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
            let data = fs::read(&entry.trashed_path).unwrap();
            if action == "append" {
                assert!(data.ends_with(b"newer content"));
            }
            if action == "rewrite" {
                assert_eq!(data, b"updated data");
            }
            assert!(!is_zstd(&entry.trashed_path));
            assert!(
                !fs::read_dir(store.home_dir().join(".trashd"))
                    .unwrap()
                    .flatten()
                    .any(|entry| entry
                        .file_name()
                        .as_encoded_bytes()
                        .starts_with(COMPRESS_PREFIX.as_bytes()))
            );
        }
    }

    #[test]
    fn compression_preserves_edits_after_staging_and_marker_write() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        for phase in ["staging", "marker"] {
            let directory = tempfile::tempdir().unwrap();
            let (store, entry) = fixture(directory.path(), "data");
            let sidecar = fs::read(&entry.info_path).unwrap();
            let inode = fs::metadata(&entry.trashed_path).unwrap().ino();
            let assert_live_stage = || {
                let stages = fs::read_dir(store.home_dir().join(".trashd"))
                    .unwrap()
                    .flatten()
                    .filter(|item| {
                        item.file_name()
                            .as_encoded_bytes()
                            .starts_with(trashd_common::store::DATA_STAGE_PREFIX.as_bytes())
                    })
                    .collect::<Vec<_>>();
                assert_eq!(stages.len(), 1);
                let stage = fs::File::open(stages[0].path()).unwrap();
                assert_eq!(
                    unsafe { libc::flock(stage.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
                    -1
                );
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            };
            let append = || {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&entry.trashed_path)
                    .unwrap()
                    .write_all(b"newer bytes")
                    .unwrap();
            };
            let result = compress_before_publish(
                &store,
                &entry,
                8192,
                CommitMode::Publish,
                || {
                    assert_live_stage();
                    if phase == "staging" {
                        append();
                    }
                },
                || {
                    assert_live_stage();
                    assert!(
                        fs::read_to_string(&entry.info_path)
                            .unwrap()
                            .contains("X-Trashd-Compressed=zstd"),
                        "the edit must follow the real marker write"
                    );
                    if phase == "marker" {
                        append();
                    }
                },
            )
            .unwrap();
            assert!(result.is_none(), "{phase}: changed source was published");
            assert_eq!(fs::metadata(&entry.trashed_path).unwrap().ino(), inode);
            assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
            let mut current = vec![b'x'; 8192];
            current.extend_from_slice(b"newer bytes");
            assert_eq!(fs::read(&entry.trashed_path).unwrap(), current);
            assert!(
                !fs::read_dir(store.home_dir().join(".trashd"))
                    .unwrap()
                    .flatten()
                    .any(|entry| entry
                        .file_name()
                        .as_encoded_bytes()
                        .starts_with(COMPRESS_PREFIX.as_bytes()))
            );
        }
    }

    // Regression (#415): --dry-run counted every candidate as "would be
    // compressed", including files the real run discards as incompressible.
    // ReportOnly must reach the same keep/discard verdict through the same
    // code, and leave the entry exactly as it was.
    #[test]
    fn dry_run_makes_the_real_keep_or_discard_decision_without_publishing() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();

        // Compressible data: the dry run reports the swap the real run would
        // make, but data, sidecar, identity and timestamps are untouched.
        let (store, entry) = fixture(dir.path(), "data");
        let path = entry.trashed_path.clone();
        let sidecar = fs::read(&entry.info_path).unwrap();
        let before = fs::metadata(&path).unwrap();
        let reported = compress_before_publish(
            &store,
            &entry,
            8192,
            CommitMode::ReportOnly,
            || panic!("a dry run must stop before publishing"),
            || panic!("a dry run must not persist"),
        )
        .unwrap();
        assert!(reported.is_some(), "8 KiB of one repeated byte compresses");
        assert_eq!(fs::read(&path).unwrap(), vec![b'x'; 8192]);
        assert!(!is_zstd(&path), "no zstd data may be written");
        assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar, "no marker");
        assert_eq!(fs::metadata(&path).unwrap().ino(), before.ino());
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            before.modified().unwrap()
        );
        assert_eq!(
            fs::read_dir(dir.path().join("Trash/files"))
                .unwrap()
                .count(),
            1
        );
        assert!(
            !fs::read_dir(dir.path().join("Trash/.trashd"))
                .unwrap()
                .flatten()
                .any(|left| left
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(COMPRESS_PREFIX.as_bytes())),
            "the discarded stage must not survive the call"
        );

        // Incompressible data: the dry run reports nothing, matching the real
        // run that discards the stage at the same verdict.
        let mut random = Vec::with_capacity(8192);
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..8192 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            random.push(state as u8);
        }
        let (store, entry) = fixture(dir.path(), "random");
        fs::write(&entry.trashed_path, &random).unwrap();
        assert!(
            compress_file_zstd(&store, &entry, 8192, CommitMode::Publish)
                .unwrap()
                .is_none(),
            "the fixture must actually be incompressible"
        );
        let sidecar = fs::read(&entry.info_path).unwrap();
        let reported = compress_before_publish(
            &store,
            &entry,
            8192,
            CommitMode::ReportOnly,
            || panic!("a dry run must stop before publishing"),
            || panic!("a dry run must not persist"),
        )
        .unwrap();
        assert!(
            reported.is_none(),
            "the dry run must agree with the real run's discard"
        );
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), random);
        assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
    }

    /// A trashd entry of 8 KiB of compressible data, trashed from `dir/name`.
    fn trashed(dir: &Path, name: &str) -> TrashStore {
        let mut config = trashd_common::Config::default();
        config.never_trash.clear();
        let store = TrashStore::open_isolated(&dir.join("Trash"), config).unwrap();
        let source = dir.join(name);
        fs::write(&source, vec![b'x'; 8192]).unwrap();
        store.trash(&source, None).unwrap();
        store
    }

    // Regression (cli-2): the dry run escaped the stored path but printed
    // the filename-derived ID raw, so a crafted name reached the terminal.
    #[test]
    fn dry_run_lines_escape_the_entry_id() {
        const CHILD: &str = "TRASHD_COMPRESS_DRY_RUN_CHILD";
        if let Some(dir) = std::env::var_os(CHILD) {
            run(&trashed(Path::new(&dir), "esc\x1b[2Jname"), "0", true);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let output = crate::util::rerun_test(
            "commands::compress::tests::dry_run_lines_escape_the_entry_id",
            CHILD,
            dir.path().as_os_str(),
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{output:?}");
        assert!(stdout.contains("1 items would be compressed"), "{stdout}");
        assert!(
            !output.stdout.contains(&0x1b),
            "raw escape in the dry run: {stdout:?}"
        );
    }

    /// Replace the root's state directory with a regular file: staging there
    /// then fails with ENOTDIR, which root cannot override either.
    fn block_state_directory(store: &TrashStore) {
        let state = store.home_dir().join(".trashd");
        fs::rename(&state, store.home_dir().join("saved-state")).unwrap();
        fs::write(&state, b"not a directory").unwrap();
    }

    // Regression (cli-3): when every compression attempt failed, `trash
    // compress` printed "Nothing to compress." and exited 0, so a timer or
    // script never noticed that nothing could be compressed.
    #[test]
    fn compress_fails_when_every_attempt_failed() {
        const CHILD: &str = "TRASHD_COMPRESS_FAILURE_CHILD";
        if let Some(dir) = std::env::var_os(CHILD) {
            let store = trashed(Path::new(&dir), "data");
            block_state_directory(&store);
            run(&store, "0", false);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let output = crate::util::rerun_test(
            "commands::compress::tests::compress_fails_when_every_attempt_failed",
            CHILD,
            dir.path().as_os_str(),
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stdout}{stderr}");
        assert!(!stdout.contains("Nothing to compress."), "{stdout}");
        assert!(
            stderr.contains("1 item(s) could not be compressed"),
            "{stderr}"
        );
    }

    // Regression (recent-changes-6): --dry-run staged a full compressed copy
    // of each candidate in the trash's state directory (up to
    // max_file_size_mb, stranded if interrupted) only to learn its length.
    // The verdict needs no stage file and no writable trash.
    #[test]
    fn dry_run_estimates_without_staging_anything() {
        let dir = tempfile::tempdir().unwrap();
        let (store, entry) = fixture(dir.path(), "data");
        block_state_directory(&store);
        let sidecar = fs::read(&entry.info_path).unwrap();
        let reported = compress_before_publish(
            &store,
            &entry,
            8192,
            CommitMode::ReportOnly,
            || panic!("a dry run must stop before publishing"),
            || panic!("a dry run must not persist"),
        )
        .unwrap();
        // The same length, and so the same verdict, as the real run's stage.
        let real_dir = tempfile::tempdir().unwrap();
        let (real_store, real_entry) = fixture(real_dir.path(), "data");
        let actual =
            compress_file_zstd(&real_store, &real_entry, 8192, CommitMode::Publish).unwrap();
        assert_eq!(reported, actual);
        assert!(actual.is_some());
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), vec![b'x'; 8192]);
        assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
    }

    // #327: compression replaces the data inode, so it must skip hard-linked
    // data, extended attributes and entries other trash tools wrote.
    #[test]
    fn only_plain_trashd_entries_are_compressed() {
        use std::os::unix::ffi::OsStrExt;
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();
        let store =
            TrashStore::open_isolated(&dir.path().join("Trash"), trashd_common::Config::default())
                .unwrap();
        let add = |name: &str, trashd: bool| {
            let data = store.home_dir().join("files").join(name);
            fs::write(&data, vec![b'x'; 8192]).unwrap();
            let mut info = TrashInfo::new(dir.path().join(name));
            if trashd {
                info.pid = Some(1);
            }
            fs::write(
                store
                    .home_dir()
                    .join("info")
                    .join(format!("{name}.trashinfo")),
                info.to_trashinfo_string(),
            )
            .unwrap();
            data
        };
        let plain = add("plain", true);
        let linked = add("linked", true);
        fs::hard_link(&linked, dir.path().join("elsewhere")).unwrap();
        let foreign = add("foreign", false);
        let labelled = add("labelled", true);
        let name = std::ffi::CString::new(labelled.as_os_str().as_bytes()).unwrap();
        let xattrs = unsafe {
            libc::setxattr(
                name.as_ptr(),
                c"user.origin".as_ptr(),
                b"x".as_ptr().cast(),
                1,
                0,
            )
        } == 0;
        run(&store, "0", false);
        let compressed = |path: &Path| is_zstd(path);
        assert!(compressed(&plain));
        assert!(
            !compressed(&linked),
            "a hard link would keep the original data"
        );
        assert!(
            !compressed(&foreign),
            "another tool would restore zstd bytes"
        );
        if xattrs {
            assert!(!compressed(&labelled), "extended attributes would be lost");
        }
    }

    // #327: attempts are staged outside files/, and leftovers of killed runs
    // are swept once stale, never a concurrent run's or a real entry.
    #[test]
    fn interrupted_attempts_are_swept_and_never_left_in_files() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            TrashStore::open_isolated(&dir.path().join("Trash"), trashd_common::Config::default())
                .unwrap();
        let root = store.home_dir().to_path_buf();
        let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        // Every attempt carries an old mtime, as a live one does just before
        // it is published (#348); only the status-change time tells them apart.
        let leftover = |path: &Path| {
            fs::write(path, b"partial").unwrap();
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(hour_ago)
                .unwrap();
        };
        let old_in_files = root.join("files/.trashd-compress-old");
        let old_in_state = root.join(".trashd/.trashd-compress-old");
        let fresh = root.join(".trashd/.trashd-compress-fresh");
        let real = root.join("files/.trashd-compress-real");
        leftover(&old_in_files);
        leftover(&old_in_state);
        leftover(&real);
        // Filesystem timestamps come from a coarse clock.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let stale = std::time::SystemTime::now();
        std::thread::sleep(std::time::Duration::from_millis(50));
        leftover(&fresh);
        fs::write(
            root.join("info/.trashd-compress-real.trashinfo"),
            TrashInfo::new(dir.path().join("x")).to_trashinfo_string(),
        )
        .unwrap();
        let entry = store.find_entry(".trashd-compress-real").unwrap();
        sweep_attempts_changed_before(std::slice::from_ref(&entry), stale);
        assert!(!old_in_files.exists() && !old_in_state.exists());
        assert!(fresh.exists(), "a concurrent run's attempt stays");
        assert!(real.exists(), "an entry with a sidecar is not an attempt");
        sweep_interrupted_attempts(std::slice::from_ref(&entry));
        assert!(fresh.exists(), "an hour has not passed");
    }

    fn compress_fixture(dir: &Path, name: &str, mode: u32) {
        let (store, entry) = fixture(dir, name);
        let path = entry.trashed_path.clone();
        let info_path = entry.info_path.clone();
        let content = vec![b'x'; 8192];
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

        assert!(
            compress_file_zstd(&store, &entry, content.len() as u64, CommitMode::Publish)
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
        assert!(
            compress_file_zstd(&store, &entry, 8192, CommitMode::Publish)
                .unwrap()
                .is_some()
        );
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
                    let _ = compress_file_zstd(&store, &entry, 8192, CommitMode::Publish);
                });
            }
        });
        assert_eq!(
            zstd::decode_all(fs::File::open(path).unwrap()).unwrap(),
            content
        );
        assert_eq!(fs::read_dir(root.join("files")).unwrap().count(), 1);
    }

    // cli-8: an application that held an flock on a file when it was
    // deleted keeps it on the inode in files/. `trash compress`, even with
    // --dry-run, blocked in flock until that process exited. It gives up
    // after a bounded wait with a busy error and leaves the entry alone.
    #[test]
    fn compression_gives_up_on_an_entry_another_process_holds_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (store, entry) = fixture(dir.path(), "data");
        let holder = fs::File::open(&entry.trashed_path).unwrap();
        holder.lock().unwrap();
        let root = store.home_dir().to_path_buf();
        for mode in [CommitMode::ReportOnly, CommitMode::Publish] {
            let (sender, receiver) = std::sync::mpsc::channel();
            let (root, entry) = (root.clone(), entry.clone());
            std::thread::spawn(move || {
                let store =
                    TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
                let result = compress_file_zstd(&store, &entry, 8192, mode);
                let _ = sender.send(result.map_err(|error| error.kind()));
            });
            let result = receiver
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("compression blocked on another process's flock");
            assert_eq!(result, Err(std::io::ErrorKind::WouldBlock));
        }
        drop(holder);
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), vec![b'x'; 8192]);
        assert!(
            !fs::read_to_string(&entry.info_path)
                .unwrap()
                .contains("X-Trashd-Compressed")
        );
    }

    #[test]
    fn failed_marker_write_preserves_original_and_removes_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let (store, mut entry) = fixture(dir.path(), "data");
        let path = entry.trashed_path.clone();
        let content = vec![b'x'; 8192];
        entry.info_path = dir.path().join("missing/info");
        let result = compress_file_zstd(&store, &entry, 8192, CommitMode::Publish);
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
        assert!(compress_file_zstd(&store, &entry, 8192, CommitMode::Publish).is_err());
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
        assert!(compress_file_zstd(&store, &entry, 8192, CommitMode::Publish).is_err());
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), vec![b'y'; 8192]);
        assert_eq!(fs::read(&entry.info_path).unwrap(), replacement);
        let fresh = store.find_entry("data").unwrap();
        fs::write(&fresh.info_path, b"changed metadata").unwrap();
        assert!(compress_file_zstd(&store, &fresh, 8192, CommitMode::Publish).is_err());
        assert_eq!(fs::read(&fresh.info_path).unwrap(), b"changed metadata");
    }

    // Regression (cli-4): compress kept "anything it accepts is restorable"
    // against max_file_size_mb as configured that day, and restore bounded
    // decompression by the one configured later. Lowering the limit left
    // compressed entries unrestorable. Both go by the entry's recorded size.
    #[test]
    fn compressed_entries_restore_under_a_lowered_file_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let open = |max_file_size_mb| {
            let mut config = trashd_common::Config::default();
            config.never_trash.clear();
            config.max_file_size_mb = max_file_size_mb;
            TrashStore::open_isolated(&dir.path().join("Trash"), config).unwrap()
        };
        let store = open(1024);
        let original = b"compressible ".repeat(200_000);
        let file = dir.path().join("app.log");
        fs::write(&file, &original).unwrap();
        let id = store.trash(&file, None).unwrap();
        run(&store, "0", false);
        assert!(is_zstd(&store.find_entry(&id).unwrap().trashed_path));
        let store = open(1);
        let restored = store.restore(&id, None).unwrap();
        assert_eq!(fs::read(restored).unwrap(), original);
    }

    // cli-4: data larger than the entry's recorded size allows (and than
    // the floor of restore's bound) is not compressed, whatever the file
    // size limit is today: a lower one tomorrow would strand it.
    #[test]
    fn compress_skips_data_restore_could_refuse_later() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            TrashStore::open_isolated(&dir.path().join("Trash"), trashd_common::Config::default())
                .unwrap();
        let data = store.home_dir().join("files/grown");
        // Sparse: only its length matters.
        fs::File::create(&data)
            .unwrap()
            .set_len(trashd_common::store::decompress_limit(Some(1024)) + 1)
            .unwrap();
        let mut info = TrashInfo::new(dir.path().join("grown"));
        info.size = Some(1024);
        fs::write(
            store.home_dir().join("info/grown.trashinfo"),
            info.to_trashinfo_string(),
        )
        .unwrap();
        run(&store, "0", false);
        assert!(!is_zstd(&data), "restore refuses what it decompresses to");
    }
}
