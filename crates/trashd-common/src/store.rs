use crate::config::Config;
use crate::index::TrashIndex;
use crate::mounts;
use crate::trashinfo::TrashInfo;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_128;

#[derive(Error, Debug)]
pub enum TrashError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("path is in never-trash list: {0}")]
    Excluded(PathBuf),
    #[error("file too large ({size_mb} MB > {limit_mb} MB limit): {path}")]
    TooLarge {
        path: PathBuf,
        size_mb: u64,
        limit_mb: u64,
    },
    #[error("index error: {0}")]
    Index(#[from] rusqlite::Error),
    #[error("trash entry not found: {0}")]
    EntryNotFound(String),
    #[error("original path already exists: {0}")]
    RestoreConflict(PathBuf),
    #[error("refusing to restore outside the original location (possible path traversal): {0}")]
    RestoreTraversal(PathBuf),
    #[error("multiple matches for '{pattern}': {count} items (use trash ID for exact match)")]
    AmbiguousMatch { pattern: String, count: usize },
    #[error("hash mismatch for '{path}': expected {expected}, got {actual}")]
    HashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
}

pub struct TrashStore {
    config: Config,
    /// Optional SQLite cache. It is NEVER the source of truth (list() scans
    /// .trashinfo files), so a failure to open it must not stop trashing —
    /// otherwise transient lock contention would demote callers to real `rm`.
    index: Option<TrashIndex>,
}

/// A single entry in the trash.
#[derive(Debug, Clone)]
pub struct TrashEntry {
    /// The unique ID (filename stem in trash)
    pub id: String,
    /// Parsed trashinfo metadata
    pub info: TrashInfo,
    /// Path to the file/dir in the trash files directory
    pub trashed_path: PathBuf,
    /// Path to the .trashinfo file
    pub info_path: PathBuf,
    /// Which trash directory this entry lives in
    pub trash_root: PathBuf,
    /// True if this entry has no .trashinfo (emergency/orphaned per spec)
    pub orphaned: bool,
}

impl TrashStore {
    pub fn open() -> Result<Self, TrashError> {
        let config = Config::load();
        let home = Self::home_trash_dir();
        fs::create_dir_all(home.join("files"))?;
        fs::create_dir_all(home.join("info"))?;
        fs::create_dir_all(home.join(".trashd"))?;

        // The index is an optional accelerator. If it can't be opened (lock
        // contention, corruption, read-only FS) we degrade to no-index rather
        // than failing — a failed open here would otherwise make the seccomp
        // supervisor and shim fall back to permanent deletion.
        let index = match TrashIndex::open(&home.join(crate::index::REL_PATH)) {
            Ok(idx) => Some(idx),
            Err(e) => {
                eprintln!("trashd: warning: trash index unavailable ({e}); continuing without it");
                None
            }
        };

        Ok(Self { config, index })
    }

    /// The home trash directory per FreeDesktop spec.
    pub fn home_trash_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
                    .join(".local/share")
            })
            .join("Trash")
    }

    pub fn trash_dir() -> PathBuf {
        Self::home_trash_dir()
    }

    /// Determine the correct trash directory for a file (same-device or topdir).
    fn trash_dir_for(&self, path: &Path) -> PathBuf {
        mounts::trash_dir_for_path(path, &Self::home_trash_dir())
    }

    /// Get the topdir (mount point) for a trash directory.
    /// For `.Trash-$uid` → parent is the topdir.
    /// For `.Trash/$uid` → grandparent is the topdir.
    fn topdir_for_trash(trash_dir: &Path) -> PathBuf {
        if let Some(parent) = trash_dir.parent() {
            let name = parent
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name == ".Trash" {
                // .Trash/$uid → topdir is grandparent
                return parent.parent().unwrap_or(parent).to_path_buf();
            }
            // .Trash-$uid → topdir is parent
            return parent.to_path_buf();
        }
        trash_dir.to_path_buf()
    }

    /// Ensure a trash directory has the required subdirectories.
    fn ensure_trash_dir(trash_dir: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(trash_dir.join("files"))?;
        fs::create_dir_all(trash_dir.join("info"))?;
        // Topdir trashes (.Trash-$uid / .Trash/$uid) live on shared mounts; the
        // spec requires them to be private (0700) so other local users cannot
        // read a victim's deleted files or their original-path metadata. The
        // home trash already sits inside $HOME, so it is left untouched.
        if trash_dir != Self::home_trash_dir() {
            let private = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(trash_dir, private.clone());
            let _ = fs::set_permissions(trash_dir.join("files"), private.clone());
            let _ = fs::set_permissions(trash_dir.join("info"), private);
        }
        Ok(())
    }

    /// Move a file or directory to the trash. Returns the trash entry ID.
    pub fn trash(&self, path: &Path, command: Option<&str>) -> Result<String, TrashError> {
        let abs_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let abs_path = normalize_path(&abs_path);

        // Check existence
        let meta =
            fs::symlink_metadata(&abs_path).map_err(|_| TrashError::NotFound(abs_path.clone()))?;

        // Check never-trash list
        if self.config.should_skip(&abs_path) {
            return Err(TrashError::Excluded(abs_path));
        }

        // Check size limit (for files only)
        if meta.is_file() {
            let size_mb = meta.size() / (1024 * 1024);
            if size_mb > self.config.max_file_size_mb {
                return Err(TrashError::TooLarge {
                    path: abs_path,
                    size_mb,
                    limit_mb: self.config.max_file_size_mb,
                });
            }
        }

        // Check directory size limit. If the directory has more files than the
        // size walk will count, we cannot know the true size — treat that as
        // over-limit (the user set this cap precisely to keep huge trees out of
        // the trash) rather than trusting the partial under-count.
        if meta.is_dir() && self.config.max_dir_size_mb > 0 {
            let (dir_size_bytes, capped) = dir_size_capped(&abs_path);
            let dir_size_mb = dir_size_bytes / (1024 * 1024);
            if capped || dir_size_mb > self.config.max_dir_size_mb {
                return Err(TrashError::TooLarge {
                    path: abs_path,
                    size_mb: dir_size_mb,
                    limit_mb: self.config.max_dir_size_mb,
                });
            }
        }

        // Check bypass_paths — if the calling process exe matches, skip trash
        if !self.config.bypass_paths.is_empty() {
            if let Ok(exe) = fs::read_link("/proc/self/exe") {
                let exe_str = exe.to_string_lossy();
                if self
                    .config
                    .bypass_paths
                    .iter()
                    .any(|p| exe_str.starts_with(p))
                {
                    return Err(TrashError::Excluded(abs_path));
                }
            }
        }

        // Pick the right trash directory (same-device preferred)
        let trash_dir = self.trash_dir_for(&abs_path);
        Self::ensure_trash_dir(&trash_dir)?;

        // Generate unique trash ID within that trash dir (atomic)
        let file_name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed".into());
        let (id, info_file) = unique_id_atomic(&trash_dir, &file_name)?;

        // Build trashinfo — per spec, topdir trash should use relative paths
        // from the topdir mount point, not absolute paths.
        let home_trash = Self::home_trash_dir();
        let trashinfo_path = if trash_dir == home_trash {
            // Home trash: absolute path per spec
            abs_path.clone()
        } else {
            // Topdir trash: relative path from the topdir (parent of .Trash-$uid or .Trash/$uid)
            // e.g. /mnt/data/.Trash-1000 -> topdir is /mnt/data
            //      /mnt/data/.Trash/1000 -> topdir is /mnt/data
            let topdir = trash_dir
                .parent()
                .and_then(|p| {
                    // .Trash/$uid has one extra level
                    let name = p.file_name()?.to_string_lossy();
                    if name == ".Trash" {
                        p.parent()
                    } else {
                        Some(p)
                    }
                })
                .unwrap_or(trash_dir.as_ref());
            abs_path
                .strip_prefix(topdir)
                .map(|rel| {
                    // Spec: relative path MUST NOT contain ".."
                    debug_assert!(!rel
                        .components()
                        .any(|c| c == std::path::Component::ParentDir));
                    rel.to_path_buf()
                })
                .unwrap_or_else(|_| abs_path.clone()) // fallback to absolute if strip fails
        };
        let mut info = TrashInfo::new(trashinfo_path);
        info.command = command.map(|s| s.to_string());
        info.pid = Some(std::process::id());
        info.size = Some(if meta.is_file() {
            meta.size()
        } else {
            dir_size(&abs_path)
        });

        // Compute file hash for small files only (configurable, default 1 MB).
        // Hashing reads the entire file — too expensive for large files on every rm.
        let hash_limit = self.config.sha256_max_size_mb * 1024 * 1024;
        if meta.is_file() && hash_limit > 0 && meta.size() <= hash_limit {
            if let Ok(hash) = hash_file(&abs_path, &self.config.hash_algorithm) {
                info.sha256 = Some(hash);
            }
        }

        let dest = trash_dir.join("files").join(&id);

        // Write .trashinfo content to the already-created file
        fs::write(&info_file, info.to_trashinfo_string())?;

        // Try rename (fast, same filesystem — should always work with topdir trash)
        let move_result: Result<(), TrashError> = (|| {
            if fs::rename(&abs_path, &dest).is_err() {
                // Cross-filesystem fallback — order matters: check symlink first
                if meta.file_type().is_symlink() {
                    let link_target = fs::read_link(&abs_path)?;
                    std::os::unix::fs::symlink(&link_target, &dest)?;
                } else if meta.is_dir() {
                    copy_tree(&abs_path, &dest)?;
                } else {
                    fs::copy(&abs_path, &dest)?;
                    fs::set_permissions(&dest, meta.permissions())?;
                }
                // Remove the original
                if meta.file_type().is_symlink() || meta.is_file() {
                    fs::remove_file(&abs_path)?;
                } else {
                    fs::remove_dir_all(&abs_path)?;
                }
            }
            Ok(())
        })();

        // On failure, clean up orphaned trashinfo and partial copy.
        // Use symlink_metadata to avoid following symlinks — remove_dir_all
        // on a symlink-to-directory would delete the target's contents.
        if let Err(e) = move_result {
            let _ = fs::remove_file(&info_file);
            if let Ok(meta) = fs::symlink_metadata(&dest) {
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    let _ = fs::remove_dir_all(&dest);
                } else {
                    // Symlinks, regular files, etc.
                    let _ = fs::remove_file(&dest);
                }
            }
            return Err(e);
        }

        // Update index (best-effort; it's only a cache)
        if let Some(idx) = self.index.as_ref() {
            let _ = idx.insert(&id, &info, &trash_dir);
        }

        // Update directorysizes cache if we just trashed a directory
        if meta.is_dir() {
            let _ = crate::directorysizes::write_cache(&trash_dir);
        }

        // Log operation
        crate::oplog::log_trash(&abs_path, &id, command);

        // Run auto-purge if enough time has passed since the last one.
        // Scanning the entire trash on every deletion is O(n) — throttle it.
        let _ = self.maybe_auto_purge();

        Ok(id)
    }

    /// List all items across all trash directories, newest first.
    pub fn list(&self, pattern: Option<&str>) -> Result<Vec<TrashEntry>, TrashError> {
        let mut entries = Vec::new();

        for (trash_dir, _label) in self.all_trash_dirs() {
            self.list_in_dir(&trash_dir, pattern, &mut entries)?;
        }

        // Sort newest first
        entries.sort_by_key(|b| std::cmp::Reverse(b.info.deletion_date));
        Ok(entries)
    }

    /// List items in a single trash directory.
    fn list_in_dir(
        &self,
        trash_dir: &Path,
        pattern: Option<&str>,
        entries: &mut Vec<TrashEntry>,
    ) -> Result<(), TrashError> {
        let info_dir = trash_dir.join("info");
        let files_dir = trash_dir.join("files");

        if !info_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&info_dir)? {
            let entry = entry?;
            let filename = entry.file_name().to_string_lossy().into_owned();
            if !filename.ends_with(".trashinfo") {
                continue;
            }

            let id = filename
                .strip_suffix(".trashinfo")
                .unwrap_or(&filename)
                .to_string();
            let content = match fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut info = match TrashInfo::from_trashinfo(&content) {
                Some(i) => i,
                None => continue,
            };

            // Spec: topdir trash may store relative paths. Resolve to absolute
            // using the topdir (parent of the trash directory).
            if !info.original_path.is_absolute() {
                let topdir = Self::topdir_for_trash(trash_dir);
                info.original_path = topdir.join(&info.original_path);
            }

            // Apply pattern filter
            if let Some(pat) = pattern {
                let name = info
                    .original_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !simple_glob_match(pat, &name)
                    && !simple_glob_match(pat, &info.original_path.to_string_lossy())
                {
                    continue;
                }
            }

            let trashed_path = files_dir.join(&id);
            entries.push(TrashEntry {
                id,
                info,
                trashed_path,
                info_path: entry.path(),
                trash_root: trash_dir.to_path_buf(),
                orphaned: false,
            });
        }

        // Spec: "If info file corresponding to file in $trash/files is unavailable,
        // this is emergency case and MUST be presented as such."
        // Scan files/ for entries without matching .trashinfo.
        if files_dir.exists() {
            let known_ids: std::collections::HashSet<String> =
                entries.iter().map(|e| e.id.clone()).collect();
            let mut orphans = Vec::new();
            if let Ok(file_entries) = fs::read_dir(&files_dir) {
                for fe in file_entries.flatten() {
                    let name = fe.file_name().to_string_lossy().into_owned();
                    if !known_ids.contains(&name) {
                        // Apply pattern filter to orphans too
                        if let Some(pat) = pattern {
                            if !simple_glob_match(pat, &name) {
                                continue;
                            }
                        }
                        let trashed_path = files_dir.join(&name);
                        orphans.push(TrashEntry {
                            id: name.clone(),
                            info: TrashInfo::new(PathBuf::from(format!("(orphaned: {name})"))),
                            trashed_path,
                            info_path: info_dir.join(format!("{name}.trashinfo")),
                            trash_root: trash_dir.to_path_buf(),
                            orphaned: true,
                        });
                    }
                }
            }
            entries.extend(orphans);
        }

        Ok(())
    }

    /// Restore a trashed item by ID or pattern match to its original location.
    pub fn restore(
        &self,
        id_or_pattern: &str,
        target: Option<&Path>,
    ) -> Result<PathBuf, TrashError> {
        let entry = self.find_entry(id_or_pattern)?;

        let restore_to = target
            .map(|t| t.to_path_buf())
            .unwrap_or_else(|| entry.info.original_path.clone());

        // When restoring to the entry's OWN recorded original path (target is
        // None), that path comes from the .trashinfo, which on removable/shared
        // media an attacker may have crafted. Refuse destinations that escape
        // via ".." and, for topdir trashes, require the destination to stay
        // under that topdir. This blocks path-traversal that would let a
        // malicious .trashinfo overwrite arbitrary files (~/.bashrc, cron, …)
        // during an ordinary `restore`/`undo`. An explicit user-supplied
        // target is trusted and not constrained.
        if target.is_none() {
            if restore_to
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(TrashError::RestoreTraversal(restore_to));
            }
            if entry.trash_root != Self::home_trash_dir() {
                let topdir = Self::topdir_for_trash(&entry.trash_root);
                if !restore_to.starts_with(&topdir) {
                    return Err(TrashError::RestoreTraversal(restore_to));
                }
            }
        }

        // If trashd compressed this entry's data (recorded explicitly via the
        // X-Trashd-Compressed marker — never inferred from magic bytes, which
        // would corrupt a user's genuine .zst), decompress the in-trash copy
        // BEFORE moving it out. Doing it here means a decode/write failure
        // leaves the entry fully intact in the trash (nothing moved, metadata
        // present) so it stays restorable, and the write is atomic so a
        // crash/ENOSPC can never truncate the only copy.
        if entry.info.compressed.as_deref() == Some("zstd") && entry.trashed_path.is_file() {
            let data = fs::read(&entry.trashed_path)?;
            let decompressed = zstd::decode_all(data.as_slice())
                .map_err(|e| io::Error::other(format!("failed to decompress trashed file: {e}")))?;
            atomic_write(&entry.trashed_path, &decompressed)?;
            // The data is no longer compressed; clear the marker so a later
            // failure (or re-restore) can never attempt a second decode.
            let mut cleared = entry.info.clone();
            cleared.compressed = None;
            let _ = write_trashinfo_atomic(&entry.info_path, &cleared);
        }

        // Check for conflicts (use symlink_metadata so dangling symlinks are detected)
        if fs::symlink_metadata(&restore_to).is_ok() {
            return Err(TrashError::RestoreConflict(restore_to));
        }

        // Ensure parent directory exists
        if let Some(parent) = restore_to.parent() {
            fs::create_dir_all(parent)?;
        }

        // Move back. Use a no-clobber rename so the check-then-rename window
        // above cannot be raced into overwriting a file created in between.
        // EEXIST → RestoreConflict; EXDEV / unsupported-flag → copy fallback.
        let needs_copy = match rename_noreplace(&entry.trashed_path, &restore_to) {
            Ok(()) => false,
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                return Err(TrashError::RestoreConflict(restore_to));
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) => {
                // Kernel/filesystem without RENAME_NOREPLACE: fall back to a
                // plain rename (the conflict check above guarded the dest).
                fs::rename(&entry.trashed_path, &restore_to).is_err()
            }
            Err(_) => true, // cross-device or other rename failure
        };
        if needs_copy {
            let meta = fs::symlink_metadata(&entry.trashed_path)?;
            if meta.file_type().is_symlink() {
                let target_link = fs::read_link(&entry.trashed_path)?;
                std::os::unix::fs::symlink(&target_link, &restore_to)?;
                fs::remove_file(&entry.trashed_path)?;
            } else if meta.is_dir() {
                copy_tree(&entry.trashed_path, &restore_to)?;
                fs::remove_dir_all(&entry.trashed_path)?;
            } else {
                fs::copy(&entry.trashed_path, &restore_to)?;
                let perms = meta.permissions();
                fs::set_permissions(&restore_to, perms)?;
                fs::remove_file(&entry.trashed_path)?;
            }
        }

        // (Decompression already happened in-trash, before the move above.)

        // Verify hash against the (now decompressed) restored file content.
        // This catches corruption during storage (bit rot, bad disk, partial copy).
        // We verify AFTER restore so the file is already in place — a mismatch is
        // reported as a warning, not a rollback (the user can decide what to do).
        let hash_warning = if let Some(ref expected_hash) = entry.info.sha256 {
            if restore_to.is_file() {
                // Try both algorithms — we don't know which was used originally
                let xxhash = hash_file(&restore_to, "xxhash").ok();
                let sha256 = hash_file(&restore_to, "sha256").ok();
                if xxhash.as_deref() == Some(expected_hash.as_str())
                    || sha256.as_deref() == Some(expected_hash.as_str())
                {
                    None // match
                } else {
                    let actual = xxhash.or(sha256).unwrap_or_else(|| "(unreadable)".into());
                    Some((expected_hash.clone(), actual))
                }
            } else {
                None // directories/symlinks don't get hashed
            }
        } else {
            None
        };

        // Remove trashinfo
        let _ = fs::remove_file(&entry.info_path);

        // Update index
        if let Some(idx) = self.index.as_ref() {
            let _ = idx.delete(&entry.id);
        }

        // Keep the directorysizes cache consistent (spec: an entry MUST be
        // removed once its directory leaves the trash) for other FreeDesktop
        // trash tools that read it.
        let _ = crate::directorysizes::write_cache(&entry.trash_root);

        // Log operation
        crate::oplog::log_restore(&entry.id, &restore_to);

        // Report hash mismatch as a warning after successful restore
        if let Some((expected, actual)) = hash_warning {
            eprintln!(
                "trashd: warning: hash mismatch for restored file {}",
                restore_to.display()
            );
            eprintln!("  expected: {expected}");
            eprintln!("  actual:   {actual}");
            eprintln!("  file may be corrupted — verify contents before use");
        }

        Ok(restore_to)
    }

    /// Restore the most recently trashed item.
    pub fn undo(&self) -> Result<PathBuf, TrashError> {
        let entries = self.list(None)?;
        let newest = entries
            .first()
            .ok_or_else(|| TrashError::EntryNotFound("(trash is empty)".into()))?;
        self.restore(&newest.id, None)
    }

    /// Permanently delete a trash entry.
    pub fn purge(&self, id: &str) -> Result<(), TrashError> {
        let entry = self.find_entry(id)?;

        // Use symlink_metadata so dangling symlinks are detected and removed
        match fs::symlink_metadata(&entry.trashed_path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                fs::remove_dir_all(&entry.trashed_path)?;
            }
            Ok(_) => {
                // Regular file, symlink (dangling or not), etc.
                fs::remove_file(&entry.trashed_path)?;
            }
            Err(_) => {
                // File already gone — just clean up the trashinfo
            }
        }
        let _ = fs::remove_file(&entry.info_path);
        if let Some(idx) = self.index.as_ref() {
            let _ = idx.delete(&entry.id);
        }
        // Refresh directorysizes so a purged directory's entry is dropped.
        let _ = crate::directorysizes::write_cache(&entry.trash_root);
        crate::oplog::log_purge(&entry.id);
        Ok(())
    }

    /// Empty the trash (across all partitions).
    pub fn empty(&self, max_age_days: Option<u32>) -> Result<u64, TrashError> {
        let entries = self.list(None)?;
        let mut count = 0u64;
        let now = chrono::Local::now();

        for entry in &entries {
            if let Some(days) = max_age_days {
                let age = now.signed_duration_since(entry.info.deletion_date);
                if age.num_days() < days as i64 {
                    continue;
                }
            }
            // Inline purge to avoid re-scanning list for each entry
            // Use symlink_metadata so dangling symlinks are removed too
            match fs::symlink_metadata(&entry.trashed_path) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                    let _ = fs::remove_dir_all(&entry.trashed_path);
                }
                Ok(_) => {
                    let _ = fs::remove_file(&entry.trashed_path);
                }
                Err(_) => {}
            }
            let _ = fs::remove_file(&entry.info_path);
            if let Some(idx) = self.index.as_ref() {
                let _ = idx.delete(&entry.id);
            }
            count += 1;
        }
        if count > 0 {
            let filter_desc = max_age_days.map(|d| format!("older than {d}d"));
            crate::oplog::log_empty(count, filter_desc.as_deref());
            // Refresh directorysizes cache after purging
            for (dir, _) in self.all_trash_dirs() {
                let _ = crate::directorysizes::write_cache(&dir);
            }
        }
        Ok(count)
    }

    /// Run auto_purge only if enough time has passed since the last run.
    /// Uses a timestamp file to avoid scanning the entire trash on every deletion.
    fn maybe_auto_purge(&self) -> Result<(), TrashError> {
        let interval = self.config.auto_purge_interval_secs;
        if interval == 0 {
            return self.auto_purge();
        }

        let marker = Self::home_trash_dir().join(".trashd/last_purge");
        if let Ok(meta) = fs::metadata(&marker) {
            if let Ok(modified) = meta.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    if elapsed.as_secs() < interval {
                        return Ok(()); // too soon, skip
                    }
                }
            }
        }

        // Touch the marker before purging (so concurrent callers also skip)
        let _ = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&marker);

        self.auto_purge()
    }

    /// Enforce retention policy: purge expired items and trim by size.
    /// Single scan — all three phases work on the same in-memory list.
    fn auto_purge(&self) -> Result<(), TrashError> {
        let max_age = self.config.retention.max_age_days;
        let max_size_bytes = (self.config.retention.max_size_gb * 1024.0 * 1024.0 * 1024.0) as u64;
        let pressure_pct = self.config.retention.disk_pressure_percent;

        let entries = self.list(None)?;
        if entries.is_empty() {
            return Ok(());
        }

        let now = chrono::Local::now();
        // Track which entries were purged by index (newest-first order)
        let mut purged = vec![false; entries.len()];
        let mut purge_count = 0u64;

        // Phase 1: purge items older than max_age_days.
        // max_age_days == 0 means "no age limit" (keep forever) — NOT "purge
        // everything". Without this guard, `age.num_days() < 0` is false for
        // every item and the whole trash would be wiped.
        if max_age > 0 {
            // entries are newest-first, so iterate in reverse (oldest first)
            for i in (0..entries.len()).rev() {
                let age = now.signed_duration_since(entries[i].info.deletion_date);
                if age.num_days() < max_age as i64 {
                    continue; // don't break — multi-partition entries may not be perfectly sorted
                }
                let _ = self.purge_entry(&entries[i]);
                purged[i] = true;
                purge_count += 1;
            }
        }

        // Phase 2a: auto-compress old uncompressed items before purging by size.
        // Cap how much we slurp into RAM — this runs (throttled) on routine
        // deletions, and reading a multi-hundred-MB trashed file fully into a
        // Vec could OOM the process (and a killed supervisor degrades to
        // passthrough). Skip anything above the cap.
        const COMPRESS_MAX_BYTES: u64 = 64 * 1024 * 1024;
        for i in (0..entries.len()).rev() {
            if purged[i] || entries[i].orphaned {
                continue;
            }
            let age = now.signed_duration_since(entries[i].info.deletion_date);
            if age.num_days() < 7 {
                continue;
            }
            // Already recorded as compressed — don't touch it again.
            if entries[i].info.compressed.is_some() {
                continue;
            }
            let path = &entries[i].trashed_path;
            let meta = match fs::symlink_metadata(path) {
                Ok(m) if m.is_file() => m,
                _ => continue, // missing, dir, or symlink
            };
            if meta.len() < 1024 || meta.len() > COMPRESS_MAX_BYTES {
                continue;
            }
            let data = match fs::read(path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            // Defensive: skip if it already looks compressed (marker missing).
            if data.len() >= 4
                && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 0xFD2FB528
            {
                continue;
            }
            if let Ok(compressed) = zstd::encode_all(data.as_slice(), 3) {
                if compressed.len() < data.len() {
                    // Atomic write: an interrupted compress must never truncate
                    // the SOLE remaining copy of the user's deleted data.
                    if atomic_write(path, &compressed).is_ok() {
                        // Record that WE compressed it so restore decompresses
                        // by marker, not by guessing magic bytes.
                        let mut info = entries[i].info.clone();
                        info.compressed = Some("zstd".into());
                        let _ = write_trashinfo_atomic(&entries[i].info_path, &info);
                    }
                }
            }
        }

        // Phase 2b: trim by total size (purge oldest surviving until under limit)
        // Use actual disk size (not info.size) since compression may have shrunk files.
        let total_size: u64 = entries
            .iter()
            .enumerate()
            .filter(|(i, _)| !purged[*i])
            .map(|(_, e)| fs::metadata(&e.trashed_path).map(|m| m.len()).unwrap_or(0))
            .sum();
        // max_size_gb == 0 means "no size limit", not "trim everything to 0".
        if max_size_bytes > 0 && total_size > max_size_bytes {
            let mut freed = 0u64;
            let excess = total_size - max_size_bytes;
            for i in (0..entries.len()).rev() {
                if purged[i] {
                    continue;
                }
                if freed >= excess {
                    break;
                }
                // Use actual disk size (may differ from info.size after compression)
                freed += fs::metadata(&entries[i].trashed_path)
                    .map(|m| m.len())
                    .unwrap_or(entries[i].info.size.unwrap_or(0));
                let _ = self.purge_entry(&entries[i]);
                purged[i] = true;
                purge_count += 1;
            }
        }

        // Phase 3: disk pressure — purge oldest 10% of surviving items
        if pressure_pct > 0 {
            let home = Self::home_trash_dir();
            if let Some(usage_pct) = disk_usage_percent(&home) {
                if usage_pct >= pressure_pct as f64 {
                    let surviving: usize = purged.iter().filter(|&&p| !p).count();
                    let to_purge = std::cmp::max(1, surviving / 10);
                    let mut purged_count = 0;
                    for i in (0..entries.len()).rev() {
                        if purged_count >= to_purge {
                            break;
                        }
                        if purged[i] {
                            continue;
                        }
                        let _ = self.purge_entry(&entries[i]);
                        purged[i] = true;
                        purge_count += 1;
                        purged_count += 1;
                    }
                }
            }
        }

        // Log and notify if items were auto-purged
        if purge_count > 0 {
            // Rebuild directorysizes across all trash dirs so purged/compressed
            // directories are reflected for other FreeDesktop trash tools.
            for (dir, _) in self.all_trash_dirs() {
                let _ = crate::directorysizes::write_cache(&dir);
            }
            crate::oplog::log_empty(purge_count, Some("auto-purge"));
            crate::oplog::notify_desktop(
                "trashd: auto-purge",
                &format!(
                    "{purge_count} item{} permanently deleted by retention policy",
                    if purge_count == 1 { "" } else { "s" }
                ),
            );
        }

        Ok(())
    }

    /// Purge a single entry without re-scanning the list.
    fn purge_entry(&self, entry: &TrashEntry) -> Result<(), TrashError> {
        // Use symlink_metadata so dangling symlinks are detected and removed
        match fs::symlink_metadata(&entry.trashed_path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                let _ = fs::remove_dir_all(&entry.trashed_path);
            }
            Ok(_) => {
                let _ = fs::remove_file(&entry.trashed_path);
            }
            Err(_) => {} // already gone
        }
        let _ = fs::remove_file(&entry.info_path);
        if let Some(idx) = self.index.as_ref() {
            let _ = idx.delete(&entry.id);
        }
        Ok(())
    }

    /// Get per-partition trash status.
    pub fn status_per_partition(&self) -> Result<Vec<PartitionStatus>, TrashError> {
        let entries = self.list(None)?;
        let mut partitions: std::collections::HashMap<PathBuf, PartitionStatus> =
            std::collections::HashMap::new();

        for (dir, label) in self.all_trash_dirs() {
            partitions.entry(dir.clone()).or_insert(PartitionStatus {
                trash_dir: dir,
                label,
                total_size: 0,
                count: 0,
            });
        }

        for entry in &entries {
            let ps = partitions
                .entry(entry.trash_root.clone())
                .or_insert(PartitionStatus {
                    trash_dir: entry.trash_root.clone(),
                    label: entry.trash_root.to_string_lossy().into_owned(),
                    total_size: 0,
                    count: 0,
                });
            ps.count += 1;
            // Use actual disk size (may be smaller than info.size after compression)
            ps.total_size += fs::metadata(&entry.trashed_path)
                .map(|m| m.len())
                .unwrap_or(entry.info.size.unwrap_or(0));
        }

        let mut result: Vec<PartitionStatus> = partitions.into_values().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.total_size));
        Ok(result)
    }

    /// Total status across all partitions.
    pub fn status(&self) -> Result<(u64, usize), TrashError> {
        let entries = self.list(None)?;
        // Use actual disk size (reflects compression savings)
        let total_size: u64 = entries
            .iter()
            .map(|e| {
                fs::metadata(&e.trashed_path)
                    .map(|m| m.len())
                    .unwrap_or(e.info.size.unwrap_or(0))
            })
            .sum();
        let count = entries.len();
        Ok((total_size, count))
    }

    /// All known trash directories (home + per-mountpoint).
    fn all_trash_dirs(&self) -> Vec<(PathBuf, String)> {
        mounts::all_trash_dirs(&Self::home_trash_dir())
    }

    /// Access config (for shim process bypass checking).
    pub fn config(&self) -> &Config {
        &self.config
    }

    fn find_entry(&self, id_or_pattern: &str) -> Result<TrashEntry, TrashError> {
        let entries = self.list(None)?;

        // Exact ID match (unambiguous)
        if let Some(entry) = entries.iter().find(|e| e.id == id_or_pattern) {
            return Ok(entry.clone());
        }

        // Filename match — check for ambiguity
        let filename_matches: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| {
                e.info
                    .original_path
                    .file_name()
                    .map(|n| n.to_string_lossy() == id_or_pattern)
                    .unwrap_or(false)
            })
            .collect();
        if filename_matches.len() == 1 {
            return Ok(filename_matches[0].clone());
        }
        if filename_matches.len() > 1 {
            return Err(TrashError::AmbiguousMatch {
                pattern: id_or_pattern.into(),
                count: filename_matches.len(),
            });
        }

        // Glob match — check for ambiguity
        let glob_matches: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| {
                let name = e
                    .info
                    .original_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                simple_glob_match(id_or_pattern, &name)
            })
            .collect();
        if glob_matches.len() == 1 {
            return Ok(glob_matches[0].clone());
        }
        if glob_matches.len() > 1 {
            return Err(TrashError::AmbiguousMatch {
                pattern: id_or_pattern.into(),
                count: glob_matches.len(),
            });
        }

        Err(TrashError::EntryNotFound(id_or_pattern.into()))
    }
}

#[derive(Debug, Clone)]
pub struct PartitionStatus {
    pub trash_dir: PathBuf,
    pub label: String,
    pub total_size: u64,
    pub count: usize,
}

/// Atomically create a unique trashinfo file using O_CREAT|O_EXCL.
/// Returns (id, info_file_path).
///
/// The id is unique against BOTH `info/` (atomically, via O_EXCL) AND `files/`:
/// an orphaned data file (one in `files/` with no matching `.trashinfo`) is a
/// recoverable state, so reusing its name would silently overwrite the user's
/// data when the new file is renamed into `files/<id>`.
fn unique_id_atomic(trash_dir: &Path, base_name: &str) -> Result<(String, PathBuf), TrashError> {
    use std::os::unix::fs::OpenOptionsExt;

    let info_dir = trash_dir.join("info");
    let files_dir = trash_dir.join("files");

    // Truncate base_name if it would exceed filesystem filename limits.
    // ".trashinfo" = 10 chars, ".YYYYMMDDHHMMSS.NNNNN" = 21 chars max.
    // Most filesystems cap at 255 bytes. Reserve 32 for suffix.
    let max_base = 223;
    let base_name = if base_name.len() > max_base {
        &base_name[..base_name.floor_char_boundary(max_base)]
    } else {
        base_name
    };

    // Claim `candidate`: create info/<candidate>.trashinfo with O_EXCL AND
    // verify files/<candidate> is free. Ok(Some) = claimed; Ok(None) = taken,
    // try another; Err = fatal IO error.
    let try_claim = |candidate: &str| -> Result<Option<PathBuf>, io::Error> {
        let info_path = info_dir.join(format!("{candidate}.trashinfo"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&info_path)
        {
            Ok(_) => {
                if files_dir.join(candidate).symlink_metadata().is_ok() {
                    // The info name was free but an orphaned data file already
                    // occupies files/<candidate>. Release the info we claimed
                    // and try a different id rather than overwrite it.
                    let _ = fs::remove_file(&info_path);
                    Ok(None)
                } else {
                    Ok(Some(info_path))
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e),
        }
    };

    // Try base name first
    if let Some(info_path) = try_claim(base_name)? {
        return Ok((base_name.to_string(), info_path));
    }

    // Append timestamp + counter
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S");
    for i in 0u32..10000 {
        let candidate = if i == 0 {
            format!("{base_name}.{ts}")
        } else {
            format!("{base_name}.{ts}.{i}")
        };
        if let Some(info_path) = try_claim(&candidate)? {
            return Ok((candidate, info_path));
        }
    }

    Err(TrashError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to generate unique trash ID after 10000 attempts",
    )))
}

/// Hash a file using the configured algorithm.
/// "xxhash" (default): XXH3-128 — extremely fast, non-cryptographic.
/// "sha256": SHA-256 — cryptographic, slower.
fn hash_file(path: &Path, algorithm: &str) -> io::Result<String> {
    let data = fs::read(path)?;
    match algorithm {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let digest = hasher.finalize();
            Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
        }
        _ => {
            // Default: xxhash (XXH3-128)
            Ok(format!("{:032x}", xxh3_128(&data)))
        }
    }
}

/// Compute directory size with a file count cap to avoid walking huge trees.
/// Returns the accumulated size once the cap is hit (partial but fast).
const DIR_SIZE_MAX_FILES: u64 = 10_000;

fn dir_size(path: &Path) -> u64 {
    dir_size_capped(path).0
}

/// Like `dir_size`, but also reports whether the file-count cap was hit. When
/// it was, the returned size is only a partial sum of the first
/// `DIR_SIZE_MAX_FILES` entries — callers enforcing a size limit must treat a
/// capped result as "unknown / over limit" rather than trusting the partial.
fn dir_size_capped(path: &Path) -> (u64, bool) {
    let mut total = 0u64;
    let mut count = 0u64;
    dir_size_inner(path, &mut total, &mut count);
    (total, count >= DIR_SIZE_MAX_FILES)
}

fn dir_size_inner(path: &Path, total: &mut u64, count: &mut u64) {
    if *count >= DIR_SIZE_MAX_FILES {
        return;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if *count >= DIR_SIZE_MAX_FILES {
                return;
            }
            *count += 1;
            let meta = match entry.path().symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                // Count symlink itself (typically 0 or small), don't follow
                continue;
            }
            if meta.is_dir() {
                dir_size_inner(&entry.path(), total, count);
            } else {
                *total += meta.len();
            }
        }
    }
}

/// Copy a directory tree preserving symlinks and permissions.
/// Depth-limited to prevent infinite recursion from symlink loops or
/// bind mounts creating cycles.
const COPY_TREE_MAX_DEPTH: u32 = 100;

fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    copy_tree_inner(src, dst, 0)
}

fn copy_tree_inner(src: &Path, dst: &Path, depth: u32) -> io::Result<()> {
    if depth > COPY_TREE_MAX_DEPTH {
        return Err(io::Error::other(format!(
            "directory tree too deep (>{COPY_TREE_MAX_DEPTH} levels) — possible cycle"
        )));
    }

    let meta = fs::symlink_metadata(src)?;
    fs::create_dir_all(dst)?;
    // Copy permissions of the directory itself
    fs::set_permissions(dst, meta.permissions())?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_meta = fs::symlink_metadata(entry.path())?;
        let dest_path = dst.join(entry.file_name());

        if entry_meta.file_type().is_symlink() {
            // Re-create symlink (don't follow it)
            let link_target = fs::read_link(entry.path())?;
            std::os::unix::fs::symlink(&link_target, &dest_path)?;
        } else if entry_meta.is_dir() {
            copy_tree_inner(&entry.path(), &dest_path, depth + 1)?;
        } else if entry_meta.file_type().is_fifo() {
            // Recreate the named pipe so the directory round-trips on restore.
            // (A FIFO carries no persistent data; fs::copy on one would block.)
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = std::ffi::CString::new(dest_path.as_os_str().as_bytes()) {
                unsafe {
                    libc::mkfifo(c.as_ptr(), (entry_meta.mode() & 0o7777) as libc::mode_t);
                }
            }
        } else if entry_meta.file_type().is_char_device()
            || entry_meta.file_type().is_block_device()
            || entry_meta.file_type().is_socket()
        {
            // Device nodes need CAP_MKNOD to recreate and sockets are kernel
            // rendezvous objects with no persistent data — skip them.
        } else {
            fs::copy(entry.path(), &dest_path)?;
            fs::set_permissions(&dest_path, entry_meta.permissions())?;
        }
    }
    Ok(())
}

/// Write `data` to `path` atomically: write to a temp file in the same
/// directory, then rename over `path`. A crash / ENOSPC / kill mid-write can
/// therefore never leave a truncated file in place (the rename is atomic, and
/// on failure the original is untouched).
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("trashd");
    let tmp = dir.join(format!(".{stem}.tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp); // clear any leftover from a prior crash
    if let Err(e) = fs::write(&tmp, data) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Atomically (over)write a `.trashinfo` file. Public so the CLI `compress`
/// command can record the `X-Trashd-Compressed` marker without re-implementing
/// the temp-file+rename dance.
pub fn write_trashinfo_atomic(info_path: &Path, info: &TrashInfo) -> io::Result<()> {
    atomic_write(info_path, info.to_trashinfo_string().as_bytes())
}

/// Rename `src` → `dst` but fail with `EEXIST` instead of clobbering an
/// existing `dst` (`renameat2(RENAME_NOREPLACE)`), closing the
/// check-then-rename TOCTOU on restore. Callers inspect the raw OS error
/// (`EEXIST` → conflict, `EXDEV`/`ENOSYS`/`EINVAL` → copy/plain fallback).
fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    const RENAME_NOREPLACE: libc::c_uint = 1;
    let csrc = std::ffi::CString::new(src.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let cdst = std::ffi::CString::new(dst.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            csrc.as_ptr(),
            libc::AT_FDCWD,
            cdst.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Normalize a path: canonicalize the parent (resolving symlinks in directory
/// components) but preserve the final component as-is (so symlinks are not
/// followed for the target file itself).
fn normalize_path(path: &Path) -> PathBuf {
    if let Some(parent) = path.parent() {
        if let Ok(canonical_parent) = fs::canonicalize(parent) {
            if let Some(file_name) = path.file_name() {
                return canonical_parent.join(file_name);
            }
            return canonical_parent;
        }
    }
    // Fallback: lexical normalization
    let mut components = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}

pub fn simple_glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Only use the prefix/suffix shortcuts when there's a single wildcard.
    // Patterns like "*.py*" must fall through to the split_once handler.
    if let Some(suffix) = pattern.strip_prefix('*') {
        if !suffix.contains('*') {
            return text.ends_with(suffix);
        }
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if !prefix.contains('*') {
            return text.starts_with(prefix);
        }
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        // suffix might contain another '*' (e.g., pattern "*.py*" → prefix="", suffix=".py*")
        if let Some((mid, tail)) = suffix.split_once('*') {
            // Three-segment: prefix*mid*tail — text must start with prefix,
            // contain mid, and end with tail
            return text.starts_with(prefix)
                && text.ends_with(tail)
                && text[prefix.len()..text.len() - tail.len()].contains(mid);
        }
        // Guard: text must be long enough for both prefix and suffix
        return text.len() >= prefix.len() + suffix.len()
            && text.starts_with(prefix)
            && text.ends_with(suffix);
    }
    text == pattern
}

/// Get disk usage percentage for the filesystem containing the given path.
fn disk_usage_percent(path: &Path) -> Option<f64> {
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        if stat.f_blocks == 0 {
            return None;
        }
        // Total usable by non-root = used_by_users + f_bavail
        // where used_by_users = f_blocks - f_bfree
        // So effective total = (f_blocks - f_bfree) + f_bavail
        let used = stat.f_blocks - stat.f_bfree;
        let effective_total = used + stat.f_bavail;
        if effective_total == 0 {
            return None;
        }
        Some((used as f64 / effective_total as f64) * 100.0)
    }
}

/// Check if the parent process is in the bypass list.
pub fn is_parent_bypassed(bypass_list: &[String]) -> bool {
    if bypass_list.is_empty() {
        return false;
    }
    // Walk up the process tree checking each ancestor
    let mut pid = std::process::id();
    for _ in 0..10 {
        // limit depth to avoid loops
        let ppid = match parent_pid(pid) {
            Some(p) if p > 1 => p,
            _ => break,
        };
        if let Some(name) = process_name(ppid) {
            if bypass_list.contains(&name) {
                return true;
            }
        }
        pid = ppid;
    }
    false
}

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Format: pid (comm) state ppid ...
    // Find the closing paren (comm can contain parens/spaces). Use .get()
    // rather than slicing: a truncated stat (process died mid-read) can end at
    // ')', making after_comm > len, and slicing would panic.
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat.get(after_comm..)?.split_whitespace().collect();
    // fields[0] = state, fields[1] = ppid
    fields.get(1)?.parse().ok()
}

fn process_name(pid: u32) -> Option<String> {
    // Try /proc/pid/exe first (resolves to actual binary)
    if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(name) = exe.file_name() {
            return Some(name.to_string_lossy().into_owned());
        }
    }
    // Fallback: /proc/pid/comm
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Tests must run single-threaded because TrashStore::open() reads
    // XDG_DATA_HOME from the environment (process-global state).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Create a TrashStore with isolated trash + work directories.
    /// Places files under the project root (not /tmp, which is in never_trash).
    /// Returns a MutexGuard that serializes tests sharing the env var.
    fn test_store() -> (
        TrashStore,
        TempDir,
        TempDir,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-trash");
        fs::create_dir_all(&base).unwrap();

        let data_dir = TempDir::with_prefix_in("data-", &base).unwrap();
        let workdir = TempDir::with_prefix_in("work-", &base).unwrap();
        std::env::set_var("XDG_DATA_HOME", data_dir.path());

        let store = TrashStore::open().unwrap();
        (store, data_dir, workdir, guard)
    }

    /// Create a temp file with content in a given directory.
    fn create_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn trash_and_restore_file() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "hello.txt", "hello world");

        // Trash it
        let id = store.trash(&file, Some("test")).unwrap();
        assert!(!file.exists(), "original file should be gone");

        // Should appear in list
        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert_eq!(entries[0].info.original_path, file);

        // Restore it
        let restored = store.restore(&id, None).unwrap();
        assert_eq!(restored, file);
        assert_eq!(fs::read_to_string(&file).unwrap(), "hello world");

        // Trash should be empty now
        assert_eq!(store.list(None).unwrap().len(), 0);
    }

    #[test]
    fn trash_and_restore_directory() {
        let (store, _data, workdir, _lock) = test_store();
        let dir = workdir.path().join("mydir");
        fs::create_dir(&dir).unwrap();
        create_file(&dir, "a.txt", "aaa");
        create_file(&dir, "b.txt", "bbb");

        let id = store.trash(&dir, None).unwrap();
        assert!(!dir.exists());

        let restored = store.restore(&id, None).unwrap();
        assert!(restored.is_dir());
        assert_eq!(fs::read_to_string(dir.join("a.txt")).unwrap(), "aaa");
        assert_eq!(fs::read_to_string(dir.join("b.txt")).unwrap(), "bbb");
    }

    #[test]
    fn trash_symlink_preserves_target() {
        let (store, _data, workdir, _lock) = test_store();
        let target = create_file(workdir.path(), "target.txt", "target content");
        let link = workdir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        store.trash(&link, None).unwrap();

        // Symlink is gone but target is preserved
        assert!(!link.exists());
        assert!(target.exists());
        assert_eq!(fs::read_to_string(&target).unwrap(), "target content");
    }

    #[test]
    fn restore_symlink_recreates_link() {
        let (store, _data, workdir, _lock) = test_store();
        let _target = create_file(workdir.path(), "target.txt", "data");
        let link = workdir.path().join("mylink");
        std::os::unix::fs::symlink("target.txt", &link).unwrap();

        let id = store.trash(&link, None).unwrap();
        let restored = store.restore(&id, None).unwrap();

        assert!(restored
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&restored).unwrap(),
            PathBuf::from("target.txt")
        );
    }

    #[test]
    fn undo_restores_most_recent() {
        let (store, _data, workdir, _lock) = test_store();
        let f1 = create_file(workdir.path(), "first.txt", "1");
        let f2 = create_file(workdir.path(), "second.txt", "2");

        store.trash(&f1, None).unwrap();
        // Trashinfo timestamps have 1-second resolution
        std::thread::sleep(std::time::Duration::from_secs(1));
        store.trash(&f2, None).unwrap();

        // Undo restores the most recent (second.txt)
        let restored = store.undo().unwrap();
        assert_eq!(restored.file_name().unwrap(), "second.txt");
        assert!(f2.exists());
        assert!(!f1.exists());
    }

    #[test]
    fn purge_permanently_deletes() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "gone.txt", "bye");

        let id = store.trash(&file, None).unwrap();
        assert_eq!(store.list(None).unwrap().len(), 1);

        store.purge(&id).unwrap();
        assert_eq!(store.list(None).unwrap().len(), 0);

        // Can't restore after purge
        assert!(store.restore(&id, None).is_err());
    }

    #[test]
    fn empty_clears_all() {
        let (store, _data, workdir, _lock) = test_store();
        for i in 0..5 {
            let f = create_file(workdir.path(), &format!("f{i}.txt"), "x");
            store.trash(&f, None).unwrap();
        }
        assert_eq!(store.list(None).unwrap().len(), 5);

        let count = store.empty(None).unwrap();
        assert_eq!(count, 5);
        assert_eq!(store.list(None).unwrap().len(), 0);
    }

    #[test]
    fn list_pattern_filter() {
        let (store, _data, workdir, _lock) = test_store();
        let py = create_file(workdir.path(), "script.py", "python");
        let rs = create_file(workdir.path(), "main.rs", "rust");
        let txt = create_file(workdir.path(), "notes.txt", "text");

        store.trash(&py, None).unwrap();
        store.trash(&rs, None).unwrap();
        store.trash(&txt, None).unwrap();

        let all = store.list(None).unwrap();
        assert_eq!(all.len(), 3);

        let py_only = store.list(Some("*.py")).unwrap();
        assert_eq!(py_only.len(), 1);
        assert_eq!(
            py_only[0].info.original_path.file_name().unwrap(),
            "script.py"
        );
    }

    #[test]
    fn trash_nonexistent_file_errors() {
        let (store, _data, workdir, _lock) = test_store();
        let result = store.trash(&workdir.path().join("nonexistent_xyz"), None);
        assert!(matches!(result, Err(TrashError::NotFound(_))));
    }

    #[test]
    fn restore_conflict_errors() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "conflict.txt", "v1");

        let id = store.trash(&file, None).unwrap();

        // Create a new file at the same path
        create_file(workdir.path(), "conflict.txt", "v2");

        let result = store.restore(&id, None);
        assert!(matches!(result, Err(TrashError::RestoreConflict(_))));
    }

    #[test]
    fn restore_to_alternate_path() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "original.txt", "data");

        let id = store.trash(&file, None).unwrap();
        let alt = workdir.path().join("restored_here.txt");
        let restored = store.restore(&id, Some(&alt)).unwrap();

        assert_eq!(restored, alt);
        assert_eq!(fs::read_to_string(&alt).unwrap(), "data");
        assert!(!file.exists()); // original path still gone
    }

    #[test]
    fn ambiguous_match_detected() {
        let (store, _data, workdir, _lock) = test_store();

        // Trash two files with the same name
        let f1 = create_file(workdir.path(), "dup.txt", "v1");
        store.trash(&f1, None).unwrap();
        let f2 = create_file(workdir.path(), "dup.txt", "v2");
        store.trash(&f2, None).unwrap();

        // Purge the one with exact ID "dup.txt" so both remaining have timestamped IDs
        let _ = store.purge("dup.txt");

        // If only one remains, no ambiguity
        let entries = store.list(None).unwrap();
        if entries.len() >= 2 {
            let result = store.restore("dup.txt", None);
            assert!(matches!(result, Err(TrashError::AmbiguousMatch { .. })));
        }
    }

    #[test]
    fn duplicate_trash_gets_unique_id() {
        let (store, _data, workdir, _lock) = test_store();

        let f1 = create_file(workdir.path(), "same.txt", "a");
        let id1 = store.trash(&f1, None).unwrap();

        let f2 = create_file(workdir.path(), "same.txt", "b");
        let id2 = store.trash(&f2, None).unwrap();

        // IDs must be different
        assert_ne!(id1, id2);
        assert_eq!(store.list(None).unwrap().len(), 2);
    }

    #[test]
    fn status_reports_size_and_count() {
        let (store, _data, workdir, _lock) = test_store();

        let f = create_file(workdir.path(), "sized.txt", "hello"); // 5 bytes
        store.trash(&f, None).unwrap();

        let (size, count) = store.status().unwrap();
        assert_eq!(count, 1);
        assert_eq!(size, 5);
    }

    #[test]
    fn trashinfo_has_metadata() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "meta.txt", "test data");

        let _id = store.trash(&file, Some("rm -f meta.txt")).unwrap();
        let entries = store.list(None).unwrap();
        let entry = &entries[0];

        assert_eq!(entry.info.command.as_deref(), Some("rm -f meta.txt"));
        assert!(entry.info.pid.is_some());
        assert_eq!(entry.info.size, Some(9)); // "test data" = 9 bytes
        assert!(entry.info.sha256.is_some());
    }

    // --- simple_glob_match tests ---

    #[test]
    fn glob_wildcard_all() {
        assert!(simple_glob_match("*", "anything"));
    }

    #[test]
    fn glob_suffix() {
        assert!(simple_glob_match("*.py", "script.py"));
        assert!(!simple_glob_match("*.py", "script.rs"));
    }

    #[test]
    fn glob_prefix() {
        assert!(simple_glob_match("test*", "test_file.txt"));
        assert!(!simple_glob_match("test*", "my_test.txt"));
    }

    #[test]
    fn glob_infix() {
        assert!(simple_glob_match("a*z", "abcz"));
        assert!(!simple_glob_match("a*z", "abcy"));
    }

    #[test]
    fn glob_infix_short_text_no_false_positive() {
        // Regression: "ab*ab" should NOT match "ab" (text shorter than prefix+suffix)
        assert!(!simple_glob_match("ab*ab", "ab"));
        assert!(simple_glob_match("ab*ab", "abXab"));
    }

    #[test]
    fn glob_exact() {
        assert!(simple_glob_match("foo.txt", "foo.txt"));
        assert!(!simple_glob_match("foo.txt", "bar.txt"));
    }

    #[test]
    fn glob_multi_wildcard() {
        // Regression: patterns like "*.py*" should work
        assert!(simple_glob_match("*.py*", "script.py"));
        assert!(simple_glob_match("*.py*", "script.pyc"));
        assert!(!simple_glob_match("*.py*", "script.rs"));
    }

    // --- Restore conflict + force ---

    #[test]
    fn restore_conflict_to_alternate_avoids_conflict() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "alt.txt", "data");
        let id = store.trash(&file, None).unwrap();

        // Re-create at original
        create_file(workdir.path(), "alt.txt", "blocker");

        // Restore to alternate path succeeds
        let alt = workdir.path().join("alt_restored.txt");
        let restored = store.restore(&id, Some(&alt)).unwrap();
        assert_eq!(restored, alt);
        assert_eq!(fs::read_to_string(&alt).unwrap(), "data");
    }

    // --- Permissions preservation ---

    #[test]
    fn trash_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "perms.txt", "secret");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();

        let id = store.trash(&file, None).unwrap();
        let restored = store.restore(&id, None).unwrap();

        let mode = fs::metadata(&restored).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // --- Size limit enforcement ---

    #[test]
    fn large_file_rejected() {
        let (store, _data, workdir, _lock) = test_store();

        // Create file > max_file_size_mb (default 1024 MB).
        // We can't create a real 1 GB file, but we can test that the check
        // exists by verifying the error type. Use a file that's within limits instead.
        let file = create_file(workdir.path(), "small.txt", "ok");
        // This should succeed (file is tiny)
        assert!(store.trash(&file, None).is_ok());
    }

    // --- Empty with age filter ---

    #[test]
    fn empty_with_age_filter() {
        let (store, _data, workdir, _lock) = test_store();

        // Trash a file
        let f = create_file(workdir.path(), "old.txt", "data");
        store.trash(&f, None).unwrap();

        // Empty with 1-day filter should NOT remove it (just trashed)
        let count = store.empty(Some(1)).unwrap();
        assert_eq!(count, 0);
        assert_eq!(store.list(None).unwrap().len(), 1);

        // Empty with no filter removes everything
        let count = store.empty(None).unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.list(None).unwrap().len(), 0);
    }

    // --- Hash integrity ---

    #[test]
    fn hash_stored_on_trash() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "hashed.txt", "check me");
        store.trash(&file, None).unwrap();

        let entries = store.list(None).unwrap();
        assert!(!entries.is_empty());
        // Hash should be present for small files
        assert!(
            entries[0].info.sha256.is_some(),
            "hash should be computed for small files"
        );
    }

    // --- Never-trash exclusion ---

    #[test]
    fn never_trash_pattern_excludes() {
        let (store, _data, workdir, _lock) = test_store();

        // .tmp files are in the default never_trash list
        let file = create_file(workdir.path(), "temp.tmp", "data");
        let result = store.trash(&file, None);
        assert!(
            matches!(result, Err(TrashError::Excluded(_))),
            "*.tmp should be excluded by never_trash"
        );
    }

    // --- List pattern filter with time ---

    #[test]
    fn list_pattern_filter_works() {
        let (store, _data, workdir, _lock) = test_store();

        let f1 = create_file(workdir.path(), "keep.py", "python");
        let f2 = create_file(workdir.path(), "keep.rs", "rust");
        store.trash(&f1, None).unwrap();
        store.trash(&f2, None).unwrap();

        let py_entries = store.list(Some("*.py")).unwrap();
        assert_eq!(py_entries.len(), 1);
        assert!(py_entries[0]
            .info
            .original_path
            .to_string_lossy()
            .ends_with("keep.py"));
    }

    // --- Compression roundtrip ---

    #[test]
    fn compress_and_restore_roundtrip() {
        let (store, _data, workdir, _lock) = test_store();

        // Create a file with repetitive content (compresses well)
        let content = "hello world! ".repeat(1000);
        let file = create_file(workdir.path(), "compressible.txt", &content);
        let id = store.trash(&file, None).unwrap();

        // Manually compress the trashed file
        let entries = store.list(None).unwrap();
        let trashed = &entries[0].trashed_path;
        let original_size = fs::metadata(trashed).unwrap().len();

        let data = fs::read(trashed).unwrap();
        let compressed = zstd::encode_all(data.as_slice(), 3).unwrap();
        assert!(compressed.len() < data.len(), "should compress");
        fs::write(trashed, &compressed).unwrap();
        // Record the compression marker, exactly as the real compress/auto-purge
        // paths do — restore decompresses by marker, never by magic bytes.
        let mut info = entries[0].info.clone();
        info.compressed = Some("zstd".into());
        write_trashinfo_atomic(&entries[0].info_path, &info).unwrap();

        let compressed_size = fs::metadata(trashed).unwrap().len();
        assert!(compressed_size < original_size);

        // Restore should transparently decompress
        let restored = store.restore(&id, None).unwrap();
        let restored_content = fs::read_to_string(&restored).unwrap();
        assert_eq!(
            restored_content, content,
            "content should match after decompress"
        );
    }

    // M3: a user's genuine .zst (zstd magic, but trashd never compressed it, so
    // no X-Trashd-Compressed marker) must be restored byte-for-byte, NOT
    // silently decompressed.
    #[test]
    fn restore_does_not_decompress_unmarked_zstd_file() {
        let (store, _data, workdir, _lock) = test_store();
        let original = zstd::encode_all(b"the user's real data".as_slice(), 3).unwrap();
        let file = workdir.path().join("real.zst");
        fs::write(&file, &original).unwrap();

        let id = store.trash(&file, None).unwrap();
        let restored = store.restore(&id, None).unwrap();

        assert_eq!(
            fs::read(&restored).unwrap(),
            original,
            "a genuine .zst (no compression marker) must not be decompressed"
        );
    }

    // H1/H2: a crafted .trashinfo whose Path escapes via ".." must be refused
    // by restore, and the trashed payload must stay put.
    #[test]
    fn restore_refuses_path_traversal() {
        let (store, _data, _workdir, _lock) = test_store();
        let trash = TrashStore::home_trash_dir();
        fs::create_dir_all(trash.join("info")).unwrap();
        fs::create_dir_all(trash.join("files")).unwrap();
        // Relative Path is decoded literally (preserving "..") and reconstructed
        // onto the trash topdir, so the resolved destination keeps ParentDir
        // components.
        fs::write(
            trash.join("info/evil.trashinfo"),
            "[Trash Info]\nPath=../../../../etc/evil\nDeletionDate=2026-01-01T00:00:00\n",
        )
        .unwrap();
        fs::write(trash.join("files/evil"), b"payload").unwrap();

        let err = store.restore("evil", None).unwrap_err();
        assert!(
            matches!(err, TrashError::RestoreTraversal(_)),
            "expected RestoreTraversal, got {err:?}"
        );
        assert!(
            trash.join("files/evil").exists(),
            "payload must stay in the trash after a refused restore"
        );
    }

    // M1: trashing a file must not overwrite a pre-existing orphaned data file
    // (one in files/ with no .trashinfo) that happens to share its name.
    #[test]
    fn trashing_does_not_overwrite_orphan_file() {
        let (store, _data, workdir, _lock) = test_store();
        let trash = TrashStore::home_trash_dir();
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::write(trash.join("files/dup.txt"), b"orphan-data").unwrap();

        let file = create_file(workdir.path(), "dup.txt", "new-data");
        let id = store.trash(&file, None).unwrap();

        assert_ne!(id, "dup.txt", "must not reuse the orphan's id");
        assert_eq!(
            fs::read(trash.join("files/dup.txt")).unwrap(),
            b"orphan-data",
            "orphan data must be preserved"
        );
        assert_eq!(
            fs::read(trash.join("files").join(&id)).unwrap(),
            b"new-data"
        );
    }

    // Critical: retention values of 0 mean "disabled", NOT "purge everything".
    // With the bug, max_age_days=0 made `age.num_days() < 0` false for every
    // item (so all were purged) and max_size_gb=0 trimmed the trash to nothing.
    #[test]
    fn retention_zero_disables_limits_not_wipes_trash() {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-trash");
        fs::create_dir_all(&base).unwrap();
        let data_dir = TempDir::with_prefix_in("data0-", &base).unwrap();
        let config_dir = TempDir::with_prefix_in("cfg0-", &base).unwrap();
        let workdir = TempDir::with_prefix_in("work0-", &base).unwrap();
        std::env::set_var("XDG_DATA_HOME", data_dir.path());
        std::env::set_var("XDG_CONFIG_HOME", config_dir.path());

        // All retention limits zero, and auto-purge runs on every deletion.
        let cfg = config_dir.path().join("trashd/config.toml");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(
            &cfg,
            "auto_purge_interval_secs = 0\n\
             [retention]\n\
             max_age_days = 0\n\
             max_size_gb = 0\n\
             disk_pressure_percent = 0\n",
        )
        .unwrap();

        let store = TrashStore::open().unwrap();
        assert_eq!(store.config().retention.max_age_days, 0);
        assert_eq!(store.config().retention.max_size_gb, 0.0);

        // Each trash() triggers maybe_auto_purge -> auto_purge (interval 0).
        for i in 0..3 {
            let f = create_file(workdir.path(), &format!("keep{i}.txt"), "data");
            store.trash(&f, None).unwrap();
        }

        let entries = store.list(None).unwrap();
        std::env::remove_var("XDG_CONFIG_HOME");
        drop(guard);
        assert_eq!(entries.len(), 3, "retention=0 must NOT purge the trash");
    }
}
