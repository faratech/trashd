use crate::config::Config;
use crate::index::TrashIndex;
use crate::mounts;
use crate::trashinfo::TrashInfo;
use sha2::{Digest, Sha256};
use xxhash_rust::xxh3::xxh3_128;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

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
    #[error("multiple matches for '{pattern}': {count} items (use trash ID for exact match)")]
    AmbiguousMatch { pattern: String, count: usize },
}

pub struct TrashStore {
    config: Config,
    index: TrashIndex,
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
}

impl TrashStore {
    pub fn open() -> Result<Self, TrashError> {
        let config = Config::load();
        let home = Self::home_trash_dir();
        fs::create_dir_all(home.join("files"))?;
        fs::create_dir_all(home.join("info"))?;
        fs::create_dir_all(home.join(".trashd"))?;

        let index = TrashIndex::open(&home.join(".trashd/index.sqlite"))?;

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

    /// Ensure a trash directory has the required subdirectories.
    fn ensure_trash_dir(trash_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(trash_dir.join("files"))?;
        fs::create_dir_all(trash_dir.join("info"))?;
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

        // Pick the right trash directory (same-device preferred)
        let trash_dir = self.trash_dir_for(&abs_path);
        Self::ensure_trash_dir(&trash_dir)?;

        // Generate unique trash ID within that trash dir (atomic)
        let file_name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed".into());
        let (id, info_file) = unique_id_atomic(&trash_dir, &file_name)?;

        // Build trashinfo
        let mut info = TrashInfo::new(abs_path.clone());
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

        // On failure, clean up orphaned trashinfo and partial copy
        if let Err(e) = move_result {
            let _ = fs::remove_file(&info_file);
            if dest.exists() {
                if dest.is_dir() {
                    let _ = fs::remove_dir_all(&dest);
                } else {
                    let _ = fs::remove_file(&dest);
                }
            }
            return Err(e);
        }

        // Update index
        let _ = self.index.insert(&id, &info, &trash_dir);

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
        entries.sort_by(|a, b| b.info.deletion_date.cmp(&a.info.deletion_date));
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

            let id = filename.strip_suffix(".trashinfo").unwrap_or(&filename).to_string();
            let content = match fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let info = match TrashInfo::from_trashinfo(&content) {
                Some(i) => i,
                None => continue,
            };

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
            });
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

        // Check for conflicts
        if restore_to.exists() {
            return Err(TrashError::RestoreConflict(restore_to));
        }

        // Ensure parent directory exists
        if let Some(parent) = restore_to.parent() {
            fs::create_dir_all(parent)?;
        }

        // Move back
        if fs::rename(&entry.trashed_path, &restore_to).is_err() {
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

        // Remove trashinfo
        let _ = fs::remove_file(&entry.info_path);

        // Update index
        let _ = self.index.delete(&entry.id);

        // Log operation
        crate::oplog::log_restore(&entry.id, &restore_to);

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
        let _ = self.index.delete(&entry.id);
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
            let _ = self.index.delete(&entry.id);
            count += 1;
        }
        if count > 0 {
            let filter_desc = max_age_days.map(|d| format!("older than {d}d"));
            crate::oplog::log_empty(count, filter_desc.as_deref());
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

        // Phase 1: purge items older than max_age_days
        // entries are newest-first, so iterate in reverse (oldest first)
        for i in (0..entries.len()).rev() {
            let age = now.signed_duration_since(entries[i].info.deletion_date);
            if age.num_days() < max_age as i64 {
                break;
            }
            let _ = self.purge_entry(&entries[i]);
            purged[i] = true;
        }

        // Phase 2: trim by total size (purge oldest surviving until under limit)
        let total_size: u64 = entries.iter().enumerate()
            .filter(|(i, _)| !purged[*i])
            .filter_map(|(_, e)| e.info.size)
            .sum();
        if total_size > max_size_bytes {
            let mut freed = 0u64;
            let excess = total_size - max_size_bytes;
            for i in (0..entries.len()).rev() {
                if purged[i] {
                    continue;
                }
                if freed >= excess {
                    break;
                }
                freed += entries[i].info.size.unwrap_or(0);
                let _ = self.purge_entry(&entries[i]);
                purged[i] = true;
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
                        purged_count += 1;
                    }
                }
            }
        }

        Ok(())
    }

    /// Purge a single entry without re-scanning the list.
    fn purge_entry(&self, entry: &TrashEntry) -> Result<(), TrashError> {
        if entry.trashed_path.is_dir() {
            let _ = fs::remove_dir_all(&entry.trashed_path);
        } else if entry.trashed_path.exists() {
            let _ = fs::remove_file(&entry.trashed_path);
        }
        let _ = fs::remove_file(&entry.info_path);
        let _ = self.index.delete(&entry.id);
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
            ps.total_size += entry.info.size.unwrap_or(0);
        }

        let mut result: Vec<PartitionStatus> = partitions.into_values().collect();
        result.sort_by(|a, b| b.total_size.cmp(&a.total_size));
        Ok(result)
    }

    /// Total status across all partitions.
    pub fn status(&self) -> Result<(u64, usize), TrashError> {
        let entries = self.list(None)?;
        let total_size: u64 = entries.iter().filter_map(|e| e.info.size).sum();
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
fn unique_id_atomic(trash_dir: &Path, base_name: &str) -> Result<(String, PathBuf), TrashError> {
    use std::os::unix::fs::OpenOptionsExt;

    let info_dir = trash_dir.join("info");

    // Truncate base_name if it would exceed filesystem filename limits.
    // ".trashinfo" = 10 chars, ".YYYYMMDDHHMMSS.NNNNN" = 21 chars max.
    // Most filesystems cap at 255 bytes. Reserve 32 for suffix.
    let max_base = 223;
    let base_name = if base_name.len() > max_base {
        &base_name[..max_base]
    } else {
        base_name
    };

    // Try base name first
    let info_path = info_dir.join(format!("{base_name}.trashinfo"));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&info_path)
    {
        Ok(_) => return Ok((base_name.to_string(), info_path)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(TrashError::Io(e)),
    }

    // Append timestamp + counter
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S");
    for i in 0u32..10000 {
        let candidate = if i == 0 {
            format!("{base_name}.{ts}")
        } else {
            format!("{base_name}.{ts}.{i}")
        };
        let info_path = info_dir.join(format!("{candidate}.trashinfo"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&info_path)
        {
            Ok(_) => return Ok((candidate, info_path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(TrashError::Io(e)),
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
            Ok(format!("{:x}", hasher.finalize()))
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
    let mut total = 0u64;
    let mut count = 0u64;
    dir_size_inner(path, &mut total, &mut count);
    total
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
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("directory tree too deep (>{COPY_TREE_MAX_DEPTH} levels) — possible cycle"),
        ));
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
        } else if entry_meta.file_type().is_fifo()
            || entry_meta.file_type().is_char_device()
            || entry_meta.file_type().is_block_device()
            || entry_meta.file_type().is_socket()
        {
            // Skip special files — fs::copy on FIFOs blocks indefinitely,
            // and device nodes require mknod to recreate
        } else {
            fs::copy(entry.path(), &dest_path)?;
            fs::set_permissions(&dest_path, entry_meta.permissions())?;
        }
    }
    Ok(())
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

fn simple_glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }
    if let Some((prefix, suffix)) = pattern.split_once('*') {
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
            if bypass_list.iter().any(|b| name == *b) {
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
    // Find the closing paren (comm can contain parens/spaces)
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
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
    fn test_store() -> (TrashStore, TempDir, TempDir, std::sync::MutexGuard<'static, ()>) {
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
        let target = create_file(workdir.path(), "target.txt", "data");
        let link = workdir.path().join("mylink");
        std::os::unix::fs::symlink("target.txt", &link).unwrap();

        let id = store.trash(&link, None).unwrap();
        let restored = store.restore(&id, None).unwrap();

        assert!(restored.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(&restored).unwrap(), PathBuf::from("target.txt"));
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
        assert_eq!(py_only[0].info.original_path.file_name().unwrap(), "script.py");
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

        let id = store.trash(&file, Some("rm -f meta.txt")).unwrap();
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
}
