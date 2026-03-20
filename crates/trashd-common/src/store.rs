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

        // Compute SHA-256 for files (skip for dirs and large files)
        if meta.is_file() && meta.size() < 100 * 1024 * 1024 {
            if let Ok(hash) = sha256_file(&abs_path) {
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

        // Run auto-purge if needed
        let _ = self.auto_purge();

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

        if entry.trashed_path.is_dir() {
            fs::remove_dir_all(&entry.trashed_path)?;
        } else if entry.trashed_path.exists() {
            fs::remove_file(&entry.trashed_path)?;
        }
        let _ = fs::remove_file(&entry.info_path);
        let _ = self.index.delete(&entry.id);
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
            if entry.trashed_path.is_dir() {
                let _ = fs::remove_dir_all(&entry.trashed_path);
            } else if entry.trashed_path.exists() {
                let _ = fs::remove_file(&entry.trashed_path);
            }
            let _ = fs::remove_file(&entry.info_path);
            let _ = self.index.delete(&entry.id);
            count += 1;
        }
        Ok(count)
    }

    /// Enforce retention policy: purge expired items and trim by size.
    fn auto_purge(&self) -> Result<(), TrashError> {
        let max_age = self.config.retention.max_age_days;
        let max_size_bytes = (self.config.retention.max_size_gb * 1024.0 * 1024.0 * 1024.0) as u64;
        let pressure_pct = self.config.retention.disk_pressure_percent;

        let entries = self.list(None)?;
        if entries.is_empty() {
            return Ok(());
        }

        let now = chrono::Local::now();

        // Phase 1: purge items older than max_age_days
        for entry in entries.iter().rev() {
            // entries are newest-first, so iterate in reverse (oldest first)
            let age = now.signed_duration_since(entry.info.deletion_date);
            if age.num_days() < max_age as i64 {
                break; // rest are newer
            }
            let _ = self.purge_entry(&entry);
        }

        // Phase 2: trim by total size (purge oldest until under limit)
        let entries = self.list(None)?;
        let total_size: u64 = entries.iter().filter_map(|e| e.info.size).sum();
        if total_size > max_size_bytes {
            let mut freed = 0u64;
            let excess = total_size - max_size_bytes;
            for entry in entries.iter().rev() {
                if freed >= excess {
                    break;
                }
                freed += entry.info.size.unwrap_or(0);
                let _ = self.purge_entry(&entry);
            }
        }

        // Phase 3: disk pressure — check free space on home trash partition
        if pressure_pct > 0 {
            let home = Self::home_trash_dir();
            if let Some(usage_pct) = disk_usage_percent(&home) {
                if usage_pct >= pressure_pct as f64 {
                    let entries = self.list(None)?;
                    // Purge oldest 10% of items
                    let to_purge = std::cmp::max(1, entries.len() / 10);
                    for entry in entries.iter().rev().take(to_purge) {
                        let _ = self.purge_entry(&entry);
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

fn sha256_file(path: &Path) -> io::Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                total += dir_size(&entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    total
}

/// Copy a directory tree preserving symlinks and permissions.
fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
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
            copy_tree(&entry.path(), &dest_path)?;
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
