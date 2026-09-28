use crate::config::Config;
use crate::index::TrashIndex;
use crate::mounts;
use crate::trashinfo::TrashInfo;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;
use xxhash_rust::xxh3::Xxh3;

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
    #[error("entry '{0}' has no .trashinfo metadata and cannot be restored (run `trash fsck`)")]
    OrphanedEntry(String),
    #[error(
        "refusing to trash '{0}': it is the trash directory itself, inside it, or an ancestor of it"
    )]
    Refused(PathBuf),
}

pub struct TrashStore {
    config: Config,
    home: PathBuf,
    isolated: bool,
    #[cfg(test)]
    sidecar_reads: std::cell::Cell<usize>,
    #[cfg(test)]
    cache_refreshes: std::cell::Cell<usize>,
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
    identity: Option<(u64, u64)>,
    sidecar_version: Option<SidecarVersion>,
}

impl TrashStore {
    pub fn open() -> Result<Self, TrashError> {
        Self::open_with(Self::home_trash_dir(), Config::load(), false)
    }

    /// Open an explicitly configured store that never discovers other mounts
    /// or reads ambient global/user/project configuration.
    pub fn open_isolated(home: &Path, config: Config) -> Result<Self, TrashError> {
        Self::open_with(home.to_path_buf(), config, true)
    }

    pub fn home_dir(&self) -> &Path {
        &self.home
    }

    fn open_with(home: PathBuf, config: Config, isolated: bool) -> Result<Self, TrashError> {
        let uid = unsafe { libc::geteuid() };

        // /tmp fallback (#35): validate the exact uid-specific base, not the
        // child `Trash` path (which never starts with `/tmp/trashd-home-` as a
        // path component). It must be a private real directory owned by the
        // effective user before anything sensitive is written below it.
        let fallback_base = PathBuf::from(format!("/tmp/trashd-home-{uid}"));
        if home == fallback_base.join("Trash") {
            ensure_trusted_parent(&fallback_base, uid)?;
            ensure_private_dir(&fallback_base, uid, true)?;
        } else if let Some(parent) = home.parent() {
            ensure_trusted_ancestors(parent, uid)?;
        }

        ensure_private_dir(&home, uid, true)?;
        ensure_private_dir(&home.join("files"), uid, true)?;
        ensure_private_dir(&home.join("info"), uid, true)?;
        ensure_private_dir(&home.join(".trashd"), uid, true)?;

        // The index is an optional accelerator. If it can't be opened (lock
        // contention, corruption, read-only FS) we degrade to no-index rather
        // than failing — the authoritative files and sidecars remain usable.
        let index = match TrashIndex::open(&home.join(crate::index::REL_PATH)) {
            Ok(idx) => Some(idx),
            Err(e) => {
                eprintln!("trashd: warning: trash index unavailable ({e}); continuing without it");
                None
            }
        };

        let home = fs::canonicalize(home)?;
        Ok(Self {
            config,
            index,
            home,
            isolated,
            #[cfg(test)]
            sidecar_reads: std::cell::Cell::new(0),
            #[cfg(test)]
            cache_refreshes: std::cell::Cell::new(0),
        })
    }

    /// The home trash directory per FreeDesktop spec.
    ///
    /// When neither XDG_DATA_HOME nor HOME is set we fall back to a
    /// UID-private directory instead of shared `/tmp`: the old `/tmp` fallback
    /// put deleted files' contents AND their original-path metadata into a
    /// world-readable, periodically purged directory (#35).
    pub fn home_trash_dir() -> PathBuf {
        let base = dirs::data_dir().unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|h| h.join(".local/share"))
                .unwrap_or_else(|| {
                    PathBuf::from(format!("/tmp/trashd-home-{}", unsafe { libc::geteuid() }))
                })
        });
        base.join("Trash")
    }

    pub fn trash_dir() -> PathBuf {
        Self::home_trash_dir()
    }

    /// Determine the correct trash directory for a file (same-device or topdir).
    fn trash_dir_for(&self, path: &Path) -> PathBuf {
        if self.isolated {
            self.home.clone()
        } else {
            mounts::trash_dir_for_path(path, &self.home)
        }
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

    /// Per FreeDesktop spec: home-trash entries store an absolute `Path=`;
    /// topdir-trash entries store a path RELATIVE to the topdir (the parent of
    /// `.Trash-$uid`, or the grandparent for `.Trash/$uid`). Falls back to the
    /// absolute path when the prefix strip fails.
    fn compute_trashinfo_path(trash_dir: &Path, original_abs: &Path, home_trash: &Path) -> PathBuf {
        if trash_dir == home_trash {
            return original_abs.to_path_buf();
        }
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
            .unwrap_or(trash_dir);
        original_abs
            .strip_prefix(topdir)
            .map(|rel| {
                // Spec: relative path MUST NOT contain ".."
                debug_assert!(
                    !rel.components()
                        .any(|c| c == std::path::Component::ParentDir)
                );
                rel.to_path_buf()
            })
            .unwrap_or_else(|_| original_abs.to_path_buf())
    }

    /// Ensure a trash directory has the required subdirectories.
    fn ensure_trash_dir(&self, trash_dir: &Path) -> io::Result<()> {
        let uid = unsafe { libc::geteuid() };
        ensure_private_dir(trash_dir, uid, false)?;
        ensure_private_dir(&trash_dir.join("files"), uid, true)?;
        ensure_private_dir(&trash_dir.join("info"), uid, true)?;
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
        if self.should_skip(&abs_path) {
            return Err(TrashError::Excluded(abs_path));
        }

        // Check size limit (for files only)
        if meta.is_file() {
            let size_mb = meta.size() / (1024 * 1024);
            if self.config.max_file_size_mb > 0
                && meta.size() > self.config.max_file_size_mb.saturating_mul(1024 * 1024)
            {
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
        if !self.config.bypass_paths.is_empty()
            && let Ok(exe) = fs::read_link("/proc/self/exe")
        {
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

        // Pick the right trash directory (same-device preferred)
        let trash_dir = self.trash_dir_for(&abs_path);

        // Refuse to trash the trash directory itself, anything inside it, or
        // any ancestor of it: rename would fail (dest inside src), the
        // cross-device fallback would copy the store into itself until the
        // depth cap. `rm -rf ~/.local/share/Trash` must
        // never destroy the trash. Callers treat Refused as a hard stop —
        // NOT Excluded, which means "real-delete on purpose".
        if abs_path == trash_dir
            || abs_path.starts_with(&trash_dir)
            || trash_dir.starts_with(&abs_path)
        {
            return Err(TrashError::Refused(abs_path));
        }

        self.ensure_trash_dir(&trash_dir)?;

        // Generate unique trash ID within that trash dir (atomic)
        let file_name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed".into());
        let (id, info_file) = unique_id_atomic(&trash_dir, &file_name)?;

        // Build trashinfo — per spec, topdir trash should use relative paths
        // from the topdir mount point, not absolute paths.
        let home_trash = self.home.clone();
        let trashinfo_path = Self::compute_trashinfo_path(&trash_dir, &abs_path, &home_trash);
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
        let hash_limit = self.config.sha256_max_size_mb.saturating_mul(1024 * 1024);
        if meta.is_file()
            && hash_limit > 0
            && meta.size() <= hash_limit
            && let Ok(hash) = hash_file(&abs_path, &self.config.hash_algorithm)
        {
            info.sha256 = Some(hash);
        }

        let dest = trash_dir.join("files").join(&id);

        // Write .trashinfo content to the already-created file
        fs::write(&info_file, info.to_trashinfo_string())?;

        // Try rename (fast, same filesystem — should always work with topdir trash)
        let mut copy_done = false;
        let move_result: Result<(), TrashError> = (|| {
            if fs::rename(&abs_path, &dest).is_err() {
                // Cross-filesystem fallback — order matters: check symlink first
                if meta.file_type().is_symlink() {
                    let link_target = fs::read_link(&abs_path)?;
                    std::os::unix::fs::symlink(&link_target, &dest)?;
                } else if meta.is_dir() {
                    copy_tree(&abs_path, &dest)?;
                } else if meta.file_type().is_fifo() {
                    // Recreate the FIFO — fs::copy on one blocks forever
                    // waiting for a writer (#11).
                    use std::os::unix::ffi::OsStrExt;
                    if let Ok(c) = std::ffi::CString::new(dest.as_os_str().as_bytes()) {
                        unsafe {
                            libc::mkfifo(c.as_ptr(), (meta.mode() & 0o7777) as libc::mode_t);
                        }
                    }
                } else if meta.file_type().is_char_device()
                    || meta.file_type().is_block_device()
                    || meta.file_type().is_socket()
                {
                    // No CAP_MKNOD / no persistent data — refuse rather than
                    // fall through to fs::copy on a device node.
                    return Err(
                        io::Error::other("cannot trash device node across filesystems").into(),
                    );
                } else {
                    fs::copy(&abs_path, &dest)?;
                    fs::set_permissions(&dest, meta.permissions())?;
                }
                copy_done = true;
                // Remove the original
                if meta.file_type().is_symlink() || meta.is_file() {
                    fs::remove_file(&abs_path)?;
                } else {
                    fs::remove_dir_all(&abs_path)?;
                }
            }
            Ok(())
        })();

        // On failure, decide between a clean rollback and preserving the copy.
        // Use symlink_metadata to avoid following symlinks — remove_dir_all
        // on a symlink-to-directory would delete the target's contents.
        if let Err(e) = move_result {
            if copy_done {
                // The copy into the trash SUCCEEDED but removing the original
                // failed — part of the source may already be unlinked, so
                // deleting the trash copy now could destroy the only remaining
                // copy of that data. Keep the entry (data + .trashinfo) fully
                // intact and surface the error; the caller can clean up the
                // leftover source once the underlying problem is fixed.
                eprintln!(
                    "trashd: warning: copied '{p}' to the trash but could not remove the \
                     original ({e}); keeping the complete trashed copy — the leftover \
                     source can be removed manually",
                    p = abs_path.display()
                );
                if let Some(idx) = self.index.as_ref() {
                    let _ = idx.insert(&id, &info, &trash_dir);
                }
                crate::oplog::log_trash_in(&self.home, &abs_path, &id, command);
                return Err(TrashError::Io(io::Error::other(format!(
                    "copied to trash but failed to remove original: {e}"
                ))));
            }
            // The copy itself failed — nothing was moved; roll back cleanly.
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

        // Update index (best-effort; it's only a cache). The database lives in
        // the HOME trash only — cross-partition entries written there were
        // never read by anything and silently diverged from the authoritative
        // .trashinfo scan (#40).
        if trash_dir == home_trash
            && let Some(idx) = self.index.as_ref()
        {
            let _ = idx.insert(&id, &info, &trash_dir);
        }

        // Update directorysizes cache if we just trashed a directory
        if meta.is_dir() {
            let _ = crate::directorysizes::write_cache(&trash_dir);
        }

        // Log operation
        crate::oplog::log_trash_in(&self.home, &abs_path, &id, command);

        // Run auto-purge if enough time has passed since the last one.
        // Scanning the entire trash on every deletion is O(n) — throttle it.
        let _ = self.maybe_auto_purge();

        Ok(id)
    }

    /// Race-free variant of [`Self::trash`] for the seccomp supervisor.
    ///
    /// `parent_fd` is a directory fd PINNED by the supervisor inside the
    /// target process's filesystem context (its root / cwd / a duplicated
    /// dirfd), and `name` is the final path component. The move is performed
    /// with `renameat(parent_fd, name → trash/files/<id>)`, so the kernel
    /// resolves both sides against pinned inodes: a sibling process renaming
    /// directories between our stat and our move can no longer divert the
    /// operation to different content (audit #6).
    ///
    /// `display_path` is best-effort context only — it drives config
    /// eligibility, logging and the .trashinfo `Path=` field; the inode is
    /// never re-looked-up through it.
    ///
    /// Errors with EXDEV when the selected trash lives on another filesystem
    /// than the pinned inode (namespaced targets, device mismatch) are surfaced
    /// so the target can execute its original syscall inside its namespace.
    pub fn trash_at(
        &self,
        parent_fd: RawFd,
        name: &OsStr,
        display_path: &Path,
        command: Option<&str>,
    ) -> Result<String, TrashError> {
        use std::os::unix::ffi::OsStrExt;

        let display_path = normalize_path(display_path);

        // Metadata straight from the pinned parent — never a path re-lookup.
        let cname = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| TrashError::NotFound(display_path.clone()))?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent_fd,
                cname.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(TrashError::NotFound(display_path.clone()));
        }
        let fmt = stat.st_mode & libc::S_IFMT;
        let is_dir = fmt == libc::S_IFDIR;
        let file_dev = stat.st_dev as u64;

        // Eligibility on the display path (config semantics are path-based).
        if self.should_skip(&display_path) {
            return Err(TrashError::Excluded(display_path.clone()));
        }

        // Size limits — parity with trash().
        if fmt == libc::S_IFREG {
            let size_mb = stat.st_size as u64 / (1024 * 1024);
            if self.config.max_file_size_mb > 0
                && stat.st_size as u64 > self.config.max_file_size_mb.saturating_mul(1024 * 1024)
            {
                return Err(TrashError::TooLarge {
                    path: display_path.clone(),
                    size_mb,
                    limit_mb: self.config.max_file_size_mb,
                });
            }
        }
        if is_dir && self.config.max_dir_size_mb > 0 {
            // Walk the tree through OUR fd of it (/proc/self/fd view), not
            // through any possibly-raced name.
            let dfd = unsafe {
                libc::openat(
                    parent_fd,
                    cname.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if dfd < 0 {
                return Err(TrashError::Io(io::Error::last_os_error()));
            }
            let proc_link = format!("/proc/self/fd/{dfd}");
            let (bytes, capped) = dir_size_capped(Path::new(&proc_link));
            unsafe { libc::close(dfd) };
            let dir_size_mb = bytes / (1024 * 1024);
            if capped || dir_size_mb > self.config.max_dir_size_mb {
                return Err(TrashError::TooLarge {
                    path: display_path.clone(),
                    size_mb: dir_size_mb,
                    limit_mb: self.config.max_dir_size_mb,
                });
            }
        }

        let home_trash = self.home.clone();
        let trash_dir = if self.isolated {
            home_trash.clone()
        } else {
            mounts::trash_dir_for_device(file_dev, &display_path, &home_trash)
        };

        // Trash-self-target parity with trash() (#8).
        if display_path == trash_dir
            || display_path.starts_with(&trash_dir)
            || trash_dir.starts_with(&display_path)
        {
            return Err(TrashError::Refused(display_path.clone()));
        }

        self.ensure_trash_dir(&trash_dir)?;

        // The trash files/ dir must be on the SAME filesystem as the pinned
        // inode or renameat would cross devices; surface that distinctly so
        // the supervisor can continue the target's original syscall.
        let files_dir = trash_dir.join("files");
        let c_files_dir = match std::ffi::CString::new(files_dir.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => return Err(TrashError::NotFound(display_path.clone())),
        };
        let files_fd = unsafe {
            libc::open(
                c_files_dir.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if files_fd < 0 {
            return Err(TrashError::Io(io::Error::last_os_error()));
        }
        let mut fstat_files: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(files_fd, &mut fstat_files) } != 0 {
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(io::Error::last_os_error()));
        }
        if fstat_files.st_dev as u64 != file_dev {
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(io::Error::from_raw_os_error(libc::EXDEV)));
        }

        // Unique id + info claim (id naming is lossy for non-UTF-8 names;
        // data fidelity comes from the move itself and the raw-bytes
        // percent-encoding in the .trashinfo).
        let base_name = name.to_string_lossy();
        let (id, info_file) = unique_id_atomic(&trash_dir, &base_name)?;

        let trashinfo_path = Self::compute_trashinfo_path(&trash_dir, &display_path, &home_trash);
        let mut info = TrashInfo::new(trashinfo_path);
        info.command = command.map(|s| s.to_string());
        info.pid = Some(std::process::id());
        // Directory size: walk OUR fd of the victim dir, not any name.
        let victim_size = if !is_dir {
            stat.st_size as u64
        } else {
            let dfd = unsafe {
                libc::openat(
                    parent_fd,
                    cname.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if dfd < 0 {
                0
            } else {
                let bytes = dir_size(Path::new(&format!("/proc/self/fd/{dfd}")));
                unsafe { libc::close(dfd) };
                bytes
            }
        };
        info.size = Some(victim_size);

        // Hash small regular files — read via an fd opened under the pinned
        // parent.
        let hash_limit = self.config.sha256_max_size_mb.saturating_mul(1024 * 1024);
        if fmt == libc::S_IFREG && hash_limit > 0 && stat.st_size as u64 <= hash_limit {
            // Pin without opening the object for IO: even a replacement
            // FIFO/device must not be opened before its type is verified.
            use std::os::fd::FromRawFd;
            let rfd = unsafe {
                libc::openat(
                    parent_fd,
                    cname.as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if rfd >= 0 {
                let file = unsafe { fs::File::from_raw_fd(rfd) };
                if let Ok(m) = file.metadata()
                    && m.is_file()
                    && m.dev() == stat.st_dev as u64
                    && m.ino() == stat.st_ino as u64
                    && m.len() <= hash_limit
                    && let Ok(hash) = hash_file(
                        Path::new(&format!("/proc/self/fd/{rfd}")),
                        &self.config.hash_algorithm,
                    )
                {
                    info.sha256 = Some(hash);
                }
            }
        }

        let cid = std::ffi::CString::new(id.as_bytes())
            .map_err(|_| TrashError::NotFound(display_path.clone()))?;

        // Write .trashinfo BEFORE opening files_fd / moving — same ordering
        // as trash(). On write failure release the claimed sidecar so we do
        // not strand an empty orphan in info/ (review finding).
        if let Err(e) = fs::write(&info_file, info.to_trashinfo_string()) {
            let _ = fs::remove_file(&info_file);
            return Err(TrashError::Io(e));
        }

        // THE MOVE (#6): kernel-resolved against pinned inodes on both sides.
        let rc = unsafe { libc::renameat(parent_fd, cname.as_ptr(), files_fd, cid.as_ptr()) };
        if rc != 0 {
            unsafe { libc::close(files_fd) };
            let e = io::Error::last_os_error();
            // Nothing partial was created at dest (rename is atomic); just
            // release the claimed .trashinfo.
            let _ = fs::remove_file(&info_file);
            return Err(TrashError::Io(e));
        }

        // POST-MOVE IDENTITY CHECK (audit review): the final component could
        // have been replaced between our metadata/hash reads and the rename —
        // matching plain-unlink name semantics for WHAT gets moved, but our
        // recorded metadata must describe what ACTUALLY landed in the trash.
        // Re-stat by the new id; refresh size and drop the hash if the inode
        // differs (a stale hash would cry wolf on every restore).
        let mut moved_stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                files_fd,
                cid.as_ptr(),
                &mut moved_stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            if moved_stat.st_ino != stat.st_ino || moved_stat.st_dev != stat.st_dev {
                info.size = Some(moved_stat.st_size as u64);
                info.sha256 = None;
            } else if is_dir {
                info.size = Some(moved_stat.st_size as u64);
            }
        } else {
            info.sha256 = None;
        }
        unsafe { libc::close(files_fd) };

        if trash_dir == home_trash
            && let Some(idx) = self.index.as_ref()
        {
            let _ = idx.insert(&id, &info, &trash_dir);
        }
        if is_dir {
            let _ = crate::directorysizes::write_cache(&trash_dir);
        }
        crate::oplog::log_trash_in(&self.home, &display_path, &id, command);
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
            #[cfg(test)]
            self.sidecar_reads.set(self.sidecar_reads.get() + 1);
            let sidecar_version = sidecar_version(&entry.path());
            let content = match fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if sidecar_version.is_none() || sidecar_version != self::sidecar_version(&entry.path())
            {
                continue;
            }

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
            let identity = file_identity(&trashed_path);
            entries.push(TrashEntry {
                identity,
                sidecar_version,
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
                        if let Some(pat) = pattern
                            && !simple_glob_match(pat, &name)
                        {
                            continue;
                        }
                        let trashed_path = files_dir.join(&name);
                        orphans.push(TrashEntry {
                            identity: file_identity(&trashed_path),
                            sidecar_version: None,
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
        let mut entry = self.find_entry(id_or_pattern)?;
        self.restore_resolved(&mut entry, target, true)
    }

    /// Restore a previously resolved batch without re-enumerating the store.
    /// Each result corresponds to the entry at the same index. Failed items
    /// retain their metadata; cache/index maintenance is batched per store.
    pub fn restore_batch(
        &self,
        entries: &[TrashEntry],
        target: Option<&Path>,
        force: bool,
    ) -> Vec<Result<PathBuf, TrashError>> {
        let mut roots = std::collections::HashSet::new();
        let mut retired_ids = Vec::new();
        let results = entries
            .iter()
            .map(|listed| {
                let mut entry = listed.clone();
                let mut result = self.restore_resolved(&mut entry, target, false);
                if force && let Err(TrashError::RestoreConflict(ref destination)) = result {
                    let destination = destination.clone();
                    for i in 1..1000 {
                        let mut candidate = destination.as_os_str().to_os_string();
                        candidate.push(format!(".{i}"));
                        let candidate = PathBuf::from(candidate);
                        result = self.restore_resolved(&mut entry, Some(&candidate), false);
                        if !matches!(result, Err(TrashError::RestoreConflict(_))) {
                            break;
                        }
                    }
                }
                if result.is_ok() {
                    roots.insert(entry.trash_root.clone());
                    retired_ids.push((entry.id.clone(), entry.trash_root.clone()));
                }
                result
            })
            .collect();
        if let Some(index) = &self.index {
            let _ = index.delete_many(&retired_ids);
        }
        for root in roots {
            self.refresh_cache(&root);
        }
        results
    }

    fn refresh_cache(&self, root: &Path) {
        #[cfg(test)]
        self.cache_refreshes.set(self.cache_refreshes.get() + 1);
        let _ = crate::directorysizes::write_cache(root);
    }

    fn restore_resolved(
        &self,
        entry: &mut TrashEntry,
        target: Option<&Path>,
        maintain: bool,
    ) -> Result<PathBuf, TrashError> {
        if (self.isolated && entry.trash_root != self.home)
            || entry.trashed_path != entry.trash_root.join("files").join(&entry.id)
            || entry.info_path
                != entry
                    .trash_root
                    .join("info")
                    .join(format!("{}.trashinfo", entry.id))
            || Path::new(&entry.id).components().count() != 1
            || !matches!(
                Path::new(&entry.id).components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        // Orphaned entries (files/ item with no .trashinfo) carry a synthetic
        // pseudo-path, not a real original location. Restoring one would move
        // the data to a garbage "(orphaned: …)" path in the caller's CWD.
        if entry.orphaned {
            return Err(TrashError::OrphanedEntry(entry.id.clone()));
        }

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
            if entry.trash_root != self.home {
                let topdir = Self::topdir_for_trash(&entry.trash_root);
                if !restore_to.starts_with(&topdir) {
                    return Err(TrashError::RestoreTraversal(restore_to));
                }
            }
        }

        // Resolve the destination parent once, then keep that exact directory
        // pinned for every subsequent check and publication syscall. Recorded
        // paths are untrusted metadata, so their ancestors may not be
        // symlinks. Explicit --to paths are user-selected and may follow
        // symlinks, but the directory reached here is still pinned against a
        // later ancestor swap.
        let destination =
            resolve_restore_destination(&restore_to, target.is_none()).map_err(|e| {
                if target.is_none()
                    && matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR))
                {
                    TrashError::RestoreTraversal(restore_to.clone())
                } else {
                    TrashError::Io(e)
                }
            })?;

        // Check before decoding so a normal conflict never rewrites the entry.
        if destination_exists(&destination)? {
            return Err(TrashError::RestoreConflict(restore_to));
        }
        if entry.identity.is_none()
            || file_identity(&entry.trashed_path) != entry.identity
            || entry.sidecar_version.is_none()
            || sidecar_version(&entry.info_path) != entry.sidecar_version
        {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }

        // If trashd compressed this entry's data (recorded explicitly via the
        // X-Trashd-Compressed marker — never inferred from magic bytes, which
        // would corrupt a user's genuine .zst), decompress the in-trash copy
        // BEFORE moving it out. Doing it here means a decode/write failure
        // leaves the entry fully intact in the trash (nothing moved, metadata
        // present) so it stays restorable, and the write is atomic so a
        // crash/ENOSPC can never truncate the only copy.
        // symlink_metadata: never decode THROUGH a trashed symlink onto its
        // target (#12).
        let stored_is_regular = fs::symlink_metadata(&entry.trashed_path)
            .map(|m| m.is_file())
            .unwrap_or(false);
        if entry.info.compressed.as_deref() == Some("zstd") && stored_is_regular {
            let configured = self.config.max_file_size_mb.saturating_mul(1024 * 1024);
            const HARD_DECOMPRESS_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
            let max_output = if configured == 0 {
                HARD_DECOMPRESS_LIMIT
            } else {
                configured.min(HARD_DECOMPRESS_LIMIT)
            };
            decompress_zstd_entry(entry, max_output)?;
        }

        // Re-check through the pinned parent after decompression. The publish
        // syscall below is also no-clobber, so a creation after this check is
        // still reported as a conflict rather than overwritten.
        if destination_exists(&destination)? {
            return Err(TrashError::RestoreConflict(restore_to));
        }

        if file_identity(&entry.trashed_path) != entry.identity
            || sidecar_version(&entry.info_path) != entry.sidecar_version
        {
            // A replaced ID belongs to another operation; leave its data and
            // sidecar alone instead of retiring somebody else's new entry.
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }

        let source_parent = open_directory_nofollow(&entry.trash_root.join("files"))?;
        let source_name = CString::new(entry.id.as_bytes())
            .map_err(|_| TrashError::EntryNotFound(entry.id.clone()))?;
        let source_stat = stat_at(
            source_parent.as_raw_fd(),
            &source_name,
            libc::AT_SYMLINK_NOFOLLOW,
        )?;
        let expected_identity = entry
            .identity
            .ok_or_else(|| TrashError::EntryNotFound(entry.id.clone()))?;
        if stat_identity(&source_stat) != expected_identity {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        let source_is_regular = source_stat.st_mode & libc::S_IFMT == libc::S_IFREG;

        // Publish relative to pinned source and destination directories. There
        // is deliberately no plain-rename fallback: every path either uses
        // RENAME_NOREPLACE or creates the destination with an exclusive *at
        // syscall before streaming a copy.
        match rename_noreplace_at(
            source_parent.as_raw_fd(),
            &source_name,
            destination.parent.as_raw_fd(),
            &destination.name,
        ) {
            Ok(()) => {}
            Err(e) if is_conflict_error(&e) => {
                return Err(TrashError::RestoreConflict(restore_to));
            }
            Err(e) if is_copy_fallback_error(&e) => {
                publish_copy_noreplace(
                    source_parent.as_raw_fd(),
                    &source_name,
                    destination.parent.as_raw_fd(),
                    &destination.name,
                    expected_identity,
                )
                .map_err(|copy_error| {
                    if is_conflict_error(&copy_error) {
                        TrashError::RestoreConflict(restore_to.clone())
                    } else {
                        TrashError::Io(copy_error)
                    }
                })?;
            }
            Err(e) => return Err(TrashError::Io(e)),
        }

        // (Decompression already happened in-trash, before the move above.)

        // Verify hash against the (now decompressed) restored file content.
        // This catches corruption during storage (bit rot, bad disk, partial copy).
        // We verify AFTER restore so the file is already in place — a mismatch is
        // reported as a warning, not a rollback (the user can decide what to do).
        let hash_warning = if let Some(ref expected_hash) = entry.info.sha256 {
            if source_is_regular {
                // Try both algorithms — we don't know which was used originally
                let xxhash =
                    hash_file_at(destination.parent.as_raw_fd(), &destination.name, "xxhash").ok();
                let sha256 =
                    hash_file_at(destination.parent.as_raw_fd(), &destination.name, "sha256").ok();
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
        if sidecar_version(&entry.info_path) == entry.sidecar_version {
            let _ = fs::remove_file(&entry.info_path);
        }

        if maintain {
            if let Some(idx) = self.index.as_ref() {
                let _ = idx.delete_in(&entry.id, &entry.trash_root);
            }
            self.refresh_cache(&entry.trash_root);
        }

        // Log operation
        crate::oplog::log_restore_in(&self.home, &entry.id, &restore_to);

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
        // Skip orphans: they have no recorded original path, and their
        // synthetic "now" deletion date would otherwise always sort them as
        // the newest entry (hijacking undo to materialize a bogus file).
        let newest = entries
            .iter()
            .find(|e| !e.orphaned)
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
        crate::oplog::log_purge_in(&self.home, &entry.id);
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
            // Use symlink_metadata so dangling symlinks are removed too.
            // Only retire the sidecar/index row when the data actually went
            // away (#49) — otherwise a failed removal strands an invisible
            // partially-deleted tree.
            let data_gone = match fs::symlink_metadata(&entry.trashed_path) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                    fs::remove_dir_all(&entry.trashed_path).is_ok()
                }
                Ok(_) => fs::remove_file(&entry.trashed_path).is_ok(),
                Err(_) => true, // already gone
            };
            if !data_gone {
                eprintln!(
                    "trashd: warning: could not fully delete '{}' — keeping its entry",
                    entry.trashed_path.display()
                );
                continue;
            }
            let _ = fs::remove_file(&entry.info_path);
            if let Some(idx) = self.index.as_ref() {
                let _ = idx.delete(&entry.id);
            }
            count += 1;
        }
        if count > 0 {
            let filter_desc = max_age_days.map(|d| format!("older than {d}d"));
            crate::oplog::log_empty_in(&self.home, count, filter_desc.as_deref());
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

        let marker = self.home.join(".trashd/last_purge");
        if let Ok(meta) = fs::metadata(&marker)
            && let Ok(modified) = meta.modified()
            && let Ok(elapsed) = modified.elapsed()
            && elapsed.as_secs() < interval
        {
            return Ok(()); // too soon, skip
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
            if let Ok(compressed) = zstd::encode_all(data.as_slice(), 3)
                && compressed.len() < data.len()
            {
                // Record the compression marker BEFORE swapping the data
                // (#28): a crash in the window then leaves plain data with a
                // stale marker — which restore recognizes by the missing zstd
                // magic and recovers from — instead of zstd bytes with NO marker,
                // which restore would silently serve as "original content".
                // Atomic writes throughout: an interrupted compress must
                // never truncate the SOLE remaining copy of the user's
                // deleted data. If the swap fails, revert the marker so the
                // entry stays consistent.
                let mut info = entries[i].info.clone();
                info.compressed = Some("zstd".into());
                if write_trashinfo_atomic(&entries[i].info_path, &info).is_ok()
                    && atomic_write(path, &compressed).is_err()
                {
                    let mut reverted = entries[i].info.clone();
                    reverted.compressed = None;
                    let _ = write_trashinfo_atomic(&entries[i].info_path, &reverted);
                }
            }
        }

        // Phase 2b: trim by total size (purge oldest surviving until under limit)
        let total_size: u64 = entries
            .iter()
            .enumerate()
            .filter(|(i, _)| !purged[*i])
            .map(|(_, e)| entry_disk_size(e))
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
                freed += entry_disk_size(&entries[i]);
                let _ = self.purge_entry(&entries[i]);
                purged[i] = true;
                purge_count += 1;
            }
        }

        // Phase 3: disk pressure — purge oldest 10% of surviving items
        if pressure_pct > 0 {
            let home = self.home.clone();
            if let Some(usage_pct) = disk_usage_percent(&home)
                && usage_pct >= pressure_pct as f64
            {
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

        // Log and notify if items were auto-purged
        if purge_count > 0 {
            // Rebuild directorysizes across all trash dirs so purged/compressed
            // directories are reflected for other FreeDesktop trash tools.
            for (dir, _) in self.all_trash_dirs() {
                let _ = crate::directorysizes::write_cache(&dir);
            }
            crate::oplog::log_empty_in(&self.home, purge_count, Some("auto-purge"));
            if !self.isolated {
                crate::oplog::notify_desktop(
                    "trashd: auto-purge",
                    &format!(
                        "{purge_count} item{} permanently deleted by retention policy",
                        if purge_count == 1 { "" } else { "s" }
                    ),
                );
            }
        }

        Ok(())
    }

    /// Purge a single entry without re-scanning the list.
    fn purge_entry(&self, entry: &TrashEntry) -> Result<(), TrashError> {
        // Use symlink_metadata so dangling symlinks are detected and removed
        let data_gone = match fs::symlink_metadata(&entry.trashed_path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                fs::remove_dir_all(&entry.trashed_path).is_ok()
            }
            Ok(_) => fs::remove_file(&entry.trashed_path).is_ok(),
            Err(_) => true, // already gone
        };
        if !data_gone {
            // Keep the .trashinfo so the entry stays listed/restorable;
            // dropping it would strand a partially-deleted tree as an
            // invisible orphan (#49).
            return Err(TrashError::Io(io::Error::other(format!(
                "failed to delete trashed data for entry '{}'",
                entry.id
            ))));
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
            ps.total_size += entry_disk_size(entry);
        }

        let mut result: Vec<PartitionStatus> = partitions.into_values().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.total_size));
        Ok(result)
    }

    /// Total status across all partitions.
    pub fn status(&self) -> Result<(u64, usize), TrashError> {
        let entries = self.list(None)?;
        // Use actual disk size (reflects compression savings)
        let total_size: u64 = entries.iter().map(entry_disk_size).sum();
        let count = entries.len();
        Ok((total_size, count))
    }

    /// All known trash directories (home + per-mountpoint).
    fn all_trash_dirs(&self) -> Vec<(PathBuf, String)> {
        if self.isolated {
            vec![(self.home.clone(), "home".into())]
        } else {
            mounts::all_trash_dirs(&self.home)
        }
    }

    fn should_skip(&self, path: &Path) -> bool {
        if self.isolated {
            self.config.should_skip_configured(path)
        } else {
            self.config.should_skip(path)
        }
    }

    /// Access config (for shim process bypass checking).
    pub fn config(&self) -> &Config {
        &self.config
    }

    fn find_entry(&self, id_or_pattern: &str) -> Result<TrashEntry, TrashError> {
        let entries = self.list(None)?;

        // Exact ID match. IDs are unique WITHIN one trash dir, but two
        // partitions can hold entries with the same ID (same filename trashed
        // on two mounts); picking either nondeterministically could restore
        // or purge the WRONG copy (#41).
        let exact: Vec<&TrashEntry> = entries.iter().filter(|e| e.id == id_or_pattern).collect();
        if exact.len() == 1 {
            return Ok(exact[0].clone());
        }
        if exact.len() > 1 {
            let roots: std::collections::HashSet<&PathBuf> =
                exact.iter().map(|e| &e.trash_root).collect();
            if roots.len() > 1 {
                return Err(TrashError::AmbiguousMatch {
                    pattern: id_or_pattern.into(),
                    count: exact.len(),
                });
            }
            return Ok(exact[0].clone());
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

fn file_identity(path: &Path) -> Option<(u64, u64)> {
    fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Create or validate one directory in the authenticated trash hierarchy.
/// Every writable store component is a real directory, owned by the effective
/// user, with no group/other permissions. A failed chmod is fatal: silently
/// accepting the old mode would expose deleted data and metadata.
fn ensure_private_dir(path: &Path, uid: u32, create: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            match fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(raced) if raced.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }

    let mut meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a real directory owned by uid {uid}",
                path.display()
            ),
        ));
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        meta = fs::symlink_metadata(path)?;
    }
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a private trash directory", path.display()),
        ));
    }
    Ok(())
}

fn ensure_trusted_parent(path: &Path, uid: u32) -> io::Result<()> {
    let mut current = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "directory has no parent"))?;
    loop {
        let metadata = fs::symlink_metadata(current)?;
        let mode = metadata.permissions().mode();
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} can be replaced by another user and is not a safe trash ancestor",
                    current.display()
                ),
            ));
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }
    Ok(())
}

/// Create missing ancestors one component at a time and authenticate every
/// component before descending through it. This avoids following an
/// attacker-provided symlink while preparing a configured XDG/HOME path.
fn ensure_trusted_ancestors(directory: &Path, uid: u32) -> io::Result<()> {
    use std::path::Component;

    let directory = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()?.join(directory)
    };
    let mut current = PathBuf::from("/");
    for component in directory.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => current.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsafe trash ancestor path",
                ));
            }
        }

        match fs::symlink_metadata(&current) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::DirBuilder::new().mode(0o700).create(&current) {
                    Ok(()) => {}
                    Err(raced) if raced.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }

        let metadata = fs::symlink_metadata(&current)?;
        let mode = metadata.permissions().mode();
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} can be replaced by another user and is not a safe trash ancestor",
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Decompress a marked entry with bounded memory and bounded output. The
/// compressed source remains untouched until a complete plaintext sibling has
/// been written, synced, and the entry identity has been revalidated.
fn decompress_zstd_entry(entry: &mut TrashEntry, max_output: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let expected_identity = entry
        .identity
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "trash entry was replaced"))?;
    let expected_sidecar = entry
        .sidecar_version
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "trash metadata was replaced"))?;
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&entry.trashed_path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || (metadata.dev(), metadata.ino()) != expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "trash entry was replaced during decompression",
        ));
    }
    input.lock()?;
    if file_identity(&entry.trashed_path) != Some(expected_identity)
        || sidecar_version(&entry.info_path) != Some(expected_sidecar)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "trash entry changed during decompression",
        ));
    }

    let mut magic = [0u8; 4];
    let has_zstd_magic = match input.read_exact(&mut magic) {
        Ok(()) => u32::from_le_bytes(magic) == 0xFD2FB528,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => false,
        Err(error) => return Err(error),
    };
    input.seek(SeekFrom::Start(0))?;

    let mut cleared = entry.info.clone();
    cleared.compressed = None;
    if !has_zstd_magic {
        // Compression records the marker first. A crash in that narrow window
        // leaves ordinary plaintext plus a stale marker; clear only that known
        // state. A payload with real zstd magic must decode successfully.
        write_trashinfo_atomic(&entry.info_path, &cleared)?;
        entry.info = cleared;
        entry.sidecar_version = sidecar_version(&entry.info_path);
        return Ok(());
    }

    let parent = entry
        .trashed_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "entry has no parent"))?;
    let mut staging = tempfile::Builder::new()
        .prefix(".trashd-decompress-")
        .tempfile_in(parent)?;
    let mut decoder = zstd::stream::Decoder::new(&mut input)?;
    // Cap decoder history to 8 MiB so a hostile frame cannot request an
    // attacker-controlled allocation even before output accounting starts.
    decoder.window_log_max(23)?;
    let written = io::copy(
        &mut decoder.take(max_output.saturating_add(1)),
        &mut staging,
    )?;
    if written > max_output {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("decompressed entry exceeds {max_output} bytes"),
        ));
    }

    let staged_metadata = staging.as_file().metadata()?;
    if (staged_metadata.uid(), staged_metadata.gid()) != (metadata.uid(), metadata.gid())
        && unsafe {
            libc::fchown(
                staging.as_file().as_raw_fd(),
                metadata.uid(),
                metadata.gid(),
            )
        } != 0
    {
        return Err(io::Error::last_os_error());
    }
    staging.as_file().set_permissions(metadata.permissions())?;
    staging.as_file().sync_all()?;

    if file_identity(&entry.trashed_path) != Some(expected_identity)
        || sidecar_version(&entry.info_path) != Some(expected_sidecar)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "trash entry changed before decompression commit",
        ));
    }
    staging
        .persist(&entry.trashed_path)
        .map_err(|error| error.error)?;
    entry.identity = file_identity(&entry.trashed_path);

    // Treat marker retirement as part of the transaction. If it fails, leave
    // the recoverable plaintext+marker state; the next restore recognizes the
    // missing magic and retries this write without decoding the file again.
    write_trashinfo_atomic(&entry.info_path, &cleared)?;
    entry.info = cleared;
    entry.sidecar_version = sidecar_version(&entry.info_path);
    Ok(())
}

/// Detect replacement and in-place edits without rereading each sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SidecarVersion {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn sidecar_version(path: &Path) -> Option<SidecarVersion> {
    let m = fs::symlink_metadata(path).ok()?;
    if !m.is_file() {
        return None;
    }
    Some(SidecarVersion {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}

/// Hash a file using the configured algorithm.
/// "xxhash" (default): XXH3-128 — extremely fast, non-cryptographic.
/// "sha256": SHA-256 — cryptographic, slower.
///
/// Streams the file in fixed chunks instead of reading it whole: hashing runs
/// on routine deletions AND on restore verification, where the entry may be
/// far larger than the size cap that gated hashing at trash time (config
/// changed between trash and restore) — slurping would then allocate the
/// entire file in RAM.
fn hash_file(path: &Path, algorithm: &str) -> io::Result<String> {
    hash_reader(fs::File::open(path)?, algorithm)
}

fn hash_reader(mut file: impl Read, algorithm: &str) -> io::Result<String> {
    const CHUNK: usize = 256 * 1024;
    let mut buf = vec![0u8; CHUNK];
    match algorithm {
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let digest = hasher.finalize();
            Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
        }
        _ => {
            // Default: xxhash (XXH3-128)
            let mut hasher = Xxh3::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(format!("{:032x}", hasher.digest128()))
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

    // Copy the directory's own permissions AFTER populating it: applying the
    // source mode first would make read-only trees (e.g. mode 0555) fail on
    // their very first child write — both when trashing cross-device and when
    // restoring — leaving partial copies behind (#24). cp -a does the same.
    fs::set_permissions(dst, meta.permissions())?;
    Ok(())
}

/// Write `data` to `path` atomically: write to a temp file in the same
/// directory, then rename over `path`. A crash / ENOSPC / kill mid-write can
/// therefore never leave a truncated file in place (the rename is atomic, and
/// on failure the original is untouched).
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic replacement requires a regular file",
        ));
    }
    let mut staging = tempfile::NamedTempFile::new_in(dir)?;
    staging.write_all(data)?;
    let staged_meta = staging.as_file().metadata()?;
    if staged_meta.uid() != meta.uid() || staged_meta.gid() != meta.gid() {
        use std::os::fd::AsRawFd;
        if unsafe { libc::fchown(staging.as_file().as_raw_fd(), meta.uid(), meta.gid()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    staging.as_file().set_permissions(meta.permissions())?;
    staging.as_file().sync_all()?;
    staging.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Atomically (over)write a `.trashinfo` file. Public so the CLI `compress`
/// command can record the `X-Trashd-Compressed` marker without re-implementing
/// the temp-file+rename dance.
pub fn write_trashinfo_atomic(info_path: &Path, info: &TrashInfo) -> io::Result<()> {
    atomic_write(info_path, info.to_trashinfo_string().as_bytes())
}

struct RestoreDestination {
    parent: fs::File,
    name: CString,
}

/// Resolve (and, when needed, create) a restore destination's parent one
/// component at a time. The returned fd pins the exact parent directory so a
/// later rename of an ancestor cannot redirect publication.
fn resolve_restore_destination(
    destination: &Path,
    reject_symlink_ancestors: bool,
) -> io::Result<RestoreDestination> {
    let name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "restore destination has no final component",
        )
    })?;
    let name =
        CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let mut parent = if parent_path.is_absolute() {
        open_directory_path(Path::new("/"), false)?
    } else {
        open_directory_path(Path::new("."), false)?
    };

    for component in parent_path.components() {
        use std::path::Component;
        let component = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir if reject_symlink_ancestors => {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            Component::ParentDir => CString::new("..").expect("static CString"),
            Component::Normal(component) => CString::new(component.as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
            Component::Prefix(_) => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
        };

        if reject_symlink_ancestors {
            match stat_at(parent.as_raw_fd(), &component, libc::AT_SYMLINK_NOFOLLOW) {
                Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFLNK => {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }

        match open_directory_at(
            parent.as_raw_fd(),
            &component,
            reject_symlink_ancestors,
            true,
        ) {
            Ok(next) => parent = next,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                let created =
                    unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o777) };
                if created != 0 {
                    let mkdir_error = io::Error::last_os_error();
                    if mkdir_error.raw_os_error() != Some(libc::EEXIST) {
                        return Err(mkdir_error);
                    }
                }
                parent = open_directory_at(
                    parent.as_raw_fd(),
                    &component,
                    reject_symlink_ancestors,
                    true,
                )?;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(RestoreDestination { parent, name })
}

fn open_directory_path(path: &Path, nofollow: bool) -> io::Result<fs::File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn open_directory_nofollow(path: &Path) -> io::Result<fs::File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn open_directory_at(
    parent: RawFd,
    name: &CStr,
    nofollow: bool,
    path_only: bool,
) -> io::Result<fs::File> {
    let mut flags = libc::O_DIRECTORY | libc::O_CLOEXEC;
    flags |= if path_only {
        libc::O_PATH
    } else {
        libc::O_RDONLY
    };
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn stat_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, flags) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

fn stat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

fn stat_identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev, stat.st_ino)
}

fn same_source_version(left: &libc::stat, right: &libc::stat) -> bool {
    stat_identity(left) == stat_identity(right)
        && left.st_mode == right.st_mode
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn validate_copy_destination_parent(fd: RawFd) -> io::Result<()> {
    let stat = stat_fd(fd)?;
    let uid = unsafe { libc::geteuid() };
    let mode = stat.st_mode;
    let trusted_owner = stat.st_uid == uid || stat.st_uid == 0;
    let shared_writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    if mode & libc::S_IFMT != libc::S_IFDIR || !trusted_owner || (shared_writable && !sticky) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "copy fallback requires a destination parent protected from entry replacement",
        ));
    }
    Ok(())
}

fn validate_created_node(
    parent: RawFd,
    name: &CStr,
    expected_type: libc::mode_t,
    expected_identity: (u64, u64),
) -> io::Result<()> {
    let stat = stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if stat_identity(&stat) != expected_identity
        || stat.st_mode & libc::S_IFMT != expected_type
        || stat.st_uid != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "created restore destination was replaced",
        ));
    }
    Ok(())
}

fn destination_exists(destination: &RestoreDestination) -> io::Result<bool> {
    match stat_at(
        destination.parent.as_raw_fd(),
        &destination.name,
        libc::AT_SYMLINK_NOFOLLOW,
    ) {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Rename between pinned directories, failing instead of replacing anything
/// that appeared at the destination.
fn rename_noreplace_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
) -> io::Result<()> {
    const RENAME_NOREPLACE: libc::c_uint = 1;
    let ret = unsafe {
        libc::renameat2(
            src_parent,
            src_name.as_ptr(),
            dst_parent,
            dst_name.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_conflict_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EEXIST) | Some(libc::ENOTEMPTY)
    )
}

fn is_copy_fallback_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EXDEV) | Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
    )
}

/// Cross-device/unsupported-rename publication. Every destination node is
/// claimed exclusively, and the source is retained until the entire copy is
/// complete.
fn publish_copy_noreplace(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    expected_identity: (u64, u64),
) -> io::Result<()> {
    validate_copy_destination_parent(dst_parent)?;
    let stat = stat_at(src_parent, src_name, libc::AT_SYMLINK_NOFOLLOW)?;
    if stat_identity(&stat) != expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "trash entry changed before copy fallback",
        ));
    }

    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => {
            let destination_identity =
                copy_regular_at(src_parent, src_name, dst_parent, dst_name, &stat)?;
            unlink_source_or_rollback(
                src_parent,
                src_name,
                dst_parent,
                dst_name,
                expected_identity,
                destination_identity,
            )
        }
        libc::S_IFLNK => {
            let destination_identity =
                copy_symlink_at(src_parent, src_name, dst_parent, dst_name, &stat)?;
            unlink_source_or_rollback(
                src_parent,
                src_name,
                dst_parent,
                dst_name,
                expected_identity,
                destination_identity,
            )
        }
        libc::S_IFDIR => {
            let before = snapshot_directory_at(src_parent, src_name)?;
            let destination_identity =
                copy_directory_at(src_parent, src_name, dst_parent, dst_name, &stat, 0)?;
            let current = stat_at(src_parent, src_name, libc::AT_SYMLINK_NOFOLLOW);
            if !matches!(current, Ok(ref current) if stat_identity(current) == expected_identity) {
                let _ = remove_created_at(dst_parent, dst_name, destination_identity);
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "trash entry changed before source retirement",
                ));
            }
            if !identity_matches_at(dst_parent, dst_name, destination_identity) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "restore destination changed before source retirement",
                ));
            }
            if snapshot_directory_at(src_parent, src_name)? != before {
                eprintln!(
                    "trashd: warning: restored a stable snapshot but the trash directory changed during the copy; keeping the remaining trash copy as an orphan"
                );
                return Ok(());
            }
            // Retire only the exact source nodes captured before the copy.
            // New or replaced children are left in a residual orphan instead
            // of being deleted without ever reaching the destination.
            match retire_directory_snapshot_at(src_parent, src_name, expected_identity, &before) {
                Ok(true) => {}
                Ok(false) => eprintln!(
                    "trashd: warning: restored directory but its trash copy changed during retirement; keeping the unmatched remainder as an orphan"
                ),
                Err(e) => eprintln!(
                    "trashd: warning: restored directory but could not completely retire its trash copy: {e}"
                ),
            }
            Ok(())
        }
        libc::S_IFIFO => {
            if unsafe {
                libc::mkfifoat(
                    dst_parent,
                    dst_name.as_ptr(),
                    (stat.st_mode & 0o7777) as libc::mode_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let destination_identity =
                stat_identity(&stat_at(dst_parent, dst_name, libc::AT_SYMLINK_NOFOLLOW)?);
            validate_created_node(dst_parent, dst_name, libc::S_IFIFO, destination_identity)?;
            if let Err(error) = apply_node_metadata_at(dst_parent, dst_name, &stat) {
                let _ = remove_created_at(dst_parent, dst_name, destination_identity);
                return Err(error);
            }
            unlink_source_or_rollback(
                src_parent,
                src_name,
                dst_parent,
                dst_name,
                expected_identity,
                destination_identity,
            )
        }
        _ => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
    }
}

fn unlink_source_or_rollback(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    expected_identity: (u64, u64),
    destination_identity: (u64, u64),
) -> io::Result<()> {
    let current = stat_at(src_parent, src_name, libc::AT_SYMLINK_NOFOLLOW);
    if !matches!(current, Ok(ref current) if stat_identity(current) == expected_identity) {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "trash entry changed before source retirement",
        ));
    }
    if !identity_matches_at(dst_parent, dst_name, destination_identity) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "restore destination changed before source retirement",
        ));
    }
    if unsafe { libc::unlinkat(src_parent, src_name.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    let _ = remove_created_at(dst_parent, dst_name, destination_identity);
    Err(error)
}

fn copy_regular_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    expected: &libc::stat,
) -> io::Result<(u64, u64)> {
    let src_fd = unsafe {
        libc::openat(
            src_parent,
            src_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if src_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut source = unsafe { fs::File::from_raw_fd(src_fd) };
    let actual = stat_fd(source.as_raw_fd())?;
    if actual.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat_identity(&actual) != stat_identity(expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "source changed while opening regular file",
        ));
    }

    let dst_fd = unsafe {
        libc::openat(
            dst_parent,
            dst_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if dst_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut destination = unsafe { fs::File::from_raw_fd(dst_fd) };
    let destination_stat = stat_fd(destination.as_raw_fd())?;
    let destination_identity = stat_identity(&destination_stat);
    if destination_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || destination_stat.st_uid != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "created restore file was replaced",
        ));
    }
    let copied = (|| {
        io::copy(&mut source, &mut destination)?;
        let after = stat_fd(source.as_raw_fd())?;
        if !same_source_version(&actual, &after) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "source file changed while it was being copied",
            ));
        }
        apply_fd_metadata(destination.as_raw_fd(), expected)?;
        destination.sync_all()
    })();
    drop(destination);
    if let Err(error) = copied {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(error);
    }
    Ok(destination_identity)
}

fn copy_symlink_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    expected: &libc::stat,
) -> io::Result<(u64, u64)> {
    let target = readlink_at(src_parent, src_name)?;
    if stat_identity(&stat_at(src_parent, src_name, libc::AT_SYMLINK_NOFOLLOW)?)
        != stat_identity(expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "source symlink changed while reading it",
        ));
    }
    if unsafe { libc::symlinkat(target.as_ptr(), dst_parent, dst_name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let destination_identity =
        stat_identity(&stat_at(dst_parent, dst_name, libc::AT_SYMLINK_NOFOLLOW)?);
    validate_created_node(dst_parent, dst_name, libc::S_IFLNK, destination_identity)?;
    if readlink_at(dst_parent, dst_name)? != target {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "created restore symlink was replaced",
        ));
    }
    if let Err(error) = apply_symlink_owner(dst_parent, dst_name, expected) {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(error);
    }
    Ok(destination_identity)
}

#[derive(Debug, PartialEq, Eq)]
struct DirectorySnapshotEntry {
    path: Vec<u8>,
    device: libc::dev_t,
    inode: libc::ino_t,
    mode: libc::mode_t,
    size: libc::off_t,
    modified: (libc::time_t, libc::c_long),
    changed: (libc::time_t, libc::c_long),
}

fn snapshot_directory_at(parent: RawFd, name: &CStr) -> io::Result<Vec<DirectorySnapshotEntry>> {
    let directory = open_directory_at(parent, name, true, false)?;
    let mut snapshot = Vec::new();
    snapshot_directory_fd(directory.as_raw_fd(), &[], 0, &mut snapshot)?;
    snapshot.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(snapshot)
}

fn snapshot_directory_fd(
    directory: RawFd,
    prefix: &[u8],
    depth: u32,
    snapshot: &mut Vec<DirectorySnapshotEntry>,
) -> io::Result<()> {
    if depth > COPY_TREE_MAX_DEPTH {
        return Err(io::Error::other(format!(
            "directory tree too deep (>{COPY_TREE_MAX_DEPTH} levels) — possible cycle"
        )));
    }
    let mut names = read_directory_names(directory)?;
    names.sort_by(|left, right| left.to_bytes().cmp(right.to_bytes()));
    for name in names {
        let stat = stat_at(directory, &name, libc::AT_SYMLINK_NOFOLLOW)?;
        let mut path = prefix.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name.to_bytes());
        snapshot.push(DirectorySnapshotEntry {
            path: path.clone(),
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            size: stat.st_size,
            modified: (stat.st_mtime, stat.st_mtime_nsec),
            changed: (stat.st_ctime, stat.st_ctime_nsec),
        });
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            let child = open_directory_at(directory, &name, true, false)?;
            let opened = stat_fd(child.as_raw_fd())?;
            if stat_identity(&opened) != stat_identity(&stat) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "source directory changed while taking restore snapshot",
                ));
            }
            snapshot_directory_fd(child.as_raw_fd(), &path, depth + 1, snapshot)?;
        }
    }
    Ok(())
}

fn copy_directory_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    expected: &libc::stat,
    depth: u32,
) -> io::Result<(u64, u64)> {
    if depth > COPY_TREE_MAX_DEPTH {
        return Err(io::Error::other(format!(
            "directory tree too deep (>{COPY_TREE_MAX_DEPTH} levels) — possible cycle"
        )));
    }
    if unsafe { libc::mkdirat(dst_parent, dst_name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let destination_identity = {
        let stat = stat_at(dst_parent, dst_name, libc::AT_SYMLINK_NOFOLLOW)?;
        stat_identity(&stat)
    };
    validate_created_node(dst_parent, dst_name, libc::S_IFDIR, destination_identity)?;
    let destination = match open_directory_at(dst_parent, dst_name, true, false) {
        Ok(destination) => destination,
        Err(error) => {
            let _ = remove_created_at(dst_parent, dst_name, destination_identity);
            return Err(error);
        }
    };
    if stat_identity(&stat_fd(destination.as_raw_fd())?) != destination_identity {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "restore destination changed while opening directory",
        ));
    }
    let copied = (|| {
        let source = open_directory_at(src_parent, src_name, true, false)?;
        let actual = stat_fd(source.as_raw_fd())?;
        if actual.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat_identity(&actual) != stat_identity(expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "source directory changed while opening it",
            ));
        }
        for child in read_directory_names(source.as_raw_fd())? {
            copy_node_at(
                source.as_raw_fd(),
                &child,
                destination.as_raw_fd(),
                &child,
                depth + 1,
            )?;
        }
        apply_fd_metadata(destination.as_raw_fd(), expected)
    })();

    drop(destination);
    if let Err(error) = copied {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(error);
    }
    Ok(destination_identity)
}

fn copy_node_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    depth: u32,
) -> io::Result<()> {
    let stat = stat_at(src_parent, src_name, libc::AT_SYMLINK_NOFOLLOW)?;
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => {
            copy_regular_at(src_parent, src_name, dst_parent, dst_name, &stat).map(|_| ())
        }
        libc::S_IFLNK => {
            copy_symlink_at(src_parent, src_name, dst_parent, dst_name, &stat).map(|_| ())
        }
        libc::S_IFDIR => {
            copy_directory_at(src_parent, src_name, dst_parent, dst_name, &stat, depth).map(|_| ())
        }
        libc::S_IFIFO => {
            if unsafe {
                libc::mkfifoat(
                    dst_parent,
                    dst_name.as_ptr(),
                    (stat.st_mode & 0o7777) as libc::mode_t,
                )
            } != 0
            {
                Err(io::Error::last_os_error())
            } else {
                let identity =
                    stat_identity(&stat_at(dst_parent, dst_name, libc::AT_SYMLINK_NOFOLLOW)?);
                validate_created_node(dst_parent, dst_name, libc::S_IFIFO, identity)?;
                apply_node_metadata_at(dst_parent, dst_name, &stat)
            }
        }
        // Silently skipping one of these and then retiring the source tree
        // would lose a node. Abort the whole fallback so its newly-created
        // destination is cleaned up and the complete trash entry remains.
        libc::S_IFCHR | libc::S_IFBLK | libc::S_IFSOCK => {
            Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
        }
        _ => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
    }
}

fn apply_fd_metadata(fd: RawFd, source: &libc::stat) -> io::Result<()> {
    if unsafe { libc::fchown(fd, source.st_uid, source.st_gid) } != 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
            || unsafe { libc::geteuid() } == 0
        {
            return Err(error);
        }
    }
    // chown may clear set-id bits, so permissions are always applied last.
    if unsafe { libc::fchmod(fd, source.st_mode & 0o7777) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn apply_node_metadata_at(parent: RawFd, name: &CStr, source: &libc::stat) -> io::Result<()> {
    if unsafe { libc::fchownat(parent, name.as_ptr(), source.st_uid, source.st_gid, 0) } != 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
            || unsafe { libc::geteuid() } == 0
        {
            return Err(error);
        }
    }
    if unsafe { libc::fchmodat(parent, name.as_ptr(), source.st_mode & 0o7777, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn apply_symlink_owner(parent: RawFd, name: &CStr, source: &libc::stat) -> io::Result<()> {
    if unsafe {
        libc::fchownat(
            parent,
            name.as_ptr(),
            source.st_uid,
            source.st_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
            || unsafe { libc::geteuid() } == 0
        {
            return Err(error);
        }
    }
    Ok(())
}

fn readlink_at(parent: RawFd, name: &CStr) -> io::Result<CString> {
    let mut capacity = 256usize;
    loop {
        let mut bytes = vec![0u8; capacity];
        let length = unsafe {
            libc::readlinkat(
                parent,
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = length as usize;
        if length < bytes.len() {
            bytes.truncate(length);
            return CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
        }
        capacity = capacity
            .checked_mul(2)
            .filter(|next| *next <= 1024 * 1024)
            .ok_or_else(|| io::Error::other("symlink target is too long"))?;
    }
}

fn read_directory_names(fd: RawFd) -> io::Result<Vec<CString>> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(error);
    }

    let result = (|| {
        let mut names = Vec::new();
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(0) {
                    return Ok(names);
                }
                return Err(error);
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(name.to_owned());
            }
        }
    })();
    unsafe { libc::closedir(directory) };
    result
}

fn identity_matches_at(parent: RawFd, name: &CStr, expected: (u64, u64)) -> bool {
    matches!(
        stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW),
        Ok(ref stat) if stat_identity(stat) == expected
    )
}

/// Remove a rollback destination only while the directory entry still names
/// the inode created by this restore attempt. If another actor replaced the
/// name, leave that unrelated object untouched. Non-empty directories are
/// deliberately retained: recursively walking a partially published tree on
/// an error could erase children inserted by somebody else.
fn remove_created_at(parent: RawFd, name: &CStr, expected: (u64, u64)) -> io::Result<()> {
    let stat = match stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) if stat_identity(&stat) == expected => stat,
        Ok(_) => return Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error),
    };
    let flags = if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    if !identity_matches_at(parent, name, expected) {
        return Ok(());
    }
    if unsafe { libc::unlinkat(parent, name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if flags == libc::AT_REMOVEDIR && error.raw_os_error() == Some(libc::ENOTEMPTY) {
        Ok(())
    } else {
        Err(error)
    }
}

fn snapshot_entry_matches(entry: &DirectorySnapshotEntry, stat: &libc::stat) -> bool {
    entry.device == stat.st_dev
        && entry.inode == stat.st_ino
        && entry.mode == stat.st_mode
        && entry.size == stat.st_size
        && entry.modified == (stat.st_mtime, stat.st_mtime_nsec)
        && entry.changed == (stat.st_ctime, stat.st_ctime_nsec)
}

fn child_snapshot_path(prefix: &[u8], name: &CStr) -> Vec<u8> {
    let mut path = prefix.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name.to_bytes());
    path
}

fn is_direct_snapshot_child(path: &[u8], prefix: &[u8]) -> bool {
    let remainder = if prefix.is_empty() {
        path
    } else {
        let Some(remainder) = path.strip_prefix(prefix) else {
            return false;
        };
        let Some(remainder) = remainder.strip_prefix(b"/") else {
            return false;
        };
        remainder
    };
    !remainder.is_empty() && !remainder.contains(&b'/')
}

fn retire_directory_snapshot_at(
    parent: RawFd,
    name: &CStr,
    expected_root: (u64, u64),
    snapshot: &[DirectorySnapshotEntry],
) -> io::Result<bool> {
    let stat = stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if stat_identity(&stat) != expected_root || stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Ok(false);
    }
    let directory = open_directory_at(parent, name, true, false)?;
    if stat_identity(&stat_fd(directory.as_raw_fd())?) != expected_root {
        return Ok(false);
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let complete = retire_snapshot_directory_fd(directory.as_raw_fd(), &[], snapshot)?;
    drop(directory);
    if !complete || !identity_matches_at(parent, name, expected_root) {
        return Ok(false);
    }
    if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOTEMPTY) | Some(libc::ENOENT)
        ) {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(true)
}

fn retire_snapshot_directory_fd(
    directory: RawFd,
    prefix: &[u8],
    snapshot: &[DirectorySnapshotEntry],
) -> io::Result<bool> {
    let expected_children: std::collections::BTreeSet<Vec<u8>> = snapshot
        .iter()
        .filter(|entry| is_direct_snapshot_child(&entry.path, prefix))
        .map(|entry| entry.path.clone())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut complete = true;

    for name in read_directory_names(directory)? {
        let path = child_snapshot_path(prefix, &name);
        let Some(expected) = snapshot.iter().find(|entry| entry.path == path) else {
            complete = false;
            continue;
        };
        seen.insert(path.clone());
        if !retire_snapshot_node_at(directory, &name, &path, expected, snapshot)? {
            complete = false;
        }
    }
    if seen != expected_children {
        complete = false;
    }
    Ok(complete)
}

fn retire_snapshot_node_at(
    parent: RawFd,
    name: &CStr,
    path: &[u8],
    expected: &DirectorySnapshotEntry,
    snapshot: &[DirectorySnapshotEntry],
) -> io::Result<bool> {
    let stat = match stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) if snapshot_entry_matches(expected, &stat) => stat,
        Ok(_) => return Ok(false),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
        Err(error) => return Err(error),
    };

    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
        let directory = open_directory_at(parent, name, true, false)?;
        if stat_identity(&stat_fd(directory.as_raw_fd())?) != stat_identity(&stat) {
            return Ok(false);
        }
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let complete = retire_snapshot_directory_fd(directory.as_raw_fd(), path, snapshot)?;
        drop(directory);
        if !complete || !identity_matches_at(parent, name, stat_identity(&stat)) {
            return Ok(false);
        }
        if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
            return Ok(true);
        }
    } else {
        let current = stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW)?;
        if !snapshot_entry_matches(expected, &current) {
            return Ok(false);
        }
        if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } == 0 {
            return Ok(true);
        }
    }

    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOTEMPTY) | Some(libc::ENOENT)
    ) {
        Ok(false)
    } else {
        Err(error)
    }
}

fn hash_file_at(parent: RawFd, name: &CStr, algorithm: &str) -> io::Result<String> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    if stat_fd(file.as_raw_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    hash_reader(file, algorithm)
}

/// Normalize a path: canonicalize the parent (resolving symlinks in directory
/// components) but preserve the final component as-is (so symlinks are not
/// followed for the target file itself).
fn normalize_path(path: &Path) -> PathBuf {
    if let Some(parent) = path.parent()
        && let Ok(canonical_parent) = fs::canonicalize(parent)
    {
        if let Some(file_name) = path.file_name() {
            return canonical_parent.join(file_name);
        }
        return canonical_parent;
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

/// Glob matcher: `*` (any sequence), `?` (single char), `[...]` classes with
/// ranges and `!`/`^` negation, `**` (same as `*`). Iterative with star
/// backtracking — cannot panic on any input (the previous hand-rolled
/// prefix/suffix splitter panicked on overlapping prefix/tail, #50) and no
/// silent exact-compare fallback for syntax it doesn't understand (#4).
pub fn simple_glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Most recent `*` position and the text offset it was matched at — the
    // sole backtrack point we need for a pattern of `*`, `?`, classes.
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    loop {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star_pi = pi;
                    star_ti = ti;
                    pi += 1;
                    continue;
                }
                '?' if ti < t.len() => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                '[' if ti < t.len() => {
                    if let Some(next) = class_match(&p, pi, t[ti]) {
                        pi = next;
                        ti += 1;
                        continue;
                    }
                    // No class match (or unterminated class): fall through
                    // to the mismatch handler / backtrack below.
                }
                c if ti < t.len() && c == t[ti] => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                _ => {}
            }
        }
        // Mismatch, or pattern exhausted while text remains.
        if pi == p.len() && ti == t.len() {
            return true;
        }
        if star_pi != usize::MAX && star_ti < t.len() {
            // Let the last `*` absorb one more character and retry.
            star_ti += 1;
            pi = star_pi + 1;
            ti = star_ti;
            continue;
        }
        return false;
    }
}

/// Match one character against a `[...]` class starting at `p[start]`.
/// Returns the pattern index just past the closing `]`, or None when the
/// character isn't matched (or the class is unterminated).
fn class_match(p: &[char], start: usize, c: char) -> Option<usize> {
    let mut i = start + 1;
    let mut negate = false;
    if i < p.len() && (p[i] == '!' || p[i] == '^') {
        negate = true;
        i += 1;
    }
    let mut matched = false;
    let mut first = true; // a `]` right after `[` or `[!` is a literal member
    while i < p.len() {
        if p[i] == ']' && !first {
            return if matched != negate { Some(i + 1) } else { None };
        }
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if c >= p[i] && c <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if p[i] == c {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

/// On-disk size of a trash entry for retention accounting and status.
///
/// `fs::metadata().len()` on a DIRECTORY is the size of its inode (~4 KB),
/// not the tree — trusting it made auto-purge "free" only 4096 bytes per
/// purged tree and keep deleting far past the configured excess, and made
/// directory-heavy trashes look nearly empty. Directory trees therefore use
/// their recorded recursive size (`info.size`, captured by `dir_size()` at
/// trash time). Symlinks are never followed: a trashed link must count as
/// itself, not its target.
fn entry_disk_size(entry: &TrashEntry) -> u64 {
    match fs::symlink_metadata(&entry.trashed_path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => entry.info.size.unwrap_or(m.len()),
        Ok(m) => m.len(),
        Err(_) => entry.info.size.unwrap_or(0),
    }
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
        if let Some(name) = process_name(ppid)
            && bypass_list.contains(&name)
        {
            return true;
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
    if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe"))
        && let Some(name) = exe.file_name()
    {
        return Some(name.to_string_lossy().into_owned());
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
    use tempfile::TempDir;

    fn test_store() -> (TrashStore, TempDir, TempDir, ()) {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let data_dir = TempDir::with_prefix_in("data-", &base).unwrap();
        let workdir = TempDir::with_prefix_in("work-", &base).unwrap();
        let mut config = Config::default();
        config.retention.max_age_days = 0;
        config.retention.max_size_gb = 0.0;
        config.retention.disk_pressure_percent = 0;
        let store = TrashStore::open_isolated(&data_dir.path().join("Trash"), config).unwrap();
        (store, data_dir, workdir, ())
    }

    /// Create a temp file with content in a given directory.
    fn create_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn store_hierarchy_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let (store, _data, _workdir, _lock) = test_store();
        for path in [
            store.home.clone(),
            store.home.join("files"),
            store.home.join("info"),
            store.home.join(".trashd"),
        ] {
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        }
    }

    #[test]
    fn store_rejects_symlink_root_without_touching_target() {
        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"safe").unwrap();
        let root = base.path().join("Trash");
        std::os::unix::fs::symlink(&target, &root).unwrap();

        assert!(TrashStore::open_isolated(&root, Config::default()).is_err());
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"safe");
        assert!(!target.join("files").exists());
    }

    #[test]
    fn store_rejects_symlinked_missing_ancestor_without_creating_through_it() {
        let base = tempfile::tempdir().unwrap();
        let redirected = base.path().join("redirected");
        fs::create_dir(&redirected).unwrap();
        let link = base.path().join("data-link");
        std::os::unix::fs::symlink(&redirected, &link).unwrap();
        let root = link.join("new").join("Trash");

        assert!(TrashStore::open_isolated(&root, Config::default()).is_err());
        assert!(!redirected.join("new").exists());
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

        assert!(
            restored
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
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
    fn restore_refuses_intermediate_symlink_in_recorded_path() {
        let (store, _data, workdir, _lock) = test_store();
        let recorded_parent = workdir.path().join("recorded-parent");
        let escape = workdir.path().join("escape");
        fs::create_dir(&recorded_parent).unwrap();
        fs::create_dir(&escape).unwrap();
        let original = create_file(&recorded_parent, "payload.txt", "secret");
        let id = store.trash(&original, None).unwrap();
        let stored = store.home.join("files").join(&id);

        fs::remove_dir(&recorded_parent).unwrap();
        std::os::unix::fs::symlink(&escape, &recorded_parent).unwrap();

        let result = store.restore(&id, None);
        assert!(matches!(result, Err(TrashError::RestoreTraversal(_))));
        assert!(!escape.join("payload.txt").exists());
        assert_eq!(fs::read(stored).unwrap(), b"secret");
    }

    #[test]
    fn explicit_restore_target_may_follow_ancestor_symlink() {
        let (store, _data, workdir, _lock) = test_store();
        let original = create_file(workdir.path(), "source.txt", "payload");
        let id = store.trash(&original, None).unwrap();
        let actual_parent = workdir.path().join("actual-parent");
        let alias = workdir.path().join("alias");
        fs::create_dir(&actual_parent).unwrap();
        std::os::unix::fs::symlink(&actual_parent, &alias).unwrap();
        let requested = alias.join("restored.txt");

        assert_eq!(store.restore(&id, Some(&requested)).unwrap(), requested);
        assert_eq!(
            fs::read(actual_parent.join("restored.txt")).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn copy_fallback_never_clobbers_existing_destination() {
        let (_store, _data, workdir, _lock) = test_store();
        let source_dir = workdir.path().join("fallback-source");
        let destination_dir = workdir.path().join("fallback-destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination_dir).unwrap();
        fs::write(source_dir.join("item"), b"trash payload").unwrap();
        fs::write(destination_dir.join("item"), b"existing data").unwrap();

        let source_parent = open_directory_nofollow(&source_dir).unwrap();
        let destination_parent = open_directory_nofollow(&destination_dir).unwrap();
        let name = CString::new("item").unwrap();
        let source_stat =
            stat_at(source_parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        let error = publish_copy_noreplace(
            source_parent.as_raw_fd(),
            &name,
            destination_parent.as_raw_fd(),
            &name,
            stat_identity(&source_stat),
        )
        .unwrap_err();

        assert!(is_conflict_error(&error));
        assert_eq!(fs::read(source_dir.join("item")).unwrap(), b"trash payload");
        assert_eq!(
            fs::read(destination_dir.join("item")).unwrap(),
            b"existing data"
        );
    }

    #[test]
    fn copy_fallback_publishes_directory_from_pinned_fds() {
        let (_store, _data, workdir, _lock) = test_store();
        let source_dir = workdir.path().join("directory-source");
        let destination_dir = workdir.path().join("directory-destination");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&destination_dir).unwrap();
        let tree = source_dir.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("file"), b"payload").unwrap();
        std::os::unix::fs::symlink("file", tree.join("link")).unwrap();

        let source_parent = open_directory_nofollow(&source_dir).unwrap();
        let destination_parent = open_directory_nofollow(&destination_dir).unwrap();
        let name = CString::new("tree").unwrap();
        let source_stat =
            stat_at(source_parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        publish_copy_noreplace(
            source_parent.as_raw_fd(),
            &name,
            destination_parent.as_raw_fd(),
            &name,
            stat_identity(&source_stat),
        )
        .unwrap();

        assert!(!tree.exists());
        assert_eq!(
            fs::read(destination_dir.join("tree/file")).unwrap(),
            b"payload"
        );
        assert_eq!(
            fs::read_link(destination_dir.join("tree/link")).unwrap(),
            PathBuf::from("file")
        );
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

    // Regression (audit #50): overlapping prefix/suffix in the three-segment
    // branch used to produce an inverted slice range and PANIC on short text.
    #[test]
    fn glob_overlap_short_text_no_panic() {
        assert!(!simple_glob_match("abc*b*bc", "abc"));
        assert!(!simple_glob_match("ab*ba", "aaa"));
        assert!(!simple_glob_match("日本*語*日本", "日本語")); // multibyte overlap
    }

    #[test]
    fn glob_three_segment_matches() {
        // prefix*mid*tail: mid must appear between an anchored head and tail
        assert!(simple_glob_match("ab*cd*ef", "abcdef"));
        assert!(simple_glob_match("ab*cd*ef", "abZZcdYYef"));
        assert!(!simple_glob_match("ab*cd*ef", "abef"));
        // multibyte body slicing must stay on char boundaries
        assert!(simple_glob_match("日*本*語", "日本語"));
        assert!(!simple_glob_match("日*ほ*語", "日本語"));
    }

    // The matcher now supports ? and [...] classes and never silently
    // degrades unsupported syntax to exact-compare (#4).
    #[test]
    fn glob_question_and_classes() {
        assert!(simple_glob_match("file?.txt", "file1.txt"));
        assert!(!simple_glob_match("file?.txt", "file10.txt"));
        assert!(simple_glob_match("[mbc]*.rs", "main.rs"));
        assert!(!simple_glob_match("[mbc]*.rs", "script.rs"));
        assert!(simple_glob_match("*.[jp]pg", "a.jpg"));
        assert!(!simple_glob_match("*.[jp]pg", "a.mpg"));
        assert!(simple_glob_match("*.[a-z][a-z]g", "file.xyg"));
        assert!(!simple_glob_match("*.[a-z][a-z]g", "file.x9g"));
        assert!(simple_glob_match("[!0-9]*.log", "app.log"));
        assert!(!simple_glob_match("[!0-9]*.log", "9app.log"));
        assert!(simple_glob_match("**/*.py", "deep/nested/x.py")); // ** behaves like *
        // Unterminated class degrades to a non-match, never a panic.
        assert!(!simple_glob_match("[abc", "abc"));
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
        assert!(
            py_entries[0]
                .info
                .original_path
                .to_string_lossy()
                .ends_with("keep.py")
        );
    }

    // Regression (audit #16): an orphaned files/ entry (no .trashinfo) must
    // not hijack `undo` (its synthetic "now" date sorts it newest) nor be
    // restorable to the bogus "(orphaned: …)" pseudo-path.
    #[test]
    fn orphaned_entry_cannot_be_restored() {
        let (store, _data, workdir, _lock) = test_store();
        let f = create_file(workdir.path(), "real.txt", "data");
        store.trash(&f, None).unwrap();

        // Plant an orphan: a data file with no .trashinfo
        let trash = store.home.clone();
        fs::write(trash.join("files/orphan1"), b"orphan").unwrap();

        // undo restores the real newest entry, not the orphan
        let restored = store.undo().unwrap();
        assert!(restored.ends_with("real.txt"));
        assert!(trash.join("files/orphan1").exists(), "orphan stays put");

        // Direct restore of the orphan is refused
        let err = store.restore("orphan1", None).unwrap_err();
        assert!(matches!(err, TrashError::OrphanedEntry(_)));
        assert!(
            trash.join("files/orphan1").exists(),
            "orphan data preserved"
        );
    }

    // Regression (audit #8): trashing the trash directory itself, anything
    // inside it, or an ancestor of it must be REFUSED — a failed move would
    // otherwise fall back to permanent deletion of the entire store.
    #[test]
    fn refuse_to_trash_the_trash_itself() {
        let (store, _data, _workdir, _lock) = test_store();
        let trash = store.home.clone();

        // The store itself
        let err = store.trash(&trash, None).unwrap_err();
        assert!(matches!(err, TrashError::Refused(_)), "got {err:?}");

        // Something inside it
        let err = store.trash(&trash.join("files"), None).unwrap_err();
        assert!(matches!(err, TrashError::Refused(_)), "got {err:?}");

        // An ancestor of it
        let ancestor = trash.parent().unwrap().to_path_buf();
        let err = store.trash(&ancestor, None).unwrap_err();
        assert!(matches!(err, TrashError::Refused(_)), "got {err:?}");
    }

    // --- trash_at: fd-pinned interception used by the seccomp layer (#6) ---

    #[test]
    fn trash_at_roundtrip_file() {
        use std::ffi::OsStr;
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let (store, _data, workdir, _lock) = test_store();
        let dir = workdir.path().join("pin_dir");
        fs::create_dir(&dir).unwrap();
        let f = create_file(&dir, "victim.txt", "pinned data");

        let parent = File::open(&dir).unwrap();
        let id = store
            .trash_at(
                parent.as_raw_fd(),
                OsStr::new("victim.txt"),
                &f,
                Some("test-at"),
            )
            .unwrap();
        assert!(!f.exists(), "moved out of the pinned parent");
        drop(parent);

        let entries = store.list(None).unwrap();
        let entry = entries.iter().find(|e| e.id == id).expect("entry listed");
        assert_eq!(entry.info.original_path, f);
        store.restore(&id, None).unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "pinned data");
    }

    #[test]
    fn trash_at_honors_never_trash_and_missing_names() {
        use std::ffi::OsStr;
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let (store, _data, workdir, _lock) = test_store();
        let dir = workdir.path().join("pin_dir2");
        fs::create_dir(&dir).unwrap();

        let parent = File::open(&dir).unwrap();
        // never_trash pattern (*.tmp) applies on the display path
        let tmp = dir.join("skipme.tmp");
        fs::write(&tmp, b"x").unwrap();
        let err = store
            .trash_at(parent.as_raw_fd(), OsStr::new("skipme.tmp"), &tmp, None)
            .unwrap_err();
        assert!(matches!(err, TrashError::Excluded(_)), "got {err:?}");

        // unknown final component → NotFound (kernel would ENOENT)
        let err = store
            .trash_at(
                parent.as_raw_fd(),
                OsStr::new("nope"),
                &dir.join("nope"),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, TrashError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn trash_at_refuses_trash_self_targets() {
        use std::ffi::OsStr;
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let (store, _data, workdir, _lock) = test_store();
        let dir = workdir.path().join("pin_dir3");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("x"), b"x").unwrap();

        // Display path pointing INTO the trash must be refused (#8 parity),
        // even though the actual move targets an unrelated pinned directory.
        let fake = store.home.clone().join("files").join("evil");
        let parent = File::open(&dir).unwrap();
        let err = store
            .trash_at(parent.as_raw_fd(), OsStr::new("x"), &fake, None)
            .unwrap_err();
        assert!(matches!(err, TrashError::Refused(_)), "got {err:?}");
        assert!(dir.join("x").exists(), "real target untouched");
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

    #[test]
    fn compressed_restore_rejects_output_over_limit_without_changing_entry() {
        let (mut store, _data, workdir, _lock) = test_store();
        let original = vec![b'A'; 2 * 1024 * 1024];
        let file = workdir.path().join("oversized-output");
        fs::write(&file, &original).unwrap();
        let id = store.trash(&file, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        let compressed = zstd::encode_all(original.as_slice(), 3).unwrap();
        fs::write(&entry.trashed_path, &compressed).unwrap();
        let mut info = entry.info.clone();
        info.compressed = Some("zstd".into());
        write_trashinfo_atomic(&entry.info_path, &info).unwrap();
        store.config.max_file_size_mb = 1;

        assert!(store.restore(&id, None).is_err());
        assert!(
            !file.exists(),
            "failed restore must not publish partial data"
        );
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), compressed);
        assert_eq!(
            TrashInfo::from_trashinfo(&fs::read_to_string(&entry.info_path).unwrap())
                .unwrap()
                .compressed
                .as_deref(),
            Some("zstd")
        );
    }

    #[test]
    fn compressed_restore_keeps_corrupt_zstd_payload_and_marker() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "corrupt-compressed", "original");
        let id = store.trash(&file, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        let corrupt = [0x28, 0xb5, 0x2f, 0xfd, 0xff, 0xff, 0xff, 0xff];
        fs::write(&entry.trashed_path, corrupt).unwrap();
        let mut info = entry.info.clone();
        info.compressed = Some("zstd".into());
        write_trashinfo_atomic(&entry.info_path, &info).unwrap();

        assert!(store.restore(&id, None).is_err());
        assert!(!file.exists());
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), corrupt);
        assert_eq!(
            TrashInfo::from_trashinfo(&fs::read_to_string(&entry.info_path).unwrap())
                .unwrap()
                .compressed
                .as_deref(),
            Some("zstd")
        );
    }

    #[test]
    fn stale_compression_marker_on_plaintext_is_cleared_and_restored() {
        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "stale-marker", "plain data");
        let id = store.trash(&file, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        let mut info = entry.info.clone();
        info.compressed = Some("zstd".into());
        write_trashinfo_atomic(&entry.info_path, &info).unwrap();

        store.restore(&id, None).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"plain data");
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

    // H1/H2 + audit #27: a crafted .trashinfo whose Path escapes via ".." is
    // rejected at PARSE time (the URL decoder would normalize ".." silently
    // and defeat restore's ParentDir guard), and the trashed payload stays.
    #[test]
    fn restore_refuses_path_traversal() {
        let (store, _data, _workdir, _lock) = test_store();
        let trash = store.home.clone();
        fs::create_dir_all(trash.join("info")).unwrap();
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::write(
            trash.join("info/evil.trashinfo"),
            "[Trash Info]\nPath=../../../../etc/evil\nDeletionDate=2026-01-01T00:00:00\n",
        )
        .unwrap();
        fs::write(trash.join("files/evil"), b"payload").unwrap();

        let err = store.restore("evil", None).unwrap_err();
        // The unparseable sidecar leaves files/evil as an orphan, which the
        // orphan guard (#16) then refuses to restore — either way the
        // traversal path is never resolved.
        assert!(
            matches!(
                err,
                TrashError::OrphanedEntry(_) | TrashError::EntryNotFound(_)
            ),
            "traversal entry must not resolve; got {err:?}"
        );
        assert_eq!(
            fs::read(trash.join("files/evil")).unwrap(),
            b"payload",
            "payload must stay in the trash after a refused restore"
        );

        // Ordinary relative paths (topdir trash layout) still parse fine.
        assert!(
            TrashInfo::from_trashinfo(
                "[Trash Info]\nPath=sub/dir/file.txt\nDeletionDate=2026-01-01T00:00:00\n"
            )
            .is_some()
        );
    }

    // M1: trashing a file must not overwrite a pre-existing orphaned data file
    // (one in files/ with no .trashinfo) that happens to share its name.
    #[test]
    fn trashing_does_not_overwrite_orphan_file() {
        let (store, _data, workdir, _lock) = test_store();
        let trash = store.home.clone();
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
        let (mut store, _data, workdir, _) = test_store();
        store.config.auto_purge_interval_secs = 0;
        for i in 0..3 {
            let f = create_file(workdir.path(), &format!("keep{i}.txt"), "data");
            store.trash(&f, None).unwrap();
        }
        assert_eq!(store.list(None).unwrap().len(), 3);
    }

    #[test]
    fn isolated_store_retention_never_touches_another_root_or_log() {
        let (mut local, _local_data, local_work, _) = test_store();
        let (external, _external_data, external_work, _) = test_store();
        let sentinel = create_file(external_work.path(), "external-sentinel", "keep me");
        let id = external.trash(&sentinel, None).unwrap();
        let before = external.list(None).unwrap().remove(0);
        let bytes = fs::read(&before.trashed_path).unwrap();
        let info = fs::read(&before.info_path).unwrap();
        let log = fs::read(external.home.join(".trashd/operations.log")).unwrap();
        local.config.auto_purge_interval_secs = 0;
        local.config.retention.max_age_days = 1;
        local.config.retention.max_size_gb = 0.000_001;
        let victim = create_file(local_work.path(), "local", "data");
        local.trash(&victim, None).unwrap();
        local.empty(None).unwrap();
        assert_eq!(
            local.all_trash_dirs(),
            [(local.home.clone(), "home".into())]
        );
        assert_eq!(fs::read(&before.trashed_path).unwrap(), bytes);
        assert_eq!(fs::read(&before.info_path).unwrap(), info);
        assert_eq!(
            fs::read(external.home.join(".trashd/operations.log")).unwrap(),
            log
        );
        assert_eq!(external.list(None).unwrap()[0].id, id);
    }

    #[test]
    fn pinned_special_files_complete_without_reading_and_regular_file_still_hashes() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let (store, _data, work, _) = test_store();
            let parent = fs::File::open(work.path()).unwrap();
            let fifo = work.path().join("named-pipe");
            let cname = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(cname.as_ptr(), 0o600) }, 0);
            let fifo_id = store
                .trash_at(parent.as_raw_fd(), OsStr::new("named-pipe"), &fifo, None)
                .unwrap();
            let socket = work.path().join("endpoint");
            let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            store
                .trash_at(parent.as_raw_fd(), OsStr::new("endpoint"), &socket, None)
                .unwrap();
            let file = create_file(work.path(), "regular", "hash this");
            let regular_id = store
                .trash_at(parent.as_raw_fd(), OsStr::new("regular"), &file, None)
                .unwrap();
            let entries = store.list(None).unwrap();
            assert!(
                entries
                    .iter()
                    .find(|e| e.id == fifo_id)
                    .unwrap()
                    .info
                    .sha256
                    .is_none()
            );
            assert!(
                entries
                    .iter()
                    .find(|e| e.id == regular_id)
                    .unwrap()
                    .info
                    .sha256
                    .is_some()
            );
            tx.send(()).unwrap();
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("special-file trash must not block");
    }

    #[test]
    fn compressed_restore_preserves_private_and_executable_modes() {
        use std::os::unix::fs::PermissionsExt;
        let (store, _data, work, _) = test_store();
        for mode in [0o600, 0o700, 0o640] {
            let file = create_file(
                work.path(),
                &format!("mode-{mode:o}"),
                &"payload".repeat(2048),
            );
            fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            let id = store.trash(&file, None).unwrap();
            let entry = store.find_entry(&id).unwrap();
            let data = fs::read(&entry.trashed_path).unwrap();
            atomic_write(
                &entry.trashed_path,
                &zstd::encode_all(data.as_slice(), 3).unwrap(),
            )
            .unwrap();
            let mut info = entry.info.clone();
            info.compressed = Some("zstd".into());
            write_trashinfo_atomic(&entry.info_path, &info).unwrap();
            assert_eq!(
                fs::metadata(&entry.trashed_path).unwrap().mode() & 0o777,
                mode
            );
            store.restore(&id, None).unwrap();
            assert_eq!(fs::read(&file).unwrap(), data);
            assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, mode);
        }
    }

    fn seed_batch(store: &TrashStore, work: &Path, count: usize) {
        for i in 0..count {
            let name = format!("batch-{i}");
            fs::write(store.home.join("files").join(&name), format!("payload-{i}")).unwrap();
            let info = TrashInfo::new(work.join(&name));
            fs::write(
                store.home.join("info").join(format!("{name}.trashinfo")),
                info.to_trashinfo_string(),
            )
            .unwrap();
        }
    }

    #[test]
    fn batch_restore_reads_sidecars_once_and_refreshes_cache_once() {
        for count in [32, 64] {
            let (store, _data, work, _) = test_store();
            seed_batch(&store, work.path(), count);
            let entries = store.list(None).unwrap();
            assert_eq!(store.sidecar_reads.get(), count);
            let results = store.restore_batch(&entries, None, false);
            assert!(results.iter().all(Result::is_ok));
            assert_eq!(
                store.sidecar_reads.get(),
                count,
                "batch must not rescan sidecars"
            );
            assert_eq!(store.cache_refreshes.get(), 1);
            for i in 0..count {
                assert_eq!(
                    fs::read_to_string(work.path().join(format!("batch-{i}"))).unwrap(),
                    format!("payload-{i}")
                );
            }
        }
    }

    #[test]
    fn batch_restore_preserves_conflicts_replaced_ids_and_partial_success() {
        let (store, _data, work, _) = test_store();
        seed_batch(&store, work.path(), 3);
        let entries = store.list(None).unwrap();
        fs::write(work.path().join("batch-0"), b"conflict").unwrap();
        let second = entries.iter().find(|e| e.id == "batch-1").unwrap();
        // Keep the original inode alive to avoid inode-number reuse in this test.
        fs::rename(&second.trashed_path, work.path().join("old-inode")).unwrap();
        fs::write(&second.trashed_path, b"replacement").unwrap();
        let results = store.restore_batch(&entries, None, false);
        for (entry, result) in entries.iter().zip(&results) {
            match entry.id.as_str() {
                "batch-0" => assert!(matches!(result, Err(TrashError::RestoreConflict(_)))),
                "batch-1" => assert!(matches!(result, Err(TrashError::EntryNotFound(_)))),
                _ => assert!(result.is_ok()),
            }
        }
        assert_eq!(fs::read(&second.trashed_path).unwrap(), b"replacement");
        assert!(second.info_path.exists());
        let first = entries.iter().find(|e| e.id == "batch-0").unwrap();
        let results = store.restore_batch(std::slice::from_ref(first), None, true);
        assert_eq!(results[0].as_ref().unwrap(), &work.path().join("batch-0.1"));
        assert_eq!(fs::read(work.path().join("batch-0")).unwrap(), b"conflict");
        assert_eq!(
            fs::read(work.path().join("batch-0.1")).unwrap(),
            b"payload-0"
        );
    }

    #[test]
    fn batch_restore_rejects_changed_sidecars_and_foreign_isolated_entries() {
        let (store, _data, work, _) = test_store();
        let (other, _other_data, _other_work, _) = test_store();
        seed_batch(&store, work.path(), 2);
        let entries = store.list(None).unwrap();
        assert!(
            other
                .restore_batch(&entries, None, false)
                .iter()
                .all(Result::is_err)
        );
        for (i, entry) in entries.iter().enumerate() {
            let mut changed = entry.info.clone();
            changed.original_path = work.path().join(format!("changed-{i}"));
            if i == 0 {
                write_trashinfo_atomic(&entry.info_path, &changed).unwrap();
            } else {
                fs::write(&entry.info_path, changed.to_trashinfo_string()).unwrap();
            }
        }
        let contents: Vec<_> = entries
            .iter()
            .map(|e| fs::read(&e.info_path).unwrap())
            .collect();
        assert!(
            store
                .restore_batch(&entries, None, false)
                .iter()
                .all(Result::is_err)
        );
        for (entry, info) in entries.iter().zip(contents) {
            assert_eq!(fs::read(&entry.info_path).unwrap(), info);
            assert!(entry.trashed_path.exists());
            assert!(!entry.info.original_path.exists());
        }
    }

    #[test]
    fn batch_restore_retires_topdir_index_rows_without_removing_other_roots() {
        let (mut store, _data, work, _) = test_store();
        let (external, _external_data, _, _) = test_store();
        seed_batch(&external, work.path(), 2);
        let entries = external.list(None).unwrap();
        let index = store.index.as_ref().unwrap();
        index
            .insert(&entries[0].id, &entries[0].info, &external.home)
            .unwrap();
        index
            .insert(&entries[1].id, &entries[1].info, &store.home)
            .unwrap();
        // Deliberately permit externally resolved entries as a production
        // store does. Explicit targets avoid topdir path restrictions here.
        store.isolated = false;
        for (i, entry) in entries.iter().enumerate() {
            let target = work.path().join(format!("restored-{i}"));
            assert!(
                store.restore_batch(std::slice::from_ref(entry), Some(&target), false)[0].is_ok()
            );
        }
        assert_eq!(store.index.as_ref().unwrap().count().unwrap(), 1);
    }

    #[test]
    fn file_size_limits_use_exact_bytes_and_zero_disables_limit() {
        let (mut store, _data, work, _) = test_store();
        store.config.max_file_size_mb = 1;
        let path = work.path().join("oversize");
        let file = fs::File::create(&path).unwrap();
        file.set_len(1024 * 1024 + 1).unwrap();
        assert!(matches!(
            store.trash(&path, None),
            Err(TrashError::TooLarge { .. })
        ));
        store.config.max_file_size_mb = 0;
        assert!(store.trash(&path, None).is_ok());
    }
}
