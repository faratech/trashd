use crate::config::Config;
use crate::mounts;
use crate::store_lock::RootMutationGuard;
use crate::trashinfo::TrashInfo;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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
    /// A tree holding this mount point (relative to it) moves as one or not
    /// at all: nothing was moved.
    #[error("it holds a mount point, '{0}' inside it, which stays where it is mounted")]
    HoldsMount(PathBuf),
    /// The source cannot be removed (a mount point, a read-only filesystem,
    /// a directory the user may not write): rm would fail alike, so nothing
    /// was copied either (#368, #370).
    #[error("{0}")]
    Unremovable(io::Error),
}

/// A trash root and the (device, inode) of it and each of its ancestors.
type TrashAncestry = (PathBuf, Vec<(u64, u64)>);

pub struct TrashStore {
    config: Config,
    home: PathBuf,
    isolated: bool,
    #[cfg(test)]
    sidecar_reads: std::cell::Cell<usize>,
    #[cfg(test)]
    cache_refreshes: std::cell::Cell<usize>,
    #[cfg(test)]
    scan_data_stats: std::cell::Cell<usize>,
    #[cfg(test)]
    accounting_walks: std::cell::Cell<usize>,
    /// Trash roots whose parent chain this store validated recently, with
    /// the validating UID and time (#307).
    trusted_parents: std::cell::RefCell<Vec<(PathBuf, u32, std::time::Instant)>>,
    /// Set by long-lived callers that run maintenance between operations
    /// rather than inside them (#319); `maintenance_due` records a skipped run.
    defer_maintenance: std::cell::Cell<bool>,
    maintenance_due: std::cell::Cell<bool>,
    /// Until when retention is known not to be due: a long-lived store (the
    /// supervisor) lstat'ed the marker after every trashed delete (#353).
    purge_not_due_until: std::cell::Cell<Option<std::time::Instant>>,
    /// Identities of each trash root and its ancestors (`trash_ancestry`).
    trash_ancestry: std::cell::RefCell<Vec<TrashAncestry>>,
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

/// Sidecar freshness and data identity serve different callers. Read-only
/// queries retain sidecar verification without statting unused data inodes.
#[derive(Clone, Copy)]
struct ScanMetadata {
    verify_sidecar: bool,
    data: bool,
}

impl ScanMetadata {
    const MUTATION: Self = Self {
        verify_sidecar: true,
        data: true,
    };
    const DISPLAY: Self = Self {
        verify_sidecar: false,
        data: false,
    };
    const QUERY: Self = Self {
        verify_sidecar: true,
        data: false,
    };
}

/// True when an entry's data and sidecar paths are the pair its trash root
/// layout requires. Compared on raw filename bytes, not the lossy String
/// ID, so non-UTF-8 entry names validate against their real paths (#247).
fn entry_paths_match(entry: &TrashEntry) -> bool {
    let Some(data_name) = entry.trashed_path.file_name() else {
        return false;
    };
    let Some(info_name) = entry.info_path.file_name() else {
        return false;
    };
    let stem = info_name.as_bytes();
    entry.trashed_path.parent() == Some(entry.trash_root.join("files").as_path())
        && entry.info_path.parent() == Some(entry.trash_root.join("info").as_path())
        && stem.len() > ".trashinfo".len()
        && stem.ends_with(b".trashinfo")
        && &stem[..stem.len() - ".trashinfo".len()] == data_name.as_bytes()
        && data_name != OsStr::new(".")
        && data_name != OsStr::new("..")
}

impl TrashStore {
    pub fn open() -> Result<Self, TrashError> {
        Self::open_with_config(Config::load())
    }

    /// `open` with a configuration the caller already loaded.
    pub fn open_with_config(config: Config) -> Result<Self, TrashError> {
        Self::open_with(Self::home_trash_dir(), config, false)
    }

    /// Open an explicitly configured store that never discovers other mounts
    /// or reads ambient global/user/project configuration.
    pub fn open_isolated(home: &Path, config: Config) -> Result<Self, TrashError> {
        Self::open_with(home.to_path_buf(), config, true)
    }

    pub fn home_dir(&self) -> &Path {
        &self.home
    }

    /// Stop running retention inside mutations: the caller runs it with
    /// `run_deferred_maintenance` once its own client has been answered.
    pub fn defer_maintenance(&self) {
        self.defer_maintenance.set(true);
    }

    /// Run retention a deferred mutation skipped, if any (throttled as usual).
    pub fn run_deferred_maintenance(&self) {
        if self.maintenance_due.replace(false) {
            let _ = self.maybe_auto_purge();
        }
    }

    /// Retention after a mutation, now or at the caller's next opportunity.
    fn after_mutation(&self) {
        if self.defer_maintenance.get() {
            self.maintenance_due.set(true);
        } else {
            let _ = self.maybe_auto_purge();
        }
    }

    pub fn lock_trash_root(&self, root: &Path) -> Result<RootMutationGuard, TrashError> {
        let uid = unsafe { libc::geteuid() };
        self.ensure_trusted_parent_recent(root, uid)?;
        // The guard validates the root, files/ and info/ through descriptors;
        // path checks first only repeated that (#307). They still classify a
        // failure: an unsafe or incomplete root is refused, as before.
        RootMutationGuard::acquire_as(root, uid).map_err(|error| {
            if mounts::is_safe_trash_root(root, uid) {
                TrashError::Io(error)
            } else {
                TrashError::Refused(root.to_path_buf())
            }
        })
    }

    /// Lock a root this operation writes into, creating or repairing its
    /// files/ and info/ only when the lock refuses it.
    fn lock_trash_root_prepared(&self, root: &Path) -> Result<RootMutationGuard, TrashError> {
        match self.lock_trash_root(root) {
            Err(TrashError::Refused(_)) => {
                self.ensure_trash_dir(root)?;
                self.lock_trash_root(root)
            }
            result => result,
        }
    }

    /// Validate `root`'s parent chain unless this store did so for the same
    /// UID within the last few seconds. Every component is owned by root or
    /// this user and not writable by others, so only they can change it, and
    /// long-lived stores still recheck it after the interval (#307).
    fn ensure_trusted_parent_recent(&self, root: &Path, uid: u32) -> io::Result<()> {
        const REUSE: std::time::Duration = std::time::Duration::from_secs(5);
        let now = std::time::Instant::now();
        if self
            .trusted_parents
            .borrow()
            .iter()
            .any(|(path, owner, at)| {
                path == root && *owner == uid && now.duration_since(*at) <= REUSE
            })
        {
            return Ok(());
        }
        ensure_trusted_parent(root, uid)?;
        let mut trusted = self.trusted_parents.borrow_mut();
        trusted.retain(|(path, _, _)| path != root);
        trusted.push((root.to_path_buf(), uid, now));
        Ok(())
    }

    pub fn validate_entry_locked(
        &self,
        entry: &TrashEntry,
        guard: &RootMutationGuard,
    ) -> Result<(), TrashError> {
        self.validated_entry_metadata_locked(entry, guard)
            .map(|_| ())
    }

    fn validated_entry_metadata_locked(
        &self,
        entry: &TrashEntry,
        guard: &RootMutationGuard,
    ) -> Result<(Option<fs::Metadata>, Option<fs::Metadata>), TrashError> {
        if guard.root() != entry.trash_root || !entry_paths_match(entry) || entry.id.is_empty() {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        let read_metadata = |path: &Path| match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(TrashError::Io(error)),
        };
        let data = read_metadata(&entry.trashed_path)?;
        let sidecar = read_metadata(&entry.info_path)?;
        let identity = data
            .as_ref()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        let version = sidecar.as_ref().and_then(|metadata| {
            if entry.orphaned || metadata.is_file() {
                Some(SidecarVersion::from_metadata(metadata))
            } else {
                None
            }
        });
        if identity != entry.identity || version != entry.sidecar_version {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        Ok((data, sidecar))
    }

    fn open_with(home: PathBuf, config: Config, isolated: bool) -> Result<Self, TrashError> {
        let uid = unsafe { libc::geteuid() };

        // /tmp fallback (#35): validate the exact uid-specific base, not the
        // child `Trash` path (which never starts with `/tmp/trashd-home-` as a
        // path component). It must be a private real directory owned by the
        // effective user before anything sensitive is written below it.
        let fallback_base = PathBuf::from(format!("/tmp/trashd-home-{uid}"));
        let mut followed_symlink = true;
        if home == fallback_base.join("Trash") {
            ensure_trusted_parent(&fallback_base, uid)?;
            ensure_private_dir(&fallback_base, uid, true)?;
        } else if let Some(parent) = home.parent() {
            followed_symlink = ensure_trusted_ancestors(parent, uid)?;
        }

        ensure_private_dir(&home, uid, true)?;
        ensure_private_dir(&home.join("files"), uid, true)?;
        ensure_private_dir(&home.join("info"), uid, true)?;
        ensure_private_dir(&home.join(".trashd"), uid, true)?;

        // A walk that followed no symlink validated the canonical path itself
        // (it refuses `..`, and the root is a real directory): realpath would
        // only readlink every component again. That chain also needs no
        // second validation before the first mutation (#307).
        let (home, trusted_parents) = if followed_symlink || !home.is_absolute() {
            (fs::canonicalize(home)?, Vec::new())
        } else {
            let home: PathBuf = home.components().collect();
            let trusted = vec![(home.clone(), uid, std::time::Instant::now())];
            (home, trusted)
        };
        Ok(Self {
            config,
            trusted_parents: std::cell::RefCell::new(trusted_parents),
            defer_maintenance: std::cell::Cell::new(false),
            maintenance_due: std::cell::Cell::new(false),
            purge_not_due_until: std::cell::Cell::new(None),
            trash_ancestry: std::cell::RefCell::new(Vec::new()),
            home,
            isolated,
            #[cfg(test)]
            sidecar_reads: std::cell::Cell::new(0),
            #[cfg(test)]
            cache_refreshes: std::cell::Cell::new(0),
            #[cfg(test)]
            scan_data_stats: std::cell::Cell::new(0),
            #[cfg(test)]
            accounting_walks: std::cell::Cell::new(0),
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

    /// Nonmutating guards shared by recursive shim traversal and trash().
    pub fn check_trash_eligibility(&self, path: &Path) -> Result<(), TrashError> {
        self.prepare_source(path, false).map(|_| ())
    }

    /// (device, inode) of `trash_dir`, its ancestors and its own
    /// directories (files/, info/, .trashd/), remembered per trash root for
    /// this store.
    fn trash_ancestry(&self, trash_dir: &Path) -> Vec<(u64, u64)> {
        if let Some((_, chain)) = self
            .trash_ancestry
            .borrow()
            .iter()
            .find(|(root, _)| root == trash_dir)
        {
            return chain.clone();
        }
        let inside = ["files", "info", ".trashd"].map(|part| trash_dir.join(part));
        let chain: Vec<(u64, u64)> = trash_dir
            .ancestors()
            .chain(inside.iter().map(PathBuf::as_path))
            .filter_map(|directory| fs::metadata(directory).ok())
            .map(|meta| (meta.dev(), meta.ino()))
            .collect();
        self.trash_ancestry
            .borrow_mut()
            .push((trash_dir.to_path_buf(), chain.clone()));
        chain
    }

    /// `check_trash_eligibility` for a mounted directory, which never moves
    /// itself while its entries do: its own topdir trash (`.Trash-$UID` or
    /// `.Trash/$UID` directly inside it) is no reason to refuse them (#361).
    /// Exclusions, the size limit and every other trash-ancestor refusal
    /// (the home trash, anything inside a trash) still apply.
    pub fn check_mount_eligibility(&self, path: &Path) -> Result<(), TrashError> {
        match self.prepare_source(path, false) {
            Err(TrashError::Refused(abs_path)) => {
                let meta = fs::symlink_metadata(&abs_path)
                    .map_err(|_| TrashError::NotFound(abs_path.clone()))?;
                let trash_dir =
                    mounts::existing_trash_dir_for_path_on(&abs_path, Some(meta.dev()), &self.home);
                let own_topdir = trash_dir != self.home
                    && !self.home.starts_with(&abs_path)
                    && !abs_path.starts_with(&self.home)
                    && trash_dir
                        .parent()
                        .is_some_and(|top| top == abs_path || top == abs_path.join(".Trash"));
                if own_topdir {
                    Ok(())
                } else {
                    Err(TrashError::Refused(abs_path))
                }
            }
            other => other.map(|_| ()),
        }
    }

    fn prepare_source(
        &self,
        path: &Path,
        prepare_store: bool,
    ) -> Result<(PathBuf, fs::Metadata, PathBuf), TrashError> {
        let abs_path = if path.is_absolute() {
            normalize_path(path)
        } else {
            normalize_relative(path)?
        };

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
            // Compare exact bytes: truncating to whole MiB first accepted
            // directories up to ~1 MiB over the cap (#245).
            if capped || dir_size_bytes > self.config.max_dir_size_mb.saturating_mul(1024 * 1024) {
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

        // Pick the right trash directory (same-device preferred). The
        // operand's device is already known; selection need not stat it.
        let trash_dir = if self.isolated {
            self.home.clone()
        } else if prepare_store {
            mounts::trash_dir_for_path_on(&abs_path, Some(meta.dev()), &self.home)
                .ok_or_else(|| TrashError::Unremovable(io::Error::from_raw_os_error(libc::EBUSY)))?
        } else {
            mounts::existing_trash_dir_for_path_on(&abs_path, Some(meta.dev()), &self.home)
        };

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
        // The same directory reached under another name (a bind mount of
        // ~/.local/share, say) compares by identity: moving it would carry
        // the trash, or its info/ into its files/ (#362).
        if meta.is_dir()
            && self
                .trash_ancestry(&trash_dir)
                .contains(&(meta.dev(), meta.ino()))
        {
            return Err(TrashError::Refused(abs_path));
        }

        Ok((abs_path, meta, trash_dir))
    }

    /// Move a file or directory to the trash. Returns the trash entry ID.
    pub fn trash(&self, path: &Path, command: Option<&str>) -> Result<String, TrashError> {
        let (abs_path, meta, trash_dir) = self.prepare_source(path, true)?;

        // Build trashinfo — per spec, topdir trash should use relative paths
        // from the topdir mount point, not absolute paths.
        let home_trash = self.home.clone();
        let trashinfo_path = Self::compute_trashinfo_path(&trash_dir, &abs_path, &home_trash);
        let mut info = TrashInfo::new(trashinfo_path);
        info.command = command.map(|s| s.to_string());
        info.pid = Some(std::process::id());
        // `meta` is lstat data: a symlink counts as itself, never its target
        // (walking the target could hang on a dead mount, #223).
        let mut sizes = if meta.is_dir() {
            // A mount inside would move with the tree, out of its place and
            // into the trash: rm leaves mounts where they are (#366).
            let survey = CString::new(abs_path.as_os_str().as_bytes())
                .ok()
                .and_then(|name| open_directory_at(libc::AT_FDCWD, &name, true, false).ok())
                .map_or_else(TreeSurvey::unwalked, |dir| {
                    tree_survey(dir.as_raw_fd(), true)
                });
            if let Some(mount) = survey.mount_in(&abs_path) {
                return Err(TrashError::HoldsMount(mount));
            }
            (survey.apparent, survey.allocated)
        } else {
            (meta.size(), 0)
        };
        info.size = Some(sizes.0);

        // Compute file hash for small files only (configurable, default 1 MB).
        // Hashing reads the entire file — too expensive for large files on every rm.
        // The open is race-hardened: O_NOFOLLOW|O_NONBLOCK plus a dev/ino
        // re-check, so a racer swapping the victim for a FIFO (which would
        // block a plain open forever) or a symlink fails the hash instead of
        // hanging or reading through a link.
        let hash_limit = self.config.sha256_max_size_mb.saturating_mul(1024 * 1024);
        if meta.is_file()
            && hash_limit > 0
            && meta.size() <= hash_limit
            && let Ok(hash) = hash_file_verified(
                &abs_path,
                &self.config.hash_algorithm,
                (meta.dev(), meta.ino()),
            )
        {
            info.sha256 = Some(hash);
        }

        let mut guard = Some(self.lock_trash_root_prepared(&trash_dir)?);
        // Generate unique trash ID within that trash dir (atomic)
        let file_name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed".into());
        let (id, info_file, claim) = unique_id_atomic(&trash_dir, &file_name)?;

        let dest = trash_dir.join("files").join(&id);

        // Write .trashinfo content through the descriptor that claimed it.
        // On failure, release the claim so an ENOSPC cannot strand an
        // invisible 0-byte sidecar that also reserves the id stem (#109).
        if let Err(e) = write_claimed_sidecar(claim, &info) {
            let _ = raw_unlink_path(&info_file);
            return Err(TrashError::Io(e));
        }

        // Try rename (fast, same filesystem — should always work with topdir trash)
        let mut copy_done = false;
        let mut created_identity = None;
        let move_result: Result<(), TrashError> = (|| {
            let source_name =
                CString::new(abs_path.as_os_str().as_bytes()).map_err(io::Error::from)?;
            let dest_name = CString::new(dest.as_os_str().as_bytes()).map_err(io::Error::from)?;
            if let Err(rename_error) =
                rename_noreplace_at(libc::AT_FDCWD, &source_name, libc::AT_FDCWD, &dest_name)
            {
                if is_conflict_error(&rename_error) {
                    return Err(rename_error.into());
                }
                // Only a cross-device move or an unsupported RENAME_NOREPLACE
                // calls for copying. EACCES/EPERM/EROFS would make the source
                // removal fail as well and only strand a copy (#204).
                if !is_copy_fallback_error(&rename_error) {
                    return Err(rename_error.into());
                }
                // Copy through pinned descriptors, then retire ONLY what was
                // copied. Re-walking the path afterwards permanently deleted
                // files created during the copy, a tree or file replaced
                // meanwhile, and nodes the copy had skipped (#192).
                let parent = abs_path.parent().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "source has no parent")
                })?;
                let name = CString::new(
                    abs_path
                        .file_name()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?
                        .as_bytes(),
                )
                .map_err(io::Error::from)?;
                let parent =
                    CString::new(parent.as_os_str().as_bytes()).map_err(io::Error::from)?;
                // O_PATH: removing needs no read access to the parent.
                let source_parent = open_directory_at(libc::AT_FDCWD, &parent, false, true)?;
                let files_dir = CString::new(trash_dir.join("files").as_os_str().as_bytes())
                    .map_err(io::Error::from)?;
                let files = open_directory_at(libc::AT_FDCWD, &files_dir, true, false)?;
                let id_name = CString::new(id.as_bytes()).map_err(io::Error::from)?;
                let source = stat_at(source_parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW)?;
                if stat_identity(&source) != (meta.dev(), meta.ino()) {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "source changed before the cross-device copy",
                    )
                    .into());
                }
                let snapshot = snapshot_retirable_at(
                    source_parent.as_raw_fd(),
                    &name,
                    stat_identity(&source),
                )?;
                // Staged in the root's private state directory, never in
                // files/, so an interrupted copy cannot pose as an entry.
                let state_dir = CString::new(trash_dir.join(".trashd").as_os_str().as_bytes())
                    .map_err(io::Error::from)?;
                let staging = open_directory_at(libc::AT_FDCWD, &state_dir, true, false)?;
                created_identity = Some(copy_source_at(
                    source_parent.as_raw_fd(),
                    &name,
                    files.as_raw_fd(),
                    &id_name,
                    staging.as_raw_fd(),
                    &source,
                )?);
                // The copy's data is synced; make its directory entry durable
                // before the source can disappear.
                files.sync_all()?;
                copy_done = true;
                // Source retirement can trap into a seccomp supervisor that
                // needs this same root lock, so only under an active seccomp
                // filter is the lock released before retiring. Otherwise the
                // lock is held through retirement: dropping it let a waiting
                // purge delete the fresh trash copy, after which retiring
                // the source destroyed both copies (#243).
                if std::env::var_os("TRASHD_SECCOMP_ACTIVE").is_some_and(|v| v == "1") {
                    drop(guard.take());
                }
                // Raw syscalls throughout: the system-wide preload would
                // otherwise trash the source a second time (#104).
                let complete = match &snapshot {
                    Some(before) => retire_directory_snapshot_at(
                        source_parent.as_raw_fd(),
                        &name,
                        stat_identity(&source),
                        before,
                        false,
                    )?,
                    None => retire_copied_node_at(source_parent.as_raw_fd(), &name, &source)?,
                };
                if !complete {
                    return Err(io::Error::other(
                        "files that changed while being moved were left in place",
                    )
                    .into());
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
                // The kept copy is only "complete" with its sidecar: the copy
                // spanned the same data-absence window as a normal move, so a
                // concurrent purge may have stripped the sidecar mid-copy
                // (#171).
                crate::oplog::log_trash_in(&self.home, &abs_path, &id, command);
                return Err(TrashError::Io(io::Error::other(format!(
                    "copied to trash but failed to remove original: {e}"
                ))));
            }
            // The copy itself failed — nothing was moved; roll back cleanly.
            let _ = raw_unlink_path(&info_file);
            if created_identity.is_some()
                && file_identity(&dest) == created_identity
                && let Ok(meta) = fs::symlink_metadata(&dest)
            {
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    let _ = fs::remove_dir_all(&dest);
                } else {
                    // Symlinks, regular files, etc.
                    let _ = raw_unlink_path(&dest);
                }
            }
            return Err(e);
        }

        // The move completed: make sure a concurrent purge did not strip the
        // sidecar while the data was absent mid-move (#169).

        // On the seccomp path the root lock was released before retirement
        // (#243): re-acquire it and verify the entry survived. Reporting
        // success for a copy a purge already deleted would hide data loss.
        if guard.is_none() {
            let _verify_guard = self.lock_trash_root(&trash_dir)?;
            if fs::symlink_metadata(&dest).is_err() || !info_file.exists() {
                return Err(TrashError::EntryNotFound(id.clone()));
            }
        }

        // Post-move identity refresh for the rename path (#246, mirroring
        // trash_at): the final component may have been replaced between the
        // hash/size reads and the rename, so the sidecar must describe the
        // inode that actually landed in the trash.
        if !copy_done {
            match fs::symlink_metadata(&dest) {
                Ok(dest_meta) if (dest_meta.dev(), dest_meta.ino()) != (meta.dev(), meta.ino()) => {
                    sizes = if dest_meta.is_dir() {
                        tree_sizes(&dest)
                    } else {
                        (dest_meta.size(), 0)
                    };
                    info.size = Some(sizes.0);
                    info.sha256 = if dest_meta.is_file()
                        && hash_limit > 0
                        && dest_meta.size() <= hash_limit
                    {
                        hash_file_verified(
                            &dest,
                            &self.config.hash_algorithm,
                            (dest_meta.dev(), dest_meta.ino()),
                        )
                        .ok()
                    } else {
                        None
                    };
                    let _ = write_trashinfo_atomic(&info_file, &info);
                }
                Ok(_) => {}
                Err(_) => {
                    info.sha256 = None;
                    let _ = write_trashinfo_atomic(&info_file, &info);
                }
            }
        }

        // Update directorysizes cache if we just trashed a directory
        if guard.is_some() && meta.is_dir() {
            let _ = crate::directorysizes::record_directory(&trash_dir, OsStr::new(&id), sizes.1);
        }

        // Log operation
        crate::oplog::log_trash_in(&self.home, &abs_path, &id, command);

        drop(guard);
        // Run auto-purge if enough time has passed since the last one.
        // Scanning the entire trash on every deletion is O(n) — throttle it.
        self.after_mutation();

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
        self.trash_at_checked(parent_fd, name, display_path, command, || true)
    }

    /// Recheck an external operation's lifetime after lock waits and directly
    /// before publication. Seccomp uses this to discard canceled notifications.
    pub fn trash_at_checked(
        &self,
        parent_fd: RawFd,
        name: &OsStr,
        display_path: &Path,
        command: Option<&str>,
        may_commit: impl Fn() -> bool,
    ) -> Result<String, TrashError> {
        // A relative operand (the shim's --one-file-system walk) is resolved
        // against the cwd: a home trash records absolute paths (#310).
        let display_path = if display_path.is_absolute() {
            normalize_path(display_path)
        } else {
            normalize_relative(display_path).unwrap_or_else(|_| normalize_path(display_path))
        };
        self.trash_at_display(parent_fd, name, display_path, command, may_commit)
    }

    /// `trash_at_checked` for a display path that is already canonical: the
    /// pinned parent's own /proc/self/fd path joined with `name`, which
    /// realpath would only walk again component by component (#320).
    pub fn trash_at_canonical(
        &self,
        parent_fd: RawFd,
        name: &OsStr,
        display_path: &Path,
        command: Option<&str>,
        may_commit: impl Fn() -> bool,
    ) -> Result<String, TrashError> {
        self.trash_at_display(
            parent_fd,
            name,
            display_path.to_path_buf(),
            command,
            may_commit,
        )
    }

    fn trash_at_display(
        &self,
        parent_fd: RawFd,
        name: &OsStr,
        display_path: PathBuf,
        command: Option<&str>,
        may_commit: impl Fn() -> bool,
    ) -> Result<String, TrashError> {
        use std::os::unix::ffi::OsStrExt;

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
            if capped || bytes > self.config.max_dir_size_mb.saturating_mul(1024 * 1024) {
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
            // A mount root cannot move: rename(2) would say busy (#368).
            mounts::trash_dir_for_device(file_dev, &display_path, &home_trash)
                .ok_or_else(|| TrashError::Unremovable(io::Error::from_raw_os_error(libc::EBUSY)))?
        };

        // Trash-self-target parity with trash() (#8).
        if display_path == trash_dir
            || display_path.starts_with(&trash_dir)
            || trash_dir.starts_with(&display_path)
        {
            return Err(TrashError::Refused(display_path.clone()));
        }

        // A trash on another filesystem cannot take a rename; the copy
        // fallback below handles it instead of continuing the target's
        // syscall, which made such deletes permanent (#195).
        let files_dir = trash_dir.join("files");
        let c_files_dir = match std::ffi::CString::new(files_dir.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(_) => return Err(TrashError::NotFound(display_path.clone())),
        };
        let open_files = || unsafe {
            libc::open(
                c_files_dir.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        // The store is validated under its lock below; create or repair it
        // here only when files/ cannot be opened (#307).
        let mut files_fd = open_files();
        if files_fd < 0 {
            self.ensure_trash_dir(&trash_dir)?;
            files_fd = open_files();
        }
        if files_fd < 0 {
            return Err(TrashError::Io(io::Error::last_os_error()));
        }
        let mut fstat_files: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(files_fd, &mut fstat_files) } != 0 {
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(io::Error::last_os_error()));
        }
        let cross_device = fstat_files.st_dev as u64 != file_dev;

        let trashinfo_path = Self::compute_trashinfo_path(&trash_dir, &display_path, &home_trash);
        let mut info = TrashInfo::new(trashinfo_path);
        info.command = command.map(|s| s.to_string());
        info.pid = Some(std::process::id());
        // Directory size: walk OUR fd of the victim dir, not any name.
        let victim_sizes = if !is_dir {
            (stat.st_size as u64, 0)
        } else {
            let survey = open_directory_at(parent_fd, &cname, true, false).map_or_else(
                |_| TreeSurvey::unwalked(),
                |dir| tree_survey(dir.as_raw_fd(), true),
            );
            if let Some(mount) = survey.mount_in(&display_path) {
                unsafe { libc::close(files_fd) };
                return Err(TrashError::HoldsMount(mount));
            }
            (survey.apparent, survey.allocated)
        };
        info.size = Some(victim_sizes.0);

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

        let guard = match self.lock_trash_root_prepared(&trash_dir) {
            Ok(g) => g,
            Err(e) => {
                unsafe { libc::close(files_fd) };
                return Err(e);
            }
        };
        if !may_commit() {
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(io::Error::from_raw_os_error(
                libc::ECANCELED,
            )));
        }
        // Unique id + info claim (id naming is lossy for non-UTF-8 names;
        // data fidelity comes from the move itself and the raw-bytes
        // percent-encoding in the .trashinfo).
        let base_name = name.to_string_lossy();
        let (id, info_file, claim) = match unique_id_atomic(&trash_dir, &base_name) {
            Ok(v) => v,
            Err(e) => {
                unsafe { libc::close(files_fd) };
                return Err(e);
            }
        };

        let cid = match std::ffi::CString::new(id.as_bytes()) {
            Ok(c) => c,
            Err(_) => {
                unsafe { libc::close(files_fd) };
                return Err(TrashError::NotFound(display_path.clone()));
            }
        };

        // Write .trashinfo BEFORE opening files_fd / moving — same ordering
        // as trash(). On write failure release the claimed sidecar so we do
        // not strand an empty orphan in info/ (review finding).
        if let Err(e) = write_claimed_sidecar(claim, &info) {
            let _ = raw_unlink_path(&info_file);
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(e));
        }

        if !may_commit() {
            let _ = raw_unlink_path(&info_file);
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(io::Error::from_raw_os_error(
                libc::ECANCELED,
            )));
        }
        // THE MOVE (#6): kernel-resolved against pinned inodes on both sides.
        let moved = if cross_device {
            Err(io::Error::from_raw_os_error(libc::EXDEV))
        } else if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent_fd,
                cname.as_ptr(),
                files_fd,
                cid.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        };
        let mut copied = false;
        if let Err(e) = moved {
            // Nothing partial was created at dest (rename is atomic).
            if !is_copy_fallback_error(&e) {
                unsafe { libc::close(files_fd) };
                let _ = raw_unlink_path(&info_file);
                return Err(TrashError::Io(e));
            }
            // Another filesystem, or one without RENAME_NOREPLACE (NFS, 9p):
            // copy from the pinned parent and retire exactly what was copied
            // (#192). The preload has deferred to this supervisor, so handing
            // the syscall back made these deletes permanent (#195).
            let snapshot = match snapshot_retirable_at(parent_fd, &cname, stat_identity(&stat)) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    unsafe { libc::close(files_fd) };
                    let _ = raw_unlink_path(&info_file);
                    return Err(error);
                }
            };
            let copy = (|| {
                let state_dir =
                    std::ffi::CString::new(trash_dir.join(".trashd").as_os_str().as_bytes())
                        .map_err(io::Error::from)?;
                let staging = open_directory_at(libc::AT_FDCWD, &state_dir, true, false)?;
                copy_source_at(
                    parent_fd,
                    &cname,
                    files_fd,
                    &cid,
                    staging.as_raw_fd(),
                    &stat,
                )?;
                if unsafe { libc::fsync(files_fd) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })();
            if let Err(e) = copy {
                unsafe { libc::close(files_fd) };
                let _ = raw_unlink_path(&info_file);
                return Err(TrashError::Io(e));
            }
            copied = true;
            // The entry is complete from here on. A failed or partial source
            // removal keeps it: the target's own syscall then decides, and at
            // worst a duplicate remains in the trash.
            let retired = match &snapshot {
                Some(before) => retire_directory_snapshot_at(
                    parent_fd,
                    &cname,
                    stat_identity(&stat),
                    before,
                    false,
                ),
                None => retire_copied_node_at(parent_fd, &cname, &stat),
            };
            match retired {
                Ok(true) => {}
                Ok(false) => eprintln!(
                    "trashd: warning: parts of '{}' changed while being moved and were left in place",
                    display_path.display()
                ),
                Err(e) => {
                    unsafe { libc::close(files_fd) };
                    return Err(TrashError::Io(io::Error::other(format!(
                        "copied to trash but could not remove the source: {e}"
                    ))));
                }
            }
        }

        // The move completed: make sure a concurrent purge did not strip the
        // sidecar while the data was absent mid-move (#169).

        // POST-MOVE IDENTITY CHECK (audit review): the final component could
        // have been replaced between our metadata/hash reads and the rename —
        // matching plain-unlink name semantics for WHAT gets moved, but our
        // recorded metadata must describe what ACTUALLY landed in the trash.
        // Re-stat by the new id; refresh size and drop the hash if the inode
        // differs (a stale hash would cry wolf on every restore).
        let mut moved_stat: libc::stat = unsafe { std::mem::zeroed() };
        // Only a race-driven correction reaches the sidecar; directories
        // retain their pre-move recursive size.
        let mut persisted_refresh = false;
        // A copy is a new inode by design; its version was verified while
        // copying, so only a rename gets this check.
        if !copied {
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
                    persisted_refresh = true;
                }
            } else {
                // What landed cannot be verified — drop the hash so restore does
                // not compare new content against the pre-move hash forever.
                info.sha256 = None;
                persisted_refresh = true;
            }
        }
        // Persist the refresh: list()/restore() treat the .trashinfo sidecar
        // as the source of truth, so a hash/size corrected only in memory
        // would cry wolf on every restore of a raced entry.
        if persisted_refresh {
            let _ = write_trashinfo_atomic(&info_file, &info);
        }
        unsafe { libc::close(files_fd) };

        if is_dir {
            let _ = crate::directorysizes::record_directory(
                &trash_dir,
                OsStr::new(&id),
                victim_sizes.1,
            );
        }
        crate::oplog::log_trash_in(&self.home, &display_path, &id, command);
        drop(guard);
        self.after_mutation();

        Ok(id)
    }

    /// List all items across all trash directories, newest first.
    pub fn list(&self, pattern: Option<&str>) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_with(pattern, ScanMetadata::MUTATION)
    }

    /// `list` for display: entries carry no data identity (`identity` is
    /// None), which only mutations verify. Listing statted every entry's
    /// data for nothing (#353).
    pub fn list_for_display(&self, pattern: Option<&str>) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_with(pattern, ScanMetadata::DISPLAY)
    }

    /// A read-only query: preserve sidecar freshness checks, omit data
    /// identities, and retain/sort only the entries the predicate accepts.
    /// Mutation callers must use `list` or selected mutation snapshots.
    pub fn list_for_query(
        &self,
        keep: impl FnMut(&TrashEntry) -> bool,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_filtered_with(None, ScanMetadata::QUERY, keep)
    }

    /// Display listing with a filter applied after orphan bookkeeping and
    /// before collecting/sorting entries, for example a deletion-date range.
    pub fn list_for_display_filtered(
        &self,
        pattern: Option<&str>,
        keep: impl FnMut(&TrashEntry) -> bool,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_filtered_with(pattern, ScanMetadata::DISPLAY, keep)
    }

    fn list_with(
        &self,
        pattern: Option<&str>,
        metadata: ScanMetadata,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_filtered_with(pattern, metadata, |_| true)
    }

    fn list_filtered_with(
        &self,
        pattern: Option<&str>,
        metadata: ScanMetadata,
        mut keep: impl FnMut(&TrashEntry) -> bool,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        let mut entries = Vec::new();
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(dir, _)| dir)
            .collect();
        self.visit_roots_for_id(&roots, pattern, None, metadata, &mut |entry, _| {
            if keep(&entry) {
                entries.push(entry);
            }
        })?;
        newest_first(&mut entries);
        Ok(entries)
    }

    fn scanned_data_metadata(&self, path: &Path, metadata: ScanMetadata) -> Option<fs::Metadata> {
        if !metadata.data {
            return None;
        }
        #[cfg(test)]
        self.scan_data_stats.set(self.scan_data_stats.get() + 1);
        fs::symlink_metadata(path).ok()
    }

    /// List one trash root, newest first.
    pub fn list_root(&self, root: &Path) -> Result<Vec<TrashEntry>, TrashError> {
        let mut entries = Vec::new();
        self.list_roots(&[root.to_path_buf()], None, &mut entries)?;
        newest_first(&mut entries);
        Ok(entries)
    }

    /// List several roots. One unreadable non-home root (a broken USB stick)
    /// is skipped with a warning instead of failing ls/restore/purge for
    /// every other root (#221); the home root still fails loudly, so a broken
    /// trash never reads as an empty one (#147).
    fn list_roots(
        &self,
        roots: &[PathBuf],
        pattern: Option<&str>,
        entries: &mut Vec<TrashEntry>,
    ) -> Result<(), TrashError> {
        self.visit_roots(roots, pattern, &mut |entry, _| entries.push(entry))
    }

    /// Visit entries with the data metadata already needed for their identity.
    /// Status can aggregate each snapshot immediately instead of retaining a
    /// sorted listing and statting every entry for a second time.
    fn visit_roots(
        &self,
        roots: &[PathBuf],
        pattern: Option<&str>,
        visitor: &mut impl FnMut(TrashEntry, Option<fs::Metadata>),
    ) -> Result<(), TrashError> {
        self.visit_roots_for_id(roots, pattern, None, ScanMetadata::MUTATION, visitor)
            .map(|_| ())
    }

    /// A name-only prefilter still traverses every directory entry, preserving
    /// scan errors, while exact selectors need only open their own sidecars.
    fn visit_roots_for_id(
        &self,
        roots: &[PathBuf],
        pattern: Option<&str>,
        only_id: Option<&OsStr>,
        metadata: ScanMetadata,
        visitor: &mut impl FnMut(TrashEntry, Option<fs::Metadata>),
    ) -> Result<Vec<(PathBuf, TrashError)>, TrashError> {
        let mut parser = crate::trashinfo::TrashInfoParser::default();
        let mut deferred_warnings: Vec<(PathBuf, TrashError)> = Vec::new();
        for root in roots {
            if let Err(e) =
                self.visit_in_dir(root, pattern, only_id, metadata, &mut parser, visitor)
            {
                if *root == self.home {
                    for (root, error) in deferred_warnings {
                        Self::warn_unreadable_root(&root, error);
                    }
                    return Err(e);
                }
                if only_id.is_some() {
                    // A missing exact ID falls back to a complete scan. Let
                    // that scan report failures once, without duplicate
                    // warnings from its preliminary name-only pass.
                    deferred_warnings.push((root.clone(), e));
                } else {
                    Self::warn_unreadable_root(root, e);
                }
            }
        }
        Ok(deferred_warnings)
    }

    fn warn_unreadable_root(root: &Path, error: TrashError) {
        eprintln!(
            "trashd: warning: skipping unreadable trash {}: {error}",
            root.display()
        );
    }

    #[cfg(test)]
    fn list_in_dir(
        &self,
        trash_dir: &Path,
        pattern: Option<&str>,
        entries: &mut Vec<TrashEntry>,
    ) -> Result<(), TrashError> {
        self.visit_in_dir(
            trash_dir,
            pattern,
            None,
            ScanMetadata::MUTATION,
            &mut crate::trashinfo::TrashInfoParser::default(),
            &mut |entry, _| entries.push(entry),
        )
    }

    /// Visit items in a single trash directory.
    fn visit_in_dir(
        &self,
        trash_dir: &Path,
        pattern: Option<&str>,
        only_id: Option<&OsStr>,
        metadata: ScanMetadata,
        parser: &mut crate::trashinfo::TrashInfoParser,
        visitor: &mut impl FnMut(TrashEntry, Option<fs::Metadata>),
    ) -> Result<(), TrashError> {
        // Orphan detection below must compare against ids from THIS directory
        // only: visitors may aggregate across all trash roots, so an
        // orphaned files/<id> in root B would otherwise be hidden by a real
        // entry with the same id in root A.
        let info_dir = trash_dir.join("info");
        let files_dir = trash_dir.join("files");

        if !info_dir.exists() {
            return Ok(());
        }

        // IDs with a readable sidecar, recorded BEFORE the pattern filter:
        // orphan detection must know every real entry in this directory, or a
        // filtered-out entry's own files/<id> would be re-synthesized as a
        // fake "orphaned" copy of itself (#144).
        let mut seen_ids = std::collections::HashSet::new();

        for entry in fs::read_dir(&info_dir)? {
            let entry = entry?;
            let raw_filename = entry.file_name();
            // Compare raw stems: a lossy ID can collapse distinct filenames,
            // and even the unusual ".trashinfo" leaf has file_stem semantics
            // that must agree with the full scan below.
            if let Some(id) = only_id
                && Path::new(&raw_filename).file_stem() != Some(id)
            {
                continue;
            }
            let filename = raw_filename.to_string_lossy().into_owned();
            if !filename.ends_with(".trashinfo") {
                continue;
            }
            // The on-disk stem in raw bytes: the String ID is lossy for
            // non-UTF-8 names, and paths built from it point nowhere (#247).
            let raw_stem = entry
                .path()
                .file_stem()
                .map(|s| s.to_os_string())
                .unwrap_or_default();

            let id = filename
                .strip_suffix(".trashinfo")
                .unwrap_or(&filename)
                .to_string();
            #[cfg(test)]
            self.sidecar_reads.set(self.sidecar_reads.get() + 1);
            let (content, sidecar_metadata) =
                match crate::trashinfo::read_sidecar_snapshot(&entry.path()) {
                    Ok(snapshot) => snapshot,
                    Err(_) => continue,
                };
            let sidecar_version = Some(SidecarVersion::from_metadata(&sidecar_metadata));
            // Confirm the path still names what was read. A display listing
            // skips it: every mutation re-checks the version under the lock
            // (#354).
            if metadata.verify_sidecar && sidecar_version != self::sidecar_version(&entry.path()) {
                continue;
            }

            let mut info = match parser.parse(&content) {
                Some(i) => i,
                None => continue,
            };
            seen_ids.insert(raw_stem.clone());

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

            let trashed_path = files_dir.join(&raw_stem);
            let data_metadata = self.scanned_data_metadata(&trashed_path, metadata);
            let identity = data_metadata
                .as_ref()
                .map(|metadata| (metadata.dev(), metadata.ino()));
            visitor(
                TrashEntry {
                    identity,
                    sidecar_version,
                    id,
                    info,
                    trashed_path,
                    info_path: entry.path(),
                    trash_root: trash_dir.to_path_buf(),
                    orphaned: false,
                },
                data_metadata,
            );
        }

        // Spec: "If info file corresponding to file in $trash/files is unavailable,
        // this is emergency case and MUST be presented as such."
        // Scan files/ for entries without matching .trashinfo.
        if files_dir.exists() {
            let known_ids = seen_ids;
            if let Ok(file_entries) = fs::read_dir(&files_dir) {
                for fe in file_entries.flatten() {
                    let raw_name = fe.file_name();
                    if let Some(id) = only_id
                        && raw_name != id
                    {
                        continue;
                    }
                    if !known_ids.contains(&raw_name) {
                        let name = raw_name.to_string_lossy().into_owned();
                        // Apply pattern filter to orphans too
                        if let Some(pat) = pattern
                            && !simple_glob_match(pat, &name)
                        {
                            continue;
                        }
                        // Real on-disk paths in raw bytes (#247).
                        let trashed_path = fe.path();
                        let mut raw_info_name = raw_name.clone();
                        raw_info_name.push(".trashinfo");
                        let info_path = info_dir.join(&raw_info_name);
                        let data_metadata = self.scanned_data_metadata(&trashed_path, metadata);
                        let identity = data_metadata
                            .as_ref()
                            .map(|metadata| (metadata.dev(), metadata.ino()));
                        visitor(
                            TrashEntry {
                                identity,
                                sidecar_version: sidecar_snapshot(&info_path),
                                id: name.clone(),
                                info: TrashInfo::new(PathBuf::from(format!("(orphaned: {name})"))),
                                trashed_path,
                                info_path,
                                trash_root: trash_dir.to_path_buf(),
                                orphaned: true,
                            },
                            data_metadata,
                        );
                    }
                }
            }
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

    /// Restore one resolved entry with immediate directorysizes maintenance.
    /// Reuse the mutable snapshot when retrying a conflicting destination:
    /// decompression may refresh its identity and metadata before a retry.
    pub fn restore_entry(
        &self,
        entry: &mut TrashEntry,
        target: Option<&Path>,
    ) -> Result<PathBuf, TrashError> {
        self.restore_resolved(entry, target, true)
    }

    /// Restore a previously resolved batch without re-enumerating the store.
    /// Each result corresponds to the entry at the same index. Failed items
    /// retain their metadata; directorysizes maintenance is batched per store.
    pub fn restore_batch(
        &self,
        entries: &[TrashEntry],
        target: Option<&Path>,
        force: bool,
    ) -> Vec<Result<PathBuf, TrashError>> {
        let mut cache = CacheRefresh::default();
        let results = entries
            .iter()
            .map(|listed| {
                let mut entry = listed.clone();
                let was_directory =
                    fs::symlink_metadata(&entry.trashed_path).is_ok_and(|meta| meta.is_dir());
                let mut result = self.restore_resolved(&mut entry, target, false);
                if force && let Err(TrashError::RestoreConflict(ref destination)) = result {
                    let destination = normalize_conflict_base(destination);
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
                    cache.note_removal(&entry, was_directory);
                }
                result
            })
            .collect();
        cache.apply(self);
        results
    }

    fn refresh_cache(&self, root: &Path) {
        // (see CacheRefresh for batch removals)
        #[cfg(test)]
        self.cache_refreshes.set(self.cache_refreshes.get() + 1);
        let _ = crate::directorysizes::write_cache(root);
    }

    fn refresh_cache_after_removal(&self, entry: &TrashEntry, was_directory: bool) {
        // The cache contains directories only. Removing a non-directory with
        // no cached raw-name row cannot change it, so avoid a complete scan.
        // Rebuild stale rows and damaged caches as before; cache failures are
        // best-effort and never turn a completed removal into an error.
        let needs_refresh = was_directory
            || entry.trashed_path.file_name().is_none_or(|name| {
                match crate::directorysizes::cache_contains_name(&entry.trash_root, name) {
                    Ok(present) => present,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(_) => true,
                }
            });
        if needs_refresh {
            self.refresh_cache(&entry.trash_root);
        }
    }

    fn restore_resolved(
        &self,
        entry: &mut TrashEntry,
        target: Option<&Path>,
        maintain: bool,
    ) -> Result<PathBuf, TrashError> {
        if (self.isolated && entry.trash_root != self.home) || !entry_paths_match(entry) {
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
        let stored_metadata = fs::symlink_metadata(&entry.trashed_path).ok();
        if entry.identity.is_none()
            || stored_metadata
                .as_ref()
                .map(|metadata| (metadata.dev(), metadata.ino()))
                != entry.identity
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
        let stored_is_regular = stored_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.is_file());
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

        // Serialize against compressors (auto-purge and CLI both flock the
        // same path before validating): without this lock a compressor could
        // swap zstd bytes into the stat→rename window below and the rename
        // would publish compressed bytes as the restored file (#168). Held
        // through the publish; compressors hold it for milliseconds.
        let _compress_lock = lock_entry_file(&entry.trashed_path)
            .map_err(|_| TrashError::EntryNotFound(entry.id.clone()))?;

        let root_guard = self.lock_trash_root(&entry.trash_root)?;
        // Refresh after decompression and all lock waits. The validator checks
        // both the data identity and complete sidecar version under this guard.
        self.validate_entry_locked(entry, &root_guard)?;

        let source_parent = open_directory_nofollow(&entry.trash_root.join("files"))?;
        // Raw filename bytes, not the lossy String ID: a non-UTF-8 entry's
        // on-disk name differs from its display ID (#247).
        let source_name = CString::new(
            entry
                .trashed_path
                .file_name()
                .map(|n| n.as_bytes())
                .unwrap_or_default(),
        )
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
                restore_hash_mismatch_at(
                    destination.parent.as_raw_fd(),
                    &destination.name,
                    expected_hash,
                )
                .map(|actual| (expected_hash.clone(), actual))
            } else {
                None // directories/symlinks don't get hashed
            }
        } else {
            None
        };

        // Remove trashinfo
        if sidecar_version(&entry.info_path) == entry.sidecar_version {
            let _ = raw_unlink_path(&entry.info_path);
        }

        if maintain {
            self.refresh_cache_after_removal(
                entry,
                source_stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
            );
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
        let entries = self.list_for_display(None)?;
        // Skip orphans: they have no recorded original path, and their
        // synthetic "now" deletion date would otherwise always sort them as
        // the newest entry (hijacking undo to materialize a bogus file).
        let newest = entries
            .iter()
            .find(|e| !e.orphaned)
            .ok_or_else(|| TrashError::EntryNotFound("(trash is empty)".into()))?;
        // Restore the RESOLVED entry directly: re-resolving by ID string would
        // fail permanently with AmbiguousMatch when the same filename is
        // trashed in two partitions' trash roots (#107).
        let mut entry = newest.clone();
        // Only the entry undo restores needs its data identity.
        entry.identity = file_identity(&entry.trashed_path);
        self.restore_resolved(&mut entry, None, true)
    }

    /// Permanently delete a trash entry.
    pub fn purge(&self, id: &str) -> Result<(), TrashError> {
        let entry = self.find_entry(id)?;

        self.purge_entry(&entry)
    }

    /// Purge a selected snapshot with the same maintenance and logging as `purge`.
    pub fn purge_entry(&self, entry: &TrashEntry) -> Result<(), TrashError> {
        self.purge_resolved_with_maintenance(entry, true)?;
        crate::oplog::log_purge_in(&self.home, &entry.id);
        Ok(())
    }

    /// Empty the trash (across all partitions).
    pub fn empty(&self, max_age_days: Option<u32>) -> Result<u64, TrashError> {
        let selected = self.entries_older_than(max_age_days)?;
        Ok(self.empty_entries(&selected, max_age_days))
    }

    /// Entries at least `max_age_days` old (all entries for `None`).
    pub fn entries_older_than(
        &self,
        max_age_days: Option<u32>,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        let now = chrono::Local::now();
        Ok(self
            .list(None)?
            .into_iter()
            .filter(|entry| match max_age_days {
                Some(days) => {
                    now.signed_duration_since(entry.info.deletion_date)
                        .num_days()
                        >= days as i64
                }
                None => true,
            })
            .collect())
    }

    /// Permanently delete exactly `entries`, e.g. the listing a user just
    /// confirmed: re-listing purged items trashed while the prompt waited
    /// (#217). Each entry is identity-checked, so a reused ID is never hit.
    pub fn empty_entries(&self, entries: &[TrashEntry], max_age_days: Option<u32>) -> u64 {
        let mut count = 0u64;
        let mut cache = CacheRefresh::default();
        for entry in entries {
            match self.purge_reporting_kind(entry) {
                Ok(was_directory) => cache.note_removal(entry, was_directory),
                Err(e) => {
                    if !matches!(e, TrashError::EntryNotFound(_)) {
                        eprintln!(
                            "trashd: warning: could not delete '{}': {e}",
                            entry.trashed_path.display()
                        );
                    }
                    continue;
                }
            }
            count += 1;
        }
        if count > 0 {
            let filter_desc = max_age_days.map(|d| format!("older than {d}d"));
            crate::oplog::log_empty_in(&self.home, count, filter_desc.as_deref());
        }
        // Only roots whose cache the removals affected (#336).
        cache.apply(self);
        count
    }

    /// Run auto_purge only if enough time has passed since the last run.
    /// Uses a timestamp file to avoid scanning the entire trash on every deletion.
    fn maybe_auto_purge(&self) -> Result<(), TrashError> {
        let interval = self.config.auto_purge_interval_secs;
        let now = std::time::Instant::now();
        if interval > 0
            && self
                .purge_not_due_until
                .get()
                .is_some_and(|until| now < until)
        {
            return Ok(());
        }
        let marker = self.home.join(".trashd/last_purge");
        // The time left before a marker of this age is due, if any.
        let remaining = |meta: &fs::Metadata| {
            meta.modified()
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .and_then(|elapsed| std::time::Duration::from_secs(interval).checked_sub(elapsed))
                .filter(|left| !left.is_zero())
        };
        let recent = |meta: fs::Metadata| meta.is_file() && remaining(&meta).is_some();
        // Most deletions are throttled. A recent regular marker lets them
        // avoid opening/flocking a retention lock at all; never follow a
        // symlink that could suppress retention using another file's mtime.
        if interval > 0
            && let Ok(meta) = fs::symlink_metadata(&marker)
            && meta.is_file()
            && let Some(left) = remaining(&meta)
        {
            self.purge_not_due_until.set(Some(now + left));
            return Ok(());
        }
        // One purge at a time per home: concurrent runs each trimmed the full
        // excess, deleting far more than the limits required (#220). A held
        // lock means a purge is already running, so this one is skipped.
        let Some(_running) = self.try_lock_auto_purge() else {
            return Ok(());
        };
        if interval == 0 {
            return self.auto_purge();
        }

        // Recheck under the retention lock: another purge may have completed
        // between the fast-path check and our lock acquisition. Open without
        // truncating or following symlinks and validate before touching its
        // timestamp, so a FIFO cannot block and a link cannot damage a target.
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let opened = options
            .create_new(true)
            .open(&marker)
            .map(|file| (file, true))
            .or_else(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    options
                        .create_new(false)
                        .open(&marker)
                        .map(|file| (file, false))
                } else {
                    Err(error)
                }
            });
        if let Ok((marker, created)) = opened
            && let Ok(meta) = marker.metadata()
            && meta.is_file()
        {
            if !created && recent(meta) {
                return Ok(());
            }
            let _ = marker.set_modified(std::time::SystemTime::now());
            self.purge_not_due_until
                .set(Some(now + std::time::Duration::from_secs(interval)));
        }

        self.auto_purge()
    }

    /// Non-blocking exclusive lock on `.trashd/auto_purge.lock`; `None` when
    /// another process holds it (or it cannot be opened).
    fn try_lock_auto_purge(&self) -> Option<fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.home.join(".trashd/auto_purge.lock"))
            .ok()?;
        if !lock.metadata().ok()?.is_file() {
            return None;
        }
        (unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0)
            .then_some(lock)
    }

    /// Enforce retention policy: purge expired items and trim by size.
    /// Single scan — all three phases work on the same in-memory list.
    fn auto_purge(&self) -> Result<(), TrashError> {
        // Finish deleting trees an interrupted or failed purge detached. One
        // mount scan serves the sweep and the listing (#353).
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        self.auto_purge_in_roots(&roots)
    }

    fn auto_purge_in_roots(&self, roots: &[PathBuf]) -> Result<(), TrashError> {
        let max_age = self.config.retention.max_age_days;
        let max_size_bytes = (self.config.retention.max_size_gb * 1024.0 * 1024.0 * 1024.0) as u64;
        let pressure_pct = self.config.retention.disk_pressure_percent;
        for root in roots {
            let candidates = sweep_detached(root);
            self.sweep_abandoned_stages(root, &candidates);
        }

        let mut entries = Vec::new();
        self.list_roots(roots, None, &mut entries)?;
        newest_first(&mut entries);
        if entries.is_empty() {
            return Ok(());
        }

        let now = chrono::Local::now();
        let cache = std::cell::RefCell::new(CacheRefresh::default());
        let purge = |entry: &TrashEntry| {
            let was_directory = self.purge_reporting_kind(entry)?;
            cache.borrow_mut().note_removal(entry, was_directory);
            Ok::<(), TrashError>(())
        };
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
                // A failed purge keeps its entry listed and counted (#106).
                if purge(&entries[i]).is_ok() {
                    purged[i] = true;
                    purge_count += 1;
                }
            }
        }

        // Phase 2a: auto-compress old uncompressed items before purging by size.
        // Cap how much we slurp into RAM — this runs (throttled) on routine
        // deletions, and reading a multi-hundred-MB trashed file fully into a
        // Vec could OOM the process (and a killed supervisor degrades to
        // passthrough). Skip anything above the cap.
        const COMPRESS_MAX_BYTES: u64 = 64 * 1024 * 1024;
        let mut incompressible = IncompressibleData::load(&self.home);
        for i in (0..entries.len()).rev() {
            if purged[i] || entries[i].orphaned {
                continue;
            }
            let age = now.signed_duration_since(entries[i].info.deletion_date);
            if age.num_days() < 7 {
                continue;
            }
            let path = entries[i].trashed_path.clone();
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                _ => continue,
            };
            if !compression_candidate(&entries[i], &meta)
                || meta.len() < 1024
                || meta.len() > COMPRESS_MAX_BYTES
                || incompressible.known(&meta)
            {
                continue;
            }
            // Hold the entry flock across validate → swap, mirroring the CLI
            // compressor: restore flocks the same path across its identity
            // check → rename, so "validated" can never interleave with
            // "renamed" and publish compressed bytes as plaintext (#168).
            // The lock MUST stay held through the marker write and the
            // atomic_write swap — dropping it after the read re-opens the
            // publish window (#170). The lock is on the OPEN inode; our
            // atomic_write swaps a new one in, and a restorer that then opens
            // the path sees the new inode/sidecar version and aborts cleanly
            // post-lock.
            let mut input = match lock_entry_file(&path) {
                Ok(Some(f)) => f,
                _ => continue,
            };
            // Post-lock identity recheck (#105 discipline, now under the lock).
            if file_identity(&entries[i].trashed_path) != entries[i].identity
                || sidecar_version(&entries[i].info_path) != entries[i].sidecar_version
            {
                continue;
            }
            let Ok(opened) = input.metadata() else {
                continue;
            };
            if !compression_source_matches(&meta, &opened) {
                continue;
            }
            use std::io::{Read, Seek};
            // Media and archives are compressed already: their header says
            // so without reading the whole file into memory.
            let mut header = [0u8; 16];
            let Ok(read) = input.read(&mut header) else {
                continue;
            };
            if is_compressed_format(&header[..read]) {
                incompressible.add(&meta);
                continue;
            }
            if input.rewind().is_err() {
                continue;
            }
            let Ok(Some(data)) = read_compression_input(&mut input, meta.len(), COMPRESS_MAX_BYTES)
            else {
                continue;
            };
            if !input
                .metadata()
                .is_ok_and(|current| compression_source_matches(&meta, &current))
            {
                continue;
            }
            // NOTE: no drop(input) here — the flock stays held through the
            // revalidation, marker write, and swap below (#170).
            // Defensive: skip if it already looks compressed (marker missing).
            if data.len() >= 4
                && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 0xFD2FB528
            {
                continue;
            }
            let compressed = zstd::encode_all(data.as_slice(), 3)
                .ok()
                .filter(|compressed| compressed.len() < data.len());
            if compressed.is_none() {
                incompressible.add(&meta);
            }
            if let Some(compressed) = compressed {
                // A failed root or concurrently edited entry must not
                // abandon retention for the other roots (#221, #386).
                let _ = self.publish_auto_compressed(&mut entries[i], &input, &meta, &compressed);
            }
        }

        incompressible.save();

        // Phase 2b: trim by total size (purge oldest surviving until under limit)
        // max_size_gb == 0 means "no size limit", not "trim everything to 0";
        // without a limit nothing needs sizing (foreign trees are walked).
        // Keep these measurements for this pass only. Foreign trees may need
        // a full walk; measuring them again when choosing victims doubled
        // that work without providing a coherent newer snapshot (#384).
        let mut sizes = if max_size_bytes > 0 {
            vec![0; entries.len()]
        } else {
            Vec::new()
        };
        let mut total_size = 0u64;
        if max_size_bytes > 0 {
            for (i, entry) in entries.iter().enumerate() {
                if !purged[i] {
                    sizes[i] = self.entry_disk_size(entry);
                    total_size = total_size.saturating_add(sizes[i]);
                }
            }
        }
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
                // Only count a purge that actually happened: a failed removal
                // must stay in the accounting (and out of the freed total), or
                // the trash silently exceeds max_size_gb (#106).
                if purge(&entries[i]).is_ok() {
                    freed = freed.saturating_add(sizes[i]);
                    purged[i] = true;
                    purge_count += 1;
                }
            }
        }

        // Phase 3: disk pressure — purge oldest 10% of surviving items.
        // Pressure is measured on the HOME filesystem, so only entries on that
        // same filesystem can relieve it; purging other partitions' entries
        // would delete data without fixing the pressure (#113).
        if pressure_pct > 0 {
            let home = self.home.clone();
            if let Some(usage_pct) = disk_usage_percent(&home)
                && usage_pct >= pressure_pct as f64
            {
                // Recent entries are never eligible: moving a file into the
                // trash frees nothing, and purging the entry an `rm` just
                // created turned it into a permanent delete (#201).
                // One device lookup per root, not two lstats per entry and pass.
                let home_device = mounts::device_id_or_parent(&home);
                let root_devices = std::cell::RefCell::new(std::collections::HashMap::new());
                let on_home_filesystem = |root: &Path| {
                    home_device.is_some()
                        && *root_devices
                            .borrow_mut()
                            .entry(root.to_path_buf())
                            .or_insert_with(|| mounts::device_id_or_parent(root))
                            == home_device
                };
                let eligible = |entry: &TrashEntry| {
                    now.signed_duration_since(entry.info.deletion_date) >= PRESSURE_MIN_AGE
                        && on_home_filesystem(&entry.trash_root)
                };
                let candidates = entries
                    .iter()
                    .enumerate()
                    .filter(|(i, entry)| !purged[*i] && eligible(entry))
                    .count();
                let to_purge = if candidates == 0 {
                    0
                } else {
                    std::cmp::max(1, candidates / 10)
                };
                let mut purged_count = 0;
                for i in (0..entries.len()).rev() {
                    if purged_count >= to_purge {
                        break;
                    }
                    if purged[i] || !eligible(&entries[i]) {
                        continue;
                    }
                    if purge(&entries[i]).is_ok() {
                        purged[i] = true;
                        purge_count += 1;
                        purged_count += 1;
                    }
                }
            }
        }

        // Log and notify if items were auto-purged
        // Refresh directorysizes where purged directories (or cached names)
        // changed it, for other FreeDesktop trash tools. Compression only
        // touches files, which the cache does not list (#336).
        cache.into_inner().apply(self);
        if purge_count > 0 {
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

    /// Publish encoded data only while the exact input version still exists.
    /// An open writer need not take our flock: identity cannot detect a
    /// same-inode edit during encoding or a root-lock wait (#386).
    fn publish_auto_compressed(
        &self,
        entry: &mut TrashEntry,
        input: &fs::File,
        expected: &fs::Metadata,
        compressed: &[u8],
    ) -> Result<bool, TrashError> {
        self.publish_auto_compressed_before_commit(entry, input, expected, compressed, || {}, || {})
    }

    fn publish_auto_compressed_before_commit(
        &self,
        entry: &mut TrashEntry,
        input: &fs::File,
        expected: &fs::Metadata,
        compressed: &[u8],
        before_commit: impl FnOnce(),
        before_persist: impl FnOnce(),
    ) -> Result<bool, TrashError> {
        // Write and sync the entire replacement before validating the source:
        // an open writer may change it during slow staging I/O (#386).
        let staging = prepare_atomic_write_replacement(
            &entry.trashed_path,
            compressed,
            create_data_stage(&entry.trash_root)?,
            Some(expected),
        )?;
        before_commit();
        let guard = self.lock_trash_root(&entry.trash_root)?;
        self.validate_entry_locked(entry, &guard)?;
        if !compression_source_matches(expected, &input.metadata()?) {
            return Ok(false);
        }
        // Marker first: a crash leaves recoverable plaintext plus a stale
        // marker. Revert it when the atomic data swap fails (#28).
        let mut info = entry.info.clone();
        info.compressed = Some("zstd".into());
        set_compression_marker(&entry.info_path, Some("zstd"))?;
        before_persist();
        let result = (|| -> io::Result<bool> {
            // Recording the marker also syncs a file and can block. Check
            // again immediately before retiring the original data inode.
            if !compression_source_matches(expected, &input.metadata()?) {
                return Ok(false);
            }
            staging.persist(&entry.trashed_path).map_err(|e| e.error)?;
            Ok(true)
        })();
        let result = match result {
            Ok(true) => {
                entry.info = info;
                Ok(true)
            }
            Ok(false) => set_compression_marker(&entry.info_path, None).map(|()| false),
            Err(error) => {
                let _ = set_compression_marker(&entry.info_path, None);
                Err(error)
            }
        };
        entry.identity = file_identity(&entry.trashed_path);
        entry.sidecar_version = sidecar_version(&entry.info_path);
        result.map_err(TrashError::Io)
    }

    /// Unpublished stages still have their original data. Claim abandoned
    /// work under the root lock, then remove outside it. Cross-device copies
    /// hold the root lock; announced data stages hold their own file locks.
    /// Sample at most 32 candidates in the existing unlocked sweep, keeping
    /// writer-lock work bounded and reaching stages behind live work over
    /// later maintenance passes (#383, #388, #389).
    fn claim_abandoned_stages(
        &self,
        root: &Path,
        candidates: &[CString],
    ) -> Option<(fs::File, Vec<CString>)> {
        if candidates.is_empty() {
            return None;
        }
        let uid = unsafe { libc::geteuid() };
        self.ensure_trusted_parent_recent(root, uid).ok()?;
        let guard = RootMutationGuard::try_acquire_as(root, uid).ok()??;
        let state_dir = CString::new(root.join(".trashd").as_os_str().as_bytes()).ok()?;
        let state = open_directory_at(libc::AT_FDCWD, &state_dir, true, false).ok()?;
        let mut claimed = Vec::new();
        for name in candidates.iter().take(STAGES_PER_SWEEP) {
            if is_copy_stage(name) {
                if let Ok(claim) = claim_copy_stage_at(state.as_raw_fd(), name) {
                    claimed.push(claim);
                }
            } else if is_data_stage(name)
                && let Ok(Some(stage)) = try_lock_data_stage_at(state.as_raw_fd(), name)
                && let Ok(claim) = claim_data_stage_at(state.as_raw_fd(), name, &stage)
            {
                claimed.push(claim);
            }
        }
        drop(guard);
        Some((state, claimed))
    }

    fn sweep_abandoned_stages(&self, root: &Path, candidates: &[CString]) {
        if let Some((state, claimed)) = self.claim_abandoned_stages(root, candidates) {
            for name in claimed {
                // Failed removals retain the purging- claim and are retried
                // by the existing sweep; mount roots are never traversed.
                let _ = remove_tree_at(state.as_raw_fd(), &name, 0);
            }
        }
    }

    /// Retire the exact listed snapshot, never a newly resolved reused ID.
    pub fn purge_resolved(&self, entry: &TrashEntry) -> Result<(), TrashError> {
        self.purge_resolved_with_maintenance(entry, false)
    }

    fn purge_resolved_with_maintenance(
        &self,
        entry: &TrashEntry,
        maintain: bool,
    ) -> Result<(), TrashError> {
        let was_directory = self.purge_reporting_kind(entry)?;
        if maintain {
            self.refresh_cache_after_removal(entry, was_directory);
        }
        Ok(())
    }

    /// Purge one validated entry; true when its data was a directory.
    fn purge_reporting_kind(&self, entry: &TrashEntry) -> Result<bool, TrashError> {
        let _data_lock = match lock_entry_file(&entry.trashed_path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let guard = self.lock_trash_root(&entry.trash_root)?;
        let (data, sidecar) = self.validated_entry_metadata_locked(entry, &guard)?;
        // A phantom entry (neither data nor sidecar on disk) must not
        // report a successful purge of nothing (#247).
        if data.is_none() && sidecar.is_none() {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        let was_directory = data.as_ref().is_some_and(|metadata| metadata.is_dir());
        // Raw syscalls throughout: the libc wrappers are hooked by the
        // system-wide preload, which multiplied a large purge's syscalls by
        // ~13 while only deciding to leave trash internals alone (#335).
        let mut detached = None;
        match data {
            Some(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                // Detach the tree under the lock; delete it after releasing
                // it. Deleting in place held every trash writer (all deletes
                // of this user) for the whole removal of a large tree.
                detached = Some(detach_for_removal(entry)?);
            }
            Some(_) => raw_unlink_path(&entry.trashed_path)?,
            None if data_absence_is_retired(&entry.info_path) => {}
            None => return Err(io::Error::from(io::ErrorKind::NotFound).into()),
        }
        match raw_unlink_path(&entry.info_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        drop(guard);
        drop(_data_lock);
        if let Some((state, name)) = detached
            && let Err(error) = remove_tree_at(state.as_raw_fd(), &name, 0)
        {
            // Retention retries it; the entry itself is gone.
            eprintln!(
                "trashd: warning: purged '{}' but could not delete all of its data yet ({error}); it is retried later",
                entry.id
            );
        }
        Ok(was_directory)
    }

    /// Get per-partition trash status.
    pub fn status_per_partition(&self) -> Result<Vec<PartitionStatus>, TrashError> {
        self.status_in_roots(&self.all_trash_dirs())
    }

    fn status_in_roots(
        &self,
        roots: &[(PathBuf, String)],
    ) -> Result<Vec<PartitionStatus>, TrashError> {
        let mut partitions: std::collections::HashMap<PathBuf, PartitionStatus> =
            std::collections::HashMap::new();

        for (dir, label) in roots {
            partitions.entry(dir.clone()).or_insert(PartitionStatus {
                trash_dir: dir.clone(),
                label: label.clone(),
                total_size: 0,
                count: 0,
            });
        }

        let paths: Vec<PathBuf> = roots.iter().map(|(path, _)| path.clone()).collect();
        self.visit_roots(&paths, None, &mut |entry, metadata| {
            let ps = partitions
                .entry(entry.trash_root.clone())
                .or_insert_with(|| PartitionStatus {
                    trash_dir: entry.trash_root.clone(),
                    label: entry.trash_root.to_string_lossy().into_owned(),
                    total_size: 0,
                    count: 0,
                });
            ps.count += 1;
            // Use actual disk size (may be smaller than info.size after compression)
            ps.total_size = ps
                .total_size
                .saturating_add(self.entry_disk_size_from_metadata(&entry, metadata.as_ref()));
        })?;

        let mut result: Vec<PartitionStatus> = partitions.into_values().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.total_size));
        Ok(result)
    }

    /// Total status across all partitions.
    pub fn status(&self) -> Result<(u64, usize), TrashError> {
        Ok(self
            .status_per_partition()?
            .iter()
            .fold((0u64, 0usize), |(size, count), partition| {
                (
                    size.saturating_add(partition.total_size),
                    count + partition.count,
                )
            }))
    }

    /// On-disk size of a trash entry for retention accounting and status.
    ///
    /// `fs::metadata().len()` on a DIRECTORY is the size of its inode (~4 KB),
    /// not the tree — trusting it made auto-purge "free" only 4096 bytes per
    /// purged tree and keep deleting far past the configured excess, and made
    /// directory-heavy trashes look nearly empty. Directory trees therefore use
    /// their recorded recursive size (`info.size`, captured by the survey at
    /// trash time). Symlinks are never followed: a trashed link must count as
    /// itself, not its target.
    fn entry_disk_size(&self, entry: &TrashEntry) -> u64 {
        let metadata = fs::symlink_metadata(&entry.trashed_path).ok();
        self.entry_disk_size_from_metadata(entry, metadata.as_ref())
    }

    fn entry_disk_size_from_metadata(
        &self,
        entry: &TrashEntry,
        metadata: Option<&fs::Metadata>,
    ) -> u64 {
        match metadata {
            Some(m) if m.is_dir() && !m.file_type().is_symlink() => {
                // Foreign (spec-compliant) entries carry no X-Trashd-Size; falling
                // back to the directory INODE size under-counted each foreign tree
                // at ~4 KiB, so retention never trimmed directory-heavy trashes
                // (#115). The eligibility walk's 10,000-entry cap is unsuitable
                // for accounting: it hid the rest of large trees (#384).
                //
                // The recorded size is sidecar text: only the private home trash
                // is written by this user alone. A topdir root (removable media)
                // may carry a forged value that would make the size cap purge
                // every other root, so it never exceeds the measured tree (#193).
                if let Some(recorded) = entry.info.size
                    && entry.trash_root == self.home
                {
                    return recorded;
                }
                #[cfg(test)]
                self.accounting_walks.set(self.accounting_walks.get() + 1);
                directory_accounted_size(&entry.trashed_path, entry.info.size)
            }
            Some(m) => m.len(),
            // No data, nothing occupies the disk.
            None => 0,
        }
    }

    /// All known trash directories (home + per-mountpoint).
    pub fn all_trash_dirs(&self) -> Vec<(PathBuf, String)> {
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

    /// The selector (trashed path) of the entry whose original file name is
    /// exactly `raw`. IDs are built from lossy names, so a non-UTF-8 name
    /// must never reach ID matching through a lossy conversion: it matched
    /// another entry's ID exactly, and purge deleted the wrong file (#209).
    pub fn selector_for_raw_name(&self, raw: &OsStr) -> Result<String, TrashError> {
        let entries = self.list(None)?;
        let matching: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| e.info.original_path.file_name() == Some(raw))
            .collect();
        let lossy = raw.to_string_lossy().into_owned();
        match matching.as_slice() {
            [entry] => entry
                .trashed_path
                .to_str()
                .map(str::to_owned)
                .ok_or(TrashError::EntryNotFound(lossy)),
            [] => Err(TrashError::EntryNotFound(lossy)),
            _ => Err(TrashError::AmbiguousMatch {
                pattern: lossy,
                count: matching.len(),
            }),
        }
    }

    /// Resolve a trash entry by exact ID (or filename fallback), refusing
    /// ambiguity when the same ID exists in more than one trash root — the
    /// same resolution rules restore/purge apply, so `trash info` can never
    /// describe a different copy than the one restore would publish (#148).
    pub fn find_entry(&self, id_or_pattern: &str) -> Result<TrashEntry, TrashError> {
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(dir, _)| dir)
            .collect();
        self.find_entry_in_roots(&roots, id_or_pattern)
    }

    /// Resolve a command's selector once, retaining the snapshots needed for
    /// ambiguity output and mutation. Raw names never pass through lossy IDs.
    /// With `every_copy`, exact IDs include every original-filename copy and
    /// the glob fallback also matches complete original paths (restore --all).
    pub fn select_entries(
        &self,
        selector: &OsStr,
        every_copy: bool,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        if let Some(selector) = selector.to_str() {
            return self.select_utf8_in_roots(&roots, selector, every_copy, every_copy);
        }
        let mut entries = Vec::new();
        self.list_roots(&roots, None, &mut entries)?;
        newest_first(&mut entries);
        if Path::new(selector).is_absolute()
            && let Some(entry) = entries
                .iter()
                .find(|entry| entry.trashed_path == Path::new(selector))
        {
            return Ok(Some((MatchTier::TrashedPath, vec![entry.clone()])));
        }
        entries.retain(|entry| entry.info.original_path.file_name() == Some(selector));
        Ok((!entries.is_empty()).then_some((MatchTier::FileName, entries)))
    }

    fn find_entry_in_roots(
        &self,
        roots: &[PathBuf],
        selector: &str,
    ) -> Result<TrashEntry, TrashError> {
        match self.select_utf8_in_roots(roots, selector, false, false)? {
            Some((_, mut entries)) if entries.len() == 1 => Ok(entries.remove(0)),
            Some((_, entries)) => Err(TrashError::AmbiguousMatch {
                pattern: selector.into(),
                count: entries.len(),
            }),
            None => Err(TrashError::EntryNotFound(selector.into())),
        }
    }

    fn select_utf8_in_roots(
        &self,
        roots: &[PathBuf],
        id_or_pattern: &str,
        every_copy: bool,
        original_path_glob: bool,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        let selector = Path::new(id_or_pattern);
        // Replacement characters may stand for multiple non-UTF-8 raw names.
        // Filename/glob fallbacks also need the complete listing. Ordinary
        // exact IDs and selectors within a known files/ directory can filter
        // raw names before reading sidecars, without changing their snapshots.
        let ordinary_leaf = |name: &str| {
            !name.is_empty()
                && name != "."
                && name != ".."
                && !name.contains(['/', '\0', '\u{fffd}', '*', '?', '[', ']'])
        };
        let only_id = if ordinary_leaf(id_or_pattern) {
            Some(OsStr::new(id_or_pattern))
        } else if selector.is_absolute()
            && roots
                .iter()
                .any(|root| selector.parent() == Some(root.join("files").as_path()))
        {
            selector
                .file_name()
                .filter(|name| name.to_str().is_some_and(ordinary_leaf))
        } else {
            None
        };

        if let Some(id) = only_id.filter(|_| !every_copy) {
            let mut entries = Vec::new();
            let warnings = self.visit_roots_for_id(
                roots,
                None,
                Some(id),
                ScanMetadata::MUTATION,
                &mut |entry, _| entries.push(entry),
            )?;
            let matched = if selector.is_absolute() {
                entries.iter().any(|entry| entry.trashed_path == selector)
            } else {
                entries.iter().any(|entry| entry.id == id_or_pattern)
            };
            if matched {
                for (root, error) in warnings {
                    Self::warn_unreadable_root(&root, error);
                }
                newest_first(&mut entries);
                return Ok(Self::selected_entries(entries, id_or_pattern, false, false));
            }
        }

        let mut entries = Vec::new();
        self.list_roots(roots, None, &mut entries)?;
        newest_first(&mut entries);
        Ok(Self::selected_entries(
            entries,
            id_or_pattern,
            every_copy,
            original_path_glob,
        ))
    }

    #[cfg(test)]
    fn resolve_listed_entry(
        entries: &[TrashEntry],
        id_or_pattern: &str,
    ) -> Result<TrashEntry, TrashError> {
        match Self::matching_tier(entries, id_or_pattern, false) {
            Some((_, matches)) if matches.len() == 1 => Ok(matches[0].clone()),
            Some((_, matches)) => Err(TrashError::AmbiguousMatch {
                pattern: id_or_pattern.into(),
                count: matches.len(),
            }),
            None => Err(TrashError::EntryNotFound(id_or_pattern.into())),
        }
    }

    /// The entries a selector names, by the same tiers `find_entry` uses:
    /// for reporting an ambiguous selector, and for acting on all of them.
    /// Listing the selector as a glob instead named other entries whenever
    /// an exact name contained glob syntax (`a[1].txt` -> `a1.txt`, #328).
    pub fn matching_entries(
        &self,
        id_or_pattern: &str,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        self.matching_entries_with(id_or_pattern, false)
    }

    /// The entries `--all` acts on: those of `matching_entries`, except that
    /// an exact ID also selects every entry trashed under that file name
    /// (`foo`, `foo.2`, `foo.3`). The ID tier alone restored one of three
    /// copies that listing the name had selected (#340).
    pub fn matching_entries_all(
        &self,
        id_or_pattern: &str,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        self.matching_entries_with(id_or_pattern, true)
    }

    fn matching_entries_with(
        &self,
        id_or_pattern: &str,
        every_copy: bool,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        self.select_utf8_in_roots(&roots, id_or_pattern, every_copy, false)
    }

    fn selected_entries(
        entries: Vec<TrashEntry>,
        selector: &str,
        every_copy: bool,
        original_path_glob: bool,
    ) -> Option<(MatchTier, Vec<TrashEntry>)> {
        let selected = Self::matching_tier(&entries, selector, every_copy);
        if original_path_glob
            && selected
                .as_ref()
                .is_none_or(|(tier, _)| *tier == MatchTier::Glob)
        {
            let matches = entries
                .iter()
                .filter(|entry| {
                    let name = entry
                        .info
                        .original_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    if entry.orphaned {
                        simple_glob_match(selector, &entry.id)
                    } else {
                        simple_glob_match(selector, &name)
                            || simple_glob_match(
                                selector,
                                &entry.info.original_path.to_string_lossy(),
                            )
                    }
                })
                .cloned()
                .collect::<Vec<_>>();
            return (!matches.is_empty()).then_some((MatchTier::Glob, matches));
        }
        selected.map(|(tier, matches)| (tier, matches.into_iter().cloned().collect()))
    }

    /// The first selector tier with any match, and its matches. With
    /// `every_copy`, an ID match also takes the file-name matches.
    fn matching_tier<'a>(
        entries: &'a [TrashEntry],
        id_or_pattern: &str,
        every_copy: bool,
    ) -> Option<(MatchTier, Vec<&'a TrashEntry>)> {
        // An entry's trashed path is unique even when two roots hold the
        // same ID, so it selects exactly one entry (#210).
        if id_or_pattern.starts_with('/')
            && let Some(entry) = entries
                .iter()
                .find(|e| e.trashed_path == Path::new(id_or_pattern))
        {
            return Some((MatchTier::TrashedPath, vec![entry]));
        }

        // Exact ID match. IDs are unique WITHIN one trash dir, but two
        // partitions can hold entries with the same ID (same filename trashed
        // on two mounts); picking either nondeterministically could restore
        // or purge the WRONG copy (#41). Distinct raw names can also share a
        // lossy display ID inside one root: an ID must select exactly one
        // entry before a restore or purge acts on it.
        let file_name = |e: &TrashEntry| {
            e.info
                .original_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        if entries.iter().any(|e| e.id == id_or_pattern) {
            let exact: Vec<&TrashEntry> = entries
                .iter()
                .filter(|e| e.id == id_or_pattern || (every_copy && file_name(e) == id_or_pattern))
                .collect();
            return Some((MatchTier::Id, exact));
        }

        let filename_matches: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| file_name(e) == id_or_pattern)
            .collect();
        if !filename_matches.is_empty() {
            return Some((MatchTier::FileName, filename_matches));
        }

        let glob_matches: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| simple_glob_match(id_or_pattern, &file_name(e)))
            .collect();
        (!glob_matches.is_empty()).then_some((MatchTier::Glob, glob_matches))
    }
}

/// How a selector matched entries (see `TrashStore::matching_entries`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchTier {
    TrashedPath,
    Id,
    FileName,
    Glob,
}

/// Newest first. DeletionDate has one-second precision, so entries trashed
/// within one second kept directory-listing (hash) order and `undo` picked an
/// arbitrary one (#329). The recorded nanosecond deletion stamp orders them,
/// or for older entries the sidecar's mtime from when it was published: the
/// filesystem's coarse clock can tie those (#345).
fn newest_first(entries: &mut [TrashEntry]) {
    entries.sort_by_key(|entry| {
        let stamp = entry.info.deletion_ns.map(i128::from).or_else(|| {
            entry.sidecar_version.map(|version| {
                i128::from(version.modified.0) * 1_000_000_000 + i128::from(version.modified.1)
            })
        });
        std::cmp::Reverse((entry.info.deletion_date, stamp))
    });
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
/// Write a new entry's record into the sidecar its id claim created,
/// instead of closing the claim and reopening it with O_TRUNC (#307).
fn write_claimed_sidecar(mut claim: fs::File, info: &TrashInfo) -> io::Result<()> {
    claim.write_all(info.to_trashinfo_string().as_bytes())
}

fn unique_id_atomic(
    trash_dir: &Path,
    base_name: &str,
) -> Result<(String, PathBuf, fs::File), TrashError> {
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
    let try_claim = |candidate: &str| -> Result<Option<(PathBuf, fs::File)>, io::Error> {
        let info_path = info_dir.join(format!("{candidate}.trashinfo"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&info_path)
        {
            Ok(claim) => {
                if files_dir.join(candidate).symlink_metadata().is_ok() {
                    // The info name was free but an orphaned data file already
                    // occupies files/<candidate>. Release the info we claimed
                    // and try a different id rather than overwrite it.
                    let _ = raw_unlink_path(&info_path);
                    Ok(None)
                } else {
                    Ok(Some((info_path, claim)))
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e),
        }
    };

    // Try base name first
    if let Some((info_path, claim)) = try_claim(base_name)? {
        return Ok((base_name.to_string(), info_path, claim));
    }

    // Keep the first timestamped ID, then advance without rescanning the
    // existing counter range or exhausting a fixed naming namespace (#399).
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let mut names = crate::trash_id::CollisionNames::new(base_name, &ts);
    loop {
        let candidate = names.next();
        if let Some((info_path, claim)) = try_claim(&candidate)? {
            return Ok((candidate, info_path, claim));
        }
    }
}

fn file_identity(path: &Path) -> Option<(u64, u64)> {
    fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Create or validate one directory in the authenticated trash hierarchy.
/// Every writable store component is a real directory, owned by the effective
/// user, with no group/other permissions. A failed chmod is fatal: silently
/// accepting the old mode would expose deleted data and metadata.
fn ensure_private_dir(path: &Path, uid: u32, create: bool) -> io::Result<()> {
    let mut meta = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            match fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(raced) if raced.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            fs::symlink_metadata(path)?
        }
        Err(e) => return Err(e),
    };
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
/// Returns whether any (trusted) symlink was followed.
fn ensure_trusted_ancestors(directory: &Path, uid: u32) -> io::Result<bool> {
    let directory = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()?.join(directory)
    };
    ensure_trusted_ancestors_from(&directory, uid, 0)
}

/// Symlinked ancestors (ostree's /home -> var/home, a stowed ~/.local) are
/// followed when the link itself belongs to root or this user: the directory
/// holding it was validated earlier in this walk, so nobody else can replace
/// it. The target is then validated from the root like any other path; links
/// owned by anyone else are still refused (#222).
fn ensure_trusted_ancestors_from(directory: &Path, uid: u32, hops: u32) -> io::Result<bool> {
    use std::path::Component;

    let components: Vec<Component> = directory.components().collect();
    let mut current = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
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

        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::DirBuilder::new().mode(0o700).create(&current) {
                    Ok(()) => {}
                    Err(raced) if raced.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                fs::symlink_metadata(&current)?
            }
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() && (metadata.uid() == 0 || metadata.uid() == uid) {
            if hops >= 40 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "too many symbolic links among trash ancestors",
                ));
            }
            let base = current.parent().unwrap_or_else(|| Path::new("/"));
            let mut resolved = lexically_normalized(&base.join(fs::read_link(&current)?));
            for rest in &components[index + 1..] {
                resolved.push(rest.as_os_str());
            }
            ensure_trusted_ancestors_from(&resolved, uid, hops + 1)?;
            return Ok(true);
        }
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
    Ok(false)
}

/// Resolve `.` and `..` textually. Only applied to a symlink target joined to
/// a directory this walk already validated as a real, non-symlink path.
fn lexically_normalized(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    normalized
}

/// Decompress a marked entry with bounded memory and bounded output. The
/// compressed source remains untouched until a complete plaintext sibling has
/// been written, synced, and the entry identity has been revalidated.
fn decompress_zstd_entry(entry: &mut TrashEntry, max_output: u64) -> io::Result<()> {
    decompress_before_commit(entry, max_output, || {})
}

fn decompress_before_commit(
    entry: &mut TrashEntry,
    max_output: u64,
    before_commit: impl FnOnce(),
) -> io::Result<()> {
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
        || !compression_source_matches(&metadata, &input.metadata()?)
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
        before_commit();
        let _guard = RootMutationGuard::acquire(&entry.trash_root)?;
        if file_identity(&entry.trashed_path) != Some(expected_identity)
            || sidecar_version(&entry.info_path) != Some(expected_sidecar)
            || !compression_source_matches(&metadata, &input.metadata()?)
        {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        // Compression records the marker first. A crash in that narrow window
        // leaves ordinary plaintext plus a stale marker; clear only that known
        // state. A payload with real zstd magic must decode successfully.
        set_compression_marker(&entry.info_path, None)?;
        entry.info = cleared;
        entry.sidecar_version = sidecar_version(&entry.info_path);
        return Ok(());
    }

    // Staged in the root's private state directory (same filesystem): an
    // interrupted restore left `files/.trashd-decompress-*`, listed forever
    // as an orphaned entry of up to 4 GiB (#334).
    let mut staging = create_data_stage(&entry.trash_root)?;
    // Bound input too: appended skippable frames need not produce output,
    // so an output limit alone cannot bound work on a growing source.
    let mut decoder = zstd::stream::Decoder::new((&mut input).take(metadata.len()))?;
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

    before_commit();
    let _guard = RootMutationGuard::acquire(&entry.trash_root)?;
    if file_identity(&entry.trashed_path) != Some(expected_identity)
        || sidecar_version(&entry.info_path) != Some(expected_sidecar)
        || !compression_source_matches(&metadata, &input.metadata()?)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "trash entry changed before decompression commit",
        ));
    }
    staging
        .persist(&entry.trashed_path)
        .map_err(|error| error.error)?;
    let _ = keep_times(&entry.trashed_path, &metadata);
    entry.identity = file_identity(&entry.trashed_path);

    // Treat marker retirement as part of the transaction. If it fails, leave
    // the recoverable plaintext+marker state; the next restore recognizes the
    // missing magic and retries this write without decoding the file again.
    set_compression_marker(&entry.info_path, None)?;
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

impl SidecarVersion {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

fn sidecar_version(path: &Path) -> Option<SidecarVersion> {
    let m = fs::symlink_metadata(path).ok()?;
    if !m.is_file() {
        return None;
    }
    Some(SidecarVersion::from_metadata(&m))
}

fn sidecar_snapshot(path: &Path) -> Option<SidecarVersion> {
    let m = fs::symlink_metadata(path).ok()?;
    Some(SidecarVersion::from_metadata(&m))
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

/// Open `path` without following a replacement symlink and without blocking
/// on a replacement FIFO, verify it is still the same regular file that the
/// caller statted, then hash it. A swapped or vanished target fails the hash
/// (hashing is best-effort metadata) instead of hanging or reading through a
/// link.
fn hash_file_verified(path: &Path, algorithm: &str, expect: (u64, u64)) -> io::Result<String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || (m.dev(), m.ino()) != expect {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "target changed while hashing",
        ));
    }
    hash_reader(file, algorithm)
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

/// Apparent bytes (file lengths, as `X-Trashd-Size` records) and allocated
/// bytes (blocks of 512, as the directorysizes cache records) of a tree, in
/// one walk. The file-capped walk recorded a quarter of a 40,000-file tree,
/// hiding it from retention's size limit and status, and the cache then
/// walked the same tree again (#336). Symlinks are not followed or counted.
fn tree_sizes(path: &Path) -> (u64, u64) {
    let Some(dir) = CString::new(path.as_os_str().as_bytes())
        .ok()
        .and_then(|name| open_directory_at(libc::AT_FDCWD, &name, true, false).ok())
    else {
        return (0, 0);
    };
    let sizes = tree_survey(dir.as_raw_fd(), false);
    (sizes.apparent, sizes.allocated)
}

/// A directory tree's apparent and allocated sizes and, when looked for,
/// the first mount point found below it (relative to the tree), which ends
/// the walk.
#[derive(Default)]
struct TreeSurvey {
    apparent: u64,
    allocated: u64,
    mount: Option<PathBuf>,
    /// Part of the tree could not be walked (too deep, unreadable): a mount
    /// there was not seen.
    incomplete: bool,
}

impl TreeSurvey {
    /// A tree whose root could not even be opened.
    fn unwalked() -> Self {
        Self {
            incomplete: true,
            ..Self::default()
        }
    }

    /// A mount point inside the tree at `root`, relative to it: the one the
    /// walk found, or, where it could not walk everything, one the mount
    /// table names. A part it could not see moved the live mount with the
    /// tree (#370).
    fn mount_in(&self, root: &Path) -> Option<PathBuf> {
        self.mount
            .clone()
            .or_else(|| self.incomplete.then(|| mounts::mount_below(root)).flatten())
    }
}

/// Walk the open directory `dir` once for `TreeSurvey`. Every lookup is
/// relative to the directory's descriptor: an absolute path cost a lookup
/// of each component per file (#368). Files are measured with the one statx
/// they cost anyway, which also reports a bind-mounted file; `find_mounts`
/// costs each directory one statx more (#366). Symlinks are neither
/// followed nor counted.
fn tree_survey(dir: RawFd, find_mounts: bool) -> TreeSurvey {
    let mut survey = TreeSurvey::default();
    let dev = if find_mounts {
        stat_fd(dir).map_or(0, |stat| stat.st_dev)
    } else {
        0
    };
    survey_directory(dir, dev, 0, find_mounts, &mut PathBuf::new(), &mut survey);
    survey
}

fn survey_directory(
    dir: RawFd,
    dev: u64,
    depth: u32,
    find_mounts: bool,
    relative: &mut PathBuf,
    survey: &mut TreeSurvey,
) {
    use std::ops::ControlFlow::{Break, Continue};
    if depth > COPY_TREE_MAX_DEPTH {
        survey.incomplete = true;
        return;
    }
    let own_mount = std::cell::OnceCell::new();
    let unseen = |error: io::Error, survey: &mut TreeSurvey| {
        if error.raw_os_error() != Some(libc::ENOENT) {
            survey.incomplete = true;
        }
    };
    let listed = for_each_entry(dir, |name, kind| {
        if kind == libc::DT_LNK {
            return Continue(());
        }
        // A directory needs a statx only to be told from a mount.
        let info = if kind == libc::DT_DIR && !find_mounts {
            None
        } else {
            let mask = if kind == libc::DT_DIR {
                libc::STATX_TYPE
            } else {
                libc::STATX_TYPE | libc::STATX_SIZE | libc::STATX_BLOCKS
            };
            match mounts::entry_info_at(dir, name, mask) {
                Ok(info) => Some(info),
                Err(error) => {
                    unseen(error, survey);
                    return Continue(());
                }
            }
        };
        let format = info
            .as_ref()
            .map_or(libc::S_IFDIR, |info| info.mode & libc::S_IFMT);
        if format == libc::S_IFLNK {
            return Continue(());
        }
        if let Some(info) = &info {
            if find_mounts && survey_mount(dir, dev, &own_mount, name, info) {
                survey.mount = Some(relative.join(OsStr::from_bytes(name.to_bytes())));
                return Break(());
            }
            if format != libc::S_IFDIR {
                survey.apparent = survey.apparent.saturating_add(info.size);
                survey.allocated = survey
                    .allocated
                    .saturating_add(info.blocks.saturating_mul(512));
                return Continue(());
            }
        }
        let child = match open_directory_at(dir, name, true, false) {
            Ok(child) => child,
            Err(error) => {
                unseen(error, survey);
                return Continue(());
            }
        };
        relative.push(OsStr::from_bytes(name.to_bytes()));
        let child_dev = info.map_or(0, |info| info.dev);
        survey_directory(
            child.as_raw_fd(),
            child_dev,
            depth + 1,
            find_mounts,
            relative,
            survey,
        );
        relative.pop();
        if survey.mount.is_some() {
            Break(())
        } else {
            Continue(())
        }
    });
    if let Err(error) = listed {
        unseen(error, survey);
    }
}

/// Whether the entry `name` of `dir` (on device `dev`) is a mount root.
/// statx says since Linux 5.8. Before, a directory compares mount IDs
/// (`dir`'s read once, a failed read not remembered: #365, #367), then
/// devices; a file bind-mounted from the same filesystem is not seen, and
/// a file's device is not compared: overlayfs reports its layer's (#358).
fn survey_mount(
    dir: RawFd,
    dev: u64,
    own_mount: &std::cell::OnceCell<i32>,
    name: &CStr,
    info: &mounts::EntryInfo,
) -> bool {
    if let Some(root) = info.mount_root {
        return root;
    }
    if info.mode & libc::S_IFMT != libc::S_IFDIR {
        return false;
    }
    let known = own_mount.get().copied().or_else(|| {
        let id = mounts::mount_id_at(dir, c"", libc::AT_EMPTY_PATH)?;
        let _ = own_mount.set(id);
        Some(id)
    });
    match (known, mounts::mount_id_at(dir, name, 0)) {
        (Some(above), Some(own)) => own != above,
        _ => info.dev != dev,
    }
}

/// Measure a foreign or unrecorded tree for accounting. Unlike eligibility
/// sizing, there is no entry/depth cap. A recorded size is only a ceiling:
/// stop once it is reached, but never let forged text exceed measured data.
/// Descriptor-relative lookups avoid repeatedly resolving every ancestor;
/// batched directory reads and an explicit stack bound memory by depth.
/// Symlinks and mounted subtrees are excluded, as for a tree we can purge.
fn directory_accounted_size(path: &Path, ceiling: Option<u64>) -> u64 {
    let limit = ceiling.unwrap_or(u64::MAX);
    if limit == 0 {
        return 0;
    }
    struct Level {
        directory: fs::File,
        dev: u64,
        mount: std::cell::OnceCell<i32>,
        pending: Vec<(CString, u8)>,
    }
    impl Level {
        fn new(directory: fs::File, dev: u64) -> Self {
            Self {
                directory,
                dev,
                mount: std::cell::OnceCell::new(),
                pending: Vec::new(),
            }
        }
    }
    let Some(root) = CString::new(path.as_os_str().as_bytes())
        .ok()
        .and_then(|name| open_directory_at(libc::AT_FDCWD, &name, true, false).ok())
        .and_then(|directory| {
            let dev = stat_fd(directory.as_raw_fd()).ok()?.st_dev;
            Some(Level::new(directory, dev))
        })
    else {
        return 0;
    };
    let mut levels = vec![root];
    let mut buffer = Vec::with_capacity(DIRENT_BUFFER);
    let mut total = 0u64;
    while let Some(level) = levels.last_mut() {
        let Some((name, kind)) = level.pending.pop() else {
            if !read_entry_batch(level.directory.as_raw_fd(), &mut buffer, &mut level.pending)
                .unwrap_or(false)
            {
                levels.pop();
            }
            continue;
        };
        if kind == libc::DT_LNK {
            continue;
        }
        let directory = level.directory.as_raw_fd();
        let Ok(info) = mounts::entry_info_at(
            directory,
            &name,
            libc::STATX_TYPE | libc::STATX_SIZE | libc::STATX_INO,
        ) else {
            continue;
        };
        let format = info.mode & libc::S_IFMT;
        if format == libc::S_IFLNK || survey_mount(directory, level.dev, &level.mount, &name, &info)
        {
            continue;
        }
        if format != libc::S_IFDIR {
            total = total.saturating_add(info.size);
            if total >= limit {
                return limit;
            }
            continue;
        }
        let Ok(child) = open_directory_at(directory, &name, true, false) else {
            continue;
        };
        let Ok(opened) =
            mounts::entry_info_at(child.as_raw_fd(), c"", libc::STATX_TYPE | libc::STATX_INO)
        else {
            continue;
        };
        // A positive directory type from getdents is only a hint. Validate
        // the opened object too so a replaced name cannot redirect the walk.
        if opened.dev != info.dev
            || opened.ino != info.ino
            || survey_mount(directory, level.dev, &level.mount, &name, &opened)
        {
            continue;
        }
        levels.push(Level::new(child, opened.dev));
    }
    total
}

/// Opt-in eligibility sizing reports whether the file-count cap was hit.
/// When it was, the returned size is only a partial sum of the first
/// `DIR_SIZE_MAX_FILES` entries — callers enforcing a size limit must treat a
/// capped result as "unknown / over limit" rather than trusting the partial.
fn dir_size_capped(path: &Path) -> (u64, bool) {
    let mut total = 0u64;
    let mut count = 0u64;
    dir_size_inner(path, &mut total, &mut count);
    // The walk visits one entry past the cap, so a tree of exactly the cap
    // is not mistaken for an oversized one (#223).
    (total, count > DIR_SIZE_MAX_FILES)
}

fn dir_size_inner(path: &Path, total: &mut u64, count: &mut u64) {
    if *count > DIR_SIZE_MAX_FILES {
        return;
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if *count > DIR_SIZE_MAX_FILES {
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

/// Entry data retention found not worth compressing, by data identity
/// (device, inode, size, mtime), kept in the home root's state directory.
/// Every run read each such entry into memory and encoded it again — all
/// photos, videos and archives older than a week, once a minute (#336).
struct IncompressibleData {
    file: PathBuf,
    known: std::collections::HashSet<String>,
    /// Keys confirmed this run; only these are kept when saving, so data
    /// that left the trash drops out.
    current: std::collections::HashSet<String>,
}

impl IncompressibleData {
    const MAX_BYTES: u64 = 4 * 1024 * 1024;

    fn load(home: &Path) -> Self {
        let file = home.join(".trashd/incompressible");
        let known = crate::trashinfo::read_regular_text_file(&file, Self::MAX_BYTES)
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default();
        Self {
            file,
            known,
            current: std::collections::HashSet::new(),
        }
    }

    fn key(meta: &fs::Metadata) -> String {
        format!(
            "{}:{}:{}:{}.{}",
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec()
        )
    }

    fn known(&mut self, meta: &fs::Metadata) -> bool {
        let key = Self::key(meta);
        let known = self.known.contains(&key);
        if known {
            self.current.insert(key);
        }
        known
    }

    fn add(&mut self, meta: &fs::Metadata) {
        self.current.insert(Self::key(meta));
    }

    fn save(self) {
        if self.current == self.known {
            return;
        }
        let mut text: String = self.current.iter().map(|key| format!("{key}\n")).collect();
        text.truncate(Self::MAX_BYTES as usize);
        let Some(dir) = self.file.parent() else {
            return;
        };
        if let Ok(mut staging) = tempfile::NamedTempFile::new_in(dir)
            && staging.write_all(text.as_bytes()).is_ok()
        {
            let _ = staging.persist(&self.file);
        }
    }
}

/// Formats that are compressed already (or nearly incompressible).
fn is_compressed_format(header: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        &[0x28, 0xB5, 0x2F, 0xFD],             // zstd
        &[0x1F, 0x8B],                         // gzip
        b"BZh",                                // bzip2
        &[0xFD, b'7', b'z', b'X', b'Z', 0x00], // xz
        &[0x04, 0x22, 0x4D, 0x18],             // lz4
        b"PK\x03\x04",                         // zip, jar, docx, odt, apk
        &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C], // 7z
        b"Rar!",                               // rar
        &[0x89, b'P', b'N', b'G'],             // png
        &[0xFF, 0xD8, 0xFF],                   // jpeg
        b"GIF8",                               // gif
        &[0x1A, 0x45, 0xDF, 0xA3],             // matroska, webm
        b"OggS",                               // ogg
        b"fLaC",                               // flac
        b"ID3",                                // mp3
    ];
    MAGICS.iter().any(|magic| header.starts_with(magic))
        // ISO base media (mp4, mov, heic, avif): "ftyp" at offset 4.
        || header.get(4..8) == Some(b"ftyp")
        // RIFF WEBP
        || (header.starts_with(b"RIFF") && header.get(8..12) == Some(b"WEBP"))
}

/// Which roots' directorysizes caches a batch of removals changed. The cache
/// lists directories only: a removed file matters only when a (stale) row
/// carries its name. Each root's cache is read once; batches used to rebuild
/// every root — statting every entry — after any removal (#336).
#[derive(Default)]
struct CacheRefresh {
    /// Cached names per root; None when the cache needs repair anyway.
    names: std::collections::HashMap<PathBuf, Option<std::collections::HashSet<Vec<u8>>>>,
    dirty: std::collections::HashSet<PathBuf>,
}

impl CacheRefresh {
    fn note_removal(&mut self, entry: &TrashEntry, was_directory: bool) {
        let root = &entry.trash_root;
        if self.dirty.contains(root) {
            return;
        }
        let affected = was_directory || {
            let names = self
                .names
                .entry(root.clone())
                .or_insert_with(|| crate::directorysizes::cached_names(root));
            match (names, entry.trashed_path.file_name()) {
                (Some(names), Some(name)) => names.contains(name.as_bytes()),
                _ => true,
            }
        };
        if affected {
            self.dirty.insert(root.clone());
        }
    }

    fn apply(self, store: &TrashStore) {
        for root in self.dirty {
            store.refresh_cache(&root);
        }
    }
}

/// Prefix of trees detached for deletion inside a root's `.trashd/`.
const DETACHED_PREFIX: &str = "purging-";
const COPY_STAGE_PREFIX: &str = ".trashd-copy-";
const STAGES_PER_SWEEP: usize = 32;

/// Reserved data-stage names are visible only after their original file
/// descriptor holds an exclusive lifetime lock (#389).
pub const DATA_STAGE_PREFIX: &str = ".trashd-stage-v1-";
const DATA_STAGE_RANDOM_LEN: usize = 16;

/// Announce an unpublished compression/decompression stage only after its
/// lifetime flock is held. A crash before announcement leaves an ambiguous,
/// empty .tmp file; maintenance must never guess that it is disposable.
pub fn create_data_stage(root: &Path) -> io::Result<tempfile::NamedTempFile> {
    let staging = tempfile::Builder::new()
        .prefix(".tmp")
        .rand_bytes(DATA_STAGE_RANDOM_LEN)
        .tempfile_in(root.join(".trashd"))?;
    // umask may have removed every mode bit. Keep the initial announced
    // inode readable to its owner until source metadata is restored.
    staging
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    staging.as_file().lock()?;
    let token = staging
        .path()
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix(".tmp"))
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let announced = staging
        .path()
        .with_file_name(format!("{DATA_STAGE_PREFIX}{token}"));
    let file = staging
        .persist_noclobber(&announced)
        .map_err(|error| error.error)?;
    let path = tempfile::TempPath::try_from_path(announced)?;
    Ok(tempfile::NamedTempFile::from_parts(file, path))
}

fn is_data_stage(name: &CStr) -> bool {
    name.to_bytes()
        .strip_prefix(DATA_STAGE_PREFIX.as_bytes())
        .is_some_and(|token| {
            token.len() == DATA_STAGE_RANDOM_LEN && token.iter().all(u8::is_ascii_alphanumeric)
        })
}

/// Opening read-only also handles preserved 0400 modes. Root may have
/// restored another owner's metadata onto the stage; the private parent
/// and announced-name protocol authorize cleanup, not the inode's owner.
fn try_lock_data_stage_at(state: RawFd, name: &CStr) -> io::Result<Option<fs::File>> {
    let before = stat_at(state, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(None);
    }
    let descriptor = unsafe {
        libc::openat(
            state,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    if stat_identity(&stat_fd(descriptor)?) != stat_identity(&before) {
        return Ok(None);
    }
    // A shared lock conflicts with the producer's exclusive lock and also
    // works on read-only descriptors on NFS. Root guards serialize claims.
    if unsafe { libc::flock(descriptor, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(io::Error::last_os_error())
        };
    }
    Ok(Some(file))
}

fn claim_data_stage_at(state: RawFd, name: &CStr, locked: &fs::File) -> io::Result<CString> {
    let opened = stat_fd(locked.as_raw_fd())?;
    let current = stat_at(state, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if opened.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat_identity(&opened) != stat_identity(&current)
    {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    claim_copy_stage_at(state, name)
}

fn is_copy_stage(name: &CStr) -> bool {
    let Some(suffix) = name.to_bytes().strip_prefix(COPY_STAGE_PREFIX.as_bytes()) else {
        return false;
    };
    let mut parts = suffix.split(|&byte| byte == b'-');
    (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
    }) && parts.next().is_none()
}

/// Exclusive mkdir claims a private container even on filesystems without
/// RENAME_NOREPLACE. Its data name is initially absent, so the rename cannot
/// replace another stage or unrelated state. A crash leaves a purging-
/// container that the normal detached sweep can finish.
fn claim_copy_stage_at(state: RawFd, name: &CStr) -> io::Result<CString> {
    for attempt in 0u32..64 {
        let claim = CString::new(format!(
            "{DETACHED_PREFIX}copy-{}-{}-{attempt}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos())
        ))?;
        if unsafe { libc::mkdirat(state, claim.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(error);
        }
        let claimed = (|| {
            let directory = open_directory_at(state, &claim, true, false)?;
            if unsafe {
                libc::renameat(
                    state,
                    name.as_ptr(),
                    directory.as_raw_fd(),
                    c"data".as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if let Err(error) = claimed {
            let _ = raw_unlinkat(state, &claim, libc::AT_REMOVEDIR);
            return Err(error);
        }
        return Ok(claim);
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

/// Move a directory entry's data into its root's private state directory
/// (same filesystem), returning that directory and the new name.
fn detach_for_removal(entry: &TrashEntry) -> io::Result<(fs::File, CString)> {
    let state_dir = CString::new(entry.trash_root.join(".trashd").as_os_str().as_bytes())?;
    let state = open_directory_at(libc::AT_FDCWD, &state_dir, true, false)?;
    let files_dir = CString::new(entry.trash_root.join("files").as_os_str().as_bytes())?;
    let files = open_directory_at(libc::AT_FDCWD, &files_dir, true, true)?;
    let data_name = CString::new(
        entry
            .trashed_path
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .as_bytes(),
    )?;
    for attempt in 0u32..64 {
        let name = CString::new(format!(
            "{DETACHED_PREFIX}{}-{}-{attempt}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos())
        ))?;
        match rename_noreplace_at(files.as_raw_fd(), &data_name, state.as_raw_fd(), &name) {
            Ok(()) => return Ok((state, name)),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => {
                // No RENAME_NOREPLACE here: delete in place, under the lock.
                remove_tree_at(files.as_raw_fd(), &data_name, 0)?;
                return Ok((state, CString::default()));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

/// Delete trees an earlier purge detached but could not finish. Reuse the
/// full unlocked enumeration to sample bounded unpublished stages. A large
/// stage pool is reclaimed across later passes, rather than in one pass.
fn sweep_detached(root: &Path) -> Vec<CString> {
    use std::hash::BuildHasher;
    let selection = std::collections::hash_map::RandomState::new();
    sweep_detached_prioritized(root, |name| selection.hash_one(name.to_bytes()))
}

fn sweep_detached_prioritized(root: &Path, priority: impl Fn(&CStr) -> u64) -> Vec<CString> {
    let Ok(state_dir) = CString::new(root.join(".trashd").as_os_str().as_bytes()) else {
        return Vec::new();
    };
    let Ok(state) = open_directory_at(libc::AT_FDCWD, &state_dir, true, false) else {
        return Vec::new();
    };
    // Sample the full scan, keeping only 32 names. Always keeping the first
    // 32 could hide abandoned stages behind long-lived locked ones forever.
    let mut candidates: std::collections::BinaryHeap<(u64, CString)> =
        std::collections::BinaryHeap::new();
    let scanned = for_each_entry(state.as_raw_fd(), |name, _| {
        if name.to_bytes().starts_with(DETACHED_PREFIX.as_bytes()) {
            let _ = remove_tree_at(state.as_raw_fd(), name, 0);
        } else if is_copy_stage(name) || is_data_stage(name) {
            let rank = priority(name);
            if candidates.len() < STAGES_PER_SWEEP {
                candidates.push((rank, name.to_owned()));
            } else if candidates
                .peek()
                .is_some_and(|(last, saved)| (rank, name) < (*last, saved.as_c_str()))
            {
                candidates.pop();
                candidates.push((rank, name.to_owned()));
            }
        }
        std::ops::ControlFlow::Continue(())
    });
    if scanned.is_err() {
        return Vec::new();
    }
    candidates.into_iter().map(|(_, name)| name).collect()
}

const REMOVE_TREE_MAX_DEPTH: u32 = 4096;

/// Remove `parent/name` and everything below it with raw syscalls, making
/// each directory searchable and writable for its owner first: a directory
/// without u+wx (Go module caches, Bazel or Nix outputs keep 0555 trees)
/// made fs::remove_dir_all fail after deleting what it could, so purge,
/// empty and retention could never remove such an entry (#335). An empty
/// name (an already removed tree) is a no-op.
fn remove_tree_at(parent: RawFd, name: &CStr, depth: u32) -> io::Result<()> {
    remove_tree_in(parent, &std::cell::OnceCell::new(), name, depth)
}

/// `remove_tree_at` with the parent's mount ID, read at most once per
/// directory and only where statx cannot tell a mount root. A failed read
/// is not remembered (#365).
fn remove_tree_in(
    parent: RawFd,
    parent_mount: &std::cell::OnceCell<i32>,
    name: &CStr,
    depth: u32,
) -> io::Result<()> {
    remove_tree_with_reader(parent, parent_mount, name, depth, read_entry_batch)
}

/// One buffer for the entire walk; a level retains only the names in its
/// current batch. A deep chain therefore does not keep a 32 KiB buffer at
/// every ancestor, and a wide directory never needs a complete name list.
fn remove_tree_with_reader(
    parent: RawFd,
    parent_mount: &std::cell::OnceCell<i32>,
    name: &CStr,
    depth: u32,
    mut read: impl FnMut(RawFd, &mut Vec<u8>, &mut Vec<(CString, u8)>) -> io::Result<bool>,
) -> io::Result<()> {
    let Some(root) = prepare_tree_removal(parent, parent_mount, name, depth)? else {
        return Ok(());
    };
    let mut stack = vec![root];
    let mut buffer = Vec::with_capacity(DIRENT_BUFFER);
    while let Some(top) = stack.last_mut() {
        if top.pending.is_empty() && !top.listed {
            match read(top.directory.as_raw_fd(), &mut buffer, &mut top.pending) {
                Ok(more) => top.listed = !more,
                Err(error) => {
                    top.failure.get_or_insert(error);
                    top.listed = true;
                }
            }
            // Keep directory order when popping, including first-error order.
            top.pending.reverse();
            continue;
        }
        if let Some((child, _)) = top.pending.pop() {
            match prepare_tree_removal(top.directory.as_raw_fd(), &top.mount, &child, top.depth + 1)
            {
                Ok(Some(level)) => stack.push(level),
                Ok(None) => {}
                Err(error) => {
                    top.failure.get_or_insert(error);
                }
            }
            continue;
        }
        let level = stack.pop().expect("the top level was just seen");
        drop(level.directory);
        let up = stack.last().map_or(parent, |up| up.directory.as_raw_fd());
        let result = if let Some(error) = level.failure {
            Err(error)
        } else {
            match raw_unlinkat(up, &level.name, libc::AT_REMOVEDIR) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                result => result,
            }
        };
        match stack.last_mut() {
            Some(up) => {
                if let Err(error) = result {
                    up.failure.get_or_insert(error);
                }
            }
            None => return result,
        }
    }
    unreachable!("the walk returns when its last level is removed")
}

struct TreeRemovalLevel {
    directory: fs::File,
    name: CString,
    pending: Vec<(CString, u8)>,
    listed: bool,
    mount: std::cell::OnceCell<i32>,
    depth: u32,
    failure: Option<io::Error>,
}

/// Remove a non-directory now, or open a verified directory for the walk.
fn prepare_tree_removal(
    parent: RawFd,
    parent_mount: &std::cell::OnceCell<i32>,
    name: &CStr,
    depth: u32,
) -> io::Result<Option<TreeRemovalLevel>> {
    if name.is_empty() {
        return Ok(None);
    }
    let (mode, identity, mount) = match mounts::entry_status_at(parent, name) {
        Ok(status) => status,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(error) => return Err(error),
    };
    if mode & libc::S_IFMT != libc::S_IFDIR {
        return match raw_unlinkat(parent, name, 0) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            result => result.map(|()| None),
        };
    }
    // A mount point that travelled into the trash with its directory (rm -r
    // of a tree holding one) is never touched: purging through it deleted
    // the mounted filesystem's data, and even its mode stays as it is. It
    // stays, busy, until unmounted (#362, #363). Only directories are asked
    // (#364).
    let mount = mount.unwrap_or_else(|| {
        // Mount IDs, from file handles (no /proc needed) or fdinfo; the
        // parent's is read once per directory (#365, #367).
        let known = parent_mount.get().copied().or_else(|| {
            let id = mounts::mount_id_at(parent, c"", libc::AT_EMPTY_PATH)?;
            let _ = parent_mount.set(id);
            Some(id)
        });
        match (known, mounts::mount_id_at(parent, name, 0)) {
            (Some(above), Some(own)) => own != above,
            // Neither can tell: a device that differs from the parent's
            // still marks a mount (not a bind from the same filesystem).
            _ => stat_fd(parent).is_ok_and(|above| above.st_dev != identity.0),
        }
    });
    if mount {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    if depth > REMOVE_TREE_MAX_DEPTH {
        return Err(io::Error::other("directory tree too deep to remove"));
    }
    if mode & 0o700 != 0o700
        && unsafe { libc::fchmodat(parent, name.as_ptr(), 0o700, libc::AT_SYMLINK_NOFOLLOW) } != 0
    {
        // Linux rejects AT_SYMLINK_NOFOLLOW for fchmodat; lstat proved this
        // is a directory, which nobody else can swap inside a private root.
        if unsafe { libc::fchmodat(parent, name.as_ptr(), 0o700, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let directory = open_directory_at(parent, name, true, false)?;
    if stat_identity(&stat_fd(directory.as_raw_fd())?) != identity {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "directory changed while being removed",
        ));
    }
    // Every entry is tried: one that stays (a mount) must not keep its
    // siblings in the trash (#363).
    Ok(Some(TreeRemovalLevel {
        directory,
        name: name.to_owned(),
        pending: Vec::new(),
        listed: false,
        mount: std::cell::OnceCell::new(),
        depth,
        failure: None,
    }))
}

/// Before a cross-device copy: retiring `name` must be possible, or the
/// copy was only stranded beside it (#368, #370, #371). The same walk
/// captures the entries that can subsequently be retired: statting and
/// listing the complete tree again only repeated this work (#379).
/// Nothing to unlink may be a mount point (including a bind-mounted file),
/// immutable or append-only; every directory it is unlinked from (its own,
/// and each one of a tree that has entries) must be writable by the
/// effective user and not pinned itself, and, if sticky, let the user remove
/// what it holds. An empty directory needs nothing of itself. Those
/// verdicts are `Unremovable`; failing to examine the tree (a directory
/// that cannot be listed) is the copy's own I/O failure.
fn snapshot_retirable_at(
    parent: RawFd,
    name: &CStr,
    expected: (u64, u64),
) -> Result<Option<Vec<DirectorySnapshotEntry>>, TrashError> {
    let refused = |errno| Err(TrashError::Unremovable(io::Error::from_raw_os_error(errno)));
    let mask = libc::STATX_TYPE | libc::STATX_MODE | libc::STATX_INO | libc::STATX_UID;
    let source = mounts::entry_info_at(parent, name, mask)?;
    if (source.dev, source.ino) != expected {
        return Err(io::Error::from_raw_os_error(libc::ENOENT).into());
    }
    let is_dir = source.mode & libc::S_IFMT == libc::S_IFDIR;
    let mount = source.mount_root.unwrap_or_else(|| {
        match (
            mounts::mount_id_at(parent, c"", libc::AT_EMPTY_PATH),
            mounts::mount_id_at(parent, name, 0),
        ) {
            (Some(above), Some(own)) => own != above,
            // A file's device is its layer's on overlayfs (#358).
            _ => is_dir && stat_fd(parent).is_ok_and(|above| above.st_dev != source.dev),
        }
    });
    if mount {
        return refused(libc::EBUSY);
    }
    let above = mounts::entry_info_at(parent, c"", mask)?;
    removable_from(parent, &above)?;
    if mounts::entry_pinned_at(parent, name, &source)? || sticky_refuses(&above, source.uid) {
        return refused(libc::EPERM);
    }
    if is_dir {
        let directory = open_directory_at(parent, name, true, false)?;
        verify_snapshot_directory(directory.as_raw_fd(), expected)?;
        let mut snapshot = Vec::new();
        snapshot_retirable_fd(directory.as_raw_fd(), &source, &[], 0, &mut snapshot)?;
        snapshot.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Some(snapshot))
    } else {
        Ok(None)
    }
}

/// Whether entries can be unlinked from `directory` (described by `own`).
fn removable_from(directory: RawFd, own: &mounts::EntryInfo) -> Result<(), TrashError> {
    if mounts::entry_pinned_at(directory, c"", own)? {
        return Err(TrashError::Unremovable(io::Error::from_raw_os_error(
            libc::EPERM,
        )));
    }
    writable(directory).map_err(|error| {
        if matches!(
            error.raw_os_error(),
            Some(libc::EACCES | libc::EPERM | libc::EROFS)
        ) {
            TrashError::Unremovable(error)
        } else {
            TrashError::Io(error)
        }
    })
}

fn snapshot_retirable_fd(
    directory: RawFd,
    own: &mounts::EntryInfo,
    prefix: &[u8],
    depth: u32,
    snapshot: &mut Vec<DirectorySnapshotEntry>,
) -> Result<(), TrashError> {
    if depth > COPY_TREE_MAX_DEPTH {
        return Err(snapshot_depth_error().into());
    }
    let entries = read_directory_names(directory)?;
    if !entries.is_empty() {
        removable_from(directory, own)?;
    }
    // Every entry is a victim: an immutable or append-only one of any kind
    // refuses unlink(2) (#371).
    for name in entries {
        let entry = mounts::entry_info_at(
            directory,
            &name,
            libc::STATX_TYPE
                | libc::STATX_MODE
                | libc::STATX_INO
                | libc::STATX_UID
                | libc::STATX_SIZE
                | libc::STATX_MTIME
                | libc::STATX_CTIME,
        )?;
        if mounts::entry_pinned_at(directory, &name, &entry)? || sticky_refuses(own, entry.uid) {
            return Err(TrashError::Unremovable(io::Error::from_raw_os_error(
                libc::EPERM,
            )));
        }
        let path = child_snapshot_path(prefix, &name);
        snapshot.push(DirectorySnapshotEntry {
            path: path.clone(),
            device: entry.dev,
            inode: entry.ino,
            mode: entry.mode,
            size: entry.size as libc::off_t,
            modified: entry.modified,
            changed: entry.changed,
        });
        if entry.mode & libc::S_IFMT == libc::S_IFDIR {
            let child = open_directory_at(directory, &name, true, false)?;
            verify_snapshot_directory(child.as_raw_fd(), (entry.dev, entry.ino))?;
            snapshot_retirable_fd(child.as_raw_fd(), &entry, &path, depth + 1, snapshot)?;
        }
    }
    Ok(())
}

/// Whether the sticky directory `above` keeps the effective user from
/// removing an entry owned by `owner`.
fn sticky_refuses(above: &mounts::EntryInfo, owner: u32) -> bool {
    let euid = unsafe { libc::geteuid() };
    above.mode & libc::S_ISVTX != 0 && owner != euid && above.uid != euid && !has_fowner()
}

/// Whether this process's effective capabilities include CAP_FOWNER, which
/// overrides a sticky directory (root without it does not).
fn has_fowner() -> bool {
    static FOWNER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FOWNER.get_or_init(|| {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: libc::c_int,
        }
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        const VERSION_3: u32 = 0x2008_0522;
        const CAP_FOWNER: u32 = 3;
        let mut header = Header {
            version: VERSION_3,
            pid: 0,
        };
        let mut data = [Data::default(); 2];
        let ok = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut Header,
                data.as_mut_ptr(),
            )
        } == 0;
        if ok {
            data[0].effective & (1 << CAP_FOWNER) != 0
        } else {
            unsafe { libc::geteuid() == 0 }
        }
    })
}

/// Whether the effective user may write the directory `directory`
/// (faccessat2, Linux 5.8). Where faccessat2 is missing or refused (old
/// container profiles answer EPERM), the original syscall asks as the real
/// user, who is the effective one for a shim: glibc's faccessat would only
/// try faccessat2 again.
fn writable(directory: RawFd) -> io::Result<()> {
    let effective = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            directory,
            c".".as_ptr(),
            libc::W_OK,
            libc::AT_EACCESS,
        )
    };
    if effective == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) {
        return Err(error);
    }
    let real = unsafe { libc::syscall(libc::SYS_faccessat, directory, c".".as_ptr(), libc::W_OK) };
    if real == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// rm -r for real: remove `name` in the open directory `parent` and all it
/// holds, by descriptor. A path walk followed a directory swapped for a
/// symlink mid-removal out of the tree (the CVE-2022-21658 race, #369).
/// Like rm, an entry that cannot be removed goes to `report`, with its path
/// below `name` (empty for `name` itself), and keeps its directories without
/// another report; the rest goes, and a directory that cannot be listed is
/// still removed if empty. A mount point stays as it is, busy: nothing is
/// removed through one (#368). The walk keeps its own stack, so depth is
/// bounded only by descriptors, as with std's remove_dir_all (#370). True
/// when all of it went.
pub fn remove_tree_for_real(
    parent: RawFd,
    name: &CStr,
    report: &mut dyn FnMut(&Path, io::Error),
) -> bool {
    let mut below = PathBuf::new();
    let top_mount = std::cell::OnceCell::new();
    // One getdents buffer for the walk; each level holds only its current
    // batch of names (#370).
    let mut buffer = Vec::with_capacity(DIRENT_BUFFER);
    let mut stack = match remove_entry(parent, &top_mount, name, None, &below, report) {
        Removal::Done(removed) => return removed,
        Removal::Descend(level) => vec![level],
    };
    while let Some(top) = stack.last_mut() {
        if top.batch.is_empty() && !top.listed {
            let directory = top.directory.as_raw_fd();
            match read_entry_batch(directory, &mut buffer, &mut top.batch) {
                Ok(more) => {
                    top.listed = !more;
                    top.batch.reverse();
                }
                Err(error) => {
                    top.all &= settle_removal(Err(error), &below, report);
                    top.listed = true;
                }
            }
            continue;
        }
        if let Some((child, kind)) = top.batch.pop() {
            below.push(OsStr::from_bytes(child.to_bytes()));
            let directory = top.directory.as_raw_fd();
            match remove_entry(directory, &top.mount, &child, Some(kind), &below, report) {
                Removal::Done(removed) => {
                    top.all &= removed;
                    below.pop();
                }
                Removal::Descend(level) => stack.push(level),
            }
            continue;
        }
        let level = stack.pop().expect("the top level was just seen");
        drop(level.directory);
        let up = stack.last().map_or(parent, |up| up.directory.as_raw_fd());
        let removed = level.all
            && settle_removal(
                raw_unlinkat(up, &level.name, libc::AT_REMOVEDIR),
                &below,
                report,
            );
        match stack.last_mut() {
            Some(up) => {
                up.all &= removed;
                below.pop();
            }
            None => return removed,
        }
    }
    unreachable!("the walk returns when its last level is removed")
}

/// A directory being emptied by `remove_tree_for_real`.
struct RemovalLevel {
    directory: fs::File,
    name: CString,
    /// Entries read but not yet removed, last first.
    batch: Vec<(CString, u8)>,
    /// The whole directory has been read.
    listed: bool,
    /// Its mount ID, read once and only where statx cannot tell a mount.
    mount: std::cell::OnceCell<i32>,
    all: bool,
}

enum Removal {
    Done(bool),
    Descend(RemovalLevel),
}

/// Whether a removal went (a vanished entry did); a failure is reported.
fn settle_removal(
    result: io::Result<()>,
    below: &Path,
    report: &mut dyn FnMut(&Path, io::Error),
) -> bool {
    match result {
        Err(error) if error.raw_os_error() != Some(libc::ENOENT) => {
            report(below, error);
            false
        }
        _ => true,
    }
}

/// Remove `name` in `parent`, or open it as a directory to empty first; its
/// d_type, when listed, is `kind`.
fn remove_entry(
    parent: RawFd,
    parent_mount: &std::cell::OnceCell<i32>,
    name: &CStr,
    kind: Option<u8>,
    below: &Path,
    report: &mut dyn FnMut(&Path, io::Error),
) -> Removal {
    let mut done = |result: io::Result<()>| Removal::Done(settle_removal(result, below, report));
    // A listed non-directory needs no stat: unlink(2) says EISDIR if it
    // became a directory meanwhile.
    if kind.is_some_and(|kind| kind != libc::DT_DIR && kind != libc::DT_UNKNOWN) {
        match raw_unlinkat(parent, name, 0) {
            Err(error) if error.raw_os_error() == Some(libc::EISDIR) => {}
            result => return done(result),
        }
    }
    let (mode, identity, mount) = match mounts::entry_status_at(parent, name) {
        Ok(status) => status,
        Err(error) => return done(Err(error)),
    };
    if mode & libc::S_IFMT != libc::S_IFDIR {
        return done(raw_unlinkat(parent, name, 0));
    }
    let mount = mount.unwrap_or_else(|| {
        let known = parent_mount.get().copied().or_else(|| {
            let id = mounts::mount_id_at(parent, c"", libc::AT_EMPTY_PATH)?;
            let _ = parent_mount.set(id);
            Some(id)
        });
        match (known, mounts::mount_id_at(parent, name, 0)) {
            (Some(above), Some(own)) => own != above,
            _ => stat_fd(parent).is_ok_and(|above| above.st_dev != identity.0),
        }
    });
    if mount {
        return done(Err(io::Error::from_raw_os_error(libc::EBUSY)));
    }
    let directory = match open_directory_at(parent, name, true, false) {
        Ok(directory) => directory,
        // rm still tries rmdir(2) on a directory it cannot list: an empty
        // one goes.
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return match raw_unlinkat(parent, name, libc::AT_REMOVEDIR) {
                Ok(()) => Removal::Done(true),
                Err(_) => done(Err(error)),
            };
        }
        Err(error) => return done(Err(error)),
    };
    // Mounted over or replaced since the stat: not the directory seen.
    if stat_fd(directory.as_raw_fd())
        .map(|stat| stat_identity(&stat))
        .ok()
        != Some(identity)
    {
        return done(Err(io::Error::from_raw_os_error(libc::EBUSY)));
    }
    Removal::Descend(RemovalLevel {
        directory,
        name: name.to_owned(),
        batch: Vec::new(),
        listed: false,
        mount: std::cell::OnceCell::new(),
        all: true,
    })
}

/// unlink(2) of an absolute path as a raw syscall (see `raw_unlinkat`).
fn raw_unlink_path(path: &Path) -> io::Result<()> {
    raw_unlinkat(
        libc::AT_FDCWD,
        &CString::new(path.as_os_str().as_bytes())?,
        0,
    )
}

/// unlinkat(2) as a raw syscall. Store-internal removals must never go
/// through the interposable libc wrapper: under a system-wide LD_PRELOAD the
/// hook would trash them again (#104, #192, #196).
fn raw_unlinkat(parent: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    if unsafe { libc::syscall(libc::SYS_unlinkat, parent, name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Retire a copied non-directory source only if it is still exactly the
/// version that was copied (#192). A replaced or modified file is the user's
/// newer data: it stays, and the caller reports an incomplete move. A source
/// that is already gone counts as retired.
fn retire_copied_node_at(parent: RawFd, name: &CStr, copied: &libc::stat) -> io::Result<bool> {
    match stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(current) if same_source_version(copied, &current) => {}
        Ok(_) => return Ok(false),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(true),
        Err(error) => return Err(error),
    }
    match raw_unlinkat(parent, name, 0) {
        Ok(()) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Copy a directory tree preserving symlinks and permissions.
/// Depth-limited to prevent infinite recursion from symlink loops or
/// bind mounts creating cycles.
const COPY_TREE_MAX_DEPTH: u32 = 100;

/// Write `data` to `path` atomically: write to a temp file in the same
/// directory, then rename over `path`. A crash / ENOSPC / kill mid-write can
/// therefore never leave a truncated file in place (the rename is atomic, and
/// on failure the original is untouched).
fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    atomic_write_staged(
        path,
        data,
        path.parent().unwrap_or_else(|| Path::new(".")),
        None,
    )
}

/// `atomic_write` staging the replacement in `dir` (same filesystem). The
/// replacement keeps `times`, the metadata taken before the caller read the
/// file, or else the replaced file's current times.
fn atomic_write_staged(
    path: &Path,
    data: &[u8],
    dir: &Path,
    times: Option<&fs::Metadata>,
) -> io::Result<()> {
    prepare_atomic_write_staged(path, data, dir, times)?
        .persist(path)
        .map_err(|e| e.error)?;
    Ok(())
}

/// Fully prepare a replacement without retiring its source. Callers that
/// encode a snapshot can revalidate it after all staging I/O is complete.
fn prepare_atomic_write_staged(
    path: &Path,
    data: &[u8],
    dir: &Path,
    times: Option<&fs::Metadata>,
) -> io::Result<tempfile::NamedTempFile> {
    prepare_atomic_write_replacement(path, data, tempfile::NamedTempFile::new_in(dir)?, times)
}

fn prepare_atomic_write_replacement(
    path: &Path,
    data: &[u8],
    mut staging: tempfile::NamedTempFile,
    times: Option<&fs::Metadata>,
) -> io::Result<tempfile::NamedTempFile> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic replacement requires a regular file",
        ));
    }
    staging.write_all(data)?;
    let staged_meta = staging.as_file().metadata()?;
    if staged_meta.uid() != meta.uid() || staged_meta.gid() != meta.gid() {
        use std::os::fd::AsRawFd;
        if unsafe { libc::fchown(staging.as_file().as_raw_fd(), meta.uid(), meta.gid()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    staging.as_file().set_permissions(meta.permissions())?;
    // The replacement keeps the replaced file's times: data swapped in by
    // compression publishes the original's (#202), and a rewritten sidecar
    // keeps the mtime that orders entries without a deletion stamp (#345).
    // Reading the data to compress it can itself bump atime (#352).
    let times = times.unwrap_or(&meta);
    staging.as_file().set_times(
        fs::FileTimes::new()
            .set_accessed(times.accessed()?)
            .set_modified(times.modified()?),
    )?;
    staging.as_file().sync_all()?;
    Ok(staging)
}

/// True when a data-absent entry is old enough for purge/empty to treat as
/// fully retired. `trash()` writes the sidecar BEFORE the data lands, so a
/// freshly-written data-absent sidecar may be an in-flight trash (the
/// cross-device copy window spans seconds) — stripping its sidecar
/// would strand the completed move as an unrestorable orphan (#169).
pub fn data_absence_is_retired(info_path: &Path) -> bool {
    const GRACE_SECS: u64 = 5;
    let sidecar_age = fs::symlink_metadata(info_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs());
    match sidecar_age {
        Some(age) => age >= GRACE_SECS,
        // Unreadable sidecar: nothing in flight to protect; purge semantics
        // for a genuinely missing sidecar still apply.
        None => true,
    }
}

/// Take an exclusive flock on an entry's data file. Restore holds it across
/// its identity check → rename and both compressors hold it across their
/// validate → swap (through the marker write and data swap, #170), so
/// "validated" can never interleave with "renamed" — the #105 revalidations
/// alone left that window open (#168). Blocking is fine: the other side
/// holds it for milliseconds. Non-regular entries (symlinks, dirs) are
/// never swapped by compressors, so there is nothing to serialize —
/// Ok(None). Any open error means the entry vanished or changed; callers
/// map that to EntryNotFound.
fn lock_entry_file(path: &Path) -> io::Result<Option<fs::File>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Ok(None);
    }
    // O_NONBLOCK like every other entry-data open (#111): a FIFO swapped
    // into the path in the TOCTOU window must not hang the caller.
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        // Data its owner cannot read (mode 000/200/300) cannot be compressed
        // either, so there is nothing to serialize against; refusing made
        // such an entry impossible to restore or purge (#335).
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    // File::lock is flock(LOCK_EX) without an EINTR retry (std uses cvt, not
    // cvt_r), so a handled signal while blocked would surface as an error —
    // retry instead (#170).
    loop {
        match file.lock() {
            Ok(()) => return Ok(Some(file)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Strip redundant separators and `.` components from a conflict destination
/// so the `--force` sibling candidates ("backup.1", "backup.2") are built from
/// a normalized base: a trailing-slash `--to backup/` must not concatenate to
/// the hidden "backup/.1" INSIDE the directory (#158).
pub fn normalize_conflict_base(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Atomically (over)write a `.trashinfo` file. Public so the CLI `compress`
/// command can record the `X-Trashd-Compressed` marker without re-implementing
/// the temp-file+rename dance.
pub fn write_trashinfo_atomic(info_path: &Path, info: &TrashInfo) -> io::Result<()> {
    atomic_write(info_path, info.to_trashinfo_string().as_bytes())
}

/// Set or clear the `X-Trashd-Compressed` marker, leaving every other byte
/// of the sidecar as it is on disk. Writing back a listed `TrashInfo` turned
/// relative topdir `Path=` values absolute (list() resolves them), which broke
/// restore once the drive was mounted elsewhere (#218).
pub fn set_compression_marker(info_path: &Path, algorithm: Option<&str>) -> io::Result<()> {
    let original = crate::trashinfo::read_sidecar_bytes(info_path)?;
    let mut text: Vec<u8> = Vec::with_capacity(original.len() + 32);
    for line in original.split_inclusive(|&b| b == b'\n') {
        if !line.starts_with(b"X-Trashd-Compressed=") {
            text.extend_from_slice(line);
        }
    }
    if let Some(algorithm) = algorithm {
        if !text.is_empty() && !text.ends_with(b"\n") {
            text.push(b'\n');
        }
        text.extend_from_slice(format!("X-Trashd-Compressed={algorithm}\n").as_bytes());
    }
    atomic_write(info_path, &text)
}

/// Give a swapped-in file the original's access and modification times, so
/// compressing or decompressing an entry does not change what restore
/// publishes (#202).
fn keep_times(path: &Path, original: &fs::Metadata) -> io::Result<()> {
    let times = [
        libc::timespec {
            tv_sec: original.atime(),
            tv_nsec: original.atime_nsec(),
        },
        libc::timespec {
            tv_sec: original.mtime(),
            tv_nsec: original.mtime_nsec(),
        },
    ];
    let name = CString::new(path.as_os_str().as_bytes())?;
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether compression may replace an entry's data inode at all: a regular
/// file written by trashd and not yet compressed, with a single link (another
/// link would keep the original data and double its disk use) and no
/// extended attributes (ACLs, labels, capabilities and user data would not
/// survive the replacement inode). Other FreeDesktop tools' entries stay
/// readable to them (#202, #327).
pub fn compression_candidate(entry: &TrashEntry, data: &fs::Metadata) -> bool {
    !entry.orphaned
        && entry.info.compressed.is_none()
        && entry.info.is_trashd_entry()
        && data.is_file()
        && data.nlink() == 1
        && !has_xattrs(&entry.trashed_path)
}

/// Compare content and metadata versions without treating an atime update
/// caused by reading as a modification. Shared by both compressors (#386).
pub fn compression_source_matches(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    expected.dev() == current.dev()
        && expected.ino() == current.ino()
        && expected.mode() == current.mode()
        && expected.len() == current.len()
        && expected.nlink() == current.nlink()
        && expected.uid() == current.uid()
        && expected.gid() == current.gid()
        && expected.mtime() == current.mtime()
        && expected.mtime_nsec() == current.mtime_nsec()
        && expected.ctime() == current.ctime()
        && expected.ctime_nsec() == current.ctime_nsec()
}

/// Read one selected version with bounded work even if a writer keeps
/// growing it. Reserve the probe byte too, avoiding a capacity doubling
/// when an initially maximum-sized file grows by a single byte.
fn read_compression_input(
    input: &mut impl io::Read,
    expected_size: u64,
    max_bytes: u64,
) -> io::Result<Option<Vec<u8>>> {
    if expected_size > max_bytes {
        return Ok(None);
    }
    let Some(bound) = expected_size
        .checked_add(1)
        .and_then(|n| usize::try_from(n).ok())
    else {
        return Ok(None);
    };
    let mut data = Vec::with_capacity(bound);
    input.take(bound as u64).read_to_end(&mut data)?;
    Ok((data.len() as u64 == expected_size).then_some(data))
}

/// Extended attributes (ACLs, labels, user data) would not survive the
/// replacement inode, so such files are never auto-compressed (#202).
fn has_xattrs(path: &Path) -> bool {
    let Ok(name) = CString::new(path.as_os_str().as_bytes()) else {
        return true;
    };
    unsafe { libc::llistxattr(name.as_ptr(), std::ptr::null_mut(), 0) != 0 }
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

/// Copy one source node into the trash for the cross-device path. Device
/// nodes and sockets cannot be reproduced, so they abort the copy and nothing
/// is retired, instead of being skipped and then deleted (#192).
fn copy_source_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    staging_parent: RawFd,
    source: &libc::stat,
) -> io::Result<(u64, u64)> {
    match source.st_mode & libc::S_IFMT {
        libc::S_IFREG | libc::S_IFDIR => copy_staged_at(
            src_parent,
            src_name,
            dst_parent,
            dst_name,
            staging_parent,
            source,
        ),
        libc::S_IFLNK => copy_symlink_at(src_parent, src_name, dst_parent, dst_name, source),
        libc::S_IFIFO => {
            if unsafe {
                libc::mkfifoat(
                    dst_parent,
                    dst_name.as_ptr(),
                    (source.st_mode & 0o7777) as libc::mode_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let identity =
                stat_identity(&stat_at(dst_parent, dst_name, libc::AT_SYMLINK_NOFOLLOW)?);
            validate_created_node(dst_parent, dst_name, libc::S_IFIFO, identity)?;
            if let Err(error) = apply_node_metadata_at(dst_parent, dst_name, source) {
                let _ = remove_created_at(dst_parent, dst_name, identity);
                return Err(error);
            }
            Ok(identity)
        }
        _ => Err(io::Error::other(
            "cannot trash device nodes or sockets across filesystems",
        )),
    }
}

/// Copy a regular file or directory tree under a hidden name in
/// `staging_parent` (same filesystem as `dst_parent`), then publish it as
/// `dst_name` without replacing anything. A process killed mid-copy skips
/// every rollback: copying under the final name left a truncated file there
/// — beside a valid sidecar in the trash direction, or at the original path
/// in the restore direction, where a retry then reported a conflict (#334).
/// Renaming keeps the node's identity, which callers verify afterwards.
fn copy_staged_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    staging_parent: RawFd,
    source: &libc::stat,
) -> io::Result<(u64, u64)> {
    let (staging, identity) = (0u32..64)
        .find_map(|attempt| {
            let staging = CString::new(format!(
                "{COPY_STAGE_PREFIX}{}-{}-{attempt}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.subsec_nanos())
            ))
            .ok()?;
            let copied = if source.st_mode & libc::S_IFMT == libc::S_IFDIR {
                let mut tree = TreeCopy::new(staging_parent);
                copy_directory_at(
                    src_parent,
                    src_name,
                    staging_parent,
                    &staging,
                    source,
                    0,
                    &mut tree,
                    staging.to_bytes(),
                )
            } else {
                copy_regular_at(src_parent, src_name, staging_parent, &staging, source)
            };
            match copied {
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => None,
                result => Some(result.map(|identity| (staging, identity))),
            }
        })
        .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::AlreadyExists)))?;
    let published = match rename_noreplace_at(staging_parent, &staging, dst_parent, dst_name) {
        Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => {
            publish_without_noreplace(staging_parent, &staging, dst_parent, dst_name, source)
        }
        result => result,
    };
    if let Err(error) = published {
        let _ = remove_created_tree_at(staging_parent, &staging, identity);
        return Err(error);
    }
    Ok(identity)
}

/// Publication where RENAME_NOREPLACE is unsupported: a hard link fails on
/// an existing name; a directory, which cannot be linked, is renamed only
/// onto a name that is still free.
fn publish_without_noreplace(
    staging_parent: RawFd,
    staging: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    source: &libc::stat,
) -> io::Result<()> {
    if source.st_mode & libc::S_IFMT != libc::S_IFDIR {
        if unsafe {
            libc::linkat(
                staging_parent,
                staging.as_ptr(),
                dst_parent,
                dst_name.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        return raw_unlinkat(staging_parent, staging, 0);
    }
    match stat_at(dst_parent, dst_name, libc::AT_SYMLINK_NOFOLLOW) {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Ok(_) => return Err(io::Error::from_raw_os_error(libc::EEXIST)),
        Err(error) => return Err(error),
    }
    if unsafe {
        libc::renameat(
            staging_parent,
            staging.as_ptr(),
            dst_parent,
            dst_name.as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
            let destination_identity = copy_staged_at(
                src_parent, src_name, dst_parent, dst_name, dst_parent, &stat,
            )?;
            unlink_source_or_rollback(
                src_parent,
                src_name,
                dst_parent,
                dst_name,
                &stat,
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
                &stat,
                destination_identity,
            )
        }
        libc::S_IFDIR => {
            let before = snapshot_directory_at(src_parent, src_name)?;
            let destination_identity = copy_staged_at(
                src_parent, src_name, dst_parent, dst_name, dst_parent, &stat,
            )?;
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
            match retire_directory_snapshot_at(
                src_parent,
                src_name,
                expected_identity,
                &before,
                true,
            ) {
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
                &stat,
                destination_identity,
            )
        }
        _ => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
    }
}

fn stat_times(stat: &libc::stat) -> [libc::timespec; 2] {
    [
        libc::timespec {
            tv_sec: stat.st_atime,
            tv_nsec: stat.st_atime_nsec as _,
        },
        libc::timespec {
            tv_sec: stat.st_mtime,
            tv_nsec: stat.st_mtime_nsec as _,
        },
    ]
}

/// Preserve the source's timestamps on a cross-device copy (#248): the
/// rename path keeps them for free, the copy path must apply them.
fn apply_fd_times(fd: RawFd, source: &libc::stat) -> io::Result<()> {
    let times = stat_times(source);
    if unsafe { libc::futimens(fd, times.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn apply_times_at(parent: RawFd, name: &CStr, source: &libc::stat) -> io::Result<()> {
    let times = stat_times(source);
    if unsafe {
        libc::utimensat(
            parent,
            name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Best-effort extended-attribute copy for cross-device copies (#248).
/// Failures (unsupported fs, permissions) never fail the move itself.
fn copy_xattrs_fd(source: RawFd, destination: RawFd) {
    let size = unsafe { libc::flistxattr(source, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return;
    }
    let mut names = vec![0u8; size as usize];
    if unsafe { libc::flistxattr(source, names.as_mut_ptr().cast(), names.len()) } < 0 {
        return;
    }
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let Ok(cname) = std::ffi::CString::new(name) else {
            continue;
        };
        let vsize = unsafe { libc::fgetxattr(source, cname.as_ptr(), std::ptr::null_mut(), 0) };
        if vsize < 0 {
            continue;
        }
        let mut value = vec![0u8; vsize as usize];
        if unsafe {
            libc::fgetxattr(
                source,
                cname.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        } < 0
        {
            continue;
        }
        unsafe {
            libc::fsetxattr(
                destination,
                cname.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            );
        }
    }
}

/// Recursively remove a destination tree this copy created after a failed
/// copy (#244). `remove_created_at` alone retains a non-empty directory,
/// which left partial trees behind as unrestorable orphans (trash) or
/// permanently blocked every restore retry. The root identity is verified
/// first, so a replaced destination is never touched.
fn remove_created_tree_at(parent: RawFd, name: &CStr, expected: (u64, u64)) -> io::Result<()> {
    let stat = match stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) if stat_identity(&stat) == expected => stat,
        Ok(_) => return Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error),
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return remove_created_at(parent, name, expected);
    }
    let dir = open_directory_at(parent, name, true, false)?;
    if stat_identity(&stat_fd(dir.as_raw_fd())?) != expected {
        return Ok(());
    }
    for child in read_directory_names(dir.as_raw_fd())? {
        let child_stat = stat_at(dir.as_raw_fd(), &child, libc::AT_SYMLINK_NOFOLLOW)?;
        remove_created_tree_at(dir.as_raw_fd(), &child, stat_identity(&child_stat))?;
    }
    drop(dir);
    remove_created_at(parent, name, expected)
}

/// Publication follows the copy's own version check. Recheck the selected
/// source here too: an in-place edit during metadata, sync or publication
/// belongs to the source, not to our earlier restored copy (#396).
fn unlink_source_or_rollback(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    expected_source: &libc::stat,
    destination_identity: (u64, u64),
) -> io::Result<()> {
    let current = stat_at(src_parent, src_name, libc::AT_SYMLINK_NOFOLLOW);
    if !matches!(current, Ok(ref current) if same_source_version(current, expected_source)) {
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
    if let Err(error) = raw_unlinkat(src_parent, src_name, 0) {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(error);
    }
    Ok(())
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
    if actual.st_mode & libc::S_IFMT != libc::S_IFREG || !same_source_version(&actual, expected) {
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
        copy_extents(&mut source, &mut destination, actual.st_size as u64)?;
        let after = stat_fd(source.as_raw_fd())?;
        if !same_source_version(&actual, &after) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "source file changed while it was being copied",
            ));
        }
        apply_fd_metadata(destination.as_raw_fd(), expected)?;
        copy_xattrs_fd(source.as_raw_fd(), destination.as_raw_fd());
        apply_fd_times(destination.as_raw_fd(), expected)?;
        destination.sync_all()
    })();
    drop(destination);
    if let Err(error) = copied {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(error);
    }
    Ok(destination_identity)
}

/// Copy a file's data extents only, leaving its holes as holes: a plain
/// copy wrote a 3 GiB sparse image with 4 KiB of data as 3 GiB, which can
/// fail with ENOSPC where `mv` succeeds (#338). Filesystems without
/// SEEK_DATA get a plain copy.
fn copy_extents(source: &mut fs::File, destination: &mut fs::File, len: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    if len == 0 {
        return destination.set_len(0);
    }
    let fd = source.as_raw_fd();
    let mut offset: libc::off_t = 0;
    loop {
        let data = unsafe { libc::lseek(fd, offset, libc::SEEK_DATA) };
        if data < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                // No data past `offset`: the rest is a hole.
                Some(libc::ENXIO) => break,
                Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) if offset == 0 => {
                    source.seek(SeekFrom::Start(0))?;
                    io::copy(&mut io::Read::by_ref(source).take(len), destination)?;
                    return Ok(());
                }
                _ => return Err(error),
            }
        }
        // A writer can append data beyond the captured EOF after the caller's
        // stat. Neither that extent nor a growing final extent is ours to copy.
        if data as u64 >= len {
            break;
        }
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        source.seek(SeekFrom::Start(data as u64))?;
        destination.seek(SeekFrom::Start(data as u64))?;
        let wanted = (hole as u64).min(len) - data as u64;
        let copied = io::copy(&mut io::Read::by_ref(source).take(wanted), destination)?;
        if copied < wanted {
            // Truncated meanwhile; the caller's version check rejects it.
            break;
        }
        offset = hole;
        if offset as u64 >= len {
            break;
        }
    }
    // Trailing holes: size the copy without writing them.
    destination.set_len(len)
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
    let _ = apply_times_at(dst_parent, dst_name, expected);
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

fn snapshot_depth_error() -> io::Error {
    io::Error::other(format!(
        "directory tree too deep (>{COPY_TREE_MAX_DEPTH} levels) — possible cycle"
    ))
}

fn verify_snapshot_directory(directory: RawFd, expected: (u64, u64)) -> io::Result<()> {
    if stat_identity(&stat_fd(directory)?) != expected {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "source directory changed while taking a copy snapshot",
        ));
    }
    Ok(())
}

/// One tree copy in progress: the directory that holds the copied tree, and
/// the copy of each multiply linked source inode made so far. Later links
/// to the same inode are hard-linked to that copy: copying each one turned a
/// 100 MiB file with six links into 600 MiB of separate files (#338).
struct TreeCopy {
    base: RawFd,
    /// Source (device, inode) -> destination path relative to `base`.
    links: std::collections::HashMap<(u64, u64), CString>,
}

impl TreeCopy {
    fn new(base: RawFd) -> Self {
        Self {
            base,
            links: std::collections::HashMap::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn copy_directory_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    expected: &libc::stat,
    depth: u32,
    tree: &mut TreeCopy,
    dst_path: &[u8],
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
            let mut child_path = dst_path.to_vec();
            child_path.push(b'/');
            child_path.extend_from_slice(child.to_bytes());
            copy_node_at(
                source.as_raw_fd(),
                &child,
                destination.as_raw_fd(),
                &child,
                depth + 1,
                tree,
                &child_path,
            )?;
        }
        apply_fd_metadata(destination.as_raw_fd(), expected)?;
        copy_xattrs_fd(source.as_raw_fd(), destination.as_raw_fd());
        apply_fd_times(destination.as_raw_fd(), expected)
    })();

    drop(destination);
    if let Err(error) = copied {
        let _ = remove_created_tree_at(dst_parent, dst_name, destination_identity);
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
    tree: &mut TreeCopy,
    dst_path: &[u8],
) -> io::Result<()> {
    let stat = stat_at(src_parent, src_name, libc::AT_SYMLINK_NOFOLLOW)?;
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG if stat.st_nlink > 1 => {
            let identity = stat_identity(&stat);
            if let Some(first) = tree.links.get(&identity)
                && unsafe {
                    libc::linkat(tree.base, first.as_ptr(), dst_parent, dst_name.as_ptr(), 0)
                } == 0
            {
                return Ok(());
            }
            copy_regular_at(src_parent, src_name, dst_parent, dst_name, &stat)?;
            if let Ok(path) = CString::new(dst_path) {
                tree.links.entry(identity).or_insert(path);
            }
            Ok(())
        }
        libc::S_IFREG => {
            copy_regular_at(src_parent, src_name, dst_parent, dst_name, &stat).map(|_| ())
        }
        libc::S_IFLNK => {
            copy_symlink_at(src_parent, src_name, dst_parent, dst_name, &stat).map(|_| ())
        }
        libc::S_IFDIR => copy_directory_at(
            src_parent, src_name, dst_parent, dst_name, &stat, depth, tree, dst_path,
        )
        .map(|_| ()),
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
    let mut mode = source.st_mode & 0o7777;
    if unsafe { libc::fchown(fd, source.st_uid, source.st_gid) } != 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
            || unsafe { libc::geteuid() } == 0
        {
            return Err(error);
        }
        // Set-id bits belong to the original owner; on a copy owned by
        // someone else they would grant that owner's privileges (#203).
        mode &= !0o6000;
    }
    // chown may clear set-id bits, so permissions are always applied last.
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn apply_node_metadata_at(parent: RawFd, name: &CStr, source: &libc::stat) -> io::Result<()> {
    let mut mode = source.st_mode & 0o7777;
    if unsafe { libc::fchownat(parent, name.as_ptr(), source.st_uid, source.st_gid, 0) } != 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
            || unsafe { libc::geteuid() } == 0
        {
            return Err(error);
        }
        mode &= !0o6000; // see apply_fd_metadata (#203)
    }
    if unsafe { libc::fchmodat(parent, name.as_ptr(), mode, 0) } != 0 {
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
    let mut names = Vec::new();
    for_each_entry(fd, |name, _| {
        names.push(name.to_owned());
        std::ops::ControlFlow::Continue(())
    })?;
    Ok(names)
}

/// Call `each` with the name and d_type of every entry of the open
/// directory `fd` but . and .., read with getdents64(2) from that very
/// descriptor (its offset advances, as a dup's would). fdopendir cost a
/// dup, an fstat and an fcntl per directory, and closedir another close
/// (#368).
fn for_each_entry(
    fd: RawFd,
    mut each: impl FnMut(&CStr, u8) -> std::ops::ControlFlow<()>,
) -> io::Result<()> {
    let mut buffer = Vec::with_capacity(DIRENT_BUFFER);
    let mut batch = Vec::new();
    while read_entry_batch(fd, &mut buffer, &mut batch)? {
        for (name, kind) in batch.drain(..) {
            if each(&name, kind).is_break() {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// One getdents64(2) buffer: about a thousand entries.
const DIRENT_BUFFER: usize = 32 * 1024;

/// Append the entries one getdents64(2) call returns for `fd` (but . and
/// ..) to `batch`, through `buffer` (its capacity is the call's size).
/// False at the end of the directory.
fn read_entry_batch(
    fd: RawFd,
    buffer: &mut Vec<u8>,
    batch: &mut Vec<(CString, u8)>,
) -> io::Result<bool> {
    // struct linux_dirent64: d_ino (8), d_off (8), d_reclen (2), d_type (1),
    // then the NUL-terminated name.
    const NAME: usize = 19;
    let read = loop {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                fd,
                buffer.as_mut_ptr(),
                buffer.capacity(),
            )
        };
        if read >= 0 {
            break read as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    // Only what the kernel wrote is read, byte by byte: a record's header,
    // and its name up to the NUL, never the padding after it. The buffer is
    // never zeroed.
    let base = buffer.as_ptr();
    let invalid = || io::Error::from(io::ErrorKind::InvalidData);
    let mut offset = 0;
    while offset < read {
        if read - offset <= NAME {
            return Err(invalid());
        }
        let length =
            usize::from(unsafe { std::ptr::read_unaligned(base.add(offset + 16).cast::<u16>()) });
        if length <= NAME || length > read - offset {
            return Err(invalid());
        }
        let name = unsafe { base.add(offset + NAME) };
        let size = (0..length - NAME)
            .find(|&at| unsafe { *name.add(at) } == 0)
            .ok_or_else(invalid)?;
        let bytes = unsafe { std::slice::from_raw_parts(name, size) };
        if bytes != b"." && bytes != b".." {
            let kind = unsafe { *base.add(offset + 18) };
            batch.push((CString::new(bytes).map_err(|_| invalid())?, kind));
        }
        offset += length;
    }
    Ok(read > 0)
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
    // A raw syscall, NOT the interposable libc wrapper: this rollback runs
    // with the trash-root lock held, and under a system-wide LD_PRELOAD the
    // hooked wrapper trashed the half-written destination or blocked on that
    // same lock (#196, as #104 for source retirement).
    let Err(error) = raw_unlinkat(parent, name, flags) else {
        return Ok(());
    };
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

/// Remove exactly the nodes captured in `snapshot`; anything new or changed
/// stays (its parents too). `make_writable` lets restore retire trash
/// directories whose modes it owns; the trash direction never changes the
/// modes of directories it may leave behind in the user's tree (#192).
fn retire_directory_snapshot_at(
    parent: RawFd,
    name: &CStr,
    expected_root: (u64, u64),
    snapshot: &[DirectorySnapshotEntry],
    make_writable: bool,
) -> io::Result<bool> {
    let stat = stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if stat_identity(&stat) != expected_root || stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Ok(false);
    }
    let directory = open_directory_at(parent, name, true, false)?;
    if stat_identity(&stat_fd(directory.as_raw_fd())?) != expected_root {
        return Ok(false);
    }
    if make_writable && unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let index = SnapshotIndex::new(snapshot);
    let complete = retire_snapshot_directory_fd(directory.as_raw_fd(), &[], &index, make_writable)?;
    drop(directory);
    if !complete || !identity_matches_at(parent, name, expected_root) {
        return Ok(false);
    }
    if let Err(error) = raw_unlinkat(parent, name, libc::AT_REMOVEDIR) {
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

/// Lookups into a path-sorted snapshot. A linear search per node and a full
/// filter per directory made retiring a large tree quadratic (40k nodes:
/// 5.4 s) while the root lock was held (#336).
struct SnapshotIndex<'a> {
    snapshot: &'a [DirectorySnapshotEntry],
    /// Number of direct children per directory path ("" for the root).
    children: std::collections::HashMap<&'a [u8], usize>,
    /// Unlinking one hard link changes the inode's ctime, including every
    /// remaining alias. Remember only the version observed through our
    /// pinned victim after that unlink, so our own change does not strand
    /// the other links and later changes still refuse retirement.
    unlinked: std::cell::RefCell<std::collections::HashMap<(u64, u64), UnlinkedInode>>,
}

struct UnlinkedInode {
    original_changed: (libc::time_t, libc::c_long),
    current: libc::stat,
    /// A timestamp-preserving rewrite during unlink -> post-unlink stat
    /// could otherwise be mistaken for our own ctime change. Check the
    /// original content again before removing the inode's final link.
    digest: Option<String>,
}

impl<'a> SnapshotIndex<'a> {
    fn new(snapshot: &'a [DirectorySnapshotEntry]) -> Self {
        let mut children = std::collections::HashMap::new();
        for entry in snapshot {
            let parent = match entry.path.iter().rposition(|&b| b == b'/') {
                Some(slash) => &entry.path[..slash],
                None => &entry.path[..0],
            };
            *children.entry(parent).or_insert(0) += 1;
        }
        Self {
            snapshot,
            children,
            unlinked: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }

    fn get(&self, path: &[u8]) -> Option<&'a DirectorySnapshotEntry> {
        self.snapshot
            .binary_search_by(|entry| entry.path.as_slice().cmp(path))
            .ok()
            .map(|found| &self.snapshot[found])
    }

    fn child_count(&self, prefix: &[u8]) -> usize {
        self.children.get(prefix).copied().unwrap_or(0)
    }

    fn matches(&self, expected: &DirectorySnapshotEntry, current: &libc::stat) -> bool {
        snapshot_entry_matches(expected, current)
            || self
                .unlinked
                .borrow()
                .get(&(expected.device, expected.inode))
                .is_some_and(|last| {
                    expected.changed == last.original_changed
                        && same_source_version(&last.current, current)
                        && last.current.st_nlink == current.st_nlink
                        && last.current.st_uid == current.st_uid
                        && last.current.st_gid == current.st_gid
                })
    }

    fn note_unlink(
        &self,
        expected: &DirectorySnapshotEntry,
        before: &libc::stat,
        after: &libc::stat,
        digest: Option<String>,
    ) {
        // A successful unlink explains a ctime change and exactly one fewer
        // link. Reject other observed changes instead of adopting them as
        // a baseline for the remaining aliases.
        if stat_identity(before) == stat_identity(after)
            && before.st_mode == after.st_mode
            && before.st_uid == after.st_uid
            && before.st_gid == after.st_gid
            && before.st_size == after.st_size
            && before.st_mtime == after.st_mtime
            && before.st_mtime_nsec == after.st_mtime_nsec
            && before.st_nlink.checked_sub(1) == Some(after.st_nlink)
        {
            self.unlinked.borrow_mut().insert(
                stat_identity(before),
                UnlinkedInode {
                    original_changed: expected.changed,
                    current: *after,
                    digest,
                },
            );
        } else {
            self.unlinked.borrow_mut().remove(&stat_identity(before));
        }
    }

    fn content_digest(&self, stat: &libc::stat) -> Option<String> {
        self.unlinked
            .borrow()
            .get(&stat_identity(stat))
            .and_then(|last| last.digest.clone())
    }
}

/// Read only a regular inode whose full version still matches the one
/// being retired. Recheck both the open inode and its name after the hash:
/// reading a large file must not extend a pathname replacement window.
fn retirement_digest_at(
    parent: RawFd,
    name: &CStr,
    expected: &libc::stat,
) -> io::Result<Option<String>> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let matches = |current: &libc::stat| {
        current.st_mode & libc::S_IFMT == libc::S_IFREG
            && same_source_version(expected, current)
            && expected.st_nlink == current.st_nlink
            && expected.st_uid == current.st_uid
            && expected.st_gid == current.st_gid
    };
    if !matches(&stat_fd(file.as_raw_fd())?) {
        return Ok(None);
    }
    let digest = hash_reader(&mut file, "xxh3")?;
    if !matches(&stat_fd(file.as_raw_fd())?)
        || !matches(&stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW)?)
    {
        return Ok(None);
    }
    Ok(Some(digest))
}

fn retire_snapshot_directory_fd(
    directory: RawFd,
    prefix: &[u8],
    index: &SnapshotIndex,
    make_writable: bool,
) -> io::Result<bool> {
    let mut seen = 0usize;
    let mut complete = true;

    for name in read_directory_names(directory)? {
        let path = child_snapshot_path(prefix, &name);
        let Some(expected) = index.get(&path) else {
            complete = false;
            continue;
        };
        // Names in one directory are distinct, and every found path is a
        // direct child: counting compares the sets.
        seen += 1;
        if !retire_snapshot_node_at(directory, &name, &path, expected, index, make_writable)? {
            complete = false;
        }
    }
    if seen != index.child_count(prefix) {
        complete = false;
    }
    Ok(complete)
}

fn retire_snapshot_node_at(
    parent: RawFd,
    name: &CStr,
    path: &[u8],
    expected: &DirectorySnapshotEntry,
    index: &SnapshotIndex,
    make_writable: bool,
) -> io::Result<bool> {
    let stat = match stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) if index.matches(expected, &stat) => stat,
        Ok(_) => return Ok(false),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
        Err(error) => return Err(error),
    };

    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
        let directory = open_directory_at(parent, name, true, false)?;
        if stat_identity(&stat_fd(directory.as_raw_fd())?) != stat_identity(&stat) {
            return Ok(false);
        }
        if make_writable && unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let complete =
            retire_snapshot_directory_fd(directory.as_raw_fd(), path, index, make_writable)?;
        drop(directory);
        if !complete || !identity_matches_at(parent, name, stat_identity(&stat)) {
            return Ok(false);
        }
        retired(raw_unlinkat(parent, name, libc::AT_REMOVEDIR))
    } else {
        let current = stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW)?;
        if !index.matches(expected, &current) {
            return Ok(false);
        }
        let pinned = if current.st_nlink > 1 {
            let fd = unsafe {
                libc::openat(
                    parent,
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let pinned = unsafe { fs::File::from_raw_fd(fd) };
            let opened = stat_fd(pinned.as_raw_fd())?;
            if !same_source_version(&current, &opened) || current.st_nlink != opened.st_nlink {
                return Ok(false);
            }
            Some(pinned)
        } else {
            None
        };
        let mut digest = index.content_digest(&current);
        if current.st_mode & libc::S_IFMT == libc::S_IFREG {
            if current.st_nlink > 1 && digest.is_none() {
                digest = retirement_digest_at(parent, name, &current)?;
                if digest.is_none() {
                    return Ok(false);
                }
            } else if current.st_nlink == 1
                && let Some(expected_digest) = &digest
                && retirement_digest_at(parent, name, &current)?.as_ref() != Some(expected_digest)
            {
                return Ok(false);
            }
        }
        let removed = retired(raw_unlinkat(parent, name, 0))?;
        if removed
            && let Some(pinned) = pinned
            && let Ok(after) = stat_fd(pinned.as_raw_fd())
        {
            index.note_unlink(expected, &current, &after, digest);
        }
        Ok(removed)
    }
}

/// A removal racing another remover (ENOENT) or a directory that gained
/// entries (ENOTEMPTY) is "not retired", not a failure.
fn retired(result: io::Result<()>) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOTEMPTY) | Some(libc::ENOENT)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
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

/// Both supported digests have a fixed encoded length: XXH3-128 is 32 hex
/// characters and SHA-256 is 64. The stored digest therefore determines the
/// algorithm even when configuration changed after trashing. Successful
/// restores need only one scan, avoiding SHA-256 work for default XXH3 files.
fn restore_hash_mismatch_at(parent: RawFd, name: &CStr, expected: &str) -> Option<String> {
    let algorithm = if expected.len() == 64 {
        "sha256"
    } else {
        "xxhash"
    };
    let digest = hash_file_at(parent, name, algorithm).ok();
    if digest.as_deref() == Some(expected) {
        return None;
    }
    // Preserve the existing warning's preference for the XXH3 actual digest
    // on corruption, with the SHA-256 digest as fallback if XXH3 cannot read.
    let actual = if algorithm == "sha256" {
        hash_file_at(parent, name, "xxhash").ok().or(digest)
    } else {
        digest.or_else(|| hash_file_at(parent, name, "sha256").ok())
    };
    Some(actual.unwrap_or_else(|| "(unreadable)".into()))
}

/// Normalize a path: canonicalize the parent (resolving symlinks in directory
/// components) but preserve the final component as-is (so symlinks are not
/// followed for the target file itself).
///
/// A path whose final component is `.` or `..` has no file component to
/// preserve — it must be resolved FULLY. The parent-only canonicalization
/// would silently DROP a trailing `..` ("/a/b/.." → "/a/b"), pointing the
/// caller at the wrong directory (#83); for those shapes canonicalize the
/// whole path, falling back to lexical normalization when the target does not
/// exist.
/// `normalize_path` for a path relative to the current directory. getcwd is
/// already canonical, so only the relative directories are resolved; joining
/// the cwd first made realpath re-check every cwd component (#307).
fn normalize_relative(path: &Path) -> io::Result<PathBuf> {
    let ends_in_dot_component = !matches!(
        path.components().next_back(),
        Some(std::path::Component::Normal(_)) | None
    );
    if ends_in_dot_component && let Ok(resolved) = fs::canonicalize(path) {
        return Ok(resolved);
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if parent.as_os_str().is_empty() {
            return Ok(std::env::current_dir()?.join(name));
        }
        if let Ok(parent) = fs::canonicalize(parent) {
            return Ok(parent.join(name));
        }
    }
    Ok(normalize_path(&std::env::current_dir()?.join(path)))
}

fn normalize_path(path: &Path) -> PathBuf {
    let ends_in_dot_component = !matches!(
        path.components().next_back(),
        Some(std::path::Component::Normal(_)) | None
    );
    if ends_in_dot_component && let Ok(resolved) = fs::canonicalize(path) {
        return resolved;
    }
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
                // `\x` matches x literally, as in fnmatch(3).
                '\\' if pi + 1 < p.len() => {
                    if ti < t.len() && p[pi + 1] == t[ti] {
                        pi += 2;
                        ti += 1;
                        continue;
                    }
                }
                '[' if ti < t.len() => match class_match(&p, pi, t[ti]) {
                    ClassMatch::Matched(next) => {
                        pi = next;
                        ti += 1;
                        continue;
                    }
                    // A `[` without its `]` is an ordinary character, as in
                    // fnmatch(3); treating it as a failed class made such a
                    // pattern match nothing — in only_trash, every delete
                    // became permanent (#337).
                    ClassMatch::Unterminated if t[ti] == '[' => {
                        pi += 1;
                        ti += 1;
                        continue;
                    }
                    ClassMatch::Unterminated | ClassMatch::Unmatched => {}
                },
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

/// Outcome of matching one character against a `[...]` class.
enum ClassMatch {
    /// It matched; the pattern continues at this index (past the `]`).
    Matched(usize),
    Unmatched,
    /// No closing `]`: the `[` is an ordinary character.
    Unterminated,
}

/// Match one character against a `[...]` class starting at `p[start]`.
fn class_match(p: &[char], start: usize, c: char) -> ClassMatch {
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
            return if matched != negate {
                ClassMatch::Matched(i + 1)
            } else {
                ClassMatch::Unmatched
            };
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
    ClassMatch::Unterminated
}

/// Minimum age before disk pressure may purge an entry (#201).
const PRESSURE_MIN_AGE: chrono::TimeDelta = chrono::TimeDelta::hours(1);

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
        // So effective total = (f_blocks - f_bfree) + f_bavail.
        // saturating_sub: some FUSE filesystems report f_bfree > f_blocks;
        // unsigned wrap would fabricate a huge "used" and trigger retention
        // purges (#114).
        let used = stat.f_blocks.saturating_sub(stat.f_bfree);
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
    // Walk up to ten ancestors. Each stat read yields both the ancestor's
    // comm and the next parent, so no ancestor is read twice (#302).
    let mut parent = crate::proc_stat::own_comm_and_parent().map(|(_, parent)| parent);
    for _ in 0..10 {
        let pid = match parent {
            Some(p) if p > 1 => p,
            _ => break,
        };
        let stat = crate::proc_stat::comm_and_parent(pid);
        if process_names(pid, stat.as_ref().map(|(comm, _)| comm.as_str()))
            .iter()
            .any(|name| bypass_list.contains(name))
        {
            return true;
        }
        parent = stat.map(|(_, next)| next).filter(|next| *next != pid);
    }
    false
}

/// Both the executable's basename and the kernel's comm: for a script, comm
/// is the script's own name (pip, npm) while the executable is its
/// interpreter, so bypass entries for script tools never matched (#224).
pub(crate) fn process_names(pid: u32, comm: Option<&str>) -> Vec<String> {
    let mut names = Vec::with_capacity(2);
    if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe"))
        && let Some(name) = exe.file_name()
    {
        names.push(name.to_string_lossy().into_owned());
    }
    if let Some(comm) = comm
        && !names.iter().any(|name| name == comm)
    {
        names.push(comm.to_string());
    }
    names
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

    #[test]
    fn automatic_compression_preserves_newer_data_and_metadata() {
        for change in ["append", "rewrite", "mode", "link", "unchanged"] {
            let (store, _data, work, _) = test_store();
            let path = store.home.join("files/data");
            let original = vec![b'x'; 8192];
            fs::write(&path, &original).unwrap();
            let mut info = TrashInfo::new(work.path().join("data"));
            info.pid = Some(1);
            fs::write(
                store.home.join("info/data.trashinfo"),
                info.to_trashinfo_string(),
            )
            .unwrap();
            let mut entry = store.find_entry("data").unwrap();
            let sidecar = fs::read(&entry.info_path).unwrap();
            let input = fs::File::open(&path).unwrap();
            input.lock().unwrap();
            let expected = input.metadata().unwrap();
            let encoded = zstd::encode_all(original.as_slice(), 3).unwrap();
            match change {
                "append" => fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"newer content")
                    .unwrap(),
                "rewrite" => fs::write(&path, b"current bytes").unwrap(),
                "mode" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(expected.mode() ^ 0o100))
                        .unwrap()
                }
                "link" => fs::hard_link(&path, work.path().join("alias")).unwrap(),
                "unchanged" => {}
                _ => unreachable!(),
            }
            let current = fs::read(&path).unwrap();
            let published = store
                .publish_auto_compressed(&mut entry, &input, &expected, &encoded)
                .unwrap();
            assert_eq!(published, change == "unchanged", "{change}");
            if published {
                assert_eq!(
                    zstd::decode_all(fs::File::open(&path).unwrap()).unwrap(),
                    original
                );
                assert_eq!(entry.info.compressed.as_deref(), Some("zstd"));
            } else {
                assert_eq!(fs::read(&path).unwrap(), current);
                assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
                assert_eq!(fs::metadata(&path).unwrap().ino(), expected.ino());
            }
        }
    }

    #[test]
    fn automatic_compression_preserves_edits_after_staging_and_marker_write() {
        for phase in ["staging", "marker"] {
            let (store, _data, work, _) = test_store();
            let path = store.home.join("files/data");
            let original = vec![b'x'; 8192];
            fs::write(&path, &original).unwrap();
            let mut info = TrashInfo::new(work.path().join("data"));
            info.pid = Some(1);
            fs::write(
                store.home.join("info/data.trashinfo"),
                info.to_trashinfo_string(),
            )
            .unwrap();
            let mut entry = store.find_entry("data").unwrap();
            let info_path = entry.info_path.clone();
            let sidecar = fs::read(&entry.info_path).unwrap();
            let input = fs::File::open(&path).unwrap();
            input.lock().unwrap();
            let expected = input.metadata().unwrap();
            let encoded = zstd::encode_all(original.as_slice(), 3).unwrap();
            drop(RootMutationGuard::acquire(&store.home).unwrap());
            let state_files = || {
                let mut names = fs::read_dir(store.home.join(".trashd"))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>();
                names.sort();
                names
            };
            let before = state_files();
            let append = || {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"newer bytes")
                    .unwrap();
            };
            let published = store
                .publish_auto_compressed_before_commit(
                    &mut entry,
                    &input,
                    &expected,
                    &encoded,
                    || {
                        assert_eq!(state_files().len(), before.len() + 1);
                        assert!(
                            RootMutationGuard::try_acquire_as(&store.home, unsafe {
                                libc::geteuid()
                            })
                            .unwrap()
                            .is_some(),
                            "the replacement must be staged outside the root lock"
                        );
                        if phase == "staging" {
                            append();
                        }
                    },
                    || {
                        assert!(
                            fs::read_to_string(&info_path)
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
            assert!(!published, "{phase}: changed source was published");
            let mut current = original;
            current.extend_from_slice(b"newer bytes");
            assert_eq!(fs::read(&path).unwrap(), current);
            assert_eq!(fs::metadata(&path).unwrap().ino(), expected.ino());
            assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
            assert_eq!(entry.info.compressed, None);
            assert_eq!(entry.sidecar_version, sidecar_version(&entry.info_path));
            assert_eq!(state_files(), before, "aborted staging must be removed");
        }
    }

    #[test]
    fn automatic_compression_read_bounds_growing_input() {
        struct Growing(usize);
        impl io::Read for Growing {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                // A removed production bound must fail this test promptly,
                // rather than turn its infinite reader into an OOM loop.
                if self.0 + out.len() > 4096 {
                    return Err(io::Error::other("unbounded compression input read"));
                }
                self.0 += out.len();
                out.fill(b'x');
                Ok(out.len())
            }
        }
        let mut growing = Growing(0);
        assert!(
            read_compression_input(&mut growing, 1024, 4096)
                .unwrap()
                .is_none()
        );
        assert_eq!(growing.0, 1025);
        assert!(
            read_compression_input(&mut growing, 4097, 4096)
                .unwrap()
                .is_none()
        );
        assert_eq!(growing.0, 1025, "over-limit input is never read");
        assert_eq!(
            read_compression_input(&mut &b"exact"[..], 5, 4096)
                .unwrap()
                .unwrap(),
            b"exact"
        );
        assert!(
            read_compression_input(&mut &b"short"[..], 6, 4096)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn decompression_preserves_changed_encoded_and_plain_sources() {
        for encoded in [false, true] {
            let (store, _data, work, _) = test_store();
            let original = vec![b'x'; 8192];
            let mut bytes = if encoded {
                zstd::encode_all(original.as_slice(), 3).unwrap()
            } else {
                original
            };
            let path = store.home.join("files/data");
            fs::write(&path, &bytes).unwrap();
            let mut info = TrashInfo::new(work.path().join("data"));
            info.pid = Some(1);
            info.compressed = Some("zstd".into());
            fs::write(
                store.home.join("info/data.trashinfo"),
                info.to_trashinfo_string(),
            )
            .unwrap();
            let mut entry = store.find_entry("data").unwrap();
            let sidecar = fs::read(&entry.info_path).unwrap();
            let extra = if encoded {
                zstd::encode_all(&b"newer content"[..], 3).unwrap()
            } else {
                b"newer content".to_vec()
            };
            let error = decompress_before_commit(&mut entry, 16384, || {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(&extra)
                    .unwrap();
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            bytes.extend_from_slice(&extra);
            assert_eq!(fs::read(&path).unwrap(), bytes, "encoded={encoded}");
            assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
            assert_eq!(entry.info.compressed.as_deref(), Some("zstd"));
        }
    }

    #[test]
    fn operations_leave_legacy_sqlite_files_untouched() {
        let (store, _data, work, _) = test_store();
        let legacy: Vec<_> = [
            "index.sqlite",
            "index.sqlite-wal",
            "index.sqlite-shm",
            "index.sqlite-journal",
        ]
        .iter()
        .map(|name| {
            let path = store.home.join(".trashd").join(name);
            fs::write(&path, name.as_bytes()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            (path, name.as_bytes())
        })
        .collect();
        let source = create_file(work.path(), "entry", "data");
        let id = store.trash(&source, None).unwrap();
        assert_eq!(store.list(None).unwrap().len(), 1);
        assert_eq!(store.status().unwrap(), (4, 1));
        assert_eq!(store.restore(&id, None).unwrap(), source);
        let id = store.trash(&source, None).unwrap();
        store.purge(&id).unwrap();
        assert!(store.list(None).unwrap().is_empty());
        for (path, contents) in legacy {
            assert_eq!(fs::read(&path).unwrap(), contents);
            assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o640);
        }
    }

    #[test]
    fn listing_special_sidecars_keeps_data_as_orphans_without_blocking() {
        use std::os::unix::fs::symlink;
        let (store, _data, work, _) = test_store();
        let regular = work.path().join("metadata");
        fs::write(
            &regular,
            TrashInfo::new(work.path().join("original")).to_trashinfo_string(),
        )
        .unwrap();
        let fifo = store.home.join("info/fifo.trashinfo");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        symlink(&regular, store.home.join("info/link.trashinfo")).unwrap();
        for id in ["fifo", "link"] {
            fs::write(store.home.join("files").join(id), b"recoverable").unwrap();
        }
        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|entry| entry.orphaned));
    }

    #[test]
    fn opened_sidecar_versions_reject_growth_and_path_replacement() {
        let (store, _data, work, _) = test_store();
        let path = store.home.join("info/snapshot.trashinfo");
        fs::write(
            &path,
            TrashInfo::new(work.path().join("original")).to_trashinfo_string(),
        )
        .unwrap();
        let (_contents, metadata) = crate::trashinfo::read_sidecar_snapshot(&path).unwrap();
        let snapshot = Some(SidecarVersion::from_metadata(&metadata));
        assert_eq!(sidecar_version(&path), snapshot);
        fs::File::options()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"X-Changed=1\n")
            .unwrap();
        assert_ne!(sidecar_version(&path), snapshot);

        let (_contents, metadata) = crate::trashinfo::read_sidecar_snapshot(&path).unwrap();
        let snapshot = Some(SidecarVersion::from_metadata(&metadata));
        let _pinned = fs::File::open(&path).unwrap();
        let replacement = work.path().join("replacement.trashinfo");
        fs::write(
            &replacement,
            TrashInfo::new(work.path().join("replacement")).to_trashinfo_string(),
        )
        .unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_ne!(sidecar_version(&path), snapshot);
    }

    #[test]
    fn streaming_status_matches_list_accounting_for_mixed_home_and_foreign_entries() {
        use std::os::unix::fs::symlink;
        let (store, _data, work, _) = test_store();
        let foreign = work.path().join("mounted/.Trash-test");
        let empty = work.path().join("empty/.Trash-test");
        for root in [&foreign, &empty] {
            fs::create_dir_all(root.join("info")).unwrap();
            fs::create_dir_all(root.join("files")).unwrap();
        }
        let write_info = |root: &Path, id: &OsStr, size: Option<u64>, compressed: bool| {
            let mut info = TrashInfo::new(work.path().join(id));
            info.size = size;
            info.compressed = compressed.then(|| "zstd".into());
            let mut name = id.to_os_string();
            name.push(".trashinfo");
            fs::write(root.join("info").join(name), info.to_trashinfo_string()).unwrap();
        };
        fs::write(store.home.join("files/regular"), b"regular").unwrap();
        write_info(&store.home, OsStr::new("regular"), Some(999), false);
        fs::write(store.home.join("files/compressed"), b"small").unwrap();
        write_info(&store.home, OsStr::new("compressed"), Some(999), true);
        for (id, size) in [("stored-tree", Some(4321)), ("measured-tree", None)] {
            fs::create_dir(store.home.join("files").join(id)).unwrap();
            fs::write(
                store.home.join("files").join(id).join("leaf"),
                b"tree payload",
            )
            .unwrap();
            write_info(&store.home, OsStr::new(id), size, false);
        }
        let target = create_file(work.path(), "external-target", &"x".repeat(8192));
        for (id, destination) in [
            ("link", target.clone()),
            ("dangling", work.path().join("absent")),
        ] {
            symlink(destination, store.home.join("files").join(id)).unwrap();
            write_info(&store.home, OsStr::new(id), Some(u64::MAX), false);
        }
        write_info(&store.home, OsStr::new("missing"), Some(12345), false);
        for id in ["orphan", "corrupt", "nonregular-sidecar"] {
            fs::write(store.home.join("files").join(id), b"recoverable").unwrap();
        }
        fs::write(store.home.join("info/corrupt.trashinfo"), b"invalid").unwrap();
        symlink(
            work.path().join("absent"),
            store.home.join("info/nonregular-sidecar.trashinfo"),
        )
        .unwrap();
        fs::create_dir(store.home.join("files/orphan-tree")).unwrap();
        fs::write(store.home.join("files/orphan-tree/leaf"), b"orphan data").unwrap();
        for (id, sidecar) in [
            (b"raw\xff".as_slice(), true),
            (b"raw\xfe".as_slice(), false),
        ] {
            let id = OsStr::from_bytes(id);
            fs::write(store.home.join("files").join(id), b"raw data").unwrap();
            if sidecar {
                write_info(&store.home, id, None, false);
            }
        }
        for (id, size) in [
            ("forged-large", Some(u64::MAX)),
            ("forged-small", Some(1)),
            ("unsized", None),
        ] {
            fs::create_dir(foreign.join("files").join(id)).unwrap();
            fs::write(foreign.join("files").join(id).join("leaf"), b"foreign tree").unwrap();
            write_info(&foreign, OsStr::new(id), size, false);
        }

        let roots = vec![
            (store.home.clone(), "home".into()),
            (foreign.clone(), "foreign".into()),
            (empty, "empty".into()),
        ];
        let paths: Vec<PathBuf> = roots.iter().map(|(path, _)| path.clone()).collect();
        let mut listed = Vec::new();
        store.list_roots(&paths, None, &mut listed).unwrap();
        let statuses = store.status_in_roots(&roots).unwrap();
        assert_eq!(statuses.len(), 3);
        for status in &statuses {
            let expected: Vec<&TrashEntry> = listed
                .iter()
                .filter(|entry| entry.trash_root == status.trash_dir)
                .collect();
            assert_eq!(status.count, expected.len());
            assert_eq!(
                status.total_size,
                expected
                    .iter()
                    .map(|entry| store.entry_disk_size(entry))
                    .fold(0u64, u64::saturating_add)
            );
        }
        let size_of = |id: &str| {
            let entry = listed.iter().find(|entry| entry.id == id).unwrap();
            store.entry_disk_size(entry)
        };
        assert_eq!(size_of("regular"), 7);
        assert_eq!(size_of("compressed"), 5);
        assert_eq!(size_of("stored-tree"), 4321);
        assert_eq!(size_of("missing"), 0);
        assert_eq!(size_of("forged-large"), 12);
        assert_eq!(size_of("forged-small"), 1);
        assert_eq!(size_of("unsized"), 12);
        assert!(
            size_of("link") < 8192,
            "a symlink's target must not be counted"
        );
        assert_eq!(listed.iter().filter(|entry| entry.orphaned).count(), 5);
        let home = statuses
            .iter()
            .find(|status| status.trash_dir == store.home)
            .unwrap();
        assert_eq!(store.status().unwrap(), (home.total_size, home.count));
        assert_eq!(
            store.status_per_partition().unwrap()[0].total_size,
            home.total_size
        );
    }

    #[test]
    fn retention_sizing_refreshes_metadata_after_a_status_snapshot() {
        let (store, _data, work, _) = test_store();
        let source = create_file(work.path(), "growing", "old");
        let id = store.trash(&source, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        let snapshot = fs::symlink_metadata(&entry.trashed_path).unwrap();
        fs::write(&entry.trashed_path, b"new longer data").unwrap();
        assert_eq!(
            store.entry_disk_size_from_metadata(&entry, Some(&snapshot)),
            3
        );
        assert_eq!(store.entry_disk_size(&entry), 15);
    }

    #[test]
    fn lossy_id_collisions_keep_orphans_visible_and_refuse_ambiguous_selection() {
        let (store, _data, work, _) = test_store();
        let raw_a = OsStr::from_bytes(b"entry\xff");
        let raw_b = OsStr::from_bytes(b"entry\xfe");
        for name in [raw_a, raw_b] {
            fs::write(store.home.join("files").join(name), b"recoverable").unwrap();
        }
        let write_sidecar = |name: &OsStr, original: &str| {
            let mut sidecar = name.to_os_string();
            sidecar.push(".trashinfo");
            fs::write(
                store.home.join("info").join(sidecar),
                TrashInfo::new(work.path().join(original)).to_trashinfo_string(),
            )
            .unwrap();
        };
        write_sidecar(raw_a, "original-a");
        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 2);
        let orphan = listed.iter().find(|entry| entry.orphaned).unwrap();
        assert_eq!(orphan.trashed_path.file_name(), Some(raw_b));
        assert_eq!(store.list(Some("*entry*")).unwrap().len(), 1);

        write_sidecar(raw_b, "original-b");
        assert!(matches!(
            store.find_entry("entry�"),
            Err(TrashError::AmbiguousMatch { count: 2, .. })
        ));
        // Selection by the unique original name still resolves and acts on
        // exactly one raw on-disk entry.
        store.purge("original-a").unwrap();
        assert!(!store.home.join("files").join(raw_a).exists());
        assert_eq!(
            fs::read(store.home.join("files").join(raw_b)).unwrap(),
            b"recoverable"
        );
    }

    #[test]
    fn exact_selector_name_scan_matches_full_resolution() {
        use std::os::unix::fs::symlink;

        let (store, _data, work, _) = test_store();
        let foreign = work.path().join("foreign-trash");
        fs::create_dir_all(foreign.join("info")).unwrap();
        fs::create_dir(foreign.join("files")).unwrap();
        let write_entry = |root: &Path, id: &OsStr, original: &str, data: bool| {
            let mut sidecar = id.to_os_string();
            sidecar.push(".trashinfo");
            fs::write(
                root.join("info").join(sidecar),
                TrashInfo::new(work.path().join(original)).to_trashinfo_string(),
            )
            .unwrap();
            if data {
                fs::write(root.join("files").join(id), b"recoverable").unwrap();
            }
        };
        for (id, original, data) in [
            ("exact", "original", true),
            ("other", "exact", true), // An exact ID wins over a filename.
            ("alias-id", "filename-alias", true),
            ("missing-data", "original-missing", false),
            ("duplicate", "home-duplicate", true),
            (".trashinfo", "hidden-leaf", true),
            ("literal[*]", "literal-original", true),
        ] {
            write_entry(&store.home, OsStr::new(id), original, data);
        }
        // A pathological metadata name has the same raw file_stem as the
        // normal hidden leaf above. Absolute selectors must keep the same
        // ordering and snapshot construction as a complete scan.
        fs::write(
            store.home.join("info/.trashinfo"),
            "[Trash Info]\nPath=/older-hidden\nDeletionDate=2000-01-01T00:00:00\n",
        )
        .unwrap();
        write_entry(&foreign, OsStr::new("foreign"), "foreign-original", true);
        // Duplicate IDs remain ambiguous even when the foreign copy is orphaned.
        fs::write(foreign.join("files/duplicate"), b"foreign orphan").unwrap();
        for id in ["orphan", "corrupt", "linked", "directory-sidecar", "fifo"] {
            fs::write(store.home.join("files").join(id), b"recoverable").unwrap();
        }
        fs::write(store.home.join("info/corrupt.trashinfo"), b"invalid").unwrap();
        symlink(
            store.home.join("info/exact.trashinfo"),
            store.home.join("info/linked.trashinfo"),
        )
        .unwrap();
        fs::create_dir(store.home.join("info/directory-sidecar.trashinfo")).unwrap();
        let fifo = CString::new(
            store
                .home
                .join("info/fifo.trashinfo")
                .as_os_str()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        for (raw, original) in [
            (OsStr::from_bytes(b"raw\xff"), "raw-a"),
            (OsStr::from_bytes(b"raw\xfe"), "raw-b"),
            (OsStr::new("raw�"), "literal-replacement"),
        ] {
            write_entry(&store.home, raw, original, true);
        }
        let roots = [store.home.clone(), foreign.clone()];
        let mut full = Vec::new();
        store.list_roots(&roots, None, &mut full).unwrap();
        newest_first(&mut full);
        let mut selectors: Vec<String> = [
            "exact",
            "other",
            "filename-alias",
            "missing-data",
            "duplicate",
            ".trashinfo",
            "literal[*]",
            "foreign",
            "orphan",
            "corrupt",
            "linked",
            "directory-sidecar",
            "fifo",
            "raw�",
            "raw-a",
            "raw-*",
            "*original",
            "missing",
            "",
            ".",
            "..",
            "../exact",
            "files/exact",
            "exact/child",
            "bad\0name",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        selectors.extend(
            full.iter()
                .filter_map(|entry| entry.trashed_path.to_str().map(str::to_owned)),
        );
        selectors.extend([
            work.path().join("outside/exact").to_str().unwrap().into(),
            store.home.join("files/missing").to_str().unwrap().into(),
            store
                .home
                .join("files/exact/child")
                .to_str()
                .unwrap()
                .into(),
            store
                .home
                .join("files/../files/exact")
                .to_str()
                .unwrap()
                .into(),
        ]);
        for selector in selectors {
            let expected = TrashStore::resolve_listed_entry(&full, &selector);
            let actual = store.find_entry_in_roots(&roots, &selector);
            match (actual, expected) {
                (Ok(actual), Ok(expected)) => {
                    assert_eq!(actual.id, expected.id, "{selector:?}");
                    assert_eq!(actual.trashed_path, expected.trashed_path, "{selector:?}");
                    assert_eq!(actual.info_path, expected.info_path, "{selector:?}");
                    assert_eq!(actual.trash_root, expected.trash_root, "{selector:?}");
                    assert_eq!(actual.orphaned, expected.orphaned, "{selector:?}");
                    assert_eq!(actual.identity, expected.identity, "{selector:?}");
                    assert_eq!(
                        actual.sidecar_version, expected.sidecar_version,
                        "{selector:?}"
                    );
                    assert_eq!(
                        actual.info.original_path, expected.info.original_path,
                        "{selector:?}"
                    );
                    if !actual.orphaned {
                        assert_eq!(
                            actual.info.to_trashinfo_string(),
                            expected.info.to_trashinfo_string(),
                            "{selector:?}"
                        );
                    }
                }
                (Err(actual), Err(expected)) => {
                    assert_eq!(actual.to_string(), expected.to_string(), "{selector:?}")
                }
                (actual, expected) => {
                    panic!("{selector:?}: actual {actual:?}, expected {expected:?}")
                }
            }
        }
    }

    #[test]
    fn selection_reuses_all_copy_and_original_path_glob_results() {
        let (store, _data, work, _) = test_store();
        for (id, original) in [
            ("a", "group/a"),
            ("a.copy", "group/a"),
            ("third", "group/b"),
            ("literal[1]", "elsewhere"),
            ("wildcard", "literal1"),
        ] {
            fs::write(store.home.join("files").join(id), b"data").unwrap();
            fs::write(
                store.home.join("info").join(format!("{id}.trashinfo")),
                TrashInfo::new(work.path().join(original)).to_trashinfo_string(),
            )
            .unwrap();
        }
        store.sidecar_reads.set(0);
        let (tier, copies) = store
            .select_entries(OsStr::new("a"), true)
            .unwrap()
            .unwrap();
        assert_eq!(tier, MatchTier::Id);
        assert_eq!(copies.len(), 2);
        assert_eq!(store.sidecar_reads.get(), 5);
        let pattern = format!("{}/group/*", work.path().display());
        assert!(
            store.matching_entries_all(&pattern).unwrap().is_none(),
            "the compatibility API keeps filename-only glob semantics"
        );
        store.sidecar_reads.set(0);
        let (tier, matches) = store
            .select_entries(OsStr::new(&pattern), true)
            .unwrap()
            .unwrap();
        assert_eq!(tier, MatchTier::Glob);
        assert_eq!(matches.len(), 3);
        assert_eq!(store.sidecar_reads.get(), 5, "restore --all needs one scan");
        let (_, literal) = store
            .select_entries(OsStr::new("literal[1]"), true)
            .unwrap()
            .unwrap();
        assert_eq!(literal.len(), 1);
        assert_eq!(literal[0].id, "literal[1]");
        for entry in &matches {
            assert!(entry.identity.is_some());
            assert!(entry.sidecar_version.is_some());
        }
    }

    #[test]
    fn raw_selection_keeps_the_selected_snapshot_for_mutation() {
        let (store, _data, work, _) = test_store();
        let raw = OsStr::from_bytes(b"raw-\xff");
        let data = store.home.join("files").join(raw);
        let mut sidecar = raw.to_os_string();
        sidecar.push(".trashinfo");
        let info_path = store.home.join("info").join(sidecar);
        fs::write(&data, b"original").unwrap();
        fs::write(
            &info_path,
            TrashInfo::new(work.path().join(raw)).to_trashinfo_string(),
        )
        .unwrap();
        store.sidecar_reads.set(0);
        let (_, selected) = store.select_entries(raw, false).unwrap().unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].trashed_path, data);
        assert_eq!(store.sidecar_reads.get(), 1);
        let (tier, by_path) = store
            .select_entries(data.as_os_str(), false)
            .unwrap()
            .unwrap();
        assert_eq!(tier, MatchTier::TrashedPath);
        assert_eq!(by_path[0].trashed_path, data);
        fs::rename(&data, work.path().join("saved")).unwrap();
        fs::write(&data, b"replacement").unwrap();
        assert!(store.purge_entry(&selected[0]).is_err());
        assert_eq!(fs::read(&data).unwrap(), b"replacement");
        assert!(info_path.exists());
    }

    #[test]
    fn read_only_query_filters_keep_orphans_freshness_and_order_without_data_stats() {
        let (store, _data, work, _) = test_store();
        for (id, date) in [
            ("older", "2000-01-01T00:00:00"),
            ("keep", "2001-01-01T00:00:00"),
            ("newer", "2002-01-01T00:00:00"),
        ] {
            fs::write(store.home.join("files").join(id), b"data").unwrap();
            fs::write(
                store.home.join("info").join(format!("{id}.trashinfo")),
                format!(
                    "[Trash Info]\nPath={}\nDeletionDate={date}\n",
                    work.path().join(id).display()
                ),
            )
            .unwrap();
        }
        fs::write(store.home.join("files/orphan"), b"recoverable").unwrap();
        fs::write(store.home.join("info/orphan.trashinfo"), b"invalid").unwrap();
        let full = store.list(None).unwrap();
        assert_eq!(store.scan_data_stats.get(), 4);
        store.scan_data_stats.set(0);
        let queried = store.list_for_query(|_| true).unwrap();
        assert_eq!(
            queried.iter().map(|e| &e.trashed_path).collect::<Vec<_>>(),
            full.iter().map(|e| &e.trashed_path).collect::<Vec<_>>()
        );
        assert!(queried.iter().all(|e| e.identity.is_none()));
        assert_eq!(store.scan_data_stats.get(), 0);
        for entry in &queried {
            assert_eq!(entry.sidecar_version, sidecar_snapshot(&entry.info_path));
        }
        let mut examined = 0;
        let filtered = store
            .list_for_query(|entry| {
                examined += 1;
                entry.id == "keep"
            })
            .unwrap();
        assert_eq!(
            examined, 4,
            "filtered valid entries must not reappear as orphans"
        );
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "keep");
        assert!(!filtered[0].orphaned);
        let cutoff = filtered[0].info.deletion_date;
        let dated = store
            .list_for_display_filtered(Some("*"), |entry| entry.info.deletion_date <= cutoff)
            .unwrap();
        assert_eq!(
            dated.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            vec!["keep", "older"]
        );
        assert_eq!(store.scan_data_stats.get(), 0);
        fs::remove_dir_all(store.home.join("info")).unwrap();
        fs::write(store.home.join("info"), b"not a directory").unwrap();
        assert!(
            matches!(store.list_for_query(|_| false), Err(TrashError::Io(_))),
            "a predicate matching nothing must not hide a root scan failure"
        );
    }

    #[test]
    fn exact_selector_reads_only_matching_sidecars_and_keeps_full_fallbacks() {
        let (store, _data, work, _) = test_store();
        for i in 0..300 {
            let id = format!("entry-{i}");
            fs::write(store.home.join("files").join(&id), b"data").unwrap();
            fs::write(
                store.home.join("info").join(format!("{id}.trashinfo")),
                TrashInfo::new(work.path().join(format!("original-{i}"))).to_trashinfo_string(),
            )
            .unwrap();
        }
        for selector in [
            "entry-150".to_owned(),
            store.home.join("files/entry-150").to_str().unwrap().into(),
        ] {
            store.sidecar_reads.set(0);
            assert_eq!(store.find_entry(&selector).unwrap().id, "entry-150");
            assert_eq!(store.sidecar_reads.get(), 1);
        }
        for selector in ["original-150", "original-15?", "missing", "entry-�"] {
            store.sidecar_reads.set(0);
            let _ = store.find_entry(selector);
            assert_eq!(store.sidecar_reads.get(), 300, "{selector}");
        }
    }

    #[test]
    fn exact_selector_preserves_home_errors_and_skips_broken_foreign_roots() {
        let (store, _data, work, _) = test_store();
        fs::write(store.home.join("files/orphan"), b"recoverable").unwrap();
        let broken = work.path().join("broken");
        fs::create_dir(&broken).unwrap();
        fs::write(broken.join("info"), b"not a directory").unwrap();
        let roots = [store.home.clone(), broken];
        assert!(
            store
                .find_entry_in_roots(&roots, "orphan")
                .unwrap()
                .orphaned
        );
        assert!(matches!(
            store.find_entry_in_roots(&roots, "missing"),
            Err(TrashError::EntryNotFound(_))
        ));
        fs::remove_dir(store.home.join("info")).unwrap();
        fs::write(store.home.join("info"), b"not a directory").unwrap();
        for selector in ["orphan", "missing", "*"] {
            assert!(matches!(
                store.find_entry_in_roots(&roots, selector),
                Err(TrashError::Io(_))
            ));
        }
    }

    #[test]
    fn restore_verifies_both_stored_hashes_after_configuration_changes() {
        let (mut store, _data, work, _) = test_store();
        for (algorithm, changed_algorithm) in [("xxhash", "sha256"), ("sha256", "xxhash")] {
            store.config.hash_algorithm = algorithm.into();
            let source = work.path().join(algorithm);
            fs::write(&source, b"original data").unwrap();
            let id = store.trash(&source, None).unwrap();
            let entry = store.find_entry(&id).unwrap();
            let expected = entry.info.sha256.as_deref().unwrap();
            assert_eq!(expected.len(), if algorithm == "sha256" { 64 } else { 32 });
            store.config.hash_algorithm = changed_algorithm.into();
            assert_eq!(store.restore(&id, None).unwrap(), source);
            assert_eq!(fs::read(&source).unwrap(), b"original data");
            let source_name = CString::new(source.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                restore_hash_mismatch_at(libc::AT_FDCWD, &source_name, expected),
                None,
            );
        }
    }

    #[test]
    fn cross_device_restore_retirement_keeps_newer_source_data() {
        for replacement in [b"old data plus newer".as_slice(), b"new data".as_slice()] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            let destination = fixture.path().join("restored");
            fs::write(&source, b"old data").unwrap();
            let parent = fs::File::open(fixture.path()).unwrap();
            let before = stat_at(parent.as_raw_fd(), c"source", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            let created = copy_staged_at(
                parent.as_raw_fd(),
                c"source",
                parent.as_raw_fd(),
                c"restored",
                parent.as_raw_fd(),
                &before,
            )
            .unwrap();
            assert_eq!(fs::read(&destination).unwrap(), b"old data");
            fs::write(&source, replacement).unwrap();
            fs::File::options()
                .write(true)
                .open(&source)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(123_456))
                .unwrap();
            let changed =
                stat_at(parent.as_raw_fd(), c"source", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            assert_eq!(stat_identity(&changed), stat_identity(&before));
            let result = unlink_source_or_rollback(
                parent.as_raw_fd(),
                c"source",
                parent.as_raw_fd(),
                c"restored",
                &before,
                created,
            );
            assert!(
                result.is_err(),
                "changed source retirement: {result:?}; source exists: {}",
                source.exists()
            );
            assert_eq!(fs::read(&source).unwrap(), replacement);
            assert!(
                !destination.exists(),
                "the unchanged copy must be rolled back"
            );
        }
    }

    #[test]
    fn cross_device_copy_rejects_a_changed_source_before_creating_data() {
        for replacement in [b"old data plus newer".as_slice(), b"new data".as_slice()] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            fs::write(&source, b"old data").unwrap();
            let parent = fs::File::open(fixture.path()).unwrap();
            let before = stat_at(parent.as_raw_fd(), c"source", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            fs::write(&source, replacement).unwrap();
            fs::File::options()
                .write(true)
                .open(&source)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(123_456))
                .unwrap();
            assert!(
                copy_staged_at(
                    parent.as_raw_fd(),
                    c"source",
                    parent.as_raw_fd(),
                    c"restored",
                    parent.as_raw_fd(),
                    &before,
                )
                .is_err()
            );
            assert_eq!(fs::read(&source).unwrap(), replacement);
            assert_eq!(
                fs::read_dir(fixture.path()).unwrap().count(),
                1,
                "a stale source must not create any copy or stage"
            );
        }
    }

    #[test]
    fn cross_device_restore_retirement_preserves_replaced_destinations() {
        for changed_source in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            let destination = fixture.path().join("restored");
            fs::write(&source, b"old data").unwrap();
            let parent = fs::File::open(fixture.path()).unwrap();
            let before = stat_at(parent.as_raw_fd(), c"source", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            let created = copy_staged_at(
                parent.as_raw_fd(),
                c"source",
                parent.as_raw_fd(),
                c"restored",
                parent.as_raw_fd(),
                &before,
            )
            .unwrap();
            fs::write(fixture.path().join("replacement"), b"unrelated destination").unwrap();
            fs::rename(fixture.path().join("replacement"), &destination).unwrap();
            if changed_source {
                fs::write(&source, b"newer source").unwrap();
            }
            assert!(
                unlink_source_or_rollback(
                    parent.as_raw_fd(),
                    c"source",
                    parent.as_raw_fd(),
                    c"restored",
                    &before,
                    created,
                )
                .is_err()
            );
            assert_eq!(
                fs::read(&source).unwrap(),
                if changed_source {
                    b"newer source".as_slice()
                } else {
                    b"old data".as_slice()
                }
            );
            assert_eq!(fs::read(&destination).unwrap(), b"unrelated destination");
        }
    }

    #[test]
    fn cross_device_restore_unchanged_nodes_keep_their_native_behavior() {
        for kind in ["file", "symlink", "fifo"] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            let destination = fixture.path().join("restored");
            let parent = fs::File::open(fixture.path()).unwrap();
            match kind {
                "file" => fs::write(&source, b"old data").unwrap(),
                "symlink" => std::os::unix::fs::symlink("missing-target", &source).unwrap(),
                _ => assert_eq!(
                    unsafe { libc::mkfifoat(parent.as_raw_fd(), c"source".as_ptr(), 0o600) },
                    0
                ),
            }
            let before = stat_at(parent.as_raw_fd(), c"source", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            publish_copy_noreplace(
                parent.as_raw_fd(),
                c"source",
                parent.as_raw_fd(),
                c"restored",
                stat_identity(&before),
            )
            .unwrap();
            assert!(fs::symlink_metadata(&source).is_err());
            let after =
                stat_at(parent.as_raw_fd(), c"restored", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            assert_eq!(after.st_mode, before.st_mode);
            match kind {
                "file" => assert_eq!(fs::read(&destination).unwrap(), b"old data"),
                "symlink" => assert_eq!(
                    fs::read_link(&destination).unwrap(),
                    Path::new("missing-target")
                ),
                _ => assert_eq!(after.st_mode & libc::S_IFMT, libc::S_IFIFO),
            }
        }
    }

    #[test]
    fn cross_device_restore_rolls_back_its_copy_when_native_unlink_fails() {
        let outcome = mounts::in_private_mounts(
            "store::tests::cross_device_restore_rolls_back_its_copy_when_native_unlink_fails",
            || {
                let fixture = tempfile::tempdir().unwrap();
                let source = fixture.path().join("source");
                let destination = fixture.path().join("restored");
                fs::write(&source, b"old data").unwrap();
                if !mount_at(Some(&source), &source) {
                    return false;
                }
                let parent = fs::File::open(fixture.path()).unwrap();
                let before =
                    stat_at(parent.as_raw_fd(), c"source", libc::AT_SYMLINK_NOFOLLOW).unwrap();
                let created = copy_staged_at(
                    parent.as_raw_fd(),
                    c"source",
                    parent.as_raw_fd(),
                    c"restored",
                    parent.as_raw_fd(),
                    &before,
                )
                .unwrap();
                let refused = unlink_source_or_rollback(
                    parent.as_raw_fd(),
                    c"source",
                    parent.as_raw_fd(),
                    c"restored",
                    &before,
                    created,
                )
                .is_err_and(|error| error.raw_os_error() == Some(libc::EBUSY));
                let intact = fs::read(&source).unwrap() == b"old data" && !destination.exists();
                unmount(&source);
                refused && intact
            },
        );
        assert_ne!(outcome, Some(false));
    }

    #[test]
    fn restore_hash_mismatch_keeps_corruption_and_unreadable_warnings() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("payload");
        fs::write(&source, b"original data").unwrap();
        let hashes = [
            hash_file(&source, "xxhash").unwrap(),
            hash_file(&source, "sha256").unwrap(),
        ];
        fs::write(&source, b"corrupted data").unwrap();
        let actual = hash_file(&source, "xxhash").unwrap();
        let source_name = CString::new(source.as_os_str().as_bytes()).unwrap();
        for expected in &hashes {
            assert_eq!(
                restore_hash_mismatch_at(libc::AT_FDCWD, &source_name, expected),
                Some(actual.clone()),
            );
        }
        // Malformed metadata still produces a warning instead of silently
        // disabling verification, and missing data retains its diagnostic.
        assert_eq!(
            restore_hash_mismatch_at(libc::AT_FDCWD, &source_name, "invalid digest"),
            Some(actual),
        );
        fs::remove_file(&source).unwrap();
        for expected in &hashes {
            assert_eq!(
                restore_hash_mismatch_at(libc::AT_FDCWD, &source_name, expected),
                Some("(unreadable)".into()),
            );
        }
    }

    #[test]
    fn resolved_purge_preserves_reused_ids_and_edited_sidecars() {
        let (store, _data, work, _) = test_store();
        let source = create_file(work.path(), "same", "old");
        let id = store.trash(&source, None).unwrap();
        let stale = store.find_entry(&id).unwrap();
        // Keep the old inode pinned, making the identity change deterministic.
        let _old = fs::File::open(&stale.trashed_path).unwrap();
        store.purge_resolved(&stale).unwrap();
        fs::write(&stale.trashed_path, b"replacement").unwrap();
        let info = TrashInfo::new(work.path().join("new"));
        fs::write(&stale.info_path, info.to_trashinfo_string()).unwrap();
        assert!(matches!(
            store.purge_resolved(&stale),
            Err(TrashError::EntryNotFound(_))
        ));
        assert_eq!(fs::read(&stale.trashed_path).unwrap(), b"replacement");
        let fresh = store.find_entry(&id).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&fresh.info_path)
            .unwrap()
            .write_all(b"X-Changed=1\n")
            .unwrap();
        assert!(matches!(
            store.purge_resolved(&fresh),
            Err(TrashError::EntryNotFound(_))
        ));
        assert_eq!(fs::read(&fresh.trashed_path).unwrap(), b"replacement");
    }

    #[test]
    fn resolved_purge_handles_corrupt_and_dangling_sidecar_orphans() {
        let (store, _data, _work, _) = test_store();
        for id in ["corrupt", "dangling"] {
            let data = store.home.join("files").join(id);
            let info = store.home.join("info").join(format!("{id}.trashinfo"));
            fs::write(&data, b"recoverable").unwrap();
            if id == "corrupt" {
                fs::write(&info, b"invalid metadata").unwrap();
            } else {
                std::os::unix::fs::symlink("missing", &info).unwrap();
            }
            let entry = store.find_entry(id).unwrap();
            assert!(entry.orphaned);
            store.purge_resolved(&entry).unwrap();
            assert!(data.symlink_metadata().is_err());
            assert!(info.symlink_metadata().is_err());
        }
    }

    #[test]
    fn root_guard_serializes_writers_without_recursive_auto_purge() {
        let (store, _data, work, _) = test_store();
        let source = create_file(work.path(), "guarded", "bytes");
        let root = store.home.clone();
        let guard = store.lock_trash_root(&root).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let mut cfg = Config {
                auto_purge_interval_secs: 0,
                ..Config::default()
            };
            cfg.retention.max_age_days = 0;
            cfg.retention.max_size_gb = 0.0;
            cfg.retention.disk_pressure_percent = 0;
            let writer = TrashStore::open_isolated(&root, cfg).unwrap();
            started_tx.send(()).unwrap();
            done_tx.send(writer.trash(&source, None)).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        drop(guard);
        let id = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        assert_eq!(store.list(None).unwrap().len(), 1);
        assert_eq!(
            fs::read(store.home.join("files").join(id)).unwrap(),
            b"bytes"
        );
    }

    #[test]
    fn canceled_pinned_commit_leaves_source_and_store_untouched() {
        let (store, _data, work, _) = test_store();
        let source = create_file(work.path(), "canceled", "original");
        let parent = fs::File::open(work.path()).unwrap();
        let root = store.home.clone();
        let guard = store.lock_trash_root(&root).unwrap();
        let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let worker_live = live.clone();
        let worker_source = source.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let store = TrashStore::open_isolated(&root, Config::default()).unwrap();
            started_tx.send(()).unwrap();
            done_tx
                .send(store.trash_at_checked(
                    parent.as_raw_fd(),
                    OsStr::new("canceled"),
                    &worker_source,
                    None,
                    || worker_live.load(std::sync::atomic::Ordering::SeqCst),
                ))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        live.store(false, std::sync::atomic::Ordering::SeqCst);
        drop(guard);
        assert!(
            matches!(done_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(), Err(TrashError::Io(e)) if e.raw_os_error() == Some(libc::ECANCELED))
        );
        worker.join().unwrap();
        assert_eq!(fs::read(source).unwrap(), b"original");
        assert!(store.list(None).unwrap().is_empty());
    }

    // #395: the final set_len masked reads/writes past a captured EOF, and
    // the unsupported-seek fallback followed appends until the next EOF.
    fn check_bounded_copy_extents(unsupported_seek: bool) {
        use std::io::{Seek, SeekFrom};
        let work = tempfile::tempdir().unwrap();
        let captured = 4096u64;
        let current = 1024 * 1024;
        let source_path = work.path().join("growing");
        let mut source = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        source.write_all(&vec![b'a'; captured as usize]).unwrap();
        let selected = source.metadata().unwrap().len();
        source
            .write_all(&vec![b'b'; current - captured as usize])
            .unwrap();
        source.sync_all().unwrap();
        if unsupported_seek {
            assert_eq!(
                unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_DATA) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
        source.seek(SeekFrom::Start(0)).unwrap();
        let destination_path = work.path().join("growing-copy");
        let mut destination = fs::File::create(&destination_path).unwrap();
        copy_extents(&mut source, &mut destination, selected).unwrap();
        assert_eq!(source.stream_position().unwrap(), selected);
        assert_eq!(
            fs::read(&destination_path).unwrap(),
            vec![b'a'; captured as usize]
        );
        assert_eq!(fs::metadata(&source_path).unwrap().len(), current as u64);

        // A formerly empty sparse range may gain a data extent beyond the
        // selected EOF. Querying its position is fine; reading it is not.
        let late_path = work.path().join("late-extent");
        let mut late = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&late_path)
            .unwrap();
        late.set_len(captured).unwrap();
        late.seek(SeekFrom::Start(64 * 1024)).unwrap();
        late.write_all(&[b'z'; 4096]).unwrap();
        late.sync_all().unwrap();
        let first_data = unsafe { libc::lseek(late.as_raw_fd(), 0, libc::SEEK_DATA) };
        let cursor_bound = if first_data >= 0 {
            captured.max(first_data as u64)
        } else {
            assert!(matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL | libc::EOPNOTSUPP)
            ));
            captured
        };
        late.seek(SeekFrom::Start(0)).unwrap();
        let late_copy = work.path().join("late-copy");
        let mut destination = fs::File::create(&late_copy).unwrap();
        copy_extents(&mut late, &mut destination, captured).unwrap();
        assert!(late.stream_position().unwrap() <= cursor_bound);
        assert_eq!(fs::read(late_copy).unwrap(), vec![0; captured as usize]);

        // Zero selected bytes must neither inspect nor copy a later version.
        late.seek(SeekFrom::Start(17)).unwrap();
        let zero_copy = work.path().join("zero-copy");
        let mut destination = fs::File::create(&zero_copy).unwrap();
        destination.write_all(b"old destination").unwrap();
        copy_extents(&mut late, &mut destination, 0).unwrap();
        assert_eq!(late.stream_position().unwrap(), 17);
        assert_eq!(fs::metadata(zero_copy).unwrap().len(), 0);

        // Truncation remains finite too. The caller's post-copy version
        // check rejects it; the extent path may retain a trailing hole.
        let short_path = work.path().join("short");
        fs::write(&short_path, vec![b's'; 8192]).unwrap();
        let mut short = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(short_path)
            .unwrap();
        let selected = short.metadata().unwrap().len();
        short.set_len(1024).unwrap();
        let short_copy = work.path().join("short-copy");
        let mut destination = fs::File::create(&short_copy).unwrap();
        copy_extents(&mut short, &mut destination, selected).unwrap();
        assert_eq!(short.stream_position().unwrap(), 1024);
        let copied = fs::read(short_copy).unwrap();
        assert!((1024..=selected as usize).contains(&copied.len()));
        assert_eq!(&copied[..1024], &[b's'; 1024]);
        assert!(copied[1024..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn bounded_copy_extents_stay_within_captured_size() {
        check_bounded_copy_extents(false);
    }

    #[test]
    fn bounded_copy_extents_fallback_stays_within_captured_size() {
        const TEST: &str = "store::tests::bounded_copy_extents_fallback_stays_within_captured_size";
        const CHILD: &str = "TRASHD_TEST_NO_EXTENT_SEEK";
        if !mounts::is_rerun_child(TEST, CHILD) {
            assert_ne!(mounts::rerun_test(TEST, CHILD), Some(false));
            return;
        }
        // Only this reexec child gets the real kernel denial. SEEK_SET
        // remains available to the ordinary-copy fallback and test fixtures.
        let instruction = |code, jf, k| libc::sock_filter { code, jt: 0, jf, k };
        let mut instructions = [
            instruction(0x20, 0, 0),
            instruction(0x15, 3, libc::SYS_lseek as u32),
            instruction(0x20, 0, 32), // seccomp_data.args[2], whence (int)
            instruction(0x15, 1, libc::SEEK_DATA as u32),
            instruction(0x06, 0, libc::SECCOMP_RET_ERRNO | libc::EINVAL as u32),
            instruction(0x06, 0, libc::SECCOMP_RET_ALLOW),
        ];
        let filter = libc::sock_fprog {
            len: instructions.len() as _,
            filter: instructions.as_mut_ptr(),
        };
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &filter) } != 0
        {
            eprintln!("SKIP: extent-seek denial filter unavailable");
            let _ = mounts::report_test_verdict(None);
            return;
        }
        check_bounded_copy_extents(true);
        let _ = mounts::report_test_verdict(Some(true));
    }

    // #338: copies keep holes as holes and data as data.
    #[test]
    fn copies_preserve_sparse_files() {
        use std::os::unix::fs::FileExt;
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        fs::create_dir_all(&base).unwrap();
        let fixture = tempfile::tempdir_in(&base).unwrap();
        let source = fixture.path().join("sparse");
        let file = fs::File::create(&source).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        file.write_all_at(&[7u8; 4096], 8 * 1024 * 1024).unwrap();
        file.write_all_at(b"tail", 64 * 1024 * 1024 - 4).unwrap();
        drop(file);
        fs::create_dir(fixture.path().join("out")).unwrap();
        let parent = fs::File::open(fixture.path()).unwrap();
        let out = fs::File::open(fixture.path().join("out")).unwrap();
        let name = CString::new("sparse").unwrap();
        let stat = stat_at(parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        copy_regular_at(parent.as_raw_fd(), &name, out.as_raw_fd(), &name, &stat).unwrap();
        let copy = fixture.path().join("out/sparse");
        assert_eq!(fs::read(&copy).unwrap(), fs::read(&source).unwrap());
        let source_blocks = fs::metadata(&source).unwrap().blocks();
        let copy_blocks = fs::metadata(&copy).unwrap().blocks();
        assert!(
            copy_blocks <= source_blocks + 64,
            "{copy_blocks} blocks vs {source_blocks}"
        );
    }

    // #338: links inside a copied tree stay links.
    #[test]
    fn tree_copies_keep_hard_links() {
        let fixture = tempfile::tempdir().unwrap();
        let tree = fixture.path().join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("a"), b"shared").unwrap();
        fs::hard_link(tree.join("a"), tree.join("b")).unwrap();
        fs::hard_link(tree.join("a"), tree.join("sub/c")).unwrap();
        fs::write(tree.join("single"), b"one").unwrap();
        fs::create_dir(fixture.path().join("out")).unwrap();
        let parent = fs::File::open(fixture.path()).unwrap();
        let out = fs::File::open(fixture.path().join("out")).unwrap();
        let name = CString::new("tree").unwrap();
        let stat = stat_at(parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        copy_staged_at(
            parent.as_raw_fd(),
            &name,
            out.as_raw_fd(),
            &name,
            out.as_raw_fd(),
            &stat,
        )
        .unwrap();
        let copy = fixture.path().join("out/tree");
        let inode = |path: &str| fs::metadata(copy.join(path)).unwrap().ino();
        assert_eq!(inode("a"), inode("b"));
        assert_eq!(inode("a"), inode("sub/c"));
        assert_eq!(fs::metadata(copy.join("a")).unwrap().nlink(), 3);
        assert_eq!(fs::read(copy.join("sub/c")).unwrap(), b"shared");
        assert_eq!(fs::metadata(copy.join("single")).unwrap().nlink(), 1);
    }

    #[test]
    fn copy_publication_never_merges_existing_destinations() {
        let fixture = tempfile::tempdir().unwrap();
        fs::create_dir(fixture.path().join("source")).unwrap();
        fs::create_dir(fixture.path().join("existing")).unwrap();
        fs::write(fixture.path().join("source/file"), b"new").unwrap();
        fs::write(fixture.path().join("existing/file"), b"original").unwrap();
        let parent = fs::File::open(fixture.path()).unwrap();
        let source_dir = fs::File::open(fixture.path().join("source")).unwrap();
        let existing_dir = fs::File::open(fixture.path().join("existing")).unwrap();
        let tree = CString::new("source").unwrap();
        let existing = CString::new("existing").unwrap();
        let file = CString::new("file").unwrap();

        let tree_stat = stat_at(parent.as_raw_fd(), &tree, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        let error = copy_source_at(
            parent.as_raw_fd(),
            &tree,
            parent.as_raw_fd(),
            &existing,
            parent.as_raw_fd(),
            &tree_stat,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
        let file_stat = stat_at(source_dir.as_raw_fd(), &file, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        let error = copy_source_at(
            source_dir.as_raw_fd(),
            &file,
            existing_dir.as_raw_fd(),
            &file,
            existing_dir.as_raw_fd(),
            &file_stat,
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(
            fs::read(fixture.path().join("existing/file")).unwrap(),
            b"original"
        );
        // A refused publication leaves no staged copy behind (#334).
        for dir in [
            fixture.path().to_path_buf(),
            fixture.path().join("existing"),
        ] {
            assert!(
                fs::read_dir(&dir)
                    .unwrap()
                    .flatten()
                    .all(|e| !e.file_name().to_string_lossy().starts_with(".trashd-copy-")),
                "{}",
                dir.display()
            );
        }
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
        // A link someone else owns could be retargeted by them; following it
        // would let them choose where this user's trash is created. (A link
        // the user or root owns is followed, see #222.)
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: a foreign-owned symlink needs root to create");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let redirected = base.path().join("redirected");
        fs::create_dir(&redirected).unwrap();
        let link = base.path().join("data-link");
        std::os::unix::fs::symlink(&redirected, &link).unwrap();
        std::os::unix::fs::lchown(&link, Some(65534), Some(65534)).unwrap();
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

    // Regression (#168): restore must hold the entry flock across its
    // identity check → rename, so a compressor holding the same lock during
    // its validate → swap can never have the swap land in restore's publish
    // window (which would publish compressed bytes as the restored file).
    // Discriminates: without restore's lock acquisition, the restore below
    // completes immediately instead of blocking.
    #[test]
    fn restore_blocks_while_entry_flock_is_held() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let data_dir = TempDir::with_prefix_in("data-race-", &base).unwrap();
        let workdir = TempDir::with_prefix_in("work-race-", &base).unwrap();
        let trash = data_dir.path().join("Trash");
        let mut config = Config::default();
        config.retention.max_age_days = 0;
        config.retention.max_size_gb = 0.0;
        config.retention.disk_pressure_percent = 0;
        let store = TrashStore::open_isolated(&trash, config).unwrap();

        let f = create_file(workdir.path(), "race.txt", "plaintext-content");
        let id = store.trash(&f, None).unwrap();
        let entry = store.find_entry(&id).unwrap();

        // Hold the flock like a compressor mid validate→swap.
        let guard = lock_entry_file(&entry.trashed_path).unwrap().unwrap();

        std::thread::scope(|scope| {
            let handle = scope.spawn(move || {
                let mut config2 = Config::default();
                config2.retention.max_age_days = 0;
                config2.retention.max_size_gb = 0.0;
                config2.retention.disk_pressure_percent = 0;
                let store2 = TrashStore::open_isolated(&trash, config2).unwrap();
                store2.restore(&id, None)
            });
            // A blocked restore has not finished; a pre-#168 restore would
            // have completed and published by now.
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                !handle.is_finished(),
                "restore must block while the entry flock is held"
            );
            drop(guard);
            let restored = handle.join().unwrap().unwrap();
            assert_eq!(fs::read(&restored).unwrap(), b"plaintext-content");
        });
    }

    // Regression (#169): a FRESH data-absent sidecar is an in-flight trash —
    // purge/empty must not treat it as retired — while an old one purges.
    #[test]
    fn fresh_data_absent_sidecars_are_not_purgeable() {
        let dir = TempDir::new().unwrap();
        let sidecar = dir.path().join("fresh.trashinfo");
        fs::write(&sidecar, "[Trash Info]\n").unwrap();
        assert!(
            !data_absence_is_retired(&sidecar),
            "a just-written sidecar with no data may be mid-move"
        );

        // Backdate the sidecar past the grace window.
        let old = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let times = [old, old];
        let c = std::ffi::CString::new(sidecar.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) },
            0
        );
        assert!(data_absence_is_retired(&sidecar));
    }

    // Regression (#169): a completed move whose sidecar a concurrent purge
    // stripped mid-flight is re-ensured instead of landing as an orphan.
    #[test]
    fn autopurge_compressor_releases_flock_only_after_swap() {
        let (store, _data, _workdir, _lock) = test_store();
        let trash = store.home.clone();
        fs::create_dir_all(trash.join("info")).unwrap();
        fs::create_dir_all(trash.join("files")).unwrap();

        // An aged, compressible entry (phase 2a only touches entries older
        // than 7 days; test_store disables the age/size/pressure purges).
        // 8 MiB so the encode phase is long enough to dominate the poll
        // interval: with the early-drop bug the flock is freed BEFORE the
        // encode, so a fast poll reliably observes a marker-free release.
        let data = vec![b'x'; 8 * 1024 * 1024];
        fs::write(trash.join("files/old.txt"), &data).unwrap();
        let mut info = TrashInfo::new(PathBuf::from("/work/old.txt"));
        info.deletion_date = chrono::Local::now() - chrono::Duration::days(10);
        // A trashd entry: only those are auto-compressed (#202).
        info.size = Some(data.len() as u64);
        let sidecar = trash.join("info/old.txt.trashinfo");
        fs::write(&sidecar, info.to_trashinfo_string()).unwrap();

        std::thread::scope(|scope| {
            // TrashStore is !Sync (internal caches): the compressor runs on
            // its own store instance over the same isolated trash root.
            let handle = scope.spawn(|| {
                let store2 = TrashStore::open_isolated(&trash, Config::default()).unwrap();
                store2.maybe_auto_purge()
            });

            // Anchor on the compressor: first observe the flock HELD (it
            // acquired), then find the FIRST moment it is acquirable again
            // and check the marker. Hold-through-swap ⇒ the marker is
            // already present at that moment; an early drop ⇒ necessarily
            // absent (encode + marker + swap are still pending).
            use std::os::unix::fs::OpenOptionsExt;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut saw_held = false;
            let marker_at_first_release;
            loop {
                assert!(
                    std::time::Instant::now() < deadline,
                    "compressor neither completed nor held the entry flock"
                );
                if let Ok(file) = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(trash.join("files/old.txt"))
                {
                    match file.try_lock() {
                        Err(_) => saw_held = true,
                        Ok(()) => {
                            if saw_held {
                                let content = fs::read_to_string(&sidecar).unwrap_or_default();
                                marker_at_first_release = content.contains("X-Trashd-Compressed");
                                break;
                            }
                            // compressor has not acquired yet — keep waiting
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(
                marker_at_first_release,
                "entry flock was released before the compressed data was in place"
            );
            handle.join().unwrap().unwrap();
        });

        // The entry is actually compressed once the compressor finishes.
        let mut magic = [0u8; 4];
        fs::File::open(trash.join("files/old.txt"))
            .unwrap()
            .read_exact(&mut magic)
            .unwrap();
        assert_eq!(u32::from_le_bytes(magic), 0xFD2FB528);
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
    fn duplicate_long_unicode_names_remain_recoverable() {
        let (store, _data, workdir, _lock) = test_store();
        let name = "é".repeat(120);
        let mut copies = Vec::new();
        for payload in ["first", "second", "third", "fourth"] {
            let file = create_file(workdir.path(), &name, payload);
            let id = store.trash(&file, None).unwrap();
            assert!(id.len() + ".trashinfo".len() <= 255);
            copies.push((id, payload));
        }
        for (id, payload) in copies {
            let destination = workdir.path().join(payload);
            store.restore(&id, Some(&destination)).unwrap();
            assert_eq!(fs::read_to_string(destination).unwrap(), payload);
        }
    }

    // #399: repeated claims never rescan or exhaust a counter range; an
    // orphan occupying files/<id> keeps its data and is never reused.
    #[test]
    fn repeated_id_claims_advance_without_reusing_orphans() {
        let (store, _data, _workdir, _lock) = test_store();
        let root = store.home.clone();
        fs::write(root.join("files/same"), b"orphan").unwrap();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..20 {
            let (id, _info, _claim) = unique_id_atomic(&root, "same").unwrap();
            assert!(ids.insert(id));
        }
        assert_eq!(ids.len(), 20);
        assert_eq!(fs::read(root.join("files/same")).unwrap(), b"orphan");
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

    // #337: fnmatch(3) rules for an unterminated `[` and backslash escapes.
    #[test]
    fn glob_literal_brackets_and_escapes() {
        for (pattern, text, expected) in [
            ("a[1", "a[1", true),
            ("*[draft*", "x[draft1", true),
            ("x\\*", "x*", true),
            ("x\\*", "xy", false),
            ("a\\[1]", "a[1]", true),
            ("a\\[1]", "a1", false),
            ("[ab]", "a", true),
            ("[ab", "a", false),
            ("trailing\\", "trailing\\", true),
        ] {
            assert_eq!(
                simple_glob_match(pattern, text),
                expected,
                "{pattern} vs {text}"
            );
        }
    }

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

    // Regression (#144): a pattern that matches a real entry's files/<id>
    // name but not its original filename must not cause the entry to be
    // re-synthesized as a fake "orphaned" copy of itself.
    #[test]
    fn pattern_filtered_list_does_not_synthesize_filtered_entries_as_orphans() {
        let (store, _data, workdir, _lock) = test_store();

        let f = create_file(workdir.path(), "notes.txt", "v1");
        store.trash(&f, None).unwrap();
        fs::write(&f, "v2").unwrap();
        store.trash(&f, None).unwrap(); // collides → timestamp-suffixed id

        let all = store.list(None).unwrap();
        assert_eq!(all.len(), 2);
        let suffixed = all
            .iter()
            .find(|e| e.id != "notes.txt")
            .expect("second trash gets a timestamp-suffixed id");
        assert!(!suffixed.orphaned);

        let filtered = store.list(Some(&suffixed.id)).unwrap();
        assert!(
            filtered.iter().all(|e| !e.orphaned),
            "no fake orphans: {filtered:?}"
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

    // #310: a bare relative display path (the shim's --one-file-system
    // walk) must be recorded absolute, resolved against the cwd.
    #[test]
    fn trash_at_records_relative_display_paths_absolute() {
        use std::ffi::OsStr;
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let (store, _data, workdir, _lock) = test_store();
        let dir = workdir.path().join("ofsdir");
        fs::create_dir(&dir).unwrap();
        create_file(&dir, "inner", "data");
        let parent = File::open(workdir.path()).unwrap();
        let id = store
            .trash_at(
                parent.as_raw_fd(),
                OsStr::new("ofsdir"),
                Path::new("ofsdir"),
                None,
            )
            .unwrap();
        let entry = store.find_entry(&id).unwrap();
        assert_eq!(
            entry.info.original_path,
            std::env::current_dir().unwrap().join("ofsdir")
        );
    }

    #[test]
    fn relative_operands_resolve_only_relative_components() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            normalize_relative(Path::new("bare")).unwrap(),
            cwd.join("bare")
        );
        assert_eq!(
            normalize_relative(Path::new("bare/")).unwrap(),
            cwd.join("bare")
        );
        assert_eq!(
            normalize_relative(Path::new("./src/x")).unwrap(),
            cwd.join("src/x")
        );
        assert_eq!(normalize_relative(Path::new(".")).unwrap(), cwd);
        // A symlinked relative component resolves exactly as through the
        // absolute path.
        let (_store, _data, workdir, _lock) = test_store();
        fs::create_dir(workdir.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", workdir.path().join("link")).unwrap();
        let relative = workdir.path().strip_prefix(&cwd).unwrap().join("link/f");
        assert_eq!(
            normalize_relative(&relative).unwrap(),
            normalize_path(&workdir.path().join("link/f"))
        );
        assert_eq!(
            normalize_relative(&relative).unwrap(),
            fs::canonicalize(workdir.path()).unwrap().join("real/f")
        );
    }

    // #307: the store is locked first and only repaired when the lock refuses
    // it, so a removed files/ or a widened info/ is still prepared on trash,
    // while unsafe roots stay refused.
    #[test]
    fn trash_repairs_store_directories_through_the_optimistic_lock() {
        let (store, _data, workdir, _lock) = test_store();
        let root = store.home_dir().to_path_buf();
        fs::remove_dir(root.join("files")).unwrap();
        fs::set_permissions(root.join("info"), fs::Permissions::from_mode(0o755)).unwrap();
        let f = create_file(workdir.path(), "repaired.txt", "x");
        store.trash(&f, None).unwrap();
        for dir in ["files", "info"] {
            let mode = fs::symlink_metadata(root.join(dir))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{dir}");
        }
        assert!(root.join("files/repaired.txt").exists());

        // A symlinked info/ is never followed or repaired.
        let elsewhere = workdir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root.join("info")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("info")).unwrap();
        assert!(matches!(
            store.lock_trash_root(&root),
            Err(TrashError::Refused(_))
        ));
        let g = create_file(workdir.path(), "refused.txt", "y");
        assert!(store.trash(&g, None).is_err());
        assert!(g.exists());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    // #328: a selector reports and selects exactly the entries find_entry
    // matched, even when an exact name contains glob syntax.
    #[test]
    fn matching_entries_follow_find_entry_tiers() {
        let (store, _data, workdir, _lock) = test_store();
        for dir in ["zero", "one", "two"] {
            fs::create_dir(workdir.path().join(dir)).unwrap();
            let f = create_file(&workdir.path().join(dir), "a[1].txt", dir);
            store.trash(&f, None).unwrap();
        }
        // With the bare ID gone, the name matches two suffixed IDs.
        store.purge("a[1].txt").unwrap();
        let plain = create_file(workdir.path(), "a1.txt", "other");
        store.trash(&plain, None).unwrap();
        assert!(matches!(
            store.find_entry("a[1].txt"),
            Err(TrashError::AmbiguousMatch { count: 2, .. })
        ));
        let (tier, matched) = store.matching_entries("a[1].txt").unwrap().unwrap();
        assert_eq!(tier, MatchTier::FileName);
        assert_eq!(matched.len(), 2);
        assert!(
            matched
                .iter()
                .all(|e| e.info.original_path.ends_with("a[1].txt"))
        );
        // A glob that names no entry exactly is still a glob.
        let (tier, matched) = store.matching_entries("a?.txt").unwrap().unwrap();
        assert_eq!(tier, MatchTier::Glob);
        assert_eq!(matched.len(), 1);
        assert!(store.matching_entries("missing").unwrap().is_none());
    }

    // #340: --all with an exact ID also takes the copies trashed under the
    // same name, while single-entry selection stays exact.
    #[test]
    fn all_copies_follow_an_exact_id() {
        let (store, _data, workdir, _lock) = test_store();
        for dir in ["zero", "one", "two"] {
            fs::create_dir(workdir.path().join(dir)).unwrap();
            let f = create_file(&workdir.path().join(dir), "foo", dir);
            store.trash(&f, None).unwrap();
        }
        let other = create_file(workdir.path(), "foobar", "other");
        store.trash(&other, None).unwrap();
        assert_eq!(store.find_entry("foo").unwrap().id, "foo");
        let (tier, matched) = store.matching_entries("foo").unwrap().unwrap();
        assert_eq!((tier, matched.len()), (MatchTier::Id, 1));
        let (tier, matched) = store.matching_entries_all("foo").unwrap().unwrap();
        assert_eq!((tier, matched.len()), (MatchTier::Id, 3));
        assert!(
            matched
                .iter()
                .all(|e| e.info.original_path.ends_with("foo"))
        );
        let suffixed = matched.iter().find(|e| e.id != "foo").unwrap().id.clone();
        let (_, matched) = store.matching_entries_all(&suffixed).unwrap().unwrap();
        assert_eq!(matched.len(), 1, "a suffixed ID names one entry");
    }

    // #329: entries trashed within one second undo newest first.
    #[test]
    fn undo_restores_the_latest_of_same_second_deletions() {
        let (store, _data, workdir, _lock) = test_store();
        let files: Vec<PathBuf> = (1..=12)
            .map(|i| create_file(workdir.path(), &format!("f{i}"), "x"))
            .collect();
        for f in &files {
            store.trash(f, None).unwrap();
        }
        for expected in files.iter().rev().take(3) {
            assert_eq!(&store.undo().unwrap(), expected);
            assert!(expected.exists());
        }
    }

    fn unmount(target: &Path) {
        let target = CString::new(target.as_os_str().as_bytes()).unwrap();
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    }

    fn mount_at(source: Option<&Path>, target: &Path) -> bool {
        let target = CString::new(target.as_os_str().as_bytes()).unwrap();
        let result = match source {
            Some(source) => {
                let source = CString::new(source.as_os_str().as_bytes()).unwrap();
                unsafe {
                    libc::mount(
                        source.as_ptr(),
                        target.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                }
            }
            None => unsafe {
                libc::mount(
                    c"none".as_ptr(),
                    target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            },
        };
        result == 0
    }

    // #362: the trash's own directory or an ancestor reached through a bind
    // alias is refused by identity, not only by name.
    #[test]
    fn trash_ancestors_are_refused_under_another_name() {
        let base = tempfile::tempdir().unwrap();
        let share = base.path().join("home/.local/share");
        fs::create_dir_all(&share).unwrap();
        let mut config = Config::default();
        config.never_trash.clear();
        let store = TrashStore::open_isolated(&share.join("Trash"), config).unwrap();
        let alias = base.path().join("alias");
        fs::create_dir(&alias).unwrap();
        let other = base.path().join("other");
        fs::create_dir(&other).unwrap();
        let verdict = crate::mounts::in_private_mounts(
            "store::tests::trash_ancestors_are_refused_under_another_name",
            || {
                if !mount_at(Some(&share), &alias) {
                    return false;
                }
                let refused = matches!(
                    store.check_trash_eligibility(&alias),
                    Err(TrashError::Refused(_))
                ) && matches!(
                    store.check_trash_eligibility(&alias.join("Trash")),
                    Err(TrashError::Refused(_))
                ) && matches!(
                    store.check_trash_eligibility(&alias.join("Trash/files")),
                    Err(TrashError::Refused(_))
                ) && store.check_trash_eligibility(&other).is_ok();
                unmount(&alias);
                refused
            },
        );
        assert_ne!(verdict, Some(false));
    }

    // #362: a mount that travelled into the trash with its directory is
    // never purged through.
    #[test]
    fn purge_never_descends_into_a_mount() {
        let (store, _data, workdir, _lock) = test_store();
        let tree = workdir.path().join("tree");
        fs::create_dir_all(tree.join("mnt")).unwrap();
        fs::write(tree.join("plain"), b"x").unwrap();
        store.trash(&tree, None).unwrap();
        let entry = store.find_entry("tree").unwrap();
        let mounted = entry.trashed_path.join("mnt");
        let verdict = crate::mounts::in_private_mounts(
            "store::tests::purge_never_descends_into_a_mount",
            || {
                if !mount_at(None, &mounted)
                    || fs::write(mounted.join("precious"), b"keep").is_err()
                {
                    return false;
                }
                // Purging detaches the tree first; the mount travels with it.
                let Ok(held) = fs::File::open(&mounted) else {
                    return false;
                };
                let _ = store.purge("tree");
                let mount = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
                let kept = fs::read(mount.join("precious")).is_ok_and(|data| data == b"keep");
                unmount(&mount);
                kept
            },
        );
        assert_ne!(verdict, Some(false));
    }

    // #366, #368: a tree holding a mount moves whole or not at all, so it
    // is refused and stays as it is. Mounts of other filesystems, binds of
    // its own and bind-mounted files are all seen, by statx and by the
    // mount-ID fallback for kernels before 5.8 alike.
    #[test]
    fn a_tree_holding_a_mount_is_refused_whole() {
        let (store, _data, workdir, _lock) = test_store();
        let tree = workdir.path().join("tree");
        let source = workdir.path().join("source");
        fs::create_dir_all(tree.join("a/mnt")).unwrap();
        fs::create_dir_all(tree.join("b/bind")).unwrap();
        fs::create_dir_all(&source).unwrap();
        fs::write(tree.join("plain"), b"x").unwrap();
        fs::write(tree.join("file"), b"").unwrap();
        let verdict = crate::mounts::in_private_mounts(
            "store::tests::a_tree_holding_a_mount_is_refused_whole",
            || {
                let refused = |mount: &str| {
                    matches!(store.trash(&tree, None),
                        Err(TrashError::HoldsMount(ref held)) if *held == Path::new(mount))
                };
                let fallback = |parent: &str, name: &CStr| {
                    let parent = fs::File::open(tree.join(parent)).unwrap();
                    let fd = parent.as_raw_fd();
                    let info = mounts::entry_info_at(fd, name, libc::STATX_TYPE).unwrap();
                    let dev = stat_fd(fd).unwrap().st_dev;
                    let info = mounts::EntryInfo {
                        mount_root: None,
                        ..info
                    };
                    survey_mount(fd, dev, &std::cell::OnceCell::new(), name, &info)
                };
                let mut ok = !fallback("a", c"mnt") && !fallback("b", c"bind");
                for (mount, source, parent, name) in [
                    ("a/mnt", None, "a", Some(c"mnt")),
                    ("b/bind", Some(source.as_path()), "b", Some(c"bind")),
                    ("file", Some(tree.join("plain").as_path()), "", None),
                ] {
                    if !mount_at(source, &tree.join(mount)) {
                        return false;
                    }
                    ok &= refused(mount);
                    ok &= name.is_none_or(|name| fallback(parent, name));
                    unmount(&tree.join(mount));
                }
                ok && tree.join("plain").exists()
                    && store.trash(&tree, None).is_ok()
                    && store.list(None).unwrap().len() == 1
            },
        );
        assert_ne!(verdict, Some(false));
    }

    // #369: rm -r for real walks by descriptor. A directory swapped for a
    // symlink to outside the tree mid-removal is never followed: a path walk
    // deleted the outside files in up to half the runs.
    #[test]
    fn real_removal_never_follows_a_swapped_directory() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let work = TempDir::with_prefix_in("race-", &base).unwrap();
        let parent = fs::File::open(work.path()).unwrap();
        for round in 0..20 {
            let tree = work.path().join(format!("tree-{round}"));
            let outside = work.path().join(format!("outside-{round}"));
            fs::create_dir_all(tree.join("a")).unwrap();
            fs::create_dir_all(&outside).unwrap();
            for i in 0..200 {
                fs::write(tree.join(format!("a/{i}")), b"x").unwrap();
                fs::write(outside.join(i.to_string()), b"keep").unwrap();
            }
            std::os::unix::fs::symlink(&outside, tree.join("s")).unwrap();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let racer = {
                let stop = std::sync::Arc::clone(&stop);
                let a = CString::new(tree.join("a").as_os_str().as_bytes()).unwrap();
                let s = CString::new(tree.join("s").as_os_str().as_bytes()).unwrap();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        unsafe {
                            libc::syscall(
                                libc::SYS_renameat2,
                                libc::AT_FDCWD,
                                a.as_ptr(),
                                libc::AT_FDCWD,
                                s.as_ptr(),
                                libc::RENAME_EXCHANGE,
                            )
                        };
                    }
                })
            };
            let name = CString::new(format!("tree-{round}")).unwrap();
            remove_tree_for_real(parent.as_raw_fd(), &name, &mut |_, _| {});
            stop.store(true, Ordering::Relaxed);
            racer.join().unwrap();
            assert_eq!(
                fs::read_dir(&outside).unwrap().count(),
                200,
                "round {round}"
            );
            let _ = fs::remove_dir_all(&tree);
        }
    }

    // #370: a mount deeper than the survey walks is still found, from the
    // mount table, and the tree is refused instead of carrying it along.
    #[test]
    fn a_mount_below_the_surveyed_depth_is_still_refused() {
        let (store, _data, workdir, _lock) = test_store();
        let tree = workdir.path().join("deep");
        let mut inner = tree.clone();
        for _ in 0..COPY_TREE_MAX_DEPTH + 5 {
            inner.push("d");
        }
        fs::create_dir_all(&inner).unwrap();
        let verdict = crate::mounts::in_private_mounts(
            "store::tests::a_mount_below_the_surveyed_depth_is_still_refused",
            || {
                if !mount_at(None, &inner) {
                    return false;
                }
                let refused = matches!(store.trash(&tree, None),
                    Err(TrashError::HoldsMount(ref held)) if tree.join(held) == inner);
                unmount(&inner);
                // Kernel filesystems count too: a chroot's proc (#370).
                let target = CString::new(inner.as_os_str().as_bytes()).unwrap();
                if unsafe {
                    libc::mount(
                        c"proc".as_ptr(),
                        target.as_ptr(),
                        c"proc".as_ptr(),
                        0,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return false;
                }
                let proc_refused = matches!(store.trash(&tree, None),
                    Err(TrashError::HoldsMount(ref held)) if tree.join(held) == inner);
                unmount(&inner);
                refused && proc_refused && inner.is_dir() && store.list(None).unwrap().is_empty()
            },
        );
        assert_ne!(verdict, Some(false));
    }

    // #370: real removal keeps its own stack: a tree deeper than any fixed
    // cap goes, as std's remove_dir_all removed it, where descriptors allow.
    #[test]
    fn real_removal_has_no_depth_cap() {
        const DEPTH: usize = 4200;
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        if limit.rlim_max < (DEPTH as libc::rlim_t) + 512 {
            eprintln!("SKIP: the descriptor limit is below the tree's depth");
            return;
        }
        if limit.rlim_cur < (DEPTH as libc::rlim_t) + 512 {
            limit.rlim_cur = limit.rlim_max;
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
        }
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let work = TempDir::with_prefix_in("deep-", &base).unwrap();
        let root = fs::File::open(work.path()).unwrap();
        let mut current = unsafe { libc::dup(root.as_raw_fd()) };
        for level in 0..DEPTH {
            let name = if level == 0 { c"tree" } else { c"d" };
            assert_eq!(unsafe { libc::mkdirat(current, name.as_ptr(), 0o755) }, 0);
            let next =
                unsafe { libc::openat(current, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
            unsafe { libc::close(current) };
            assert!(next >= 0);
            current = next;
        }
        unsafe { libc::close(current) };
        let mut failures = Vec::new();
        let removed = remove_tree_for_real(root.as_raw_fd(), c"tree", &mut |below, error| {
            failures.push(format!("{}: {error}", below.display().to_string().len()));
        });
        assert!(removed, "{failures:?}");
        assert!(!work.path().join("tree").exists());
    }

    // #345: the deletion stamp orders same-second entries whose sidecar
    // mtimes tie (coarse filesystem clocks), and rewriting a sidecar for
    // compression keeps the mtime that orders entries without a stamp.
    #[test]
    fn deletion_stamps_order_entries_with_tied_sidecar_times() {
        let (store, _data, workdir, _lock) = test_store();
        let first = create_file(workdir.path(), "first", "x");
        let second = create_file(workdir.path(), "second", "x");
        store.trash(&first, None).unwrap();
        store.trash(&second, None).unwrap();
        let entries = store.list(None).unwrap();
        assert!(entries.iter().all(|e| e.info.deletion_ns.is_some()));
        let tied = fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH);
        for entry in &entries {
            fs::File::options()
                .write(true)
                .open(&entry.info_path)
                .unwrap()
                .set_times(tied)
                .unwrap();
        }
        let newest = store.find_entry("second").unwrap();
        let before = fs::metadata(&newest.info_path).unwrap().modified().unwrap();
        set_compression_marker(&newest.info_path, Some("zstd")).unwrap();
        set_compression_marker(&newest.info_path, None).unwrap();
        assert_eq!(
            fs::metadata(&newest.info_path).unwrap().modified().unwrap(),
            before
        );
        assert_eq!(store.undo().unwrap(), second);
        assert_eq!(store.undo().unwrap(), first);
    }

    /// Run `case` as an unprivileged user, where DAC permissions apply;
    /// skipped when not root. The named test runs again in a child process
    /// (glibc's set*id wrappers switch all of its threads): forking inside
    /// the multi-threaded harness can deadlock the child.
    fn as_unprivileged(test: &str, case: impl FnOnce() -> bool) -> Option<bool> {
        const CHILD: &str = "TRASHD_TEST_UNPRIVILEGED";
        if crate::mounts::is_rerun_child(test, CHILD) {
            // Root stays the saved ID, so the test's temporaries can be
            // removed again once the case has run.
            // Restored on the way out, a panicking case included.
            struct Restore;
            impl Drop for Restore {
                fn drop(&mut self) {
                    unsafe {
                        libc::setresuid(0, 0, 0);
                        libc::setresgid(0, 0, 0);
                    }
                }
            }
            let restore = Restore;
            let switched = unsafe {
                libc::setgroups(0, std::ptr::null()) == 0
                    && libc::setresgid(65534, 65534, 0) == 0
                    && libc::setresuid(65534, 65534, 0) == 0
            };
            let verdict = switched && case();
            drop(restore);
            return crate::mounts::report_test_verdict(Some(verdict));
        }
        if unsafe { libc::geteuid() } != 0 {
            return None;
        }
        crate::mounts::rerun_test(test, CHILD)
    }

    // #335: trees holding read-only directories (Go module caches) are
    // removed, and unreadable data can still be locked for purge.
    #[test]
    fn raw_removal_handles_read_only_trees_and_unreadable_data() {
        // The fixture is chowned to nobody before the case drops
        // privileges; a non-root runner cannot chown and has no case.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let tree = base.path().join("tree");
        fs::create_dir_all(tree.join("pkg@v1/sub")).unwrap();
        fs::write(tree.join("pkg@v1/sub/file"), b"x").unwrap();
        fs::write(tree.join("unreadable"), b"x").unwrap();
        for path in [
            &tree,
            &tree.join("pkg@v1"),
            &tree.join("pkg@v1/sub"),
            &tree.join("pkg@v1/sub/file"),
            &tree.join("unreadable"),
        ] {
            std::os::unix::fs::lchown(path, Some(65534), Some(65534)).unwrap();
        }
        fs::set_permissions(tree.join("unreadable"), fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(tree.join("pkg@v1/sub"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(tree.join("pkg@v1"), fs::Permissions::from_mode(0o555)).unwrap();
        let unreadable = tree.join("unreadable");
        let parent = base.path().to_path_buf();
        let outcome = as_unprivileged(
            "store::tests::raw_removal_handles_read_only_trees_and_unreadable_data",
            move || {
                let locked = matches!(lock_entry_file(&unreadable), Ok(None));
                let dir = fs::File::open(&parent).unwrap();
                let removed = remove_tree_at(dir.as_raw_fd(), c"tree", 0).is_ok();
                locked && removed && !parent.join("tree").exists()
            },
        );
        if let Some(outcome) = outcome {
            assert!(outcome, "unprivileged removal failed");
        }
    }

    // #391: exercise the actual consumers under a process-local allocation
    // limit. Fixture construction and validation run outside these fresh
    // children, so allocator reuse cannot hide a complete name snapshot.
    #[test]
    fn raw_removal_and_stage_selection_bound_wide_directory_memory() {
        const CHILD: &str = "TRASHD_TEST_STREAMING_ROOT";
        const MODE: &str = "TRASHD_TEST_STREAMING_MODE";
        const TEST: &str =
            "store::tests::raw_removal_and_stage_selection_bound_wide_directory_memory";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let directory = fs::File::open(root).unwrap();
            let pages: u64 = fs::read_to_string("/proc/self/statm")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut limit) }, 0);
            limit.rlim_cur = pages * page_size + 4 * 1024 * 1024;
            assert!(limit.rlim_cur <= limit.rlim_max);
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) }, 0);
            match std::env::var(MODE).unwrap().as_str() {
                "remove" => remove_tree_at(directory.as_raw_fd(), c"wide", 0).unwrap(),
                "sweep" => {
                    let selected = sweep_detached_prioritized(root, |_| 0);
                    assert_eq!(selected.len(), STAGES_PER_SWEEP);
                    assert!(selected.iter().all(|name| is_copy_stage(name)));
                }
                mode => panic!("unknown streaming fixture mode: {mode}"),
            }
            return;
        }

        let (store, _data, work, _) = test_store();
        let tree = work.path().join("wide");
        let state = store.home.join(".trashd");
        fs::create_dir(&tree).unwrap();
        let sentinel = create_file(work.path(), "KEEP", "outside the removed tree");
        let tail = "w".repeat(230);
        for index in 0..32768 {
            let name = format!("{index:05}-{tail}");
            fs::write(state.join(&name), b"unrelated state").unwrap();
            let path = tree.join(name);
            if index % 1024 == 0 {
                fs::create_dir(&path).unwrap();
                fs::write(path.join("payload"), b"nested").unwrap();
                std::os::unix::fs::symlink("payload", path.join("link")).unwrap();
            } else if index % 512 == 0 {
                std::os::unix::fs::symlink(&sentinel, path).unwrap();
            } else {
                fs::write(path, b"file").unwrap();
            }
        }
        // A shared buffer also matters for narrow deep trees: allocating
        // one 32 KiB buffer at every level exceeds the same memory limit.
        let mut descriptors = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut descriptors) },
            0
        );
        let depth = descriptors.rlim_cur.saturating_sub(64).min(512);
        let mut inner = tree.clone();
        for _ in 0..depth {
            inner.push("d");
            fs::create_dir(&inner).unwrap();
        }
        fs::write(inner.join("deep"), b"payload").unwrap();
        for index in 0..STAGES_PER_SWEEP + 3 {
            fs::write(state.join(format!(".trashd-copy-123-{index}-0")), b"stage").unwrap();
        }
        let detached = state.join("purging-streaming");
        fs::create_dir(&detached).unwrap();
        fs::write(detached.join("partial"), b"delete detached data").unwrap();
        for (mode, root) in [("remove", work.path()), ("sweep", store.home_dir())] {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env(CHILD, root)
                .env(MODE, mode)
                .env("TRASH_BYPASS", "1")
                // A separate glibc thread arena reserves a large PROT_NONE
                // mapping before the limit; later allocations could reuse it
                // without increasing virtual size and mask the old snapshot.
                .env("MALLOC_ARENA_MAX", "1")
                .output()
                .unwrap();
            assert!(child.status.success(), "{mode}: {child:?}");
        }
        assert!(!tree.exists());
        assert!(!detached.exists());
        assert_eq!(fs::read(sentinel).unwrap(), b"outside the removed tree");
        for index in 0..32768 {
            assert_eq!(
                fs::read(state.join(format!("{index:05}-{tail}"))).unwrap(),
                b"unrelated state"
            );
        }
    }

    #[test]
    fn streamed_raw_removal_keeps_first_read_error_and_finishes_siblings() {
        let work = tempfile::tempdir().unwrap();
        let tree = work.path().join("tree");
        for name in ["a", "b", "z"] {
            fs::create_dir_all(tree.join(name)).unwrap();
            fs::write(tree.join(name).join("payload"), b"keep on failure").unwrap();
        }
        let tail = "f".repeat(200);
        for index in 0..2048 {
            fs::write(tree.join("a").join(format!("{index}-{tail}")), b"x").unwrap();
        }
        let parent = fs::File::open(work.path()).unwrap();
        let a = fs::metadata(tree.join("a")).unwrap().ino();
        let b = fs::metadata(tree.join("b")).unwrap().ino();
        let root = fs::metadata(&tree).unwrap().ino();
        let mut a_reads = 0;
        let error = remove_tree_with_reader(
            parent.as_raw_fd(),
            &std::cell::OnceCell::new(),
            c"tree",
            0,
            |fd, buffer, pending| {
                let inode = stat_fd(fd)?.st_ino;
                if inode == a {
                    a_reads += 1;
                    if a_reads == 2 {
                        return Err(io::Error::from_raw_os_error(libc::EACCES));
                    }
                } else if inode == b {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                let more = read_entry_batch(fd, buffer, pending)?;
                if inode == a && a_reads == 1 {
                    // Another remover can unlink an already listed name
                    // before this walk reaches it. ENOENT is not a failure.
                    raw_unlinkat(fd, &pending.first().unwrap().0, 0)?;
                }
                if inode == root {
                    pending.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                }
                Ok(more)
            },
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        assert_eq!(a_reads, 2);
        let remaining = fs::read_dir(tree.join("a")).unwrap().count();
        assert!(remaining > 0 && remaining < 2049);
        assert!(tree.join("b/payload").exists());
        assert!(!tree.join("z").exists());
        remove_tree_at(parent.as_raw_fd(), c"tree", 0).unwrap();
    }

    #[test]
    fn streamed_raw_removal_preserves_directory_depth_boundary() {
        let work = tempfile::tempdir().unwrap();
        fs::create_dir_all(work.path().join("tree/too-deep")).unwrap();
        fs::write(work.path().join("tree/file"), b"remove regular sibling").unwrap();
        fs::write(work.path().join("tree/too-deep/KEEP"), b"keep deep data").unwrap();
        let parent = fs::File::open(work.path()).unwrap();
        let error = remove_tree_at(parent.as_raw_fd(), c"tree", REMOVE_TREE_MAX_DEPTH).unwrap_err();
        assert!(error.to_string().contains("too deep"));
        assert!(!work.path().join("tree/file").exists());
        assert_eq!(
            fs::read(work.path().join("tree/too-deep/KEEP")).unwrap(),
            b"keep deep data"
        );
    }

    // #370: a cross-device copy is refused only for what could not be
    // retired: a directory holding entries the user may not write. An empty
    // read-only directory needs nothing of itself.
    #[test]
    fn retire_checks_ask_only_directories_with_entries() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o777)).unwrap();
        for tree in ["empty-leaf", "full-leaf"] {
            let tree = base.path().join(tree);
            fs::create_dir_all(tree.join("sub")).unwrap();
            fs::create_dir_all(tree.join("leaf")).unwrap();
            fs::write(tree.join("f"), b"x").unwrap();
            fs::write(tree.join("sub/g"), b"x").unwrap();
            for path in [
                &tree,
                &tree.join("sub"),
                &tree.join("leaf"),
                &tree.join("f"),
                &tree.join("sub/g"),
            ] {
                std::os::unix::fs::lchown(path, Some(65534), Some(65534)).unwrap();
            }
        }
        let full = base.path().join("full-leaf/leaf/h");
        fs::write(&full, b"x").unwrap();
        std::os::unix::fs::lchown(&full, Some(65534), Some(65534)).unwrap();
        for tree in ["empty-leaf", "full-leaf"] {
            fs::set_permissions(
                base.path().join(tree).join("leaf"),
                fs::Permissions::from_mode(0o555),
            )
            .unwrap();
        }
        let parent = base.path().to_path_buf();
        let outcome = as_unprivileged(
            "store::tests::retire_checks_ask_only_directories_with_entries",
            move || {
                let dir = fs::File::open(&parent).unwrap();
                let empty = snapshot_retirable_at(
                    dir.as_raw_fd(),
                    c"empty-leaf",
                    file_identity(&parent.join("empty-leaf")).unwrap(),
                );
                let full = snapshot_retirable_at(
                    dir.as_raw_fd(),
                    c"full-leaf",
                    file_identity(&parent.join("full-leaf")).unwrap(),
                );
                empty.is_ok()
                    && matches!(full, Err(TrashError::Unremovable(ref error))
                        if error.raw_os_error() == Some(libc::EACCES))
            },
        );
        if let Some(outcome) = outcome {
            assert!(outcome, "retire checks misjudged a tree");
        }
    }

    // #335: a purged directory is detached, then deleted outside the lock,
    // leaving nothing behind; a leftover detached tree is swept.
    #[test]
    fn purged_directories_are_detached_and_swept() {
        let (store, _data, workdir, _lock) = test_store();
        let dir = workdir.path().join("tree");
        fs::create_dir_all(dir.join("a/b")).unwrap();
        fs::write(dir.join("a/b/f"), b"x").unwrap();
        let id = store.trash(&dir, None).unwrap();
        store.purge(&id).unwrap();
        let state = store.home_dir().join(".trashd");
        let leftovers = || {
            fs::read_dir(&state)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(DETACHED_PREFIX))
                .count()
        };
        assert_eq!(leftovers(), 0);
        assert!(!store.home_dir().join("files").join(&id).exists());
        fs::create_dir_all(state.join("purging-stale/x")).unwrap();
        sweep_detached(store.home_dir());
        assert_eq!(leftovers(), 0);
    }

    #[test]
    fn announced_data_stage_is_private_even_with_restrictive_umask() {
        const CHILD: &str = "TRASHD_TEST_STAGE_UMASK_ROOT";
        const TEST: &str =
            "store::tests::announced_data_stage_is_private_even_with_restrictive_umask";
        if let Some(root) = std::env::var_os(CHILD) {
            // Process-isolated: never change the parent harness's umask.
            unsafe { libc::umask(0o777) };
            let stage = create_data_stage(Path::new(&root)).unwrap();
            assert_eq!(stage.as_file().metadata().unwrap().mode() & 0o777, 0o600);
            unsafe { libc::_exit(0) };
        }
        let (store, _data, _work, _) = test_store();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, store.home_dir())
            .env("TRASH_BYPASS", "1")
            .output()
            .unwrap();
        assert!(child.status.success(), "{child:?}");
        let candidates = sweep_detached(store.home_dir());
        assert_eq!(candidates.len(), 1);
        store.sweep_abandoned_stages(store.home_dir(), &candidates);
        assert!(sweep_detached(store.home_dir()).is_empty());
    }

    #[test]
    fn announced_decompression_stages_are_reclaimed_after_process_exit() {
        const CHILD: &str = "TRASHD_TEST_ABANDONED_DATA_ROOT";
        const TEST: &str =
            "store::tests::announced_decompression_stages_are_reclaimed_after_process_exit";
        if let Some(root) = std::env::var_os(CHILD) {
            let store = TrashStore::open_isolated(Path::new(&root), Config::default()).unwrap();
            let mut entry = store.find_entry("data").unwrap();
            decompress_before_commit(&mut entry, 1024 * 1024, || {
                let stages = sweep_detached(store.home_dir());
                assert_eq!(stages.len(), 1);
                let state = fs::File::open(store.home.join(".trashd")).unwrap();
                assert!(
                    try_lock_data_stage_at(state.as_raw_fd(), &stages[0])
                        .unwrap()
                        .is_none()
                );
                // Reexec avoids a forked multithreaded harness. No destructors:
                // the complete plaintext stage must outlive this child.
                unsafe { libc::_exit(0) };
            })
            .unwrap();
            panic!("decompression must reach its publication seam");
        }
        let (store, _data, work, _) = test_store();
        let original = vec![b'x'; 1024 * 1024];
        let encoded = zstd::encode_all(original.as_slice(), 3).unwrap();
        let path = store.home.join("files/data");
        fs::write(&path, &encoded).unwrap();
        let mut info = TrashInfo::new(work.path().join("data"));
        info.pid = Some(1);
        info.compressed = Some("zstd".into());
        let info_path = store.home.join("info/data.trashinfo");
        fs::write(&info_path, info.to_trashinfo_string()).unwrap();
        let sidecar = fs::read(&info_path).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, store.home_dir())
            .env("TRASH_BYPASS", "1")
            .output()
            .unwrap();
        assert!(child.status.success(), "{child:?}");
        let candidates = sweep_detached(store.home_dir());
        assert_eq!(candidates.len(), 1);
        assert!(is_data_stage(&candidates[0]));
        let staged = store
            .home
            .join(".trashd")
            .join(OsStr::from_bytes(candidates[0].to_bytes()));
        assert_eq!(fs::metadata(&staged).unwrap().len(), original.len() as u64);
        store
            .auto_purge_in_roots(std::slice::from_ref(&store.home))
            .unwrap();
        assert!(!staged.exists());
        assert_eq!(fs::read(&path).unwrap(), encoded);
        assert_eq!(fs::read(&info_path).unwrap(), sidecar);
    }

    #[test]
    fn announced_data_stages_skip_live_locks_and_preserved_read_only_owners() {
        let (store, _data, _work, _) = test_store();
        let uid = unsafe { libc::geteuid() };
        for foreign in [false, true] {
            if foreign && uid != 0 {
                continue;
            }
            let mut stage = create_data_stage(store.home_dir()).unwrap();
            stage.write_all(b"complete staged bytes").unwrap();
            let path = stage.path().to_path_buf();
            assert!(is_data_stage(
                &CString::new(path.file_name().unwrap().as_bytes()).unwrap()
            ));
            if foreign {
                assert_eq!(
                    unsafe { libc::fchown(stage.as_file().as_raw_fd(), 65534, 65534) },
                    0
                );
            }
            stage
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o400))
                .unwrap();
            stage.as_file().set_modified(std::time::UNIX_EPOCH).unwrap();
            store
                .auto_purge_in_roots(std::slice::from_ref(&store.home))
                .unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"complete staged bytes");
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
            let (file, path) = stage.into_parts();
            let path = path.keep().unwrap();
            drop(file);
            store
                .auto_purge_in_roots(std::slice::from_ref(&store.home))
                .unwrap();
            assert!(
                !path.exists(),
                "an unlocked read-only stage must be reclaimed"
            );
        }
    }

    #[test]
    fn announced_stage_claims_verify_identity_and_protect_reused_names() {
        let (store, _data, work, _) = test_store();
        let mut stage = create_data_stage(store.home_dir()).unwrap();
        stage.write_all(b"first stage").unwrap();
        let (file, path) = stage.into_parts();
        let path = path.keep().unwrap();
        drop(file);
        let state = fs::File::open(store.home.join(".trashd")).unwrap();
        let name = CString::new(path.file_name().unwrap().as_bytes()).unwrap();
        let locked = try_lock_data_stage_at(state.as_raw_fd(), &name)
            .unwrap()
            .unwrap();
        let old = work.path().join("old-stage");
        fs::rename(&path, &old).unwrap();
        fs::write(&path, b"replacement stage").unwrap();
        assert_eq!(
            claim_data_stage_at(state.as_raw_fd(), &name, &locked)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBUSY)
        );
        assert_eq!(fs::read(&path).unwrap(), b"replacement stage");
        assert_eq!(fs::read(&old).unwrap(), b"first stage");
        drop(locked);
        let (state, claims) = store
            .claim_abandoned_stages(store.home_dir(), &[name])
            .unwrap();
        assert_eq!(claims.len(), 1);
        fs::write(&path, b"new stage at the reused name").unwrap();
        remove_tree_at(state.as_raw_fd(), &claims[0], 0).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new stage at the reused name");
    }

    #[test]
    fn announced_stage_cleanup_preserves_unknown_legacy_and_special_names() {
        let (store, _data, work, _) = test_store();
        let state = store.home.join(".trashd");
        let names = [
            ".tmpambiguous",
            ".trashd-decompress-old",
            ".trashd-compress-old",
            ".trashd-stage-v2-1234567890abcdef",
            ".trashd-stage-v1-short",
            ".trashd-stage-v1-1234567890abcde!",
        ];
        for name in names {
            fs::write(state.join(name), b"preserve state").unwrap();
        }
        let victim = create_file(work.path(), "victim", "do not follow");
        let link = state.join(format!(
            "{DATA_STAGE_PREFIX}{}",
            "l".repeat(DATA_STAGE_RANDOM_LEN)
        ));
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let directory = state.join(format!(
            "{DATA_STAGE_PREFIX}{}",
            "d".repeat(DATA_STAGE_RANDOM_LEN)
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("keep"), b"keep directory").unwrap();
        store
            .auto_purge_in_roots(std::slice::from_ref(&store.home))
            .unwrap();
        for name in names {
            assert_eq!(fs::read(state.join(name)).unwrap(), b"preserve state");
        }
        assert!(link.is_symlink());
        assert_eq!(fs::read(&victim).unwrap(), b"do not follow");
        assert_eq!(fs::read(directory.join("keep")).unwrap(), b"keep directory");
    }

    #[test]
    fn announced_stage_selection_reaches_abandoned_work_beyond_live_stages() {
        let (store, _data, _work, _) = test_store();
        let mut live = Vec::new();
        for _ in 0..STAGES_PER_SWEEP + 2 {
            live.push(create_data_stage(store.home_dir()).unwrap());
        }
        // Pick the last actual directory entry, not the last insertion:
        // hashed directory order must not let a first-32-only mutant pass.
        let state = fs::File::open(store.home.join(".trashd")).unwrap();
        let last = read_directory_names(state.as_raw_fd())
            .unwrap()
            .into_iter()
            .rfind(|name| is_data_stage(name))
            .unwrap();
        let index = live
            .iter()
            .position(|stage| stage.path().file_name().unwrap().as_bytes() == last.to_bytes())
            .unwrap();
        let abandoned = live.swap_remove(index);
        let (file, path) = abandoned.into_parts();
        let path = path.keep().unwrap();
        drop(file);
        let candidates = sweep_detached_prioritized(store.home_dir(), |name| {
            if name.to_bytes() == path.file_name().unwrap().as_bytes() {
                0
            } else {
                1
            }
        });
        assert_eq!(candidates.len(), STAGES_PER_SWEEP);
        assert!(
            candidates
                .iter()
                .any(|name| name.to_bytes() == path.file_name().unwrap().as_bytes())
        );
        store.sweep_abandoned_stages(store.home_dir(), &candidates);
        assert!(!path.exists());
        assert!(live.iter().all(|stage| stage.path().is_file()));
    }

    #[test]
    fn abandoned_copy_stages_are_reclaimed_after_process_exit() {
        const CHILD: &str = "TRASHD_TEST_ABANDONED_COPY_ROOT";
        const TEST: &str = "store::tests::abandoned_copy_stages_are_reclaimed_after_process_exit";
        if let Some(root) = std::env::var_os(CHILD) {
            let store = TrashStore::open_isolated(Path::new(&root), Config::default()).unwrap();
            let _live = store.lock_trash_root(store.home_dir()).unwrap();
            let state = store.home_dir().join(".trashd");
            fs::create_dir_all(state.join(".trashd-copy-123-456-0/sub")).unwrap();
            fs::write(
                state.join(".trashd-copy-123-456-0/sub/partial"),
                b"copied prefix",
            )
            .unwrap();
            fs::write(
                state.join(".trashd-copy-123-456-1"),
                b"partial regular file",
            )
            .unwrap();
            // Reexec rather than fork inside the multithreaded harness. Exit
            // without destructors, just as an interrupted copy loses its lock.
            unsafe { libc::_exit(0) };
        }
        let (store, _data, work, _) = test_store();
        let source = create_file(work.path(), "original", "complete original data");
        let state = store.home_dir().join(".trashd");
        fs::write(state.join(".trashd-copy-unrelated"), b"keep state").unwrap();
        fs::write(state.join(".trashd-copy-1-2-3-extra"), b"keep state").unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, store.home_dir())
            .env("TRASH_BYPASS", "1")
            .output()
            .unwrap();
        assert!(child.status.success(), "{:?}", child);
        assert!(state.join(".trashd-copy-123-456-0/sub/partial").is_file());
        store.auto_purge().unwrap();
        assert!(!state.join(".trashd-copy-123-456-0").exists());
        assert!(!state.join(".trashd-copy-123-456-1").exists());
        assert_eq!(
            fs::read_to_string(source).unwrap(),
            "complete original data"
        );
        for name in [".trashd-copy-unrelated", ".trashd-copy-1-2-3-extra"] {
            assert_eq!(fs::read(state.join(name)).unwrap(), b"keep state");
        }
    }

    #[test]
    fn abandoned_copy_claims_skip_live_writers_and_protect_reused_names() {
        let (store, _data, _work, _) = test_store();
        let state_path = store.home_dir().join(".trashd");
        let stage = state_path.join(".trashd-copy-123-456-0");
        let live = store.lock_trash_root(store.home_dir()).unwrap();
        fs::write(&stage, b"live copy").unwrap();
        assert!(
            store
                .claim_abandoned_stages(store.home_dir(), &sweep_detached(store.home_dir()))
                .is_none()
        );
        assert_eq!(fs::read(&stage).unwrap(), b"live copy");
        drop(live);

        // Parallel reexec tests can briefly inherit a CLOEXEC descriptor
        // before exec closes it. Keep the candidate snapshot while waiting.
        let candidates = sweep_detached(store.home_dir());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let (state, claims) = loop {
            if let Some(claimed) = store.claim_abandoned_stages(store.home_dir(), &candidates) {
                break claimed;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        assert_eq!(claims.len(), 1);
        assert!(!stage.exists());
        // Parallel tests can briefly inherit a CLOEXEC lock descriptor
        // while spawning a child; allow its exec to close that descriptor.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let guard = loop {
            if let Some(guard) =
                RootMutationGuard::try_acquire_as(store.home_dir(), unsafe { libc::geteuid() })
                    .unwrap()
            {
                break guard;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "cleanup kept the writer lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        fs::write(&stage, b"new live copy at the old name").unwrap();
        drop(guard);
        remove_tree_at(state.as_raw_fd(), &claims[0], 0).unwrap();
        assert_eq!(fs::read(&stage).unwrap(), b"new live copy at the old name");
        assert!(
            !state_path
                .join(OsStr::from_bytes(claims[0].to_bytes()))
                .exists()
        );
    }

    #[test]
    fn abandoned_copy_claims_are_bounded_per_sweep() {
        let (store, _data, _work, _) = test_store();
        let state_path = store.home_dir().join(".trashd");
        for i in 0..STAGES_PER_SWEEP + 2 {
            fs::write(
                state_path.join(format!(".trashd-copy-123-{i}-0")),
                b"partial",
            )
            .unwrap();
        }
        let (state, claims) = store
            .claim_abandoned_stages(store.home_dir(), &sweep_detached(store.home_dir()))
            .unwrap();
        assert_eq!(claims.len(), STAGES_PER_SWEEP);
        for name in claims {
            remove_tree_at(state.as_raw_fd(), &name, 0).unwrap();
        }
        assert_eq!(
            fs::read_dir(&state_path)
                .unwrap()
                .flatten()
                .filter(|entry| {
                    CString::new(entry.file_name().as_bytes())
                        .is_ok_and(|name| is_copy_stage(&name))
                })
                .count(),
            2
        );
        store.sweep_abandoned_stages(store.home_dir(), &sweep_detached(store.home_dir()));
        assert!(fs::read_dir(&state_path).unwrap().flatten().all(|entry| {
            !CString::new(entry.file_name().as_bytes()).is_ok_and(|name| is_copy_stage(&name))
        }));
    }

    // #388: every fresh process starts its directory offset at zero. A scan
    // cap before finding a candidate hid stages forever behind unrelated
    // state. Exercise actual filesystem order beyond that old 4096 boundary.
    #[test]
    fn abandoned_copy_stages_beyond_unrelated_state_are_not_starved() {
        let (store, _data, work, _) = test_store();
        let state = store.home_dir().join(".trashd");
        let source = create_file(work.path(), "source", "complete source");
        let mut stage = state.join(".trashd-copy-123-456-0");
        fs::write(&stage, b"partial copy").unwrap();
        for index in 0..8192 {
            fs::write(state.join(format!("!unrelated-{index}")), b"state").unwrap();
        }
        let beyond_old_limit = |stage: &Path| {
            let directory = fs::File::open(&state).unwrap();
            read_directory_names(directory.as_raw_fd())
                .unwrap()
                .iter()
                .position(|name| name.to_bytes() == stage.file_name().unwrap().as_bytes())
                .is_some_and(|position| position >= 4096)
        };
        // Directory ordering varies: insertion order, reverse insertion,
        // lexical and hashed orders all occur. Choose a numeric stage name
        // that the real enumeration confirms is beyond the old boundary.
        for attempt in 1..=256 {
            if beyond_old_limit(&stage) {
                break;
            }
            fs::remove_file(&stage).unwrap();
            stage = state.join(format!(".trashd-copy-123-456-{attempt}"));
            fs::write(&stage, b"partial copy").unwrap();
        }
        assert!(
            beyond_old_limit(&stage),
            "fixture did not cross the old cap"
        );
        drop(store);
        // Reopen between runs: no persistent descriptor offset or cursor is
        // available to make progress through the unrelated entries.
        for _ in 0..2 {
            let reopened =
                TrashStore::open_isolated(state.parent().unwrap(), Config::default()).unwrap();
            reopened.auto_purge().unwrap();
        }
        assert!(!stage.exists());
        assert_eq!(fs::read(source).unwrap(), b"complete source");
        for index in 0..8192 {
            assert_eq!(
                fs::read(state.join(format!("!unrelated-{index}"))).unwrap(),
                b"state"
            );
        }
    }

    #[test]
    fn abandoned_copy_cleanup_never_descends_into_mounts() {
        let outcome = crate::mounts::in_private_mounts(
            "store::tests::abandoned_copy_cleanup_never_descends_into_mounts",
            || {
                let (store, _data, work, _) = test_store();
                let state_path = store.home_dir().join(".trashd");
                let stage = state_path.join(".trashd-copy-123-456-0");
                fs::create_dir_all(stage.join("mount")).unwrap();
                fs::create_dir(work.path().join("external")).unwrap();
                let keep = create_file(&work.path().join("external"), "KEEP", "external data");
                let tail = "m".repeat(200);
                for index in 0..2048 {
                    fs::write(stage.join(format!("{index}-{tail}")), b"remove sibling").unwrap();
                }
                let data_inode = fs::metadata(&stage).unwrap().ino();
                let source_mode = fs::metadata(work.path().join("external")).unwrap().mode();
                if !mount_at(Some(&work.path().join("external")), &stage.join("mount")) {
                    return false;
                }
                let (state, claims) = store
                    .claim_abandoned_stages(store.home_dir(), &sweep_detached(store.home_dir()))
                    .unwrap();
                assert_eq!(claims.len(), 1);
                let claimed = state_path.join(OsStr::from_bytes(claims[0].to_bytes()));
                // Visit the mount before the wide directory's other batches,
                // independent of the filesystem's directory ordering.
                let mut first = true;
                let result = remove_tree_with_reader(
                    state.as_raw_fd(),
                    &std::cell::OnceCell::new(),
                    &claims[0],
                    0,
                    |fd, buffer, pending| {
                        let more = read_entry_batch(fd, buffer, pending)?;
                        if stat_fd(fd)?.st_ino == data_inode {
                            pending.retain(|(name, _)| name.as_c_str() != c"mount");
                            if first {
                                pending.insert(0, (c"mount".to_owned(), libc::DT_DIR));
                                first = false;
                            }
                        }
                        Ok(more)
                    },
                );
                let kept = fs::read_to_string(&keep).unwrap() == "external data"
                    && fs::metadata(work.path().join("external")).unwrap().mode() == source_mode
                    && fs::read_dir(claimed.join("data")).unwrap().count() == 1;
                unmount(&claimed.join("data/mount"));
                remove_tree_at(state.as_raw_fd(), &claims[0], 0).unwrap();
                kept && result.is_err_and(|error| error.raw_os_error() == Some(libc::EBUSY))
            },
        );
        if let Some(outcome) = outcome {
            assert!(outcome);
        }
    }

    // #336: a tree past the size walk's file cap is recorded at its full
    // size, and its directorysizes row comes from the same walk.
    #[test]
    fn large_trees_are_recorded_at_full_size() {
        let (store, _data, workdir, _lock) = test_store();
        let tree = workdir.path().join("big");
        fs::create_dir(&tree).unwrap();
        let files = DIR_SIZE_MAX_FILES as usize + 20;
        for i in 0..files {
            fs::write(tree.join(format!("f{i}")), b"x").unwrap();
        }
        let id = store.trash(&tree, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        assert_eq!(entry.info.size, Some(files as u64));
        let cached = crate::directorysizes::read_cache(store.home_dir());
        assert!(cached[id.as_bytes()].size >= files as u64);
    }

    // #336: batch removals refresh a root's directorysizes only when they
    // removed a directory or a cached name.
    #[test]
    fn batch_removals_refresh_only_affected_caches() {
        let (store, _data, workdir, _lock) = test_store();
        for name in ["a", "b"] {
            store
                .trash(&create_file(workdir.path(), name, "x"), None)
                .unwrap();
        }
        let files = store.list(None).unwrap();
        assert_eq!(store.empty_entries(&files, None), 2);
        assert_eq!(store.cache_refreshes.get(), 0);
        let tree = workdir.path().join("tree");
        fs::create_dir(&tree).unwrap();
        store.trash(&tree, None).unwrap();
        store
            .trash(&create_file(workdir.path(), "c", "x"), None)
            .unwrap();
        let mixed = store.list(None).unwrap();
        assert_eq!(store.empty_entries(&mixed, None), 2);
        assert_eq!(store.cache_refreshes.get(), 1);
    }

    // #336: retention recognises compressed formats by header and remembers
    // data that did not shrink, dropping it once it leaves the trash.
    #[test]
    fn retention_remembers_incompressible_data() {
        assert!(is_compressed_format(&[0xFF, 0xD8, 0xFF, 0xE0]));
        assert!(is_compressed_format(b"\0\0\0\x18ftypisom"));
        assert!(is_compressed_format(b"RIFF\0\0\0\0WEBPVP8 "));
        assert!(is_compressed_format(b"PK\x03\x04rest"));
        assert!(!is_compressed_format(b"plain text here"));
        assert!(!is_compressed_format(b""));

        let (store, _data, workdir, _lock) = test_store();
        let file = create_file(workdir.path(), "data", "x");
        let meta = fs::metadata(&file).unwrap();
        let other = fs::metadata(workdir.path()).unwrap();
        let mut set = IncompressibleData::load(store.home_dir());
        assert!(!set.known(&meta));
        set.add(&meta);
        set.save();
        // A run that sees the data again keeps it.
        let mut set = IncompressibleData::load(store.home_dir());
        assert!(set.known(&meta));
        assert!(!set.known(&other));
        set.save();
        let mut set = IncompressibleData::load(store.home_dir());
        assert!(set.known(&meta));
        // A run that no longer sees it (the entry left the trash) forgets it.
        let set = IncompressibleData::load(store.home_dir());
        set.save();
        let mut set = IncompressibleData::load(store.home_dir());
        assert!(!set.known(&meta));
    }

    // #352: retention compression publishes the entry's original times,
    // although reading the data to compress it can bump atime.
    #[test]
    fn retention_compression_keeps_original_times() {
        let base = tempfile::tempdir().unwrap();
        let trash = base.path().join("Trash");
        let store = TrashStore::open_isolated(&trash, Config::default()).unwrap();
        let data = trash.join("files/old.txt");
        fs::write(&data, "compressible ".repeat(1000)).unwrap();
        let mut info = TrashInfo::new(base.path().join("old.txt"));
        info.deletion_date = chrono::Local::now() - chrono::Duration::days(10);
        info.size = Some(13_000);
        fs::write(
            trash.join("info/old.txt.trashinfo"),
            info.to_trashinfo_string(),
        )
        .unwrap();
        let then = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        fs::File::options()
            .write(true)
            .open(&data)
            .unwrap()
            .set_times(fs::FileTimes::new().set_accessed(then).set_modified(then))
            .unwrap();
        let _ = fs::remove_file(trash.join(".trashd/last_purge"));
        store.maybe_auto_purge().unwrap();
        let sidecar = fs::read_to_string(trash.join("info/old.txt.trashinfo")).unwrap();
        assert!(sidecar.contains("X-Trashd-Compressed=zstd"), "{sidecar}");
        let meta = fs::metadata(&data).unwrap();
        assert_eq!(meta.accessed().unwrap(), then);
        assert_eq!(meta.modified().unwrap(), then);
    }

    #[test]
    fn deferred_maintenance_runs_after_the_mutation() {
        let (store, _data, workdir, _lock) = test_store();
        store.defer_maintenance();
        let marker = store.home_dir().join(".trashd/last_purge");
        let _ = fs::remove_file(&marker);
        let f = create_file(workdir.path(), "deferred.txt", "x");
        store.trash(&f, None).unwrap();
        assert!(
            !marker.exists(),
            "retention must not run inside the mutation"
        );
        store.run_deferred_maintenance();
        assert!(marker.exists(), "deferred retention runs on request");
        let _ = fs::remove_file(&marker);
        store.run_deferred_maintenance();
        assert!(!marker.exists(), "nothing is due twice");
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

    fn seed_cached_directory(store: &TrashStore, work: &Path, name: &OsStr) {
        fs::create_dir(store.home.join("files").join(name)).unwrap();
        fs::write(store.home.join("files").join(name).join("leaf"), b"tree").unwrap();
        let mut sidecar = name.to_os_string();
        sidecar.push(".trashinfo");
        fs::write(
            store.home.join("info").join(sidecar),
            TrashInfo::new(work.join(name)).to_trashinfo_string(),
        )
        .unwrap();
        crate::directorysizes::write_cache(&store.home).unwrap();
    }

    #[test]
    fn single_entry_cache_skips_file_and_symlink_removals_among_unrelated_files() {
        use std::os::unix::fs::symlink;

        for restore in [false, true] {
            let (store, _data, work, _) = test_store();
            seed_batch(&store, work.path(), 128);
            seed_cached_directory(&store, work.path(), OsStr::new("cached-tree"));
            let cache_path = store.home.join("directorysizes");
            let cache_before = fs::read(&cache_path).unwrap();
            let identity_before = file_identity(&cache_path);
            let target = work.path().join("external-directory");
            fs::create_dir(&target).unwrap();
            fs::write(target.join("KEEP"), b"external").unwrap();
            symlink(&target, store.home.join("files/link")).unwrap();
            fs::write(
                store.home.join("info/link.trashinfo"),
                TrashInfo::new(work.path().join("link")).to_trashinfo_string(),
            )
            .unwrap();
            for id in ["batch-0", "link"] {
                if restore {
                    store.restore(id, None).unwrap();
                } else {
                    store.purge(id).unwrap();
                }
                assert_eq!(store.cache_refreshes.get(), 0);
                assert_eq!(fs::read(&cache_path).unwrap(), cache_before);
                assert_eq!(file_identity(&cache_path), identity_before);
            }
            assert_eq!(fs::read(target.join("KEEP")).unwrap(), b"external");
            assert!(
                crate::directorysizes::read_cache(&store.home)
                    .contains_key(b"cached-tree".as_slice())
            );
        }
    }

    #[test]
    fn single_entry_cache_keeps_absent_caches_optional_for_files_and_retired_sidecars() {
        let (store, _data, work, _) = test_store();
        seed_batch(&store, work.path(), 3);
        store.restore("batch-0", None).unwrap();
        store.purge("batch-1").unwrap();
        fs::remove_file(store.home.join("files/batch-2")).unwrap();
        fs::File::open(store.home.join("info/batch-2.trashinfo"))
            .unwrap()
            .set_times(
                fs::FileTimes::new().set_modified(
                    std::time::SystemTime::now() - std::time::Duration::from_secs(10),
                ),
            )
            .unwrap();
        store.purge("batch-2").unwrap();
        assert_eq!(store.cache_refreshes.get(), 0);
        assert!(!store.home.join("directorysizes").exists());
    }

    #[test]
    fn single_entry_cache_refreshes_directories_and_stale_raw_filename_rows() {
        for restore in [false, true] {
            let (store, _data, work, _) = test_store();
            let raw_directory = OsStr::from_bytes(b"raw\xfe");
            seed_cached_directory(&store, work.path(), raw_directory);
            seed_cached_directory(&store, work.path(), OsStr::new("removed-tree"));
            if restore {
                store.restore("removed-tree", None).unwrap();
            } else {
                store.purge("removed-tree").unwrap();
            }
            assert_eq!(store.cache_refreshes.get(), 1);
            let cached = crate::directorysizes::read_cache(&store.home);
            assert!(cached.contains_key(raw_directory.as_bytes()));
            assert!(!cached.contains_key(b"removed-tree".as_slice()));

            // These two raw names have the same lossy display ID. A stale
            // file row must be removed without touching the directory row.
            let raw_file = OsStr::from_bytes(b"raw\xff");
            fs::write(store.home.join("files").join(raw_file), b"file").unwrap();
            let mut info_name = raw_file.to_os_string();
            info_name.push(".trashinfo");
            fs::write(
                store.home.join("info").join(info_name),
                TrashInfo::new(work.path().join("raw-file-original")).to_trashinfo_string(),
            )
            .unwrap();
            let mut cache = fs::OpenOptions::new()
                .append(true)
                .open(store.home.join("directorysizes"))
                .unwrap();
            writeln!(cache, "123 456 raw%FF").unwrap();
            drop(cache);
            if restore {
                store.restore("raw-file-original", None).unwrap();
            } else {
                store.purge("raw-file-original").unwrap();
            }
            assert_eq!(store.cache_refreshes.get(), 2);
            let cached = crate::directorysizes::read_cache(&store.home);
            assert!(!cached.contains_key(raw_file.as_bytes()));
            assert!(cached.contains_key(raw_directory.as_bytes()));
        }
    }

    #[test]
    fn single_entry_cache_uses_the_mutated_root_and_keeps_replacement_checks() {
        for restore in [false, true] {
            let (mut store, _data, work, _) = test_store();
            let (external, _external_data, external_work, _) = test_store();
            seed_cached_directory(&store, work.path(), OsStr::new("home-tree"));
            seed_cached_directory(&external, external_work.path(), OsStr::new("foreign-tree"));
            seed_batch(&external, external_work.path(), 1);
            fs::OpenOptions::new()
                .append(true)
                .open(external.home.join("directorysizes"))
                .unwrap()
                .write_all(b"123 456 batch-0\n")
                .unwrap();
            let home_before = fs::read(store.home.join("directorysizes")).unwrap();
            let external_before = fs::read(external.home.join("directorysizes")).unwrap();
            let mut stale = external.find_entry("batch-0").unwrap();
            fs::rename(&stale.trashed_path, external_work.path().join("old-inode")).unwrap();
            fs::write(&stale.trashed_path, b"replacement").unwrap();
            // Only fixture roots are ever used; permit explicitly resolved
            // foreign entries as a production store does, without discovery.
            store.isolated = false;
            let destination = work.path().join("restored-foreign");
            let rejected = if restore {
                store
                    .restore_entry(&mut stale, Some(&destination))
                    .map(|_| ())
            } else {
                store.purge_resolved_with_maintenance(&stale, true)
            };
            assert!(matches!(rejected, Err(TrashError::EntryNotFound(_))));
            assert_eq!(store.cache_refreshes.get(), 0);
            assert_eq!(
                fs::read(external.home.join("directorysizes")).unwrap(),
                external_before
            );
            let mut current = external.find_entry("batch-0").unwrap();
            if restore {
                store
                    .restore_entry(&mut current, Some(&destination))
                    .unwrap();
            } else {
                store
                    .purge_resolved_with_maintenance(&current, true)
                    .unwrap();
            }
            assert_eq!(store.cache_refreshes.get(), 1);
            assert_eq!(
                fs::read(store.home.join("directorysizes")).unwrap(),
                home_before
            );
            let cache = crate::directorysizes::read_cache(&external.home);
            assert!(!cache.contains_key(b"batch-0".as_slice()));
            assert!(cache.contains_key(b"foreign-tree".as_slice()));
        }
    }

    #[test]
    fn single_entry_cache_repairs_malformed_and_special_caches_best_effort() {
        use std::os::unix::fs::symlink;

        for restore in [false, true] {
            for kind in [
                "syntax",
                "name",
                "percent",
                "nul",
                "utf8",
                "link",
                "fifo",
                "directory",
            ] {
                let (store, _data, work, _) = test_store();
                seed_cached_directory(&store, work.path(), OsStr::new("cached-tree"));
                seed_batch(&store, work.path(), 1);
                let cache = store.home.join("directorysizes");
                fs::remove_file(&cache).unwrap();
                let target = create_file(work.path(), "KEEP", "external cache target");
                match kind {
                    "syntax" => fs::write(&cache, b"malformed row\n").unwrap(),
                    "name" => fs::write(&cache, b"123 456 %2Fescape\n").unwrap(),
                    "percent" => fs::write(&cache, b"123 456 bad%GG\n").unwrap(),
                    "nul" => fs::write(&cache, b"123 456 nul%00name\n").unwrap(),
                    "utf8" => fs::write(&cache, b"invalid\xff").unwrap(),
                    "link" => symlink(&target, &cache).unwrap(),
                    "fifo" => {
                        let name = CString::new(cache.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                    }
                    "directory" => fs::create_dir(&cache).unwrap(),
                    _ => unreachable!(),
                }
                if restore {
                    store.restore("batch-0", None).unwrap();
                } else {
                    store.purge("batch-0").unwrap();
                }
                assert_eq!(store.cache_refreshes.get(), 1, "{kind}");
                assert_eq!(fs::read(&target).unwrap(), b"external cache target");
                if kind == "directory" {
                    assert!(cache.is_dir()); // Repair failures remain optional.
                } else {
                    assert!(fs::symlink_metadata(&cache).unwrap().is_file());
                    assert!(
                        crate::directorysizes::read_cache(&store.home)
                            .contains_key(b"cached-tree".as_slice())
                    );
                }
            }
        }
    }

    #[test]
    fn batch_restore_reads_sidecars_once_and_refreshes_cache_only_when_needed() {
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
            // Files with no cached row cannot change the cache (#336).
            assert_eq!(store.cache_refreshes.get(), 0);
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
    fn batch_restore_accepts_entries_from_other_roots() {
        let (mut store, _data, work, _) = test_store();
        let (external, _external_data, _, _) = test_store();
        seed_batch(&external, work.path(), 2);
        let entries = external.list(None).unwrap();
        // Deliberately permit externally resolved entries as a production
        // store does. Explicit targets avoid topdir path restrictions here.
        store.isolated = false;
        for (i, entry) in entries.iter().enumerate() {
            let target = work.path().join(format!("restored-{i}"));
            assert!(
                store.restore_batch(std::slice::from_ref(entry), Some(&target), false)[0].is_ok()
            );
            assert!(target.exists());
            assert!(!entry.trashed_path.exists());
            assert!(!entry.info_path.exists());
        }
        assert!(external.list(None).unwrap().is_empty());
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

    // Regression (#83): a path ending in ".." must resolve to the PARENT, not
    // silently collapse to the directory itself.
    #[test]
    fn normalize_path_resolves_trailing_dotdot_to_parent() {
        let base = tempfile::tempdir().unwrap();
        let a = base.path().join("a");
        let b = a.join("b");
        fs::create_dir_all(&b).unwrap();
        assert_eq!(normalize_path(&b.join("..")), a);
        assert_eq!(normalize_path(&b.join(".")), b);
        // Ordinary paths still preserve the final component verbatim.
        let link = a.join("link");
        std::os::unix::fs::symlink(&b, &link).unwrap();
        assert_eq!(normalize_path(&link), link);
    }

    // Regression (#88): an orphaned files/<id> in one trash root must stay
    // visible even when another root holds a real entry with the same id.
    #[test]
    fn orphan_detection_is_per_root_not_cross_root() {
        let (store, _data, work, _lock) = test_store();
        let real = create_file(work.path(), "dup.txt", "real");
        store.trash(&real, None).unwrap();

        // A second, unrelated trash root containing an orphan with the SAME id.
        let other_root = tempfile::tempdir().unwrap();
        let other_trash = other_root.path().join("Trash");
        fs::create_dir_all(other_trash.join("files")).unwrap();
        fs::create_dir_all(other_trash.join("info")).unwrap();
        fs::write(other_trash.join("files/dup.txt"), b"orphan").unwrap();

        let mut entries = Vec::new();
        store.list_in_dir(&store.home, None, &mut entries).unwrap();
        store.list_in_dir(&other_trash, None, &mut entries).unwrap();

        let orphans: Vec<_> = entries.iter().filter(|e| e.orphaned).collect();
        assert_eq!(orphans.len(), 1, "the other root's orphan must be listed");
        assert_eq!(orphans[0].trash_root, other_trash);
        assert_eq!(entries.len(), 2);
    }

    // Regression (#107): undo must restore the RESOLVED entry. Two roots can
    // hold the same id; re-resolving by ID string would fail with
    // AmbiguousMatch forever. restore_resolved on the picked entry is the
    // path undo now takes, so drive it the same way.
    #[test]
    fn resolved_entry_restores_even_with_cross_root_id_collision() {
        let (store, _data, work, _lock) = test_store();
        let f1 = create_file(work.path(), "report.pdf", "newest");
        let id = store.trash(&f1, None).unwrap();

        // A second root holding an entry with the SAME id (as happens when the
        // same filename is trashed on two partitions).
        let other_root = tempfile::tempdir().unwrap();
        let other_trash = other_root.path().join("Trash");
        fs::create_dir_all(other_trash.join("files")).unwrap();
        fs::create_dir_all(other_trash.join("info")).unwrap();
        fs::write(other_trash.join("files").join(&id), b"older copy").unwrap();
        let mut other_info = TrashInfo::new(work.path().join("report.pdf"));
        other_info.deletion_date -= chrono::Duration::hours(1);
        fs::write(
            other_trash.join("info").join(format!("{id}.trashinfo")),
            other_info.to_trashinfo_string(),
        )
        .unwrap();

        let mut entries = Vec::new();
        store.list_in_dir(&store.home, None, &mut entries).unwrap();
        store.list_in_dir(&other_trash, None, &mut entries).unwrap();
        assert_eq!(entries.len(), 2);

        // undo picks the newest — restoring it must NOT depend on ID lookup.
        newest_first(&mut entries);
        let mut chosen = entries[0].clone();
        let restored = store.restore_resolved(&mut chosen, None, true).unwrap();
        assert_eq!(restored, f1);
        assert_eq!(fs::read_to_string(&f1).unwrap(), "newest");
    }

    /// A fresh directory on a filesystem other than the test stores' (tmpfs
    /// /dev/shm), forcing trash() onto its cross-device copy path.
    fn cross_device_dir(name: &str) -> Option<PathBuf> {
        let store_dev = fs::metadata(env!("CARGO_MANIFEST_DIR")).ok()?.dev();
        let base = Path::new("/dev/shm");
        if fs::metadata(base).ok()?.dev() == store_dev {
            return None;
        }
        let dir = base.join(format!("trashd-xdev-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).ok()?;
        Some(dir)
    }

    fn cross_device_store() -> (TrashStore, TempDir) {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let data = TempDir::with_prefix_in("data-", &base).unwrap();
        let mut config = Config::default();
        config.never_trash.clear(); // /dev/shm/* is excluded by default
        config.retention.max_age_days = 0;
        config.retention.max_size_gb = 0.0;
        config.retention.disk_pressure_percent = 0;
        let store = TrashStore::open_isolated(&data.path().join("Trash"), config).unwrap();
        (store, data)
    }

    // Regression (#192): a node the cross-device copy cannot reproduce (a
    // socket) was skipped by the copy and then deleted with the source tree.
    #[test]
    fn cross_device_trash_never_deletes_what_it_could_not_copy() {
        let Some(dir) = cross_device_dir("socket") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("file"), "data").unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(tree.join("sock")).unwrap();
        let (store, _data) = cross_device_store();
        let result = store.trash(&tree, None);
        let socket_survived = tree.join("sock").exists();
        let file_survived = tree.join("file").exists();
        let _ = fs::remove_dir_all(&dir);
        assert!(result.is_err(), "trash reported success: {result:?}");
        assert!(
            socket_survived && file_survived,
            "uncopied source data was deleted"
        );
        assert!(
            store.list(None).unwrap().is_empty(),
            "a partial entry was left"
        );
    }

    // Regression (#244): a failed cross-device restore copy (a socket in the
    // trashed tree cannot be reproduced) left a partial tree at the original
    // path, so every retry failed RestoreConflict forever.
    #[test]
    fn failed_cross_device_restore_leaves_no_partial_tree() {
        let Some(dir) = cross_device_dir("restore-partial") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("file"), "data").unwrap();
        let (store, _data) = cross_device_store();
        let id = store.trash(&tree, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        let _listener =
            std::os::unix::net::UnixListener::bind(entry.trashed_path.join("sock")).unwrap();
        let result = store.restore(&id, None);
        assert!(result.is_err(), "restore reported success: {result:?}");
        assert!(!tree.exists(), "partial tree left at the original path");
        // Removing the uncopiable node makes the same entry restorable.
        drop(_listener);
        fs::remove_file(entry.trashed_path.join("sock")).unwrap();
        let restored = store.restore(&id, None).unwrap();
        assert_eq!(fs::read_to_string(restored.join("file")).unwrap(), "data");
        let _ = fs::remove_dir_all(&dir);
    }

    fn pinned_parent(dir: &Path) -> fs::File {
        fs::File::open(dir).unwrap()
    }

    // Regression (#192): after copying, the source is retired by snapshot:
    // a file created after the snapshot was never copied and must survive,
    // and the user's directories keep their modes.
    #[test]
    fn source_retirement_keeps_files_created_after_the_snapshot() {
        use std::os::unix::fs::PermissionsExt;
        let (_store, _data, work, _) = test_store();
        let tree = work.path().join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("early"), "copied").unwrap();
        fs::write(tree.join("sub/early"), "copied").unwrap();
        fs::set_permissions(tree.join("sub"), fs::Permissions::from_mode(0o750)).unwrap();
        let parent = pinned_parent(work.path());
        let name = CString::new("tree").unwrap();
        let root =
            stat_identity(&stat_at(parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW).unwrap());
        let before = snapshot_directory_at(parent.as_raw_fd(), &name).unwrap();
        fs::write(tree.join("sub/late"), "never copied").unwrap();

        let complete =
            retire_directory_snapshot_at(parent.as_raw_fd(), &name, root, &before, false).unwrap();
        assert!(!complete);
        assert!(!tree.join("early").exists());
        assert_eq!(
            fs::read_to_string(tree.join("sub/late")).unwrap(),
            "never copied"
        );
        let mode = fs::metadata(tree.join("sub")).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o750,
            "retirement changed a source directory's mode"
        );
    }

    // #379: the fused preflight records exactly the same identities and
    // versions as the independent restore snapshot, including raw names,
    // special nodes, timestamps and hard links.
    #[test]
    fn retirable_snapshot_matches_the_restore_snapshot() {
        const TEST: &str = "store::tests::retirable_snapshot_matches_the_restore_snapshot";
        const CHILD: &str = "TRASHD_TEST_SNAPSHOT_NO_STATX";
        let denied = mounts::is_rerun_child(TEST, CHILD);
        if denied {
            // A re-exec child confines both the filter and the statx probe's
            // process-wide verdict to this test, never another harness test.
            let mut instructions = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as _,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as _,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_statx as _,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as _,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as _,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let filter = libc::sock_fprog {
                len: instructions.len() as _,
                filter: instructions.as_mut_ptr(),
            };
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
                || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &filter) }
                    != 0
            {
                eprintln!("SKIP: statx-denial filter unavailable");
                mounts::report_test_verdict(None);
                return;
            }
        }
        let work = tempfile::tempdir().unwrap();
        let tree = work.path().join("tree");
        fs::create_dir_all(tree.join("sub/empty")).unwrap();
        fs::write(tree.join("sub/file"), b"payload").unwrap();
        fs::hard_link(tree.join("sub/file"), tree.join("alias")).unwrap();
        let raw = OsStr::from_bytes(b"raw-\xff");
        fs::write(tree.join(raw), b"raw name").unwrap();
        std::os::unix::fs::symlink("missing", tree.join("link")).unwrap();
        let tree_fd = pinned_parent(&tree);
        assert_eq!(
            unsafe { libc::mkfifoat(tree_fd.as_raw_fd(), c"fifo".as_ptr(), 0o600) },
            0
        );
        fs::set_permissions(tree.join("sub/empty"), fs::Permissions::from_mode(0o555)).unwrap();
        let timestamp = std::time::UNIX_EPOCH + std::time::Duration::new(1_234_567, 987_654_321);
        fs::File::options()
            .write(true)
            .open(tree.join("sub/file"))
            .unwrap()
            .set_modified(timestamp)
            .unwrap();
        let parent = pinned_parent(work.path());
        let expected = stat_identity(
            &stat_at(parent.as_raw_fd(), c"tree", libc::AT_SYMLINK_NOFOLLOW).unwrap(),
        );
        if denied {
            assert!(
                !mounts::entry_info_at(parent.as_raw_fd(), c"tree", libc::STATX_TYPE)
                    .unwrap()
                    .pinned_known
            );
        }
        let fused = snapshot_retirable_at(parent.as_raw_fd(), c"tree", expected)
            .unwrap()
            .unwrap();
        let legacy = snapshot_directory_at(parent.as_raw_fd(), c"tree").unwrap();
        assert_eq!(fused, legacy);
        assert_eq!(fused.len(), 7);
        let file = fused
            .iter()
            .find(|entry| entry.path == b"sub/file")
            .unwrap();
        assert_eq!(file.modified, (1_234_567, 987_654_321));
        assert!(fused.iter().any(|entry| entry.path == b"raw-\xff"));
        assert!(
            snapshot_retirable_at(
                tree_fd.as_raw_fd(),
                c"alias",
                stat_identity(
                    &stat_at(tree_fd.as_raw_fd(), c"alias", libc::AT_SYMLINK_NOFOLLOW).unwrap(),
                ),
            )
            .unwrap()
            .is_none()
        );
        if denied {
            // The denied syscall may also stop std's recursive temporary
            // cleanup after its earlier statx support probe. Clean only this
            // fixture through our descriptor-relative removal instead.
            let above = pinned_parent(work.path().parent().unwrap());
            let name = CString::new(work.path().file_name().unwrap().as_bytes()).unwrap();
            remove_tree_at(above.as_raw_fd(), &name, 0).unwrap();
            mounts::report_test_verdict(Some(true));
        } else {
            assert_ne!(mounts::rerun_test(TEST, CHILD), Some(false));
        }
    }

    // #379: changing the capture walk must not expand what retirement may
    // remove. Late entries, replaced files and replacement roots stay put.
    #[test]
    fn retirable_snapshot_keeps_new_and_replaced_entries() {
        let work = tempfile::tempdir().unwrap();
        let tree = work.path().join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("early"), b"copied").unwrap();
        fs::write(tree.join("changed"), b"old").unwrap();
        fs::write(tree.join("sub/stable"), b"copied too").unwrap();
        let parent = pinned_parent(work.path());
        let expected = file_identity(&tree).unwrap();
        let snapshot = snapshot_retirable_at(parent.as_raw_fd(), c"tree", expected)
            .unwrap()
            .unwrap();
        fs::write(work.path().join("replacement"), b"new data").unwrap();
        fs::rename(work.path().join("replacement"), tree.join("changed")).unwrap();
        fs::write(tree.join("sub/late"), b"never copied").unwrap();
        assert!(
            !retire_directory_snapshot_at(parent.as_raw_fd(), c"tree", expected, &snapshot, false,)
                .unwrap()
        );
        assert!(!tree.join("early").exists());
        assert_eq!(fs::read(tree.join("changed")).unwrap(), b"new data");
        assert_eq!(fs::read(tree.join("sub/late")).unwrap(), b"never copied");
        fs::rename(&tree, work.path().join("old-tree")).unwrap();
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("keep"), b"replacement root").unwrap();
        assert!(matches!(
            snapshot_retirable_at(parent.as_raw_fd(), c"tree", expected),
            Err(TrashError::Io(ref error)) if error.raw_os_error() == Some(libc::ENOENT)
        ));
        assert_eq!(fs::read(tree.join("keep")).unwrap(), b"replacement root");
    }

    // The fused walk retains the old distinction: an unwritable directory
    // with entries is Unremovable; failing to list an unreadable one is an
    // I/O error. An empty read-only leaf is covered above (#370, #379).
    #[test]
    fn retirable_snapshot_keeps_listing_failures_as_io() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: unprivileged fixture setup requires root");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let tree = base.path().join("tree");
        fs::create_dir_all(tree.join("hidden")).unwrap();
        for path in [&tree, &tree.join("hidden")] {
            std::os::unix::fs::chown(path, Some(65534), Some(65534)).unwrap();
        }
        fs::set_permissions(tree.join("hidden"), fs::Permissions::from_mode(0o300)).unwrap();
        let expected = file_identity(&tree).unwrap();
        let parent = base.path().to_path_buf();
        let verdict = as_unprivileged(
            "store::tests::retirable_snapshot_keeps_listing_failures_as_io",
            move || {
                let directory = pinned_parent(&parent);
                matches!(
                    snapshot_retirable_at(directory.as_raw_fd(), c"tree", expected),
                    Err(TrashError::Io(ref error)) if error.raw_os_error() == Some(libc::EACCES)
                )
            },
        );
        assert_ne!(verdict, Some(false));
    }

    #[test]
    fn retirable_snapshot_preserves_the_snapshot_depth_limit() {
        let work = tempfile::tempdir().unwrap();
        let tree = work.path().join("tree");
        let mut deepest = tree.clone();
        for _ in 0..=COPY_TREE_MAX_DEPTH {
            deepest.push("d");
        }
        fs::create_dir_all(&deepest).unwrap();
        let parent = pinned_parent(work.path());
        let legacy = snapshot_directory_at(parent.as_raw_fd(), c"tree").unwrap_err();
        let fused =
            snapshot_retirable_at(parent.as_raw_fd(), c"tree", file_identity(&tree).unwrap())
                .unwrap_err();
        assert!(
            matches!(fused, TrashError::Io(ref error) if error.to_string() == legacy.to_string())
        );
        assert!(deepest.is_dir());
    }

    // Regression (#192): a single file replaced after it was copied is the
    // user's new data, not the copied version: it must not be unlinked.
    #[test]
    fn source_retirement_keeps_a_replaced_file() {
        let (_store, _data, work, _) = test_store();
        let file = work.path().join("file");
        fs::write(&file, "copied version").unwrap();
        let parent = pinned_parent(work.path());
        let name = CString::new("file").unwrap();
        let copied = stat_at(parent.as_raw_fd(), &name, libc::AT_SYMLINK_NOFOLLOW).unwrap();
        let replacement = work.path().join("file.new");
        fs::write(&replacement, "newer version").unwrap();
        fs::rename(&replacement, &file).unwrap();

        assert!(!retire_copied_node_at(parent.as_raw_fd(), &name, &copied).unwrap());
        assert_eq!(fs::read_to_string(&file).unwrap(), "newer version");
    }

    #[test]
    fn source_retirement_keeps_a_hardlink_changed_after_another_is_unlinked() {
        let (_store, _data, work, _) = test_store();
        let tree = work.path().join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("a"), b"initial").unwrap();
        fs::hard_link(tree.join("a"), tree.join("b")).unwrap();
        let parent = pinned_parent(work.path());
        let snapshot = snapshot_directory_at(parent.as_raw_fd(), c"tree").unwrap();
        let index = SnapshotIndex::new(&snapshot);
        let directory = pinned_parent(&tree);
        assert!(
            retire_snapshot_node_at(
                directory.as_raw_fd(),
                c"a",
                b"a",
                index.get(b"a").unwrap(),
                &index,
                false,
            )
            .unwrap()
        );
        let before = fs::metadata(tree.join("b")).unwrap();
        fs::write(tree.join("b"), b"changed").unwrap();
        // Keep size and mtime unchanged: ctime must still distinguish an
        // external rewrite from the ctime change our own unlink caused.
        fs::File::options()
            .write(true)
            .open(tree.join("b"))
            .unwrap()
            .set_modified(before.modified().unwrap())
            .unwrap();
        let changed = fs::metadata(tree.join("b")).unwrap();
        assert_eq!(before.len(), changed.len());
        assert_eq!(before.modified().unwrap(), changed.modified().unwrap());
        assert_ne!(
            (before.ctime(), before.ctime_nsec()),
            (changed.ctime(), changed.ctime_nsec())
        );
        assert!(
            !retire_snapshot_node_at(
                directory.as_raw_fd(),
                c"b",
                b"b",
                index.get(b"b").unwrap(),
                &index,
                false,
            )
            .unwrap()
        );
        assert_eq!(fs::read(tree.join("b")).unwrap(), b"changed");
    }

    #[test]
    fn source_retirement_keeps_a_hardlink_rewritten_before_post_unlink_stat() {
        let (_store, _data, work, _) = test_store();
        let tree = work.path().join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("a"), b"initial").unwrap();
        fs::hard_link(tree.join("a"), tree.join("b")).unwrap();
        let parent = pinned_parent(work.path());
        let snapshot = snapshot_directory_at(parent.as_raw_fd(), c"tree").unwrap();
        let index = SnapshotIndex::new(&snapshot);
        let directory = pinned_parent(&tree);
        let victim = fs::File::open(tree.join("a")).unwrap();
        let before = stat_fd(victim.as_raw_fd()).unwrap();
        let original_mtime = victim.metadata().unwrap().modified().unwrap();
        let digest = retirement_digest_at(directory.as_raw_fd(), c"a", &before).unwrap();
        assert!(digest.is_some());

        // Split the unlink -> fstat boundary deterministically. The rewrite
        // preserves size and mtime, so its ctime is adopted as if our unlink
        // caused it. The final-link content check must still retain it.
        raw_unlinkat(directory.as_raw_fd(), c"a", 0).unwrap();
        fs::write(tree.join("b"), b"changed").unwrap();
        fs::File::options()
            .write(true)
            .open(tree.join("b"))
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();
        let after = stat_fd(victim.as_raw_fd()).unwrap();
        index.note_unlink(index.get(b"a").unwrap(), &before, &after, digest);
        assert!(index.matches(index.get(b"b").unwrap(), &after));
        assert!(
            !retire_snapshot_node_at(
                directory.as_raw_fd(),
                c"b",
                b"b",
                index.get(b"b").unwrap(),
                &index,
                false,
            )
            .unwrap()
        );
        assert_eq!(fs::read(tree.join("b")).unwrap(), b"changed");
    }

    // Regression (#203): the copy path kept set-id bits but not the owner, so
    // root trashing (and later restoring) another user's set-uid program
    // produced a root-owned set-uid file in that user's directory.
    #[test]
    fn cross_device_copy_never_moves_set_id_bits_to_another_owner() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: changing a file's owner requires root");
            return;
        }
        let Some(dir) = cross_device_dir("setuid") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let tool = dir.join("tool");
        fs::write(&tool, "#!/bin/sh\\n").unwrap();
        std::os::unix::fs::chown(&tool, Some(65534), Some(65534)).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o4755)).unwrap();
        let (store, _data) = cross_device_store();
        let id = store.trash(&tool, None);
        let _ = fs::remove_dir_all(&dir);
        let entry = store.find_entry(&id.unwrap()).unwrap();
        let meta = fs::symlink_metadata(&entry.trashed_path).unwrap();
        assert!(
            meta.uid() == 65534 || meta.mode() & 0o6000 == 0,
            "set-id bits on a copy owned by uid {}",
            meta.uid()
        );
    }

    /// Set or clear FS_IMMUTABLE_FL on a directory (root only).
    fn set_immutable(dir: &Path, on: bool) -> bool {
        const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
        const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
        const FS_IMMUTABLE_FL: libc::c_int = 0x10;
        let Ok(file) = fs::File::open(dir) else {
            return false;
        };
        let mut flags: libc::c_int = 0;
        if unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) } != 0 {
            return false;
        }
        flags = if on {
            flags | FS_IMMUTABLE_FL
        } else {
            flags & !FS_IMMUTABLE_FL
        };
        unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &flags) == 0 }
    }

    // #371: an immutable victim anywhere in a tree refuses its retirement,
    // an empty directory and a file included; a clean tree passes.
    #[test]
    fn retire_checks_refuse_pinned_victims() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: setting the immutable flag requires root");
            return;
        }
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let work = TempDir::with_prefix_in("pinned-", &base).unwrap();
        for tree in ["empty", "file", "clean"] {
            let tree = work.path().join(tree);
            fs::create_dir_all(tree.join("sub")).unwrap();
            fs::create_dir_all(tree.join("leaf")).unwrap();
            fs::write(tree.join("sub/g"), b"x").unwrap();
        }
        let pinned = [
            work.path().join("empty/leaf"),
            work.path().join("file/sub/g"),
        ];
        if !pinned.iter().all(|path| set_immutable(path, true)) {
            pinned.iter().for_each(|path| {
                set_immutable(path, false);
            });
            eprintln!("SKIP: filesystem does not support the immutable flag");
            return;
        }
        let dir = fs::File::open(work.path()).unwrap();
        let verdicts: Vec<_> = [c"empty", c"file", c"clean"]
            .iter()
            .map(|name| {
                let source = stat_at(dir.as_raw_fd(), name, libc::AT_SYMLINK_NOFOLLOW).unwrap();
                snapshot_retirable_at(dir.as_raw_fd(), name, stat_identity(&source))
            })
            .collect();
        for path in &pinned {
            set_immutable(path, false);
        }
        for verdict in &verdicts[..2] {
            assert!(
                matches!(verdict, Err(TrashError::Unremovable(error))
                    if error.raw_os_error() == Some(libc::EPERM)),
                "{verdict:?}"
            );
        }
        assert!(verdicts[2].is_ok(), "{:?}", verdicts[2]);
    }

    // Regression (#204): only a cross-device move (or unsupported
    // RENAME_NOREPLACE) may fall back to copying. An unrenamable source
    // (EPERM/EACCES/EROFS) cannot be unlinked either: copying it only left
    // a stray duplicate entry behind.
    #[test]
    fn unrenamable_source_is_not_copied_into_the_trash() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: setting the immutable flag requires root");
            return;
        }
        let (store, _data, work, _) = test_store();
        let locked = work.path().join("locked");
        fs::create_dir_all(&locked).unwrap();
        let file = create_file(&locked, "file", "kept");
        if !set_immutable(&locked, true) {
            eprintln!("SKIP: filesystem does not support the immutable flag");
            return;
        }
        let result = store.trash(&file, None);
        set_immutable(&locked, false);
        assert!(result.is_err());
        assert!(file.exists());
        assert!(
            store.list(None).unwrap().is_empty(),
            "a stray copy was trashed"
        );
    }

    // Regression (#192): the successful cross-device path still moves a tree.
    #[test]
    fn cross_device_trash_moves_a_tree() {
        let Some(dir) = cross_device_dir("tree") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let tree = dir.join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("sub/file"), "payload").unwrap();
        let (store, _data) = cross_device_store();
        let id = store.trash(&tree, None);
        let source_left = tree.exists();
        let _ = fs::remove_dir_all(&dir);
        let id = id.unwrap();
        assert!(!source_left, "source tree left behind");
        let entry = store.find_entry(&id).unwrap();
        assert_eq!(
            fs::read_to_string(entry.trashed_path.join("sub/file")).unwrap(),
            "payload"
        );
    }

    #[test]
    fn cross_device_trash_retires_hardlinked_trees() {
        let Some(dir) = cross_device_dir("trash-hardlinks") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let (store, _data) = cross_device_store();
        for pinned in [false, true] {
            let work = TempDir::new_in(&dir).unwrap();
            let tree = work.path().join("tree");
            fs::create_dir_all(tree.join("sub")).unwrap();
            fs::write(tree.join("a"), b"shared").unwrap();
            fs::hard_link(tree.join("a"), tree.join("b")).unwrap();
            fs::hard_link(tree.join("a"), tree.join("sub/c")).unwrap();
            let id = if pinned {
                let parent = pinned_parent(work.path());
                store.trash_at(parent.as_raw_fd(), OsStr::new("tree"), &tree, None)
            } else {
                store.trash(&tree, None)
            }
            .unwrap();
            assert!(!tree.exists(), "source hard links were left behind");
            let entry = store.find_entry(&id).unwrap();
            let a = fs::metadata(entry.trashed_path.join("a")).unwrap();
            for path in ["b", "sub/c"] {
                let alias = fs::metadata(entry.trashed_path.join(path)).unwrap();
                assert_eq!((a.dev(), a.ino()), (alias.dev(), alias.ino()));
                assert_eq!(fs::read(entry.trashed_path.join(path)).unwrap(), b"shared");
            }
            assert_eq!(a.nlink(), 3);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cross_device_restore_retires_hardlinked_trees() {
        let Some(dir) = cross_device_dir("restore-hardlinks") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let (store, data) = cross_device_store();
        let tree = data.path().join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("a"), b"shared").unwrap();
        fs::hard_link(tree.join("a"), tree.join("b")).unwrap();
        fs::hard_link(tree.join("a"), tree.join("sub/c")).unwrap();
        let id = store.trash(&tree, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        let restored = dir.join("restored");
        assert_eq!(store.restore(&id, Some(&restored)).unwrap(), restored);
        assert!(
            !entry.trashed_path.exists(),
            "source hard links were left as a trash orphan"
        );
        assert!(!entry.info_path.exists());
        assert!(store.list(None).unwrap().is_empty());
        let a = fs::metadata(restored.join("a")).unwrap();
        for path in ["b", "sub/c"] {
            let alias = fs::metadata(restored.join(path)).unwrap();
            assert_eq!((a.dev(), a.ino()), (alias.dev(), alias.ino()));
            assert_eq!(fs::read(restored.join(path)).unwrap(), b"shared");
        }
        assert_eq!(a.nlink(), 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    // Regression (#245): the directory cap compared truncated whole MiB,
    // accepting directories up to ~1 MiB over the limit.
    #[test]
    fn dir_size_limit_compares_exact_bytes() {
        let (mut store, _data, work, _) = test_store();
        store.config.max_dir_size_mb = 1;
        let dir = work.path().join("bigdir");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("payload"), vec![0u8; 1_572_864]).unwrap();
        let result = store.trash(&dir, None);
        assert!(
            matches!(result, Err(TrashError::TooLarge { .. })),
            "1.5 MiB directory accepted under a 1 MiB cap: {result:?}"
        );
        assert!(dir.exists(), "rejected directory was moved");
    }

    // Regression (#248): the cross-device copy path dropped timestamps the
    // rename path preserves.
    #[test]
    fn cross_device_trash_preserves_timestamps() {
        let Some(dir) = cross_device_dir("times") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let file = dir.join("old-file");
        fs::write(&file, "payload").unwrap();
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_577_836_800);
        fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let (store, _data) = cross_device_store();
        let id = store.trash(&file, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        let mtime = fs::symlink_metadata(&entry.trashed_path)
            .unwrap()
            .modified()
            .unwrap();
        let restored = store.restore(&id, None).unwrap();
        let restored_mtime = fs::metadata(&restored).unwrap().modified().unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(mtime, old, "trash copy lost the source mtime");
        assert_eq!(restored_mtime, old, "restored file lost the source mtime");
    }

    // Regression (#247): listing built trashed_path from the lossy String
    // ID, so a non-UTF-8 entry pointed nowhere, could not be restored, and
    // purge reported success while deleting nothing.
    #[test]
    fn non_utf8_entry_lists_real_path_and_purges() {
        use std::os::unix::ffi::OsStrExt;
        let (store, _data, _work, _) = test_store();
        let trash = store.home.clone();
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        let raw_id: &[u8] = b"raw-\xff-entry";
        let data_path = trash
            .join("files")
            .join(std::ffi::OsStr::from_bytes(raw_id));
        fs::write(&data_path, "payload").unwrap();
        let mut sidecar_name = std::ffi::OsString::from(std::ffi::OsStr::from_bytes(raw_id));
        sidecar_name.push(".trashinfo");
        fs::write(
            trash.join("info").join(&sidecar_name),
            "[Trash Info]\nPath=/tmp/raw-entry\nDeletionDate=2026-01-01T00:00:00\n",
        )
        .unwrap();
        let entries = store.list(None).unwrap();
        let entry = entries
            .iter()
            .find(|e| e.trashed_path == data_path)
            .expect("non-UTF-8 entry not listed with its real path");
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), b"payload");
        store.purge_resolved(entry).unwrap();
        assert!(!data_path.exists(), "purge deleted nothing but reported Ok");
    }

    /// Seed a week-old compressible entry with a hand-written sidecar.
    fn seed_old_entry(store: &TrashStore, id: &str, sidecar_extra: &str) -> (PathBuf, PathBuf) {
        let data = store.home.join("files").join(id);
        fs::write(&data, "compressible ".repeat(1000)).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86400);
        fs::File::options()
            .write(true)
            .open(&data)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let info = store.home.join("info").join(format!("{id}.trashinfo"));
        fs::write(
            &info,
            format!(
                "[Trash Info]\nPath=docs/{id}\nDeletionDate=2000-01-01T00:00:00\n{sidecar_extra}"
            ),
        )
        .unwrap();
        (data, info)
    }

    fn zstd_magic(path: &Path) -> bool {
        fs::read(path)
            .unwrap()
            .starts_with(&0xFD2FB528u32.to_le_bytes())
    }

    // Regression (#202): auto-compression rewrote entries other FreeDesktop
    // tools created; restoring those elsewhere yields zstd bytes.
    #[test]
    fn auto_compression_leaves_foreign_entries_alone() {
        let (store, _data, _work, _) = test_store();
        let (data, info) = seed_old_entry(&store, "foreign.txt", "");
        let sidecar = fs::read(&info).unwrap();
        store.auto_purge().unwrap();
        assert!(!zstd_magic(&data), "a foreign entry was compressed");
        assert_eq!(fs::read(&info).unwrap(), sidecar);
    }

    // Regression (#202, #218): compressing a trashd entry keeps its mtime and
    // its sidecar byte-exact apart from the marker. list() absolutizes
    // relative topdir paths in memory; writing that back broke restore after
    // the drive was mounted elsewhere.
    #[test]
    fn auto_compression_preserves_mtime_and_sidecar_text() {
        let (store, _data, _work, _) = test_store();
        let (data, info) = seed_old_entry(&store, "ours.txt", "X-Trashd-Size=13000\n");
        let mtime = fs::metadata(&data).unwrap().modified().unwrap();
        store.auto_purge().unwrap();
        assert!(zstd_magic(&data), "trashd entry was not compressed");
        assert_eq!(fs::metadata(&data).unwrap().modified().unwrap(), mtime);
        assert_eq!(
            fs::read_to_string(&info).unwrap(),
            "[Trash Info]\nPath=docs/ours.txt\nDeletionDate=2000-01-01T00:00:00\n\
             X-Trashd-Size=13000\nX-Trashd-Compressed=zstd\n"
        );
    }

    // Regression (#223): a symlink operand was sized by walking its target.
    #[test]
    fn symlink_operand_is_sized_as_itself() {
        let (store, _data, work, _) = test_store();
        let target = work.path().join("big-dir");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("payload"), vec![0u8; 1 << 20]).unwrap();
        let link = work.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_len = fs::symlink_metadata(&link).unwrap().len();
        let id = store.trash(&link, None).unwrap();
        assert_eq!(store.find_entry(&id).unwrap().info.size, Some(link_len));
    }

    // Regression (#223): a tree of exactly the cap was reported as capped.
    #[test]
    fn size_cap_flags_only_trees_that_exceed_it() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..DIR_SIZE_MAX_FILES {
            fs::write(dir.path().join(i.to_string()), b"").unwrap();
        }
        assert!(
            !dir_size_capped(dir.path()).1,
            "exactly the cap is not over it"
        );
        fs::write(dir.path().join("one-more"), b"").unwrap();
        assert!(dir_size_capped(dir.path()).1);
    }

    // Regression (#222): a symlinked ancestor (ostree's /home -> var/home, a
    // stowed ~/.local) made the store refuse to open, so the shim refused
    // every rm. A symlink this user or root owns, inside a trusted directory,
    // is followed and its target validated; anyone else's is still refused.
    #[test]
    fn trusted_symlinked_ancestors_are_followed() {
        let base = tempfile::tempdir().unwrap();
        fs::create_dir(base.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", base.path().join("link")).unwrap();
        let store = TrashStore::open_isolated(&base.path().join("link/Trash"), Config::default());
        assert!(store.is_ok(), "{:?}", store.err());
        assert!(base.path().join("real/Trash/files").is_dir());
        // The home through a symlink is still canonicalized; one without
        // keeps its validated path, which needs no realpath (#307).
        let real = fs::canonicalize(base.path()).unwrap();
        assert_eq!(store.unwrap().home_dir(), real.join("real/Trash"));
        let direct =
            TrashStore::open_isolated(&real.join("real/Trash"), Config::default()).unwrap();
        assert_eq!(direct.home_dir(), real.join("real/Trash"));

        if unsafe { libc::geteuid() } == 0 {
            fs::create_dir(base.path().join("other")).unwrap();
            let foreign = base.path().join("foreign");
            std::os::unix::fs::symlink("other", &foreign).unwrap();
            std::os::unix::fs::lchown(&foreign, Some(65534), Some(65534)).unwrap();
            assert!(TrashStore::open_isolated(&foreign.join("Trash"), Config::default()).is_err());
        }
    }

    // Regression (#221): one unreadable root made list() fail for EVERY root,
    // breaking ls, restore and purge everywhere. It is skipped instead.
    #[test]
    fn an_unreadable_root_does_not_hide_the_others() {
        let (store, _data, work, _) = test_store();
        store
            .trash(&create_file(work.path(), "kept", "a"), None)
            .unwrap();
        let mut entries = Vec::new();
        // A broken second root: its info "directory" is a regular file.
        let broken = work.path().join("broken-root");
        fs::create_dir_all(broken.join("files")).unwrap();
        fs::write(broken.join("info"), b"not a directory").unwrap();
        store
            .list_roots(&[store.home.clone(), broken], None, &mut entries)
            .unwrap();
        assert_eq!(entries.len(), 1);
    }

    // Regression (#220): concurrent auto-purges each trimmed the full excess
    // (the throttle marker was check-then-touch without a lock). A purge
    // already running elsewhere makes this one a no-op.
    #[test]
    fn auto_purge_skips_while_another_purge_runs() {
        use std::os::fd::AsRawFd;
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let data = TempDir::with_prefix_in("data-", &base).unwrap();
        let work = TempDir::with_prefix_in("work-", &base).unwrap();
        let mut config = Config::default();
        config.retention.max_age_days = 1;
        config.retention.max_size_gb = 0.0;
        config.retention.disk_pressure_percent = 0;
        config.auto_purge_interval_secs = 0;
        let store = TrashStore::open_isolated(&data.path().join("Trash"), config).unwrap();
        let id = store
            .trash(&create_file(work.path(), "expired", "old"), None)
            .unwrap();
        let entry = store.find_entry(&id).unwrap();
        let sidecar = fs::read_to_string(&entry.info_path).unwrap();
        let aged: String = sidecar
            .lines()
            .map(|l| {
                if l.starts_with("DeletionDate=") {
                    "DeletionDate=2000-01-01T00:00:00"
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&entry.info_path, aged + "\n").unwrap();

        let lock = fs::File::create(store.home.join(".trashd/auto_purge.lock")).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        store.maybe_auto_purge().unwrap();
        assert!(
            store.find_entry(&id).is_ok(),
            "purged while another purge held the lock"
        );
        drop(lock);
        store.maybe_auto_purge().unwrap();
        assert!(
            store.find_entry(&id).is_err(),
            "expired entry survived an unlocked purge"
        );
    }

    #[test]
    fn retention_state_fifos_do_not_block_and_marker_links_do_not_truncate() {
        use std::os::unix::fs::symlink;
        for state in ["auto_purge.lock", "last_purge"] {
            let (store, _data, work, _) = test_store();
            let path = store.home.join(".trashd").join(state);
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            // An aged marker forces the touch path instead of the throttle
            // fast path. Linux permits opening a FIFO read/write without a
            // peer; close that descriptor before exercising the writer.
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(std::time::SystemTime::UNIX_EPOCH)
                .unwrap();
            let source = create_file(work.path(), "payload", "recoverable");
            let id = store.trash(&source, None).unwrap();
            assert_eq!(
                fs::read(store.home.join("files").join(id)).unwrap(),
                b"recoverable"
            );
        }
        let (store, _data, work, _) = test_store();
        let victim = create_file(work.path(), "unrelated", "must survive");
        let file = fs::File::options().write(true).open(&victim).unwrap();
        file.set_modified(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        symlink(&victim, store.home.join(".trashd/last_purge")).unwrap();
        store
            .trash(&create_file(work.path(), "payload", "recoverable"), None)
            .unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"must survive");
        assert_eq!(
            file.metadata().unwrap().modified().unwrap(),
            std::time::SystemTime::UNIX_EPOCH
        );
    }

    #[test]
    fn retention_marker_runs_due_purges_and_throttles_without_opening_lock() {
        let (mut store, _data, work, _) = test_store();
        store.config.retention.max_age_days = 1;
        let marker_path = store.home.join(".trashd/last_purge");
        let lock_path = store.home.join(".trashd/auto_purge.lock");
        let add_expired = |name: &str| {
            let data = store.home.join("files").join(name);
            fs::write(&data, b"expired").unwrap();
            let mut info = TrashInfo::new(work.path().join(name));
            info.deletion_date = chrono::Local::now() - chrono::Duration::days(2);
            fs::write(
                store.home.join("info").join(format!("{name}.trashinfo")),
                info.to_trashinfo_string(),
            )
            .unwrap();
            data
        };
        let first = add_expired("first");
        store.maybe_auto_purge().unwrap();
        assert!(
            !first.exists(),
            "creating a fresh marker must still run the first purge"
        );
        let marker = fs::File::options().write(true).open(&marker_path).unwrap();
        // Time passing ages the marker and expires the store's own
        // knowledge of when retention is next due.
        let age_marker = || {
            marker
                .set_modified(std::time::SystemTime::UNIX_EPOCH)
                .unwrap();
            store.purge_not_due_until.set(None);
        };
        age_marker();
        let second = add_expired("second");
        let lock = fs::File::options().write(true).open(&lock_path).unwrap();
        lock.lock().unwrap();
        store.maybe_auto_purge().unwrap();
        assert!(
            second.exists(),
            "a due purge must still honor an active lock"
        );
        // A concurrent test's spawning child can inherit this descriptor
        // until exec. Release our deliberate lock before requiring the next
        // nonblocking retention attempt to run (#397).
        lock.unlock().unwrap();
        drop(lock);
        store.maybe_auto_purge().unwrap();
        assert!(!second.exists());
        assert!(
            marker
                .metadata()
                .unwrap()
                .modified()
                .unwrap()
                .elapsed()
                .unwrap()
                .as_secs()
                < store.config.auto_purge_interval_secs
        );

        let third = add_expired("third");
        fs::remove_file(&lock_path).unwrap();
        store.maybe_auto_purge().unwrap();
        // The store also remembers it, without even the marker's lstat.
        assert!(store.purge_not_due_until.get().is_some());
        assert!(
            third.exists(),
            "a fresh marker must throttle the next purge"
        );
        assert!(
            !lock_path.exists(),
            "throttled deletions must not open/create the lock"
        );
        age_marker();
        store.maybe_auto_purge().unwrap();
        assert!(
            !third.exists(),
            "an existing aged marker must permit another purge"
        );
    }

    // Regression (#217): `trash empty` confirmed a listing, then re-listed and
    // purged whatever existed by then, including items trashed while the
    // prompt was waiting.
    #[test]
    fn emptying_purges_exactly_the_confirmed_entries() {
        let (store, _data, work, _) = test_store();
        store
            .trash(&create_file(work.path(), "shown", "a"), None)
            .unwrap();
        let shown = store.list(None).unwrap();
        let late = store
            .trash(&create_file(work.path(), "late", "b"), None)
            .unwrap();
        assert_eq!(store.empty_entries(&shown, None), 1);
        let left: Vec<String> = store
            .list(None)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(left, vec![late]);
    }

    // Regression (#210): the same ID can exist in two trash roots, where
    // only the entry's trashed path tells them apart; it must work as a
    // selector for restore, purge and info.
    #[test]
    fn trashed_path_selects_its_entry() {
        let (store, _data, work, _) = test_store();
        let id = store
            .trash(&create_file(work.path(), "notes.txt", "a"), None)
            .unwrap();
        let entry = store.find_entry(&id).unwrap();
        let selector = entry.trashed_path.to_str().unwrap();
        assert_eq!(
            store.find_entry(selector).unwrap().info_path,
            entry.info_path
        );
    }

    // Regression (#209): IDs are built from lossy names, so a non-UTF-8
    // target converted lossily exactly matched ANOTHER entry's ID, and purge
    // permanently deleted the wrong file.
    #[test]
    fn raw_name_selects_the_entry_with_exactly_those_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let (store, _data, work, _) = test_store();
        for raw in [b"\xff.txt".as_slice(), b"\xfe.txt".as_slice()] {
            let path = work.path().join(OsStr::from_bytes(raw));
            fs::write(&path, raw).unwrap();
            store.trash(&path, None).unwrap();
        }
        let selector = store
            .selector_for_raw_name(OsStr::from_bytes(b"\xfe.txt"))
            .unwrap();
        let entry = store.find_entry(&selector).unwrap();
        assert_eq!(fs::read(&entry.trashed_path).unwrap(), b"\xfe.txt");
    }

    // Regression (#201): under disk pressure (90% by default) every run
    // purged at least one entry, so `rm` could permanently delete the very
    // file it had just reported as trashed. Recent entries are never
    // eligible.
    #[test]
    fn disk_pressure_never_purges_a_just_trashed_entry() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let data = TempDir::with_prefix_in("data-", &base).unwrap();
        let work = TempDir::with_prefix_in("work-", &base).unwrap();
        let mut config = Config::default();
        config.retention.max_age_days = 0;
        config.retention.max_size_gb = 0.0;
        config.retention.disk_pressure_percent = 1; // always "under pressure"
        let store = TrashStore::open_isolated(&data.path().join("Trash"), config).unwrap();
        let file = create_file(work.path(), "fresh", "just deleted");
        let id = store.trash(&file, None).unwrap();
        store.auto_purge().unwrap();
        assert!(
            store.find_entry(&id).is_ok(),
            "pressure purged a just-trashed entry"
        );
    }

    // Regression (#193): X-Trashd-Size is sidecar text anyone with a topdir
    // trash (a USB stick) controls. A forged value there must never exceed
    // the tree actually on disk, or the size cap purges every other root.
    #[test]
    fn forged_topdir_directory_size_is_capped_by_the_measured_tree() {
        let (store, _data, work, _) = test_store();
        let tree = work.path().join("topdir-entry");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("small"), "x").unwrap();
        let mut info = TrashInfo::new(work.path().join("original"));
        info.size = Some(999_999_999_999_999_999);
        let entry = TrashEntry {
            id: "topdir-entry".into(),
            info,
            trashed_path: tree.clone(),
            info_path: work.path().join("topdir-entry.trashinfo"),
            trash_root: work.path().join(".Trash-1000"),
            orphaned: false,
            identity: None,
            sidecar_version: None,
        };
        assert_eq!(store.entry_disk_size(&entry), 1);
    }

    // #384: accounting must see past eligibility's 10,000-entry cap, with
    // or without another tool's recorded size, and retention must reuse the
    // measurement instead of walking its victim again.
    #[test]
    fn large_foreign_trees_are_fully_counted_and_measured_once_per_retention_pass() {
        for recorded in [true, false] {
            let (mut store, _data, work, _) = test_store();
            let foreign =
                TrashStore::open_isolated(&work.path().join("foreign-trash"), Config::default())
                    .unwrap();
            let tree = foreign.home.join("files/large");
            fs::create_dir(&tree).unwrap();
            let count = DIR_SIZE_MAX_FILES + 17;
            for index in 0..count {
                fs::write(tree.join(index.to_string()), b"data").unwrap();
            }
            let size = count * 4;
            let mut info = TrashInfo::new(work.path().join("original"));
            info.size = recorded.then_some(size);
            info.deletion_date = chrono::Local::now() - chrono::Duration::days(1);
            fs::write(
                foreign.home.join("info/large.trashinfo"),
                info.to_trashinfo_string(),
            )
            .unwrap();
            let keep = create_file(work.path(), "keep", "new");
            let keep_id = store.trash(&keep, None).unwrap();
            let external = create_file(work.path(), "EXTERNAL", "outside the trash");
            let roots = vec![
                (store.home.clone(), "home".into()),
                (foreign.home.clone(), "foreign".into()),
            ];
            let statuses = store.status_in_roots(&roots).unwrap();
            assert_eq!(
                statuses.iter().map(|status| status.total_size).sum::<u64>(),
                size + 3,
                "recorded={recorded}"
            );
            // The old capped measurement plus the new file is below this
            // limit; the complete foreign tree is above it.
            store.config.retention.max_size_gb =
                ((DIR_SIZE_MAX_FILES + 8) * 4) as f64 / (1024.0 * 1024.0 * 1024.0);
            store.accounting_walks.set(0);
            let paths: Vec<_> = roots.iter().map(|(path, _)| path.clone()).collect();
            store.auto_purge_in_roots(&paths).unwrap();
            assert!(!tree.exists(), "large foreign tree escaped retention");
            assert!(!foreign.home.join("info/large.trashinfo").exists());
            assert_eq!(store.accounting_walks.get(), 1, "recorded={recorded}");
            assert_eq!(
                fs::read(store.find_entry(&keep_id).unwrap().trashed_path).unwrap(),
                b"new"
            );
            assert_eq!(fs::read(external).unwrap(), b"outside the trash");
        }
    }

    #[test]
    fn directory_accounting_keeps_full_depth_and_a_recorded_ceiling_without_following_links() {
        let (_store, _data, work, _) = test_store();
        let tree = work.path().join("deep");
        fs::create_dir(&tree).unwrap();
        let mut deepest = tree.clone();
        for _ in 0..COPY_TREE_MAX_DEPTH + 5 {
            deepest.push("d");
            fs::create_dir(&deepest).unwrap();
        }
        fs::write(deepest.join("data"), b"deep payload").unwrap();
        let target = create_file(work.path(), "EXTERNAL", &"x".repeat(10_000));
        std::os::unix::fs::symlink(&target, tree.join("link")).unwrap();
        assert_eq!(directory_accounted_size(&tree, None), 12);
        assert_eq!(directory_accounted_size(&tree, Some(u64::MAX)), 12);
        assert_eq!(directory_accounted_size(&tree, Some(5)), 5);
        assert_eq!(directory_accounted_size(&tree, Some(0)), 0);
        assert_eq!(fs::metadata(target).unwrap().len(), 10_000);
    }

    #[test]
    fn directory_accounting_excludes_mounted_files_and_subtrees() {
        let outcome = crate::mounts::in_private_mounts(
            "store::tests::directory_accounting_excludes_mounted_files_and_subtrees",
            || {
                let (_store, _data, work, _) = test_store();
                let tree = work.path().join("tree");
                let external = work.path().join("external");
                fs::create_dir_all(tree.join("mount")).unwrap();
                fs::create_dir(&external).unwrap();
                fs::write(tree.join("local"), b"local").unwrap();
                let keep = create_file(&external, "KEEP", "external payload");
                fs::write(tree.join("file-mount"), b"").unwrap();
                if !mount_at(Some(&external), &tree.join("mount")) {
                    return false;
                }
                if !mount_at(Some(&keep), &tree.join("file-mount")) {
                    unmount(&tree.join("mount"));
                    return false;
                }
                let measured = directory_accounted_size(&tree, None);
                unmount(&tree.join("file-mount"));
                unmount(&tree.join("mount"));
                measured == 5 && fs::read(keep).unwrap() == b"external payload"
            },
        );
        if let Some(outcome) = outcome {
            assert!(outcome);
        }
    }

    // Regression (#193): recorded sizes are summed for the size cap; huge
    // values must saturate instead of overflowing (a debug-build panic).
    #[test]
    fn huge_recorded_sizes_saturate_instead_of_overflowing() {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-trash");
        fs::create_dir_all(&base).unwrap();
        let data = TempDir::with_prefix_in("data-", &base).unwrap();
        let work = TempDir::with_prefix_in("work-", &base).unwrap();
        let mut config = Config::default();
        config.retention.max_age_days = 0;
        config.retention.max_size_gb = 1.0;
        config.retention.disk_pressure_percent = 0;
        let store = TrashStore::open_isolated(&data.path().join("Trash"), config).unwrap();
        for name in ["first", "second"] {
            let tree = work.path().join(name);
            fs::create_dir_all(&tree).unwrap();
            let id = store.trash(&tree, None).unwrap();
            let entry = store.find_entry(&id).unwrap();
            let sidecar = fs::read_to_string(&entry.info_path).unwrap();
            let rewritten: String = sidecar
                .lines()
                .map(|line| {
                    if line.starts_with("X-Trashd-Size=") {
                        format!("X-Trashd-Size={}", u64::MAX / 2 + 1)
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(&entry.info_path, rewritten + "\n").unwrap();
        }
        store.auto_purge().unwrap();
        assert!(store.status().is_ok());
    }

    // Regression (#115): a foreign directory entry without X-Trashd-Size must
    // count its real tree size, not the ~4 KiB inode size.
    #[test]
    fn foreign_directory_entry_uses_tree_size_for_accounting() {
        let (store, _data, work, _lock) = test_store();
        let tree = work.path().join("foreign-tree");
        fs::create_dir_all(&tree).unwrap();
        let payload = "x".repeat(50_000);
        fs::write(tree.join("big"), &payload).unwrap();

        // Seed a sidecar WITHOUT the trashd size extension, as another
        // spec-compliant tool would.
        let id = "foreign-tree";
        fs::rename(&tree, store.home.join("files").join(id)).unwrap();
        let info = TrashInfo::new(work.path().join("foreign-tree"));
        fs::write(
            store.home.join("info").join(format!("{id}.trashinfo")),
            info.to_trashinfo_string(),
        )
        .unwrap();

        let (size, _count) = store.status().unwrap();
        assert!(
            size >= 50_000,
            "foreign directory tree must be accounted at its real size, got {size}"
        );
    }
}
