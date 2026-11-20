use crate::config::Config;
pub use crate::config::ExclusionKind;
use crate::mounts;
use crate::store_lock::RootMutationGuard;
use crate::trashinfo::TrashInfo;

mod cleanup;
mod listing;
pub use cleanup::CleanupReport;
use cleanup::*;
use listing::newest_first;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
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
    /// Configured to be deleted for real, for `kind`: a verdict for this
    /// path alone, never for what a directory holds (common-policy-1).
    #[error("path is {kind}: {path}")]
    Excluded { path: PathBuf, kind: ExclusionKind },
    #[error("file too large ({size_mb} MB > {limit_mb} MB limit): {path}")]
    TooLarge {
        path: PathBuf,
        size_mb: u64,
        limit_mb: u64,
    },
    #[error("trash entry not found: {0}")]
    EntryNotFound(String),
    #[error("unfinished deletion jobs remain: {0}; retry `trash empty`")]
    CleanupPending(usize),
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
    /// Runs once between a scan's info/ and files/ passes, as a writer
    /// racing the unlocked listing would.
    #[cfg(test)]
    between_scan_passes: std::cell::RefCell<Option<Box<dyn FnOnce() + Send>>>,
    /// Runs once right before `trash` or `trash_at` moves its operand, as a
    /// process replacing the operand after it was sized would.
    #[cfg(test)]
    before_move: std::cell::RefCell<Option<Box<dyn FnOnce()>>>,
    /// Runs once between a conflicting restore and its first `--force`
    /// retry, as a process changing the destination's directories would.
    #[cfg(test)]
    before_forced_retry: std::cell::RefCell<Option<Box<dyn FnOnce()>>>,
    /// The cross-device move's durability steps, in order.
    #[cfg(test)]
    durability_events: std::cell::RefCell<Vec<&'static str>>,
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
    /// How long an explicit purge, empty or restore waits for an entry lock
    /// before it reports the entry busy ([`ENTRY_LOCK_WAIT`]).
    entry_lock_wait: std::time::Duration,
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

/// An entry's data name in files/ and sidecar name in info/, raw bytes.
fn entry_names(entry: &TrashEntry) -> Result<(CString, CString), TrashError> {
    let name = |path: &Path| {
        path.file_name()
            .and_then(|name| CString::new(name.as_bytes()).ok())
            .ok_or_else(|| TrashError::EntryNotFound(entry.id.clone()))
    };
    Ok((name(&entry.trashed_path)?, name(&entry.info_path)?))
}

/// Where a restore puts an entry, which decides how far the path is
/// trusted.
#[derive(Clone, Copy)]
enum RestoreTarget<'a> {
    /// The path the entry's sidecar records. That is text anyone who can
    /// write the medium may have crafted: it stays below its topdir and is
    /// reached through no symlink.
    Recorded,
    /// A free name beside the recorded path, for a `--force` retry. It is
    /// derived from the same text, so it is confined like it: passed on as
    /// a destination the user chose, it left the topdir and followed
    /// symlinks (store-core-8, cli-6).
    BesideRecorded(&'a Path),
    /// A destination the user named: trusted, symlinks included.
    Explicit(&'a Path),
}

impl<'a> RestoreTarget<'a> {
    fn of(target: Option<&'a Path>) -> Self {
        target.map_or(Self::Recorded, Self::Explicit)
    }
}

/// `name` (files/ or info/) of the trash root at `root`, opened following
/// no symlink in the root or in `name`, and on the root's own device
/// (EXDEV otherwise): how an unlocked caller reaches a topdir root's store
/// (security-1).
fn open_store_child(root: &Path, name: &CStr) -> io::Result<fs::File> {
    let root_dir = crate::fdops::open_dir_nofollow_at(
        libc::AT_FDCWD,
        &CString::new(root.as_os_str().as_bytes())?,
    )?;
    let child = crate::fdops::open_dir_nofollow_at(root_dir.as_raw_fd(), name)?;
    if stat_fd(child.as_raw_fd())?.st_dev != stat_fd(root_dir.as_raw_fd())?.st_dev {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(child)
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

    /// `lock_trash_root` for a purge or a repair. A root that lost its
    /// info/ holds only data nothing describes, which the listing shows as
    /// orphans (#403); the lock validates info/ too and refused the root,
    /// so no purge could remove them and `empty` left them there on every
    /// run (store-metadata-4). The missing info/ is put back first.
    pub fn lock_trash_root_repaired(&self, root: &Path) -> Result<RootMutationGuard, TrashError> {
        match self.lock_trash_root(root) {
            Err(TrashError::Refused(_)) => {
                // Whoever put it back, a concurrent purge included: the
                // lock judges what is there now.
                let _ = restore_missing_info_dir(root, unsafe { libc::geteuid() });
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
        // Through the directories the lock validated, never the entry's
        // paths: a FUSE or NFS server can answer files/ or info/ with a
        // symlink once the lock checked them, and the paths then named
        // whatever it points at, /etc/shadow included (security-1).
        let (data_name, info_name) = entry_names(entry)?;
        let read_metadata = |dir: &fs::File, name: &CStr| match crate::fdops::metadata_nofollow_at(
            dir.as_raw_fd(),
            name,
        ) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(TrashError::Io(error)),
        };
        let data = read_metadata(guard.files(), &data_name)?;
        let sidecar = read_metadata(guard.info(), &info_name)?;
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
        // An orphan snapshot whose sidecar now parses came from a listing
        // that raced the entry's publication. Writers publish the sidecar
        // and then the data under this lock, so the sidecar is complete here
        // and the entry is live (store-core-1).
        if entry.orphaned
            && sidecar.as_ref().is_some_and(fs::Metadata::is_file)
            && crate::trashinfo::read_sidecar_at(guard.info().as_raw_fd(), &info_name)
                .is_ok_and(|content| TrashInfo::from_trashinfo(&content).is_some())
        {
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
            entry_lock_wait: ENTRY_LOCK_WAIT,
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
            #[cfg(test)]
            between_scan_passes: std::cell::RefCell::new(None),
            #[cfg(test)]
            before_move: std::cell::RefCell::new(None),
            #[cfg(test)]
            before_forced_retry: std::cell::RefCell::new(None),
            #[cfg(test)]
            durability_events: std::cell::RefCell::new(Vec::new()),
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

        // Check never-trash list. The trash itself, anything in it and its
        // ancestors stay refused even so: excluded first, a whitelist miss
        // on `~/.local` deleted the trash for real (cross-layer-5).
        if let Some(kind) = self.exclusion(&abs_path) {
            let trash_dir = self.existing_trash_dir(&abs_path, meta.dev());
            let identity = meta.is_dir().then(|| (meta.dev(), meta.ino()));
            self.refuse_trash_itself(&abs_path, identity, &trash_dir)?;
            return Err(TrashError::Excluded {
                path: abs_path,
                kind,
            });
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

        // bypass_paths names the deleting program, which only the caller
        // knows: matched here against /proc/self/exe, inside the shim it
        // named the shim, and a prefix covering trashd's install directory
        // made every rm a real delete (cross-layer-4). The shim checks its
        // caller instead, before opening the store.

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

        let identity = meta.is_dir().then(|| (meta.dev(), meta.ino()));
        self.refuse_trash_itself(&abs_path, identity, &trash_dir)?;
        // A directory is checked once its tree has been surveyed.
        if meta.is_file() {
            self.check_retention_cap(&abs_path, meta.size(), &trash_dir)?;
        }

        Ok((abs_path, meta, trash_dir))
    }

    /// The trash `path` (on `dev`) would go to, without preparing one.
    fn existing_trash_dir(&self, path: &Path, dev: u64) -> PathBuf {
        if self.isolated {
            self.home.clone()
        } else {
            mounts::existing_trash_dir_for_path_on(path, Some(dev), &self.home)
        }
    }

    /// Refuse to trash the trash directory itself, anything inside it, or
    /// any ancestor of it: rename would fail (dest inside src), the
    /// cross-device fallback would copy the store into itself until the
    /// depth cap. `rm -rf ~/.local/share/Trash` must never destroy the
    /// trash. Callers treat Refused as a hard stop — NOT Excluded, which
    /// means "real-delete on purpose". A directory's `identity` is compared
    /// too: the same directory reached under another name (a bind mount of
    /// ~/.local/share, say) would carry the trash, or its info/ into its
    /// files/ (#362).
    fn refuse_trash_itself(
        &self,
        path: &Path,
        identity: Option<(u64, u64)>,
        trash_dir: &Path,
    ) -> Result<(), TrashError> {
        if path == trash_dir
            || path.starts_with(trash_dir)
            || trash_dir.starts_with(path)
            || identity.is_some_and(|identity| self.trash_ancestry(trash_dir).contains(&identity))
        {
            return Err(TrashError::Refused(path.to_path_buf()));
        }
        Ok(())
    }

    /// Make a new entry's sidecar and its info/ entry durable before a
    /// cross-device source is retired, after which the trash copy is the
    /// only copy: torn by a crash, it came back an orphan without its
    /// original path (store-core-5). A same-device rename skips this; every
    /// trapped unlink of an `rm -rf` would pay two more fsyncs.
    fn sync_new_sidecar(&self, claim: &fs::File, info: &fs::File) -> io::Result<()> {
        claim.sync_data()?;
        #[cfg(test)]
        self.durability_events.borrow_mut().push("sidecar");
        info.sync_all()?;
        #[cfg(test)]
        self.durability_events.borrow_mut().push("info");
        Ok(())
    }

    /// retention.max_size_gb in bytes; 0 means no size limit.
    fn retention_size_cap(&self) -> u64 {
        (self.config.retention.max_size_gb * 1024.0 * 1024.0 * 1024.0) as u64
    }

    /// Whether `root` is on the home trash's filesystem: the only trash the
    /// size cap governs (store-core-3).
    fn on_home_filesystem(&self, root: &Path) -> bool {
        if root == self.home {
            return true;
        }
        let home = mounts::device_id_or_parent(&self.home);
        home.is_some() && mounts::device_id_or_parent(root) == home
    }

    /// Refuse an operand larger than the size cap of the trash it would land
    /// in. Retention could only fit it by purging it, and first every other
    /// entry; the delete that just succeeded became permanent (store-core-2).
    /// Like the other size caps, this is a refusal: nothing moves (#10).
    fn check_retention_cap(
        &self,
        path: &Path,
        size: u64,
        trash_dir: &Path,
    ) -> Result<(), TrashError> {
        let cap = self.retention_size_cap();
        if cap == 0 || size <= cap || !self.on_home_filesystem(trash_dir) {
            return Ok(());
        }
        Err(TrashError::TooLarge {
            path: path.to_path_buf(),
            size_mb: size / (1024 * 1024),
            limit_mb: cap / (1024 * 1024),
        })
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
            let survey = match CString::new(abs_path.as_os_str().as_bytes()) {
                Ok(name) => tree_survey_at(libc::AT_FDCWD, &name, true),
                Err(error) => TreeSurvey::unwalked(error.into()),
            };
            if let Some(mount) = survey.mount_in(&abs_path) {
                return Err(TrashError::HoldsMount(mount));
            }
            self.check_retention_cap(&abs_path, survey.apparent, &trash_dir)?;
            survey.sizes()
        } else {
            EntrySizes::of_file(meta.size())
        };
        info.size = sizes.apparent;

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

        let locked = self.lock_trash_root_prepared(&trash_dir)?;
        // Every step below that touches the store goes through the
        // descriptors this lock validated, kept past it (the copy fallback
        // releases the lock to retire its source): resolved again by path,
        // files/ or info/ could be a symlink a FUSE or NFS server answered
        // once the lock checked them (security-2).
        let files = locked.files().try_clone()?;
        let info_dir = locked.info().try_clone()?;
        // Generate unique trash ID within that trash dir (atomic)
        let file_name = abs_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unnamed".into());
        let (id, _, mut claim) = unique_id_atomic(&trash_dir, &locked, &file_name)?;
        let mut guard = Some(locked);
        let id_name = CString::new(id.as_bytes()).map_err(io::Error::from)?;
        let info_name = CString::new(format!("{id}.trashinfo")).map_err(io::Error::from)?;
        let release_claim = || {
            let _ = raw_unlinkat(info_dir.as_raw_fd(), &info_name, 0);
        };

        // Write .trashinfo content through the descriptor that claimed it.
        // On failure, release the claim so an ENOSPC cannot strand an
        // invisible 0-byte sidecar that also reserves the id stem (#109).
        if let Err(e) = write_claimed_sidecar(&mut claim, &info) {
            release_claim();
            return Err(TrashError::Io(e));
        }

        // Try rename (fast, same filesystem — should always work with topdir trash)
        let mut copy_done = false;
        let mut created_identity = None;
        let mut copy_lock = None;
        let move_result: Result<(), TrashError> = (|| {
            let source_name =
                CString::new(abs_path.as_os_str().as_bytes()).map_err(io::Error::from)?;
            #[cfg(test)]
            if let Some(hook) = self.before_move.borrow_mut().take() {
                hook();
            }
            if let Err(rename_error) =
                rename_noreplace_at(libc::AT_FDCWD, &source_name, files.as_raw_fd(), &id_name)
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
                let staging = guard
                    .as_ref()
                    .map(|locked| locked.state().as_raw_fd())
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
                created_identity = Some(copy_source_at(
                    source_parent.as_raw_fd(),
                    &name,
                    files.as_raw_fd(),
                    &id_name,
                    staging,
                    &source,
                )?);
                // The copy's data is synced; make its directory entry durable
                // before the source can disappear.
                files.sync_all()?;
                #[cfg(test)]
                self.durability_events.borrow_mut().push("files");
                self.sync_new_sidecar(&claim, &info_dir)?;
                copy_done = true;
                // Source retirement unlinks, which trap into a seccomp
                // supervisor that may be waiting for this same root lock, so
                // the lock is released before retiring (store-core-4). The
                // environment cannot say whether this process is filtered
                // (`sudo` resets it inside a wrapped session), and retiring a
                // large tree held every trash writer of this user. The fresh
                // copy keeps its entry lock instead: a purge must not delete
                // it while retiring the source destroys the other copy (#243).
                copy_lock = lock_published_copy(files.as_raw_fd(), &id_name);
                drop(guard.take());
                // Raw syscalls throughout: the system-wide preload would
                // otherwise trash the source a second time (#104).
                #[cfg(test)]
                self.durability_events.borrow_mut().push("retire");
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
            // The copy itself failed — nothing was moved; roll back cleanly,
            // through the descriptors it was made in.
            release_claim();
            if let Some(created) = created_identity
                && stat_at(files.as_raw_fd(), &id_name, libc::AT_SYMLINK_NOFOLLOW)
                    .is_ok_and(|copy| stat_identity(&copy) == created)
            {
                let _ = remove_tree_at(files.as_raw_fd(), &id_name, 0);
            }
            return Err(e);
        }

        // The move completed: make sure a concurrent purge did not strip the
        // sidecar while the data was absent mid-move (#169).

        // The copy path released the root lock before retirement: re-acquire
        // it and verify the entry survived. Reporting success for a copy a
        // purge already deleted would hide data loss.
        let verify_guard = if guard.is_none() {
            let verify_guard = self.lock_trash_root(&trash_dir)?;
            if stat_at(files.as_raw_fd(), &id_name, libc::AT_SYMLINK_NOFOLLOW).is_err()
                || stat_at(info_dir.as_raw_fd(), &info_name, libc::AT_SYMLINK_NOFOLLOW).is_err()
            {
                return Err(TrashError::EntryNotFound(id.clone()));
            }
            Some(verify_guard)
        } else {
            None
        };
        drop(copy_lock);

        // Post-move identity refresh for the rename path (#246, mirroring
        // trash_at): the final component may have been replaced between the
        // hash/size reads and the rename, so the sidecar must describe the
        // inode that actually landed in the trash.
        if !copy_done {
            match crate::fdops::metadata_nofollow_at(files.as_raw_fd(), &id_name) {
                Ok(dest_meta) if (dest_meta.dev(), dest_meta.ino()) != (meta.dev(), meta.ino()) => {
                    sizes = if dest_meta.is_dir() {
                        tree_sizes_at(files.as_raw_fd(), &id_name)
                    } else {
                        EntrySizes::of_file(dest_meta.size())
                    };
                    info.size = sizes.apparent;
                    info.sha256 = if dest_meta.is_file()
                        && hash_limit > 0
                        && dest_meta.size() <= hash_limit
                    {
                        hash_file_verified_at(
                            files.as_raw_fd(),
                            &id_name,
                            &self.config.hash_algorithm,
                            (dest_meta.dev(), dest_meta.ino()),
                        )
                        .ok()
                    } else {
                        None
                    };
                    let _ = replace_sidecar_at(info_dir.as_raw_fd(), &info_name, &info);
                }
                Ok(_) => {}
                Err(_) => {
                    info.sha256 = None;
                    let _ = replace_sidecar_at(info_dir.as_raw_fd(), &info_name, &info);
                }
            }
        }

        // Update the directorysizes cache if a directory landed: `sizes`
        // describes what did, which a race can make another type than the
        // operand had before the move (recent-changes-9).
        if let Some(allocated) = sizes.allocated {
            let _ = crate::directorysizes::record_directory(&trash_dir, OsStr::new(&id), allocated);
        }

        drop(guard);
        drop(verify_guard);
        // The log is not part of publication: write it after releasing the
        // lock every trash writer waits on (store-metadata-3).
        crate::oplog::log_trash_in(&self.home, &abs_path, &id, command);
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
        // The trash, anything in it and its ancestors stay refused even
        // where excluded, as in prepare_source (cross-layer-5).
        if let Some(kind) = self.exclusion(&display_path) {
            let trash_dir = self.existing_trash_dir(&display_path, file_dev);
            self.refuse_trash_itself(&display_path, None, &trash_dir)?;
            return Err(TrashError::Excluded {
                path: display_path,
                kind,
            });
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
        // The retention size cap, as in trash(); a tree after its survey.
        if fmt == libc::S_IFREG {
            self.check_retention_cap(&display_path, stat.st_size as u64, &trash_dir)?;
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

        let trashinfo_path = Self::compute_trashinfo_path(&trash_dir, &display_path, &home_trash);
        let mut info = TrashInfo::new(trashinfo_path);
        info.command = command.map(|s| s.to_string());
        info.pid = Some(std::process::id());
        // Directory size: walk OUR fd of the victim dir, not any name.
        let mut victim_sizes = if !is_dir {
            EntrySizes::of_file(stat.st_size as u64)
        } else {
            let survey = tree_survey_at(parent_fd, &cname, true);
            if let Some(mount) = survey.mount_in(&display_path) {
                unsafe { libc::close(files_fd) };
                return Err(TrashError::HoldsMount(mount));
            }
            if let Err(error) = self.check_retention_cap(&display_path, survey.apparent, &trash_dir)
            {
                unsafe { libc::close(files_fd) };
                return Err(error);
            }
            survey.sizes()
        };
        info.size = victim_sizes.apparent;

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

        let locked = match self.lock_trash_root_prepared(&trash_dir) {
            Ok(g) => g,
            Err(e) => {
                unsafe { libc::close(files_fd) };
                return Err(e);
            }
        };
        // From here on the store is reached only through the descriptors
        // this lock validated: files/ was opened by path above only to tell
        // a cross-device move early, and a FUSE or NFS server could have
        // answered that lookup, or any later one, with a symlink
        // (security-2).
        let pinned = locked
            .files()
            .try_clone()
            .and_then(|files| Ok((files, locked.info().try_clone()?)));
        unsafe { libc::close(files_fd) };
        let (files_fd, info_dir) = match pinned {
            Ok((files, info)) => (files.into_raw_fd(), info),
            Err(e) => return Err(TrashError::Io(e)),
        };
        let cross_device = match stat_fd(files_fd) {
            Ok(files) => files.st_dev != file_dev,
            Err(e) => {
                unsafe { libc::close(files_fd) };
                return Err(TrashError::Io(e));
            }
        };
        let mut guard = Some(locked);
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
        let claimed = match guard.as_ref() {
            Some(locked) => unique_id_atomic(&trash_dir, locked, &base_name),
            None => Err(TrashError::Io(io::Error::from_raw_os_error(libc::EBADF))),
        };
        let (id, mut claim) = match claimed {
            Ok((id, _, claim)) => (id, claim),
            Err(e) => {
                unsafe { libc::close(files_fd) };
                return Err(e);
            }
        };
        let info_name = match CString::new(format!("{id}.trashinfo")) {
            Ok(name) => name,
            Err(_) => {
                unsafe { libc::close(files_fd) };
                return Err(TrashError::NotFound(display_path.clone()));
            }
        };
        let release_claim = || {
            let _ = raw_unlinkat(info_dir.as_raw_fd(), &info_name, 0);
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
        if let Err(e) = write_claimed_sidecar(&mut claim, &info) {
            release_claim();
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(e));
        }

        if !may_commit() {
            release_claim();
            unsafe { libc::close(files_fd) };
            return Err(TrashError::Io(io::Error::from_raw_os_error(
                libc::ECANCELED,
            )));
        }
        #[cfg(test)]
        if let Some(hook) = self.before_move.borrow_mut().take() {
            hook();
        }
        // THE MOVE (#6): kernel-resolved against pinned inodes on both sides.
        let moved = if cross_device {
            Err(io::Error::from_raw_os_error(libc::EXDEV))
        } else {
            rename_noreplace_at(parent_fd, &cname, files_fd, &cid)
        };
        let mut copied = false;
        let mut copy_lock = None;
        if let Err(e) = moved {
            // Nothing partial was created at dest (rename is atomic).
            if !is_copy_fallback_error(&e) {
                unsafe { libc::close(files_fd) };
                release_claim();
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
                    release_claim();
                    return Err(error);
                }
            };
            let copy = (|| {
                // Staged in the state directory the lock validated.
                let staging = guard
                    .as_ref()
                    .map(|locked| locked.state().as_raw_fd())
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?;
                copy_source_at(parent_fd, &cname, files_fd, &cid, staging, &stat)?;
                if unsafe { libc::fsync(files_fd) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                #[cfg(test)]
                self.durability_events.borrow_mut().push("files");
                self.sync_new_sidecar(&claim, &info_dir)
            })();
            if let Err(e) = copy {
                unsafe { libc::close(files_fd) };
                release_claim();
                return Err(TrashError::Io(e));
            }
            copied = true;
            // The entry is complete from here on. A failed or partial source
            // removal keeps it: the target's own syscall then decides, and at
            // worst a duplicate remains in the trash. Retirement unlinks, so
            // it runs without the root lock, as in trash() (store-core-4):
            // the shim calls this inside filtered sessions.
            copy_lock = lock_published_copy(files_fd, &cid);
            drop(guard.take());
            #[cfg(test)]
            self.durability_events.borrow_mut().push("retire");
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

        // Retirement ran without the root lock: re-acquire it and verify the
        // entry survived, as trash() does.
        let verify_guard = if guard.is_none() {
            let verify_guard = match self.lock_trash_root(&trash_dir) {
                Ok(verify_guard) => verify_guard,
                Err(e) => {
                    unsafe { libc::close(files_fd) };
                    return Err(e);
                }
            };
            if stat_at(files_fd, &cid, libc::AT_SYMLINK_NOFOLLOW).is_err()
                || stat_at(info_dir.as_raw_fd(), &info_name, libc::AT_SYMLINK_NOFOLLOW).is_err()
            {
                unsafe { libc::close(files_fd) };
                return Err(TrashError::EntryNotFound(id.clone()));
            }
            Some(verify_guard)
        } else {
            None
        };
        drop(copy_lock);

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
                    // A raced directory replacement must not record the new
                    // directory inode's st_size (~4 KiB) as the tree's size:
                    // mirror trash() and re-survey what actually landed, or
                    // retention accounting undercounts a large tree (#414).
                    // By the type that landed: the replacement need not be
                    // of the operand's (recent-changes-9).
                    victim_sizes = if moved_stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                        tree_sizes_at(files_fd, &cid)
                    } else {
                        EntrySizes::of_file(moved_stat.st_size as u64)
                    };
                    info.size = victim_sizes.apparent;
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
            let _ = replace_sidecar_at(info_dir.as_raw_fd(), &info_name, &info);
        }
        unsafe { libc::close(files_fd) };

        // A row for the directory that landed, as in trash().
        if let Some(allocated) = victim_sizes.allocated {
            let _ = crate::directorysizes::record_directory(&trash_dir, OsStr::new(&id), allocated);
        }
        drop(guard);
        drop(verify_guard);
        // After releasing the lock every trash writer waits on, as in trash().
        crate::oplog::log_trash_in(&self.home, &display_path, &id, command);
        self.after_mutation();

        Ok(id)
    }

    /// Restore a trashed item by ID or pattern match to its original location.
    pub fn restore(
        &self,
        id_or_pattern: &str,
        target: Option<&Path>,
    ) -> Result<PathBuf, TrashError> {
        let mut entry = self.find_entry(id_or_pattern)?;
        self.restore_resolved(&mut entry, RestoreTarget::of(target), true)
    }

    /// Restore one resolved entry with immediate directorysizes maintenance.
    /// Reuse the mutable snapshot when retrying a conflicting destination:
    /// decompression may refresh its identity and metadata before a retry.
    pub fn restore_entry(
        &self,
        entry: &mut TrashEntry,
        target: Option<&Path>,
    ) -> Result<PathBuf, TrashError> {
        self.restore_resolved(entry, RestoreTarget::of(target), true)
    }

    /// `restore_entry` that, where the destination is taken, restores beside
    /// it under the first free `.N` suffix (`restore --force`).
    pub fn restore_entry_renamed(
        &self,
        entry: &mut TrashEntry,
        target: Option<&Path>,
    ) -> Result<PathBuf, TrashError> {
        self.restore_resolved_renamed(entry, target, true)
    }

    fn restore_resolved_renamed(
        &self,
        entry: &mut TrashEntry,
        target: Option<&Path>,
        maintain: bool,
    ) -> Result<PathBuf, TrashError> {
        let mut result = self.restore_resolved(entry, RestoreTarget::of(target), maintain);
        if let Err(TrashError::RestoreConflict(ref destination)) = result {
            // Off a normalized base, so a trailing-slash `--to backup/`
            // yields the sibling "backup.1", not a hidden "backup/.1"
            // inside the directory (#158).
            let destination = normalize_conflict_base(destination);
            #[cfg(test)]
            if let Some(hook) = self.before_forced_retry.borrow_mut().take() {
                hook();
            }
            for i in 1..1000 {
                let mut candidate = destination.as_os_str().to_os_string();
                candidate.push(format!(".{i}"));
                let candidate = PathBuf::from(candidate);
                // Beside the recorded path only what that path may be;
                // beside the caller's own target, the caller's choice.
                let beside = match target {
                    None => RestoreTarget::BesideRecorded(&candidate),
                    Some(_) => RestoreTarget::Explicit(&candidate),
                };
                result = self.restore_resolved(entry, beside, maintain);
                if !matches!(result, Err(TrashError::RestoreConflict(_))) {
                    break;
                }
            }
        }
        result
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
                let result = if force {
                    self.restore_resolved_renamed(&mut entry, target, false)
                } else {
                    self.restore_resolved(&mut entry, RestoreTarget::of(target), false)
                };
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
        target: RestoreTarget<'_>,
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

        let (restore_to, recorded) = match target {
            RestoreTarget::Recorded => (entry.info.original_path.clone(), true),
            RestoreTarget::BesideRecorded(path) => (path.to_path_buf(), true),
            RestoreTarget::Explicit(path) => (path.to_path_buf(), false),
        };

        // When restoring to the entry's OWN recorded original path, or to a
        // name derived from it, that path comes from the .trashinfo, which on
        // removable/shared media an attacker may have crafted. Refuse
        // destinations that escape via ".." and, for topdir trashes, require
        // the destination to stay under that topdir. This blocks
        // path-traversal that would let a malicious .trashinfo overwrite
        // arbitrary files (~/.bashrc, cron, …) during an ordinary
        // `restore`/`undo`. An explicit user-supplied target is trusted and
        // not constrained.
        if recorded {
            if restore_to
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            {
                return Err(TrashError::RestoreTraversal(restore_to));
            }
            if entry.trash_root != self.home {
                let topdir = Self::topdir_for_trash(&entry.trash_root);
                // Strictly below it: an empty `Path=` names the topdir
                // itself, which conflicts, and the `.N` name beside it is
                // outside (cli-6).
                if !restore_to
                    .strip_prefix(&topdir)
                    .is_ok_and(|below| below.file_name().is_some())
                {
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
        let destination = resolve_restore_destination(&restore_to, recorded).map_err(|e| {
            if recorded && matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
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
            let max_output = self.restore_decompress_limit(entry.info.size);
            decompress_zstd_entry(entry, max_output, self.entry_lock_deadline())?;
        }

        // Re-check through the pinned parent after decompression. The publish
        // syscall below is also no-clobber, so a creation after this check is
        // still reported as a conflict rather than overwritten.
        if destination_exists(&destination)? {
            return Err(TrashError::RestoreConflict(restore_to));
        }

        // Serialize against compressors and purges (auto-purge, the CLI and
        // purge all flock the entry before validating): without this lock a
        // compressor could swap zstd bytes into the stat→rename window below
        // and the rename would publish compressed bytes as the restored file
        // (#168), and a purge could delete an entry being copied across
        // filesystems without the root lock. Held through the publish. A
        // busy entry is reported as such, never as already gone (cli-5).
        let entry_lock = lock_entry_file_until(&entry.trashed_path, self.entry_lock_deadline())
            .map_err(|error| {
                if error.kind() == io::ErrorKind::WouldBlock {
                    TrashError::Io(error)
                } else {
                    TrashError::EntryNotFound(entry.id.clone())
                }
            })?;

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
        let copy = match rename_noreplace_at(
            source_parent.as_raw_fd(),
            &source_name,
            destination.parent.as_raw_fd(),
            &destination.name,
        ) {
            Ok(()) => false,
            Err(e) if is_conflict_error(&e) => {
                return Err(TrashError::RestoreConflict(restore_to));
            }
            Err(e) if is_copy_fallback_error(&e) => true,
            Err(e) => return Err(TrashError::Io(e)),
        };
        let root_guard = if copy {
            // The copy and the retirement of the trash copy run without the
            // root lock, under the entry lock alone: retirement unlinks, which
            // trap into a seccomp supervisor that may be waiting for this
            // lock (store-core-4), and a long copy held every trash writer of
            // this user meanwhile (store-metadata-6).
            drop(root_guard);
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
            // The restore is complete: a root that can no longer be locked
            // only keeps the sidecar, which purge retires as data-absent.
            self.lock_trash_root(&entry.trash_root).ok()
        } else {
            Some(root_guard)
        };
        // Remove the trashinfo: detach it under the root lock if it is still
        // the version restored, and delete it after releasing the lock.
        // Through the lock's info/ descriptor, never the path (security-1).
        let sidecar = root_guard.as_ref().and_then(|guard| {
            let (_, info_name) = entry_names(entry).ok()?;
            let current = crate::fdops::metadata_nofollow_at(guard.info().as_raw_fd(), &info_name)
                .ok()
                .filter(fs::Metadata::is_file)
                .map(|metadata| SidecarVersion::from_metadata(&metadata));
            if current != entry.sidecar_version {
                return None;
            }
            let mut detached = Detached::open_in(guard).ok()?;
            detached
                .take_at(guard.info().as_raw_fd(), &info_name)
                .ok()?;
            Some(detached)
        });
        drop(root_guard);
        drop(entry_lock);
        if let Some(sidecar) = sidecar {
            let _ = sidecar.remove();
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

        if maintain {
            self.refresh_cache_after_removal(
                entry,
                source_stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
            );
        }

        // Log operation
        crate::oplog::log_restore_in(&self.home, &entry.id, &restore_to);

        // Report hash mismatch as a warning after successful restore. The
        // path and digest come from the sidecar: escape them (cli-2).
        if let Some((expected, actual)) = hash_warning {
            eprintln!(
                "trashd: warning: hash mismatch for restored file {}",
                crate::display::printable_path(&restore_to)
            );
            eprintln!("  expected: {}", crate::display::printable(&expected));
            eprintln!("  actual:   {actual}");
            eprintln!("  file may be corrupted — verify contents before use");
        }

        Ok(restore_to)
    }

    /// How many bytes restore lets a compressed entry decompress to: what
    /// `decompress_limit` allows its recorded size. `max_file_size_mb` was
    /// the bound, but it only says what may enter the trash: lowering it
    /// left every larger entry compressed before unrestorable, and
    /// automatic compression never looked at it (store-core-7). It can
    /// still widen the bound, as before, for an entry whose recorded size
    /// is missing or stale.
    fn restore_decompress_limit(&self, recorded_size: Option<u64>) -> u64 {
        let configured = match self.config.max_file_size_mb {
            0 => HARD_DECOMPRESS_LIMIT,
            limit => limit.saturating_mul(1024 * 1024),
        };
        decompress_limit(recorded_size)
            .max(configured)
            .min(HARD_DECOMPRESS_LIMIT)
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
        self.restore_resolved(&mut entry, RestoreTarget::Recorded, true)
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

    /// Empty the trash (across all partitions) and retry detached cleanup.
    /// Return an error when any detached deletion job still cannot finish.
    pub fn empty(&self, max_age_days: Option<u32>) -> Result<u64, TrashError> {
        let selected = self.entries_older_than(max_age_days)?;
        let count = self.empty_entries(&selected, max_age_days);
        let cleanup = self.cleanup_unfinished()?;
        if cleanup.pending > 0 {
            return Err(TrashError::CleanupPending(cleanup.pending));
        }
        Ok(count)
    }

    /// Entries at least `max_age_days` old (all entries for `None`).
    pub fn entries_older_than(
        &self,
        max_age_days: Option<u32>,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        let now = chrono::Local::now();
        // Age is known from the sidecar alone: filter before the data stat
        // so a mostly-young trash does not stat every data inode (and
        // retain every entry) just to discard it.
        let mut entries = self.list_mutation_filtered(|info| match max_age_days {
            Some(days) => now.signed_duration_since(info.deletion_date).num_days() >= days as i64,
            None => true,
        })?;
        // Data whose metadata cannot be parsed has no known age; the purge
        // refuses it too, so the preview matches what is deleted.
        if max_age_days.is_some() {
            entries.retain(|entry| !has_unparsed_sidecar(entry));
        }
        Ok(entries)
    }

    /// Permanently delete exactly `entries`, e.g. the listing a user just
    /// confirmed: re-listing purged items trashed while the prompt waited
    /// (#217). Each entry is identity-checked, so a reused ID is never hit.
    pub fn empty_entries(&self, entries: &[TrashEntry], max_age_days: Option<u32>) -> u64 {
        self.empty_entries_reporting(entries, max_age_days).0
    }

    /// `empty_entries` that also reports how many selected entries could not
    /// be deleted, so callers can report a partial empty as a failure
    /// instead of success (#409). Entries that had already vanished are not
    /// failures: the requested end state was reached.
    pub fn empty_entries_reporting(
        &self,
        entries: &[TrashEntry],
        max_age_days: Option<u32>,
    ) -> (u64, u64) {
        let mut count = 0u64;
        let mut failed = 0u64;
        let mut cache = CacheRefresh::default();
        for entry in entries {
            // Isolation boundary (#428), matching purge_resolved and
            // restore_resolved: an isolated store must not delete an entry
            // that was resolved in another store's trash root.
            if self.isolated && entry.trash_root != self.home {
                failed += 1;
                eprintln!(
                    "trashd: warning: refusing to delete '{}': it belongs to another trash root",
                    crate::display::printable_path(&entry.trashed_path)
                );
                continue;
            }
            let deadline = self.entry_lock_deadline();
            match self.purge_reporting_kind(entry, max_age_days.is_some(), deadline) {
                Ok(was_directory) => cache.note_removal(entry, was_directory),
                Err(e) => {
                    // A refused snapshot is not always a vanished entry: one
                    // compressed or touched since the listing is still in
                    // the trash, and is not deleted (#217) (store-core-6).
                    let reason = match e {
                        TrashError::EntryNotFound(_) if !Self::entry_outlived_snapshot(entry) => {
                            continue;
                        }
                        TrashError::EntryNotFound(_) => {
                            "it changed after it was selected; run `trash empty` again".into()
                        }
                        e => e.to_string(),
                    };
                    eprintln!(
                        "trashd: warning: could not delete '{}': {}",
                        crate::display::printable_path(&entry.trashed_path),
                        crate::display::printable(&reason)
                    );
                    failed += 1;
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
        (count, failed)
    }

    /// Whether the entry a refused snapshot names is still in the trash:
    /// its sidecar still records the same original path and deletion date,
    /// so it changed (was compressed, its sidecar rewritten or touched)
    /// rather than vanished. A sidecar recording anything else belongs to a
    /// different entry trashed under the same ID since (store-core-6).
    fn entry_outlived_snapshot(entry: &TrashEntry) -> bool {
        let Some(mut info) = crate::trashinfo::read_sidecar(&entry.info_path)
            .ok()
            .and_then(|content| TrashInfo::from_trashinfo(&content))
        else {
            return false;
        };
        if !info.original_path.is_absolute() {
            info.original_path =
                Self::topdir_for_trash(&entry.trash_root).join(&info.original_path);
        }
        !entry.orphaned
            && info.original_path == entry.info.original_path
            && info.deletion_date == entry.info.deletion_date
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
        // mount scan serves the sweep and the listing (#353). It probes no
        // network or FUSE mount: retention runs inside rm and the seccomp
        // supervisor, which a stat waiting on a dead server hung
        // (security-4).
        let roots: Vec<PathBuf> = if self.isolated {
            vec![self.home.clone()]
        } else {
            mounts::retention_trash_dirs(&self.home)
                .into_iter()
                .map(|(root, _)| root)
                .collect()
        };
        self.auto_purge_in_roots(&roots)
    }

    fn auto_purge_in_roots(&self, roots: &[PathBuf]) -> Result<(), TrashError> {
        let max_age = self.config.retention.max_age_days;
        let max_size_bytes = self.retention_size_cap();
        let pressure_pct = self.config.retention.disk_pressure_percent;
        // Failure to finish earlier cleanup must not prevent retention of
        // ordinary entries. Explicit cleanup reports these failures instead.
        let _ = self.cleanup_unfinished_in_roots(roots);

        let mut entries = Vec::new();
        self.list_roots(roots, None, &mut entries)?;
        let now = chrono::Local::now();
        // A DeletionDate in the future (clock skew, or media whose author
        // chose it) orders as "just deleted", never as newer than every real
        // entry (store-core-3). Only this pass's snapshots change.
        for entry in &mut entries {
            entry.info.deletion_date = entry.info.deletion_date.min(now);
        }
        newest_first(&mut entries);
        if entries.is_empty() {
            return Ok(());
        }

        // Every entry lock this pass waits for shares one budget: a busy
        // entry is skipped and retried on the next pass (store-core-9).
        let lock_deadline =
            std::time::Instant::now() + self.entry_lock_wait.min(RETENTION_ENTRY_LOCK_BUDGET);
        let cache = std::cell::RefCell::new(CacheRefresh::default());
        let purge = |entry: &TrashEntry| {
            let was_directory = self.purge_reporting_kind(entry, true, lock_deadline)?;
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
        // Opt-in: other file managers restore files/<id> byte for byte, so a
        // compressed entry came back from them as zstd data (store-metadata-5).
        // Cap how much we slurp into RAM (COMPRESS_MAX_BYTES) — this runs
        // (throttled) on routine deletions, and reading a multi-hundred-MB
        // trashed file fully into a Vec could OOM the process (and a killed
        // supervisor degrades to passthrough). Skip anything above the cap.
        let auto_compress = self.config.retention.auto_compress;
        let mut incompressible = IncompressibleData::load(&self.home);
        for i in (0..entries.len()).rev() {
            if !auto_compress || purged[i] || entries[i].orphaned {
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
            // A busy entry is skipped until the next pass.
            let mut input = match lock_entry_file_until(&path, lock_deadline) {
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

        if auto_compress {
            incompressible.save();
        }

        // Size and pressure trimming act only on roots on the home
        // filesystem. Pressure is measured there, so only those entries can
        // relieve it (#113); and bytes in a root elsewhere (removable media,
        // whose author controls sizes and dates) must never justify purging
        // the home trash (store-core-3). One device lookup per root.
        let home_device = mounts::device_id_or_parent(&self.home);
        let root_devices = std::cell::RefCell::new(std::collections::HashMap::new());
        let on_home_filesystem = |root: &Path| {
            home_device.is_some()
                && *root_devices
                    .borrow_mut()
                    .entry(root.to_path_buf())
                    .or_insert_with(|| mounts::device_id_or_parent(root))
                    == home_device
        };
        // Recent entries are never eligible: moving a file into the trash
        // frees nothing, and purging the entry an `rm` just created turned it
        // into a permanent delete (#201, store-core-2). Nor is data whose
        // metadata cannot be parsed: its age is unknown.
        let eligible = |entry: &TrashEntry| {
            now.signed_duration_since(entry.info.deletion_date) >= PRESSURE_MIN_AGE
                && on_home_filesystem(&entry.trash_root)
                && !has_unparsed_sidecar(entry)
        };

        // Phase 2b: trim by total size (purge oldest eligible until under limit)
        // max_size_gb == 0 means "no size limit", not "trim everything to 0";
        // without a limit nothing needs sizing (foreign trees are walked).
        // Keep these measurements for this pass only. Foreign trees may need
        // a full walk; measuring them again when choosing victims doubled
        // that work without providing a coherent newer snapshot (#384).
        if max_size_bytes > 0 {
            let mut sizes = vec![0; entries.len()];
            let mut total_size = 0u64;
            for (i, entry) in entries.iter().enumerate() {
                if !purged[i] && on_home_filesystem(&entry.trash_root) {
                    sizes[i] = self.entry_disk_size(entry);
                    // An entry larger than the whole cap could only fit by
                    // purging it alone: counting it purged every other entry
                    // and then it too (store-core-2). Trashing one is refused;
                    // one already here (a lowered cap, another tool's) is
                    // left to age-based retention.
                    if sizes[i] <= max_size_bytes {
                        total_size = total_size.saturating_add(sizes[i]);
                    }
                }
            }
            let excess = total_size.saturating_sub(max_size_bytes);
            let victims: Vec<usize> = if excess > 0 {
                (0..entries.len())
                    .rev()
                    .filter(|&i| !purged[i] && sizes[i] <= max_size_bytes && eligible(&entries[i]))
                    .collect()
            } else {
                Vec::new()
            };
            // Purging older entries that cannot bring the trash under the cap
            // only loses them; wait until enough entries are old enough.
            let available = victims
                .iter()
                .fold(0u64, |sum, &i| sum.saturating_add(sizes[i]));
            if excess > 0 && available >= excess {
                let mut freed = 0u64;
                for i in victims {
                    if freed >= excess {
                        break;
                    }
                    // Only count a purge that actually happened: a failed
                    // removal must stay in the accounting (and out of the
                    // freed total), or the trash silently exceeds
                    // max_size_gb (#106).
                    if purge(&entries[i]).is_ok() {
                        freed = freed.saturating_add(sizes[i]);
                        purged[i] = true;
                        purge_count += 1;
                    }
                }
            }
        }

        // Phase 3: disk pressure — purge oldest 10% of surviving items.
        if pressure_pct > 0
            && let Some(usage_pct) = disk_usage_percent(&self.home)
            && usage_pct >= pressure_pct as f64
        {
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

    /// Retire the exact listed snapshot, never a newly resolved reused ID.
    pub fn purge_resolved(&self, entry: &TrashEntry) -> Result<(), TrashError> {
        self.purge_resolved_with_maintenance(entry, false)
    }

    fn purge_resolved_with_maintenance(
        &self,
        entry: &TrashEntry,
        maintain: bool,
    ) -> Result<(), TrashError> {
        // Mirror restore_resolved's isolation boundary (#428): an isolated
        // store is confined to its own root, so it must refuse an entry that
        // was resolved through another store's trash — otherwise
        // open_isolated (the destructive-test API) could permanently delete
        // foreign roots' data. Listing can never yield such an entry (an
        // isolated store scans only its own root), so this only guards
        // callers handing in entries from elsewhere. Retention over roots
        // given explicitly to auto_purge_in_roots still crosses roots.
        if self.isolated && entry.trash_root != self.home {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        let was_directory = self.purge_reporting_kind(entry, false, self.entry_lock_deadline())?;
        if maintain {
            self.refresh_cache_after_removal(entry, was_directory);
        }
        Ok(())
    }

    /// When an explicit command stops waiting for an entry lock.
    fn entry_lock_deadline(&self) -> std::time::Instant {
        std::time::Instant::now() + self.entry_lock_wait
    }

    /// Purge one validated entry; true when its data was a directory. A purge
    /// `by_age` (retention, `empty --older`) never takes data whose sidecar
    /// exists but cannot be parsed: its age is unknown (`has_unparsed_sidecar`).
    /// An entry still locked at `lock_deadline` is busy (`WouldBlock`).
    fn purge_reporting_kind(
        &self,
        entry: &TrashEntry,
        by_age: bool,
        lock_deadline: std::time::Instant,
    ) -> Result<bool, TrashError> {
        let (data_name, info_name) = entry_names(entry)?;
        // The entry lock goes through a files/ that follows no symlink too:
        // by path it opened and locked whatever a symlink named (security-1).
        let _data_lock = match open_store_child(&entry.trash_root, c"files")
            .and_then(|files| lock_entry_file_at(files.as_raw_fd(), &data_name, lock_deadline))
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let guard = self.lock_trash_root_repaired(&entry.trash_root)?;
        let (data, sidecar) = self.validated_entry_metadata_locked(entry, &guard)?;
        // The lock serializes this purge only if it holds the data the root
        // lock just validated.
        if let (Some(lock), Some(data)) = (&_data_lock, &data)
            && stat_identity(&stat_fd(lock.as_raw_fd())?) != (data.dev(), data.ino())
        {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        if by_age && entry.orphaned && sidecar.as_ref().is_some_and(fs::Metadata::is_file) {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        // A phantom entry (neither data nor sidecar on disk) must not
        // report a successful purge of nothing (#247).
        if data.is_none() && sidecar.is_none() {
            return Err(TrashError::EntryNotFound(entry.id.clone()));
        }
        let was_directory = data.as_ref().is_some_and(|metadata| metadata.is_dir());
        // Detach data and sidecar under the lock; delete them after releasing
        // it (`Detached`, store-core-4). Raw syscalls throughout: the libc
        // wrappers are hooked by the system-wide preload, which multiplied a
        // large purge's syscalls by ~13 while only deciding to leave trash
        // internals alone (#335).
        // Detached through the lock's descriptors (security-1).
        let mut detached = Detached::open_in(&guard)?;
        match data {
            Some(_) => detached.take_at(guard.files().as_raw_fd(), &data_name)?,
            None if data_absence_is_retired(&entry.info_path) => {}
            None => return Err(io::Error::from(io::ErrorKind::NotFound).into()),
        }
        let sidecar = match detached.take_at(guard.info().as_raw_fd(), &info_name) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
        drop(guard);
        drop(_data_lock);
        if let Err(error) = detached.remove() {
            // Retention retries it; the entry itself is gone.
            eprintln!(
                "trashd: warning: purged '{}' but could not delete all of its data yet ({error}); it is retried later",
                crate::display::printable(&entry.id)
            );
        }
        sidecar?;
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
                pending_cleanup: self.pending_cleanup_in_root(dir)?,
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
                    pending_cleanup: 0,
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
                directory_accounted_size(
                    &entry.trashed_path,
                    entry.info.size,
                    entry.trash_root != self.home,
                )
            }
            // A sparse file claims any apparent size while occupying nothing:
            // in a root others may write, count no more than its allocated
            // blocks (store-core-3).
            Some(m) if entry.trash_root != self.home => m.len().min(m.blocks().saturating_mul(512)),
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

    fn exclusion(&self, path: &Path) -> Option<ExclusionKind> {
        if self.isolated {
            self.config.exclusion_configured(path)
        } else {
            self.config.exclusion(path)
        }
    }

    /// Access config (for shim process bypass checking).
    pub fn config(&self) -> &Config {
        &self.config
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

#[derive(Debug, Clone)]
pub struct PartitionStatus {
    pub trash_dir: PathBuf,
    pub label: String,
    pub total_size: u64,
    pub count: usize,
    /// Detached deletion jobs still occupying private state. Excluded from
    /// ordinary item counts and sizes because they were already purged.
    pub pending_cleanup: usize,
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
fn write_claimed_sidecar(claim: &mut fs::File, info: &TrashInfo) -> io::Result<()> {
    claim.write_all(info.to_trashinfo_string().as_bytes())
}

/// The claim goes through the directories `guard` validated (security-2);
/// `trash_dir` only names the returned sidecar path.
fn unique_id_atomic(
    trash_dir: &Path,
    guard: &RootMutationGuard,
    base_name: &str,
) -> Result<(String, PathBuf, fs::File), TrashError> {
    let name_max = crate::trash_id::name_max(&trash_dir.join("info"));
    unique_id_atomic_within(trash_dir, guard, base_name, name_max)
}

/// `unique_id_atomic` with ids sized for a NAME_MAX of `name_max`. A name
/// the filesystem still refuses as too long is claimed again shorter: it is
/// no storage failure (cross-layer-6).
fn unique_id_atomic_within(
    trash_dir: &Path,
    guard: &RootMutationGuard,
    base_name: &str,
    mut name_max: usize,
) -> Result<(String, PathBuf, fs::File), TrashError> {
    loop {
        match claim_unique_id(trash_dir, guard, base_name, name_max) {
            Err(TrashError::Io(error)) if error.raw_os_error() == Some(libc::ENAMETOOLONG) => {
                name_max =
                    crate::trash_id::smaller_name_max(name_max).ok_or(TrashError::Io(error))?;
            }
            claimed => return claimed,
        }
    }
}

fn claim_unique_id(
    trash_dir: &Path,
    guard: &RootMutationGuard,
    base_name: &str,
    name_max: usize,
) -> Result<(String, PathBuf, fs::File), TrashError> {
    let info_dir = trash_dir.join("info");
    let (files, info) = (guard.files().as_raw_fd(), guard.info().as_raw_fd());
    let occupied = |data: &CStr| stat_at(files, data, libc::AT_SYMLINK_NOFOLLOW).is_ok();

    // Room for ".trashinfo" and a collision suffix within NAME_MAX.
    let base_name = crate::trash_id::base_within(base_name, name_max);

    // Claim `candidate`: create info/<candidate>.trashinfo with O_EXCL AND
    // verify files/<candidate> is free. Ok(Some) = claimed; Ok(None) = taken,
    // try another; Err = fatal IO error.
    let try_claim = |candidate: &str| -> Result<Option<(PathBuf, fs::File)>, io::Error> {
        // An orphaned data file occupying files/<candidate> is skipped before
        // its info name is claimed: releasing a claim unlinks, which under
        // the root lock traps into a seccomp supervisor that may be waiting
        // for that lock (store-core-4).
        let data = CString::new(candidate)?;
        if occupied(&data) {
            return Ok(None);
        }
        let sidecar = format!("{candidate}.trashinfo");
        let sidecar_name = CString::new(sidecar.as_bytes())?;
        let info_path = info_dir.join(&sidecar);
        match crate::fdops::create_excl_at(info, &sidecar_name, 0o600) {
            Ok(claim) => {
                if occupied(&data) {
                    // Data appeared at files/<candidate> after the check
                    // (another tool). Release the info we claimed and try a
                    // different id rather than overwrite it: detached, it is
                    // deleted by the next sweep, outside the lock.
                    let released = Detached::open_in(guard)
                        .and_then(|mut released| released.take_at(info, &sidecar_name));
                    if released.is_err() {
                        let _ = raw_unlinkat(info, &sidecar_name, 0);
                    }
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
    let mut names = crate::trash_id::CollisionNames::new(base_name, &ts, name_max);
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
        #[cfg(test)]
        crate::fdops::repair_probe::run(path);
        // Through the directory just checked, never by path: chmod(2)
        // follows a symlink that a FUSE or NFS server can answer for the
        // next lookup, which made the caller chmod any file (security-3).
        crate::fdops::fchmod_pinned_dir(
            libc::AT_FDCWD,
            &CString::new(path.as_os_str().as_bytes())?,
            (meta.dev(), meta.ino()),
            0o700,
        )?;
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

/// Put back the info/ of the trash root at `root`, where the root and its
/// files/ are real directories of `uid` with mode 0700 and nothing is at
/// info/. Nothing else is created or repaired: a purge never makes a store,
/// and an info/ that is there but is not private stays for the lock to
/// refuse. Through a descriptor of the validated root, never its path.
fn restore_missing_info_dir(root: &Path, uid: u32) -> io::Result<()> {
    let private = |directory: &fs::File| {
        directory
            .metadata()
            .is_ok_and(|meta| meta.is_dir() && meta.uid() == uid && meta.mode() & 0o777 == 0o700)
    };
    let root_dir = crate::fdops::open_dir_nofollow_at(
        libc::AT_FDCWD,
        &CString::new(root.as_os_str().as_bytes())?,
    )?;
    let files = crate::fdops::open_dir_nofollow_at(root_dir.as_raw_fd(), c"files")?;
    if !private(&root_dir) || !private(&files) {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    // Fails on anything already there, a dangling symlink included.
    if unsafe { libc::mkdirat(root_dir.as_raw_fd(), c"info".as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Whatever the umask left of the mode.
    let info = crate::fdops::open_dir_nofollow_at(root_dir.as_raw_fd(), c"info")?;
    if unsafe { libc::fchmod(info.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
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

/// The most plaintext retention's automatic compression reads into memory.
const COMPRESS_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// No entry decompresses to more than this, whatever its sidecar records.
const HARD_DECOMPRESS_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

/// How many bytes a compressed entry may decompress to under any
/// configuration: the size its sidecar recorded when it was trashed, at
/// least what automatic compression accepts and at most 4 GiB. A compressor
/// leaves alone what is larger.
pub fn decompress_limit(recorded_size: Option<u64>) -> u64 {
    recorded_size
        .unwrap_or(0)
        .clamp(COMPRESS_MAX_BYTES, HARD_DECOMPRESS_LIMIT)
}

/// Decompress a marked entry with bounded memory and bounded output. The
/// compressed source remains untouched until a complete plaintext sibling has
/// been written, synced, and the entry identity has been revalidated.
/// An entry lock still held at `lock_deadline` makes the entry busy.
fn decompress_zstd_entry(
    entry: &mut TrashEntry,
    max_output: u64,
    lock_deadline: std::time::Instant,
) -> io::Result<()> {
    decompress_before_commit(entry, max_output, lock_deadline, || {})
}

fn decompress_before_commit(
    entry: &mut TrashEntry,
    max_output: u64,
    lock_deadline: std::time::Instant,
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
    lock_entry_data_until(&input, lock_deadline)?;
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

/// Whether `path` is a regular sidecar that parses as trash metadata.
fn sidecar_parses(path: &Path) -> bool {
    crate::trashinfo::read_sidecar(path)
        .ok()
        .and_then(|content| TrashInfo::from_trashinfo(&content))
        .is_some()
}

/// An orphan whose sidecar path holds a regular file: its metadata exists
/// but could not be parsed (a corrupt file, a claim torn by a crash), so its
/// age is unknown and the data may be recoverable by hand. Retention never
/// purges it, matching fsck; an explicit purge still may.
fn has_unparsed_sidecar(entry: &TrashEntry) -> bool {
    entry.orphaned
        && fs::symlink_metadata(&entry.info_path).is_ok_and(|metadata| metadata.is_file())
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
    hash_file_verified_at(
        libc::AT_FDCWD,
        &CString::new(path.as_os_str().as_bytes())?,
        algorithm,
        expect,
    )
}

/// `hash_file_verified` of the entry `name` of the directory `dir`.
fn hash_file_verified_at(
    dir: RawFd,
    name: &CStr,
    algorithm: &str,
    expect: (u64, u64),
) -> io::Result<String> {
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
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
    // 64KiB is past the point of read-syscall amortization for page-cache
    // files; a 256KiB buffer only adds first-touch page faults per call.
    const CHUNK: usize = 64 * 1024;
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
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(digest.len() * 2);
            for b in digest.iter() {
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
            Ok(out)
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
/// The tree is `name` in the directory `dir`.
fn tree_sizes_at(dir: RawFd, name: &CStr) -> EntrySizes {
    tree_survey_at(dir, name, false).sizes()
}

/// Allocated bytes of the tree at `path`, for a directorysizes row: the
/// survey's, so a rebuilt row equals the one recorded with the entry
/// (store-metadata-9).
pub(crate) fn tree_allocated_bytes(path: &Path) -> u64 {
    CString::new(path.as_os_str().as_bytes()).map_or(0, |name| {
        tree_survey_at(libc::AT_FDCWD, &name, false).allocated
    })
}

/// Replace the sidecar `name` of a locked root's info/ (`dir`, the lock's
/// descriptor) with `info`, through a temporary file beside it: the
/// `write_trashinfo_atomic` of a freshly published entry, which by path
/// wrote wherever a symlinked info/ pointed (security-2).
fn replace_sidecar_at(dir: RawFd, name: &CStr, info: &TrashInfo) -> io::Result<()> {
    for attempt in 0u32..64 {
        let staged = CString::new(format!(
            ".trashd-sidecar-{}-{attempt}.tmp",
            std::process::id()
        ))?;
        let mut file = match crate::fdops::create_excl_at(dir, &staged, 0o600) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            opened => opened?,
        };
        let published = file
            .write_all(info.to_trashinfo_string().as_bytes())
            .and_then(|()| {
                if unsafe { libc::renameat(dir, staged.as_ptr(), dir, name.as_ptr()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        if published.is_err() {
            let _ = raw_unlinkat(dir, &staged, 0);
        }
        return published;
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

/// A directory tree's apparent and allocated sizes and, when looked for,
/// the first mount point found below it (relative to the tree), which ends
/// the walk.
#[derive(Default)]
struct TreeSurvey {
    /// The lengths of the tree's files.
    apparent: u64,
    /// The blocks of its files and of its directories themselves, the root
    /// included, as `du -B1` counts them (store-metadata-9).
    allocated: u64,
    mount: Option<PathBuf>,
    /// Part of the tree could not be walked (unreadable, out of
    /// descriptors): a mount there was not seen.
    incomplete: bool,
    /// The walk ran out of descriptors, so the sizes lack an unknown part
    /// of a tree that can be measured (store-fs-1).
    exhausted: bool,
}

impl TreeSurvey {
    /// A tree whose root could not even be opened.
    fn unwalked(error: io::Error) -> Self {
        let mut survey = Self::default();
        survey.unseen(error);
        survey.incomplete = true;
        survey
    }

    /// Note a part of the tree that could not be walked. A name that
    /// vanished after it was listed is no part of it.
    fn unseen(&mut self, error: io::Error) {
        match error.raw_os_error() {
            Some(libc::ENOENT) => {}
            Some(libc::EMFILE | libc::ENFILE) => {
                self.incomplete = true;
                self.exhausted = true;
            }
            _ => self.incomplete = true,
        }
    }

    /// The sizes an entry records. A walk that ran out of descriptors
    /// records none: X-Trashd-Size is trusted as it stands for the life of
    /// a home-trash entry, and without one accounting measures the tree.
    fn sizes(&self) -> EntrySizes {
        EntrySizes {
            apparent: (!self.exhausted).then_some(self.apparent),
            allocated: (!self.exhausted).then_some(self.allocated),
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

/// What a new entry records of its size: `X-Trashd-Size` (apparent bytes)
/// and, for a directory, its directorysizes row (allocated bytes). None
/// where they are not known.
#[derive(Clone, Copy)]
struct EntrySizes {
    apparent: Option<u64>,
    allocated: Option<u64>,
}

impl EntrySizes {
    /// Anything but a directory: its length, and no directorysizes row.
    fn of_file(length: u64) -> Self {
        Self {
            apparent: Some(length),
            allocated: None,
        }
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
    let dev = match stat_fd(dir) {
        Ok(root) => {
            survey.allocated = (root.st_blocks as u64).saturating_mul(512);
            root.st_dev
        }
        Err(_) => 0,
    };
    survey_directory(dir, dev, find_mounts, &mut survey);
    survey
}

/// `tree_survey` of the tree `name` in the directory `dir`.
fn tree_survey_at(dir: RawFd, name: &CStr, find_mounts: bool) -> TreeSurvey {
    match open_directory_at(dir, name, true, false) {
        Ok(root) => tree_survey(root.as_raw_fd(), find_mounts),
        Err(error) => TreeSurvey::unwalked(error),
    }
}

/// A directory of the survey: the tree root (borrowed from the caller) or
/// an opened descendant (owned; closed when its level is done).
enum SurveyDir {
    Root(RawFd),
    Owned(fs::File),
}

impl SurveyDir {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Root(fd) => *fd,
            Self::Owned(file) => file.as_raw_fd(),
        }
    }
}

/// One directory the survey is in: its descriptor, and the subdirectories
/// listed in it that are still to be walked, by name.
struct SurveyLevel {
    directory: SurveyDir,
    dev: u64,
    /// The directory's path from the tree's root, to report a mount.
    relative: PathBuf,
    own_mount: std::cell::OnceCell<i32>,
    /// Last one first, each with the identity its statx reported, if it
    /// took one.
    subdirectories: Vec<(CString, Option<(u64, u64)>)>,
    /// The directory was read to its end.
    listed: bool,
}

impl SurveyLevel {
    fn new(directory: SurveyDir, dev: u64, relative: PathBuf) -> Self {
        Self {
            directory,
            dev,
            relative,
            own_mount: std::cell::OnceCell::new(),
            subdirectories: Vec::new(),
            listed: false,
        }
    }

    /// Read on in the directory: measure what is not a directory and queue
    /// the subdirectories. It reads until some are queued and then one
    /// batch more, which finds the end of all but huge directories, so the
    /// walk knows when it descends into the last one. Break on a mount.
    fn list(
        &mut self,
        find_mounts: bool,
        buffer: &mut Vec<u8>,
        batch: &mut Vec<(CString, u8)>,
        survey: &mut TreeSurvey,
    ) -> std::ops::ControlFlow<()> {
        let dir = self.directory.as_raw_fd();
        while !self.listed {
            let queued = !self.subdirectories.is_empty();
            match read_entry_batch(dir, buffer, batch) {
                Ok(true) => {}
                Ok(false) => self.listed = true,
                Err(error) => {
                    survey.unseen(error);
                    self.listed = true;
                }
            }
            for (name, kind) in batch.drain(..) {
                if kind == libc::DT_LNK {
                    continue;
                }
                // A directory needs a statx only to be told from a mount.
                let info = if kind == libc::DT_DIR && !find_mounts {
                    None
                } else {
                    let mut mask = libc::STATX_TYPE;
                    if kind != libc::DT_DIR {
                        mask |= libc::STATX_SIZE | libc::STATX_BLOCKS;
                    }
                    if find_mounts {
                        mask |= libc::STATX_INO;
                    }
                    match mounts::entry_info_at(dir, &name, mask) {
                        Ok(info) => Some(info),
                        Err(error) => {
                            survey.unseen(error);
                            continue;
                        }
                    }
                };
                let format = info
                    .as_ref()
                    .map_or(libc::S_IFDIR, |info| info.mode & libc::S_IFMT);
                if format == libc::S_IFLNK {
                    continue;
                }
                if let Some(info) = &info {
                    if find_mounts && survey_mount(dir, self.dev, &self.own_mount, &name, info) {
                        survey.mount = Some(self.relative.join(OsStr::from_bytes(name.to_bytes())));
                        return std::ops::ControlFlow::Break(());
                    }
                    if format != libc::S_IFDIR {
                        survey.apparent = survey.apparent.saturating_add(info.size);
                        survey.allocated = survey
                            .allocated
                            .saturating_add(info.blocks.saturating_mul(512));
                        continue;
                    }
                }
                let identity = info
                    .filter(|_| find_mounts)
                    .map(|info| (info.dev, info.ino));
                self.subdirectories.push((name, identity));
            }
            if queued {
                break;
            }
        }
        // Depth-first in listing order: the first-listed subdirectory's
        // whole subtree completes before its siblings.
        self.subdirectories.reverse();
        std::ops::ControlFlow::Continue(())
    }
}

fn survey_directory(dir: RawFd, dev: u64, find_mounts: bool, survey: &mut TreeSurvey) {
    // An explicit stack instead of recursion: no depth cap can truncate a
    // real tree's size (#429). A directory's subdirectories wait as names
    // and each is opened when the walk reaches it. Opened while their
    // parent was listed, a directory with more subdirectories than the
    // descriptor limit was sized without most of them (store-fs-1). A level
    // holds its one descriptor only while something is left to list in it,
    // so a chain of directories needs one however deep. A tree both deep
    // and branching at every level can still exhaust the limit: it degrades
    // to `incomplete`, like an unreadable directory, and to `exhausted`.
    let mut levels = vec![SurveyLevel::new(SurveyDir::Root(dir), dev, PathBuf::new())];
    let mut buffer = Vec::with_capacity(DIRENT_BUFFER);
    let mut batch = Vec::new();
    while let Some(level) = levels.last_mut() {
        let Some((name, listed_as)) = level.subdirectories.pop() else {
            if level.listed {
                levels.pop();
            } else if level
                .list(find_mounts, &mut buffer, &mut batch, survey)
                .is_break()
            {
                // The tree's mount ended the walk: nothing else counts.
                return;
            }
            continue;
        };
        let opened = open_directory_at(level.directory.as_raw_fd(), &name, true, false)
            .and_then(|child| Ok((stat_fd(child.as_raw_fd())?, child)));
        let (stat, child) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                survey.unseen(error);
                continue;
            }
        };
        // The name can be replaced between its statx and the open: only the
        // directory found not to be a mount is walked.
        if listed_as.is_some_and(|identity| identity != stat_identity(&stat)) {
            survey.incomplete = true;
            continue;
        }
        survey.allocated = survey
            .allocated
            .saturating_add((stat.st_blocks as u64).saturating_mul(512));
        let child = SurveyLevel::new(
            SurveyDir::Owned(child),
            stat.st_dev,
            level.relative.join(OsStr::from_bytes(name.to_bytes())),
        );
        if level.listed && level.subdirectories.is_empty() {
            levels.pop();
        }
        levels.push(child);
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
/// With `allocated`, a file counts no more than its allocated blocks, so
/// sparse files in a root others may write cannot inflate it (store-core-3).
fn directory_accounted_size(path: &Path, ceiling: Option<u64>, allocated: bool) -> u64 {
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
            libc::STATX_TYPE | libc::STATX_SIZE | libc::STATX_INO | libc::STATX_BLOCKS,
        ) else {
            continue;
        };
        let format = info.mode & libc::S_IFMT;
        if format == libc::S_IFLNK || survey_mount(directory, level.dev, &level.mount, &name, &info)
        {
            continue;
        }
        if format != libc::S_IFDIR {
            let size = if allocated {
                info.size.min(info.blocks.saturating_mul(512))
            } else {
                info.size
            };
            total = total.saturating_add(size);
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
    #[cfg(test)]
    TREE_STATUS_PROBE.with_borrow(|probe| {
        if let Some(probe) = probe {
            probe(name);
        }
    });
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
    // Another remover may finish this directory first: the sweep of detached
    // jobs runs unlocked beside a purge still removing its tree. A detached
    // tree is private and only shrinks, so a directory gone since its status
    // was read is already removed, not a failure (store-metadata-10).
    let gone = |error: io::Error| match error.raw_os_error() {
        Some(libc::ENOENT) => Ok(None),
        _ => Err(error),
    };
    // Through a descriptor of the directory just statted, never by name: a
    // process that kept a descriptor in a group-writable directory of a
    // trashed tree can still swap entries there, and the path-following
    // retry this replaced chmodded whatever a swapped-in symlink named
    // (store-fs-2). A swapped entry fails here; the next sweep unlinks it.
    if mode & 0o700 != 0o700
        && let Err(error) = crate::fdops::fchmod_pinned_dir(parent, name, identity, 0o700)
    {
        return gone(error);
    }
    let directory = match open_directory_at(parent, name, true, false) {
        Ok(directory) => directory,
        Err(error) => return gone(error),
    };
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

/// A test hook called with the name a store operation is about to act on.
#[cfg(test)]
type NameProbe = std::cell::RefCell<Option<Box<dyn Fn(&CStr)>>>;

#[cfg(test)]
thread_local! {
    /// Runs before every store-internal unlink on this thread, with the
    /// name being unlinked: tests check which locks are held (store-core-4).
    static UNLINK_PROBE: NameProbe = const { std::cell::RefCell::new(None) };
    /// Runs once a tree removal has read a directory's status, before it
    /// changes or opens it: tests act as a concurrent remover there.
    static TREE_STATUS_PROBE: NameProbe = const { std::cell::RefCell::new(None) };
    /// The errno every RENAME_NOREPLACE fails with on this thread, as on a
    /// filesystem without the flag (NFS, 9p).
    static NOREPLACE_ERRNO: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    /// What a restore by copy did on this thread, in order: "sync" once the
    /// destination was made durable, "retire" before the trash copy goes.
    static RESTORE_COPY_EVENTS: std::cell::RefCell<Vec<&'static str>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// The errno making a restored copy durable fails with on this thread.
    static DESTINATION_SYNC_ERRNO: std::cell::Cell<Option<i32>> =
        const { std::cell::Cell::new(None) };
}

/// unlinkat(2) as a raw syscall. Store-internal removals must never go
/// through the interposable libc wrapper: under a system-wide LD_PRELOAD the
/// hook would trash them again (#104, #192, #196).
fn raw_unlinkat(parent: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    #[cfg(test)]
    UNLINK_PROBE.with_borrow(|probe| {
        if let Some(probe) = probe {
            probe(name);
        }
    });
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

/// How long an explicit command (purge, empty, restore, compress) waits for
/// an entry lock before it reports the entry busy. trashd's own holders keep
/// it for at most a few seconds (encoding up to 64 MiB and syncing it); a
/// longer hold is a process that flock()ed the file before it was deleted:
/// the lock moved into the trash with the inode (store-core-9, cli-8).
pub const ENTRY_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The most one retention pass waits for entry locks in total. Retention
/// skips a busy entry and retries it on its next pass; in the seccomp
/// supervisor it runs on the thread that answers every trapped delete.
const RETENTION_ENTRY_LOCK_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// flock(LOCK_EX) on `file`, retrying a contended lock until `deadline`.
/// At least one attempt is made; expiry is a `WouldBlock` error. Polling
/// rather than blocking: a blocking flock waited forever on a holder outside
/// trashd (store-core-9).
pub(crate) fn lock_file_until(file: &fs::File, deadline: std::time::Instant) -> io::Result<()> {
    let mut pause = std::time::Duration::from_millis(1);
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {}
            _ => return Err(error),
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(error);
        }
        std::thread::sleep(pause.min(left));
        pause = (pause * 2).min(std::time::Duration::from_millis(50));
    }
}

/// [`lock_file_until`] on an entry's data, which reports expiry as a busy
/// entry. Public for the CLI compressor, which serializes on the same lock.
pub fn lock_entry_data_until(file: &fs::File, deadline: std::time::Instant) -> io::Result<()> {
    lock_file_until(file, deadline).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "the trash entry is busy: another process holds a lock on it",
            )
        } else {
            error
        }
    })
}

/// Take an exclusive flock on an entry's data. Restore holds it across its
/// identity check → publication and both compressors hold it across their
/// validate → swap (through the marker write and data swap, #170), so
/// "validated" can never interleave with "renamed" — the #105 revalidations
/// alone left that window open (#168). Purge takes it too, so a directory
/// entry is locked as well: restore copies one across filesystems, and the
/// copy fallbacks retire their source, without the root lock (store-core-4).
/// The wait ends at `deadline` with a busy (`WouldBlock`) error, never an
/// indefinite block (store-core-9). Symlinks and special files are never
/// opened: Ok(None). Any open error means the entry vanished or changed;
/// callers map that to EntryNotFound.
fn lock_entry_file_until(
    path: &Path,
    deadline: std::time::Instant,
) -> io::Result<Option<fs::File>> {
    lock_entry_file_at(
        libc::AT_FDCWD,
        &CString::new(path.as_os_str().as_bytes())?,
        deadline,
    )
}

/// `lock_entry_file_until` for the entry `name` of the directory `dir`.
fn lock_entry_file_at(
    dir: RawFd,
    name: &CStr,
    deadline: std::time::Instant,
) -> io::Result<Option<fs::File>> {
    let metadata = stat_at(dir, name, libc::AT_SYMLINK_NOFOLLOW)?;
    let directory = match metadata.st_mode & libc::S_IFMT {
        libc::S_IFDIR => libc::O_DIRECTORY,
        libc::S_IFREG => 0,
        _ => return Ok(None),
    };
    // O_NONBLOCK like every other entry-data open (#111): a FIFO swapped
    // into the path in the TOCTOU window must not hang the caller.
    let opened = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | directory,
        )
    };
    let opened = if opened < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(opened) })
    };
    let file = match opened {
        Ok(file) => file,
        // Data its owner cannot read (mode 000/200/300) cannot be compressed
        // either, so there is nothing to serialize against; refusing made
        // such an entry impossible to restore or purge (#335).
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    match lock_entry_data_until(&file, deadline) {
        Ok(()) => Ok(Some(file)),
        // Where a directory cannot be locked (NFS emulates flock with write
        // locks, and a directory is never open for writing), it is purged
        // and restored unlocked, as before directories took this lock.
        Err(error)
            if directory != 0
                && matches!(
                    error.raw_os_error(),
                    Some(libc::EBADF | libc::ENOLCK | libc::EOPNOTSUPP | libc::EINVAL)
                ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Lock the data a copy fallback just published as `files/<id>` before it
/// releases the root lock to retire the source: purge waits for (and then
/// reports busy) an entry whose source is still being retired, so it can
/// never delete the fresh copy and leave the retirement to delete the only
/// other one (#243). Never waits: a holder already queued for the root lock
/// would deadlock with us. Without the lock the retirement proceeds as a
/// move followed by that purge.
fn lock_published_copy(files: RawFd, id: &CStr) -> Option<fs::File> {
    let status = stat_at(files, id, libc::AT_SYMLINK_NOFOLLOW).ok()?;
    let directory = match status.st_mode & libc::S_IFMT {
        libc::S_IFDIR => libc::O_DIRECTORY,
        libc::S_IFREG => 0,
        _ => return None,
    };
    let fd = unsafe {
        libc::openat(
            files,
            id.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | directory,
        )
    };
    if fd < 0 {
        return None;
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    (unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(file)
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
/// that appeared at the destination. The raw syscall, as the supervisor's
/// move has always been.
fn rename_noreplace_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
) -> io::Result<()> {
    #[cfg(test)]
    if let Some(errno) = NOREPLACE_ERRNO.get() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    crate::fdops::rename_noreplace_at(src_parent, src_name, dst_parent, dst_name)
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

/// How a staged copy may take its final name on a filesystem without
/// RENAME_NOREPLACE (NFS, 9p, FUSE without rename2).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Publication {
    /// Into the user's tree (restore): nothing there may be replaced, and
    /// no directory operation guarantees that, so a directory is refused.
    Strict,
    /// Into the files/ of a locked private trash root, under an id its
    /// claim in info/ reserved: nobody else creates names there, so a
    /// directory may be renamed over one made exclusively for it.
    PrivateRoot,
}

/// Copy one source node into the trash for the cross-device path:
/// `dst_parent` is the files/ of a trash root whose lock the caller holds,
/// `dst_name` an id claimed in it. Device nodes and sockets cannot be
/// reproduced, so they abort the copy and nothing is retired, instead of
/// being skipped and then deleted (#192).
fn copy_source_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    staging_parent: RawFd,
    source: &libc::stat,
) -> io::Result<(u64, u64)> {
    match source.st_mode & libc::S_IFMT {
        libc::S_IFREG | libc::S_IFDIR => copy_staged_at_with_rename(
            src_parent,
            src_name,
            dst_parent,
            dst_name,
            staging_parent,
            source,
            Publication::PrivateRoot,
            rename_noreplace_at,
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
/// This is the restore direction (`Publication::Strict`); `copy_source_at`
/// is the trash direction.
fn copy_staged_at(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    staging_parent: RawFd,
    source: &libc::stat,
) -> io::Result<(u64, u64)> {
    copy_staged_at_with_rename(
        src_parent,
        src_name,
        dst_parent,
        dst_name,
        staging_parent,
        source,
        Publication::Strict,
        rename_noreplace_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn copy_staged_at_with_rename(
    src_parent: RawFd,
    src_name: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    staging_parent: RawFd,
    source: &libc::stat,
    publication: Publication,
    rename: impl FnOnce(RawFd, &CStr, RawFd, &CStr) -> io::Result<()>,
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
    let published = match rename(staging_parent, &staging, dst_parent, dst_name) {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
            ) =>
        {
            publish_without_noreplace(
                staging_parent,
                &staging,
                dst_parent,
                dst_name,
                source,
                identity,
                publication,
            )
        }
        result => result,
    };
    if let Err(error) = published {
        let _ = remove_created_tree_at(staging_parent, &staging, identity);
        return Err(error);
    }
    Ok(identity)
}

/// Publication where RENAME_NOREPLACE is unsupported: regular files can be
/// linked exclusively. There is no equivalent directory operation: a plain
/// rename could replace a competing empty directory after any absence
/// check, so a directory is published only into a private trash root
/// (`Publication`). `staged` is the identity of the staged copy.
fn publish_without_noreplace(
    staging_parent: RawFd,
    staging: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    source: &libc::stat,
    staged: (u64, u64),
    publication: Publication,
) -> io::Result<()> {
    if source.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return match publication {
            Publication::Strict => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cannot publish a directory without atomic no-replace support; source retained",
            )),
            Publication::PrivateRoot => {
                publish_directory_over_claim(staging_parent, staging, dst_parent, dst_name, staged)
            }
        };
    }
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
    raw_unlinkat(staging_parent, staging, 0)
}

/// Publish a staged directory into the files/ of a private trash root
/// without RENAME_NOREPLACE (store-fs-3). The name is taken with an
/// exclusive mkdir, which fails on anything already there, and the staged
/// tree is then renamed over that directory: rename(2) replaces a directory
/// only while it is empty, so the one thing it can replace is the directory
/// just made. Refusing instead made every recursive delete fail on an NFS
/// or 9p home, each after a full copy.
fn publish_directory_over_claim(
    staging_parent: RawFd,
    staging: &CStr,
    dst_parent: RawFd,
    dst_name: &CStr,
    staged: (u64, u64),
) -> io::Result<()> {
    if unsafe { libc::mkdirat(dst_parent, dst_name.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let claimed = stat_identity(&stat_at(dst_parent, dst_name, libc::AT_SYMLINK_NOFOLLOW)?);
    let published =
        validate_created_node(dst_parent, dst_name, libc::S_IFDIR, claimed).and_then(|()| {
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
        });
    if let Err(error) = published {
        // Only the empty directory made above: `remove_created_at` leaves
        // anything else, and anything in it, where it is.
        let _ = remove_created_at(dst_parent, dst_name, claimed);
        return Err(error);
    }
    if !identity_matches_at(dst_parent, dst_name, staged) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "published trash directory was replaced",
        ));
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
            // Durable before the trash copy goes, or not restored at all.
            if let Err(error) = sync_restored_copy(dst_parent, true) {
                let _ = remove_created_tree_at(dst_parent, dst_name, destination_identity);
                return Err(error);
            }
            // Retire only the exact source nodes captured before the copy.
            // New or replaced children are left in a residual orphan instead
            // of being deleted without ever reaching the destination.
            #[cfg(test)]
            RESTORE_COPY_EVENTS.with_borrow_mut(|events| events.push("retire"));
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
/// Failures (unsupported fs, permissions) never fail the move itself. From
/// a nosuid source, capabilities and `trusted.*` stay behind (security-2).
fn copy_xattrs_fd(source: RawFd, destination: RawFd, nosuid_source: bool) {
    let size = unsafe { libc::flistxattr(source, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return;
    }
    let mut names = vec![0u8; size as usize];
    if unsafe { libc::flistxattr(source, names.as_mut_ptr().cast(), names.len()) } < 0 {
        return;
    }
    for name in names
        .split(|b| *b == 0)
        .filter(|n| !n.is_empty() && !(nosuid_source && crate::fdops::privileged_xattr(n)))
    {
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
    // A copied directory has its source's mode once its children are done.
    // Without u+wx (0555 trees: Go module caches, Nix and Bazel outputs)
    // nothing in it can be unlinked, and the rollback of a copy that failed
    // later left the tree where it was staged: in a restore, hidden beside
    // the destination, where no sweep looks (store-fs-4). It is this copy's
    // own directory: opened up through a descriptor of that very inode.
    if stat.st_mode & 0o700 != 0o700 {
        let _ = crate::fdops::fchmod_pinned_dir(parent, name, expected, 0o700);
    }
    let dir = open_directory_at(parent, name, true, false)?;
    if stat_identity(&stat_fd(dir.as_raw_fd())?) != expected {
        return Ok(());
    }
    // Every child is tried: one that stays must not keep its siblings.
    let mut failure = None;
    for child in read_directory_names(dir.as_raw_fd())? {
        let removed =
            stat_at(dir.as_raw_fd(), &child, libc::AT_SYMLINK_NOFOLLOW).and_then(|child_stat| {
                remove_created_tree_at(dir.as_raw_fd(), &child, stat_identity(&child_stat))
            });
        if let Err(error) = removed
            && error.raw_os_error() != Some(libc::ENOENT)
        {
            failure.get_or_insert(error);
        }
    }
    drop(dir);
    match failure {
        Some(error) => Err(error),
        None => remove_created_at(parent, name, expected),
    }
}

/// Make a restored copy's name in `dst_parent` durable before its trash
/// copy is retired. The copy's data is synced under its staging name, but
/// the rename to its final name is not, and the trash is on another
/// filesystem, which commits on its own: a crash could keep the trash
/// copy's unlink and lose the rename (store-fs-7). A `tree` syncs its
/// filesystem, for the entries of the directories inside it too.
/// `dst_parent` is pinned with O_PATH, which fsync refuses, so the
/// directory is reopened as itself. Where that cannot be done at all (a
/// directory its user may write but not read, a filesystem that syncs no
/// directories) the restore goes on as it did before; a sync that fails
/// is an error.
fn sync_restored_copy(dst_parent: RawFd, tree: bool) -> io::Result<()> {
    let synced = (|| {
        #[cfg(test)]
        if let Some(errno) = DESTINATION_SYNC_ERRNO.get() {
            return Err(io::Error::from_raw_os_error(errno));
        }
        let directory = crate::fdops::open_dir_nofollow_at(dst_parent, c".")?;
        let synced = if tree {
            unsafe { libc::syncfs(directory.as_raw_fd()) }
        } else {
            unsafe { libc::fsync(directory.as_raw_fd()) }
        };
        if synced != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    match synced {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EACCES | libc::EPERM | libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(()) => {
            #[cfg(test)]
            RESTORE_COPY_EVENTS.with_borrow_mut(|events| events.push("sync"));
            Ok(())
        }
    }
}

/// Publication follows the copy's own version check. Recheck the selected
/// source here too: an in-place edit during metadata, sync or publication
/// belongs to the source, not to our earlier restored copy (#396). The
/// published copy is made durable before the source goes; if it cannot be,
/// it is removed and the source stays.
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
    if let Err(error) = sync_restored_copy(dst_parent, false) {
        let _ = remove_created_at(dst_parent, dst_name, destination_identity);
        return Err(error);
    }
    #[cfg(test)]
    RESTORE_COPY_EVENTS.with_borrow_mut(|events| events.push("retire"));
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
        // Set-id bits and capabilities copied off a nosuid filesystem would
        // take effect here (security-2). Directories keep theirs: setgid on
        // one only sets the group of what is created in it.
        let mut applied = *expected;
        let nosuid = crate::fdops::on_nosuid_filesystem(source.as_raw_fd());
        if nosuid {
            applied.st_mode &= !0o6000;
        }
        apply_fd_metadata(
            destination.as_raw_fd(),
            &applied,
            source.as_raw_fd(),
            nosuid,
        )?;
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
        apply_fd_metadata(
            destination.as_raw_fd(),
            expected,
            source.as_raw_fd(),
            crate::fdops::on_nosuid_filesystem(source.as_raw_fd()),
        )?;
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

/// Give the copy `fd` what `source` describes and the open `original` (on
/// a nosuid filesystem or not) carries: its owner, then its extended
/// attributes, then its mode.
fn apply_fd_metadata(
    fd: RawFd,
    source: &libc::stat,
    original: RawFd,
    nosuid_source: bool,
) -> io::Result<()> {
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
    // After the owner, which clears capabilities, and before the mode: a
    // `user.*` attribute needs write permission on the inode, whatever the
    // descriptor was opened for. Set once the copy had its source's mode,
    // every read-only file and directory lost them (store-fs-5).
    copy_xattrs_fd(original, fd, nosuid_source);
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

/// Minimum age before size or disk-pressure trimming may purge an entry
/// (#201, store-core-2).
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

    // security-3: repairing a store directory's mode never follows a symlink
    // swapped in after its owner and type were checked: chmod(2) of the path
    // made the caller chmod any file to 0700.
    #[test]
    fn private_dir_repair_never_follows_a_swapped_symlink() {
        let fixture = TempDir::new().unwrap();
        let uid = unsafe { libc::geteuid() };
        let sentinel = fixture.path().join("sentinel");
        fs::write(&sentinel, b"keep").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o644)).unwrap();
        let dir = fixture.path().join("Trash");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        crate::fdops::repair_probe::swap_for_symlink(&dir, &sentinel);
        let repaired = ensure_private_dir(&dir, uid, false);
        crate::fdops::repair_probe::set(None);
        assert!(repaired.is_err());
        assert_eq!(
            fs::metadata(&sentinel).unwrap().mode() & 0o7777,
            0o644,
            "the repair chmodded the symlink's target"
        );
        // Without a swap the repair still happens.
        fs::remove_file(&dir).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir, uid, false).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o700);
    }

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
            let error =
                decompress_before_commit(&mut entry, 16384, std::time::Instant::now(), || {
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
    fn pending_cleanup_reads_tolerate_secondary_errors_but_preserve_home_errors() {
        let (store, _data, work, _) = test_store();
        fs::write(store.home.join("files/home-entry"), b"home bytes").unwrap();
        fs::create_dir(store.home.join(".trashd/purging-interrupted")).unwrap();
        let foreign = work.path().join("foreign-trash");
        fs::create_dir_all(foreign.join("info")).unwrap();
        fs::create_dir(foreign.join("files")).unwrap();
        fs::write(foreign.join("files/foreign-entry"), b"foreign bytes").unwrap();
        fs::write(foreign.join(".trashd"), b"malformed state directory").unwrap();
        let roots = vec![
            (store.home.clone(), "home".into()),
            (foreign.clone(), "foreign".into()),
        ];
        let partitions = store.status_in_roots(&roots).unwrap();
        assert_eq!(
            partitions
                .iter()
                .map(|partition| partition.count)
                .sum::<usize>(),
            2
        );
        assert_eq!(
            partitions
                .iter()
                .map(|partition| partition.pending_cleanup)
                .sum::<usize>(),
            1
        );
        assert_eq!(store.pending_cleanup().unwrap(), 1);
        assert_eq!(store.pending_cleanup_in_root(&foreign).unwrap(), 0);
        // Read-only tolerance must not conceal failures to perform cleanup.
        assert!(
            store
                .cleanup_unfinished_in_roots(std::slice::from_ref(&foreign))
                .is_err()
        );
        fs::rename(store.home.join(".trashd"), store.home.join("saved-state")).unwrap();
        fs::write(
            store.home.join(".trashd"),
            b"malformed home state directory",
        )
        .unwrap();
        assert!(store.status_in_roots(&roots).is_err());
        assert!(store.pending_cleanup().is_err());
        assert_eq!(
            fs::read(store.home.join("files/home-entry")).unwrap(),
            b"home bytes"
        );
        assert_eq!(
            fs::read(foreign.join("files/foreign-entry")).unwrap(),
            b"foreign bytes"
        );
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
    fn entries_older_than_stats_only_selected_data() {
        let (store, _data, work, _) = test_store();
        for (id, date) in [
            ("old", "2000-01-01T00:00:00"),
            ("young", "2999-01-01T00:00:00"),
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
        store.scan_data_stats.set(0);
        let selected = store.entries_older_than(Some(30)).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "old");
        assert!(selected[0].identity.is_some(), "mutation snapshot");
        assert_eq!(
            store.scan_data_stats.get(),
            1,
            "young entry must be rejected from its sidecar, without a data stat"
        );
        // Selected snapshots still purge for real.
        assert_eq!(store.empty_entries(&selected, Some(30)), 1);
        assert!(!store.home.join("files/old").exists());
        assert!(store.home.join("files/young").exists());
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

    // The absence check can become stale while a copy is staged. Simulate
    // each unsupported atomic-rename result at the publication boundary and
    // create a competing empty directory at exactly that point.
    #[test]
    fn unsupported_directory_publication_keeps_competitors_and_source() {
        for errno in [libc::ENOSYS, libc::EINVAL, libc::EOPNOTSUPP] {
            for competing in [false, true] {
                let (store, _data, work, _) = test_store();
                let source = work.path().join("tree");
                fs::create_dir(&source).unwrap();
                fs::write(source.join("payload"), b"recoverable bytes").unwrap();
                let id = store.trash(&source, None).unwrap();
                let entry = store.find_entry(&id).unwrap();
                let sidecar = fs::read(&entry.info_path).unwrap();
                let destination = work.path().join("restored");
                assert!(!destination.exists());
                let source_parent = fs::File::open(store.home.join("files")).unwrap();
                let source_name = CString::new(id).unwrap();
                let before = stat_at(
                    source_parent.as_raw_fd(),
                    &source_name,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
                .unwrap();
                let destination_parent = fs::File::open(work.path()).unwrap();
                let competitor = std::cell::Cell::new(None);
                let result = copy_staged_at_with_rename(
                    source_parent.as_raw_fd(),
                    &source_name,
                    destination_parent.as_raw_fd(),
                    c"restored",
                    destination_parent.as_raw_fd(),
                    &before,
                    Publication::Strict,
                    |_, _, _, _| {
                        assert!(!destination.exists());
                        if competing {
                            fs::create_dir(&destination).unwrap();
                            fs::set_permissions(&destination, fs::Permissions::from_mode(0o711))
                                .unwrap();
                            let metadata = fs::metadata(&destination).unwrap();
                            competitor.set(Some((metadata.ino(), metadata.mode())));
                        }
                        Err(io::Error::from_raw_os_error(errno))
                    },
                );
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                assert!(error.to_string().contains("atomic no-replace"));
                assert_eq!(
                    fs::metadata(&entry.trashed_path).unwrap().ino(),
                    before.st_ino
                );
                assert_eq!(
                    fs::read(entry.trashed_path.join("payload")).unwrap(),
                    b"recoverable bytes"
                );
                assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
                if let Some((inode, mode)) = competitor.get() {
                    let metadata = fs::metadata(&destination).unwrap();
                    assert_eq!((metadata.ino(), metadata.mode()), (inode, mode));
                    assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
                } else {
                    assert!(!destination.exists());
                }
                assert!(fs::read_dir(work.path()).unwrap().all(|entry| {
                    !entry
                        .unwrap()
                        .file_name()
                        .as_bytes()
                        .starts_with(COPY_STAGE_PREFIX.as_bytes())
                }));
            }
        }
    }

    #[test]
    fn unsupported_regular_publication_keeps_exclusive_link_fallback() {
        for competing in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            let destination = fixture.path().join("restored");
            fs::write(&source, b"source bytes").unwrap();
            let parent = fs::File::open(fixture.path()).unwrap();
            let before = stat_at(parent.as_raw_fd(), c"source", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            let result = copy_staged_at_with_rename(
                parent.as_raw_fd(),
                c"source",
                parent.as_raw_fd(),
                c"restored",
                parent.as_raw_fd(),
                &before,
                Publication::Strict,
                |_, _, _, _| {
                    if competing {
                        fs::write(&destination, b"competing bytes").unwrap();
                    }
                    Err(io::Error::from_raw_os_error(libc::ENOSYS))
                },
            );
            assert_eq!(result.is_ok(), !competing);
            if competing {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EEXIST));
            }
            assert_eq!(fs::read(&source).unwrap(), b"source bytes");
            assert_eq!(
                fs::read(&destination).unwrap(),
                if competing {
                    b"competing bytes".as_slice()
                } else {
                    b"source bytes".as_slice()
                }
            );
            assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 2);
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
        let guard = lock_entry_file_until(&entry.trashed_path, std::time::Instant::now())
            .unwrap()
            .unwrap();

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
                let mut config = Config::default();
                config.retention.auto_compress = true;
                let store2 = TrashStore::open_isolated(&trash, config).unwrap();
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
        let guard = RootMutationGuard::acquire(&root).unwrap();
        for _ in 0..20 {
            let (id, _info, _claim) = unique_id_atomic(&root, &guard, "same").unwrap();
            assert!(ids.insert(id));
        }
        assert_eq!(ids.len(), 20);
        assert_eq!(fs::read(root.join("files/same")).unwrap(), b"orphan");
    }

    // cross-layer-6: a sidecar name the filesystem refuses as too long is a
    // naming problem, not a storage failure: a shorter id is claimed. The
    // budget here is above what the filesystem takes, as a filesystem may
    // report one.
    #[test]
    fn ids_shrink_to_what_the_filesystem_takes() {
        let (store, _data, _workdir, _lock) = test_store();
        let name = "n".repeat(254);
        let guard = RootMutationGuard::acquire(&store.home).unwrap();
        let (first, info, _claim) =
            unique_id_atomic_within(&store.home, &guard, &name, 400).unwrap();
        let (second, _, _) = unique_id_atomic_within(&store.home, &guard, &name, 400).unwrap();
        assert_ne!(first, second);
        assert!(info.exists());
        for id in [first, second] {
            assert!(id.len() + ".trashinfo".len() <= 255, "{}", id.len());
        }
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
            matches!(result, Err(TrashError::Excluded { .. })),
            "*.tmp should be excluded by never_trash"
        );
    }

    /// `test_store` with its own configuration.
    fn configured_store(config: impl FnOnce(&mut Config)) -> (TrashStore, TempDir, TempDir) {
        let (_, data, work, _) = test_store();
        let mut configured = Config::default();
        configured.retention.max_age_days = 0;
        configured.retention.max_size_gb = 0.0;
        configured.retention.disk_pressure_percent = 0;
        config(&mut configured);
        let store = TrashStore::open_isolated(&data.path().join("Trash"), configured).unwrap();
        (store, data, work)
    }

    // common-policy-1/2, shim-1: the store says why a path stays out of the
    // trash. A directory excluded by its own name (a whitelist miss, or a
    // `*~` backup) is then judged entry by entry by the shim, instead of
    // deleted for real as a whole tree.
    #[test]
    fn exclusions_say_why() {
        use std::ffi::OsStr;
        use std::os::fd::AsRawFd;
        let (store, _data, work) = configured_store(|config| {
            config.never_trash = vec!["*~".into()];
            config.only_trash = vec!["src/*".into()];
        });
        let src = work.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("main.rs"), b"fn main() {}").unwrap();
        let backup = work.path().join("thesis~");
        fs::create_dir(&backup).unwrap();
        let kind = |result: Result<String, TrashError>| match result {
            Err(TrashError::Excluded { kind, .. }) => Some(kind),
            other => panic!("not excluded: {other:?}"),
        };
        assert_eq!(
            kind(store.trash(&src, None)),
            Some(ExclusionKind::NotWhitelisted)
        );
        assert_eq!(
            kind(store.trash(&backup, None)),
            Some(ExclusionKind::NeverTrash)
        );
        let parent = fs::File::open(work.path()).unwrap();
        assert_eq!(
            kind(store.trash_at(parent.as_raw_fd(), OsStr::new("src"), &src, None)),
            Some(ExclusionKind::NotWhitelisted)
        );
        // What the whitelist names inside it is trashed.
        store.trash(&src.join("main.rs"), None).unwrap();
    }

    // cross-layer-5: the trash, anything in it and its ancestors are refused
    // even where policy excludes them. Excluded first, `rm -rf ~/.local`
    // under a whitelist deleted the trash for real with everything else.
    #[test]
    fn excluded_trash_and_its_ancestors_are_still_refused() {
        use std::ffi::OsStr;
        use std::os::fd::AsRawFd;
        let (_, data, work, _) = test_store();
        let share = work.path().join("share");
        let mut config = Config {
            only_trash: vec!["*.rs".into()],
            ..Config::default()
        };
        config.retention.max_age_days = 0;
        config.retention.max_size_gb = 0.0;
        config.retention.disk_pressure_percent = 0;
        let store = TrashStore::open_isolated(&share.join("Trash"), config).unwrap();
        drop(data);
        let refused =
            |result: Result<String, TrashError>| matches!(result, Err(TrashError::Refused(_)));
        assert!(refused(store.trash(&share, None)));
        assert!(refused(store.trash(&share.join("Trash/files"), None)));
        let parent = fs::File::open(work.path()).unwrap();
        assert!(refused(store.trash_at(
            parent.as_raw_fd(),
            OsStr::new("share"),
            &share,
            None
        )));
        // Elsewhere the whitelist still decides.
        let other = create_file(work.path(), "notes.txt", "x");
        assert!(matches!(
            store.trash(&other, None),
            Err(TrashError::Excluded { .. })
        ));
    }

    // cross-layer-4: bypass_paths names the deleting process. The store
    // matched its own executable, which inside the shim is the shim: a
    // prefix covering trashd's install directory made every shim operand a
    // real delete while the other layers trashed it.
    #[test]
    fn bypass_paths_never_match_the_stores_own_executable() {
        let exe = fs::read_link("/proc/self/exe").unwrap();
        let prefix = format!("{}/", exe.parent().unwrap().display());
        let (store, _data, work) = configured_store(|config| config.bypass_paths = vec![prefix]);
        let file = create_file(work.path(), "kept.txt", "data");
        store.trash(&file, None).expect("trashed, not excluded");
        assert!(!file.exists());
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
                let locked = matches!(
                    lock_entry_file_until(&unreadable, std::time::Instant::now()),
                    Ok(None)
                );
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
    fn unfinished_cleanup_preserves_ordinary_entries_and_live_work() {
        let (mut store, _data, work, _) = test_store();
        let source = create_file(work.path(), "ordinary", "keep ordinary bytes");
        let id = store.trash(&source, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        // Even ordinary entries eligible for retention stay outside cleanup.
        let mut info = entry.info.clone();
        info.deletion_date -= chrono::Duration::days(90);
        fs::write(&entry.info_path, info.to_trashinfo_string()).unwrap();
        let sidecar = fs::read(&entry.info_path).unwrap();
        store.config.retention.max_age_days = 1;
        let state = store.home.join(".trashd");
        fs::create_dir_all(state.join("purging-interrupted/nested")).unwrap();
        fs::write(
            state.join("purging-interrupted/nested/payload"),
            b"retired bytes",
        )
        .unwrap();
        fs::write(state.join(".trashd-copy-123-456-0"), b"abandoned copy").unwrap();
        let mut abandoned = create_data_stage(store.home_dir()).unwrap();
        abandoned.write_all(b"abandoned encoding").unwrap();
        let (file, path) = abandoned.into_parts();
        let abandoned = path.keep().unwrap();
        drop(file);
        let live = create_data_stage(store.home_dir()).unwrap();
        fs::write(state.join("unknown-state"), b"keep unknown bytes").unwrap();
        let before = store.status_per_partition().unwrap();
        assert_eq!(before[0].count, 1);
        assert_eq!(before[0].pending_cleanup, 1);
        assert!(
            state.join("purging-interrupted/nested/payload").exists(),
            "status mutated pending data"
        );
        let report = store.cleanup_unfinished().unwrap();
        assert_eq!(
            report,
            CleanupReport {
                removed: 3,
                pending: 0
            }
        );
        assert!(!abandoned.exists());
        assert!(live.path().exists());
        assert_eq!(
            fs::read(state.join("unknown-state")).unwrap(),
            b"keep unknown bytes"
        );
        assert_eq!(
            fs::read(&entry.trashed_path).unwrap(),
            b"keep ordinary bytes"
        );
        assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
        assert_eq!(store.status_per_partition().unwrap()[0].pending_cleanup, 0);
    }

    #[test]
    fn empty_retries_unfinished_cleanup_without_selected_entries() {
        let (store, _data, work, _) = test_store();
        let fresh = create_file(work.path(), "fresh", "retain fresh bytes");
        let id = store.trash(&fresh, None).unwrap();
        let state = store.home.join(".trashd/purging-interrupted");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("payload"), b"retired bytes").unwrap();
        assert_eq!(store.empty(Some(30)).unwrap(), 0);
        assert!(!state.exists());
        assert_eq!(
            fs::read(store.find_entry(&id).unwrap().trashed_path).unwrap(),
            b"retain fresh bytes"
        );
        store.purge(&id).unwrap();
        fs::create_dir(&state).unwrap();
        fs::write(state.join("payload"), b"more retired bytes").unwrap();
        assert!(store.list(None).unwrap().is_empty());
        assert_eq!(store.empty(None).unwrap(), 0);
        assert!(!state.exists());
    }

    #[test]
    fn unfinished_cleanup_reports_and_retries_busy_mounts() {
        let outcome = mounts::in_private_mounts(
            "store::tests::unfinished_cleanup_reports_and_retries_busy_mounts",
            || {
                let (store, _data, work, _) = test_store();
                let pending = store.home.join(".trashd/purging-busy");
                let mount = pending.join("mount");
                fs::create_dir_all(&mount).unwrap();
                let outside = work.path().join("outside");
                fs::create_dir(&outside).unwrap();
                fs::write(outside.join("KEEP"), b"external bytes").unwrap();
                if !mount_at(Some(&outside), &mount) {
                    return false;
                }
                let report = store.cleanup_unfinished().unwrap();
                let status = store.status_per_partition().unwrap();
                assert!(matches!(
                    store.empty(None),
                    Err(TrashError::CleanupPending(1))
                ));
                let preserved = fs::read(outside.join("KEEP")).unwrap() == b"external bytes";
                unmount(&mount);
                let retried = store.cleanup_unfinished().unwrap();
                report
                    == CleanupReport {
                        removed: 0,
                        pending: 1,
                    }
                    && status[0].pending_cleanup == 1
                    && preserved
                    && retried
                        == CleanupReport {
                            removed: 1,
                            pending: 0,
                        }
                    && !pending.exists()
            },
        );
        assert_ne!(outcome, Some(false));
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
            decompress_before_commit(&mut entry, 1024 * 1024, std::time::Instant::now(), || {
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
        let mut config = Config::default();
        config.retention.auto_compress = true;
        let store = TrashStore::open_isolated(&trash, config).unwrap();
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
        assert!(matches!(err, TrashError::Excluded { .. }), "got {err:?}");

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

    // The bound follows the entry, not max_file_size_mb (store-core-7): data
    // that decodes to more than the entry's recorded size and more than
    // automatic compression ever accepts is refused, and nothing changes.
    #[test]
    fn compressed_restore_rejects_output_over_limit_without_changing_entry() {
        let (mut store, _data, workdir, _lock) = test_store();
        let original = vec![b'A'; 2 * 1024 * 1024];
        let file = workdir.path().join("oversized-output");
        fs::write(&file, &original).unwrap();
        let id = store.trash(&file, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        assert_eq!(entry.info.size, Some(original.len() as u64));
        let oversized = vec![b'A'; COMPRESS_MAX_BYTES as usize + 1];
        let compressed = zstd::encode_all(oversized.as_slice(), 3).unwrap();
        drop(oversized);
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

    // Regression (#428): an isolated store must refuse to purge an entry that
    // belongs to a foreign trash root — the same boundary restore_resolved
    // already enforces. open_isolated is the destructive-test API, so a hole
    // here would let one store's tests delete another store's data.
    #[test]
    fn isolated_store_refuses_foreign_purge() {
        let (store_a, _data, work, _lock) = test_store();
        let doomed = create_file(work.path(), "foreign.txt", "keep me");
        let id = store_a.trash(&doomed, None).unwrap();
        let entry = store_a.find_entry(&id).unwrap();

        let other_root = tempfile::tempdir().unwrap();
        let store_b =
            TrashStore::open_isolated(&other_root.path().join("Trash"), Config::default()).unwrap();
        assert!(
            store_b.purge_resolved(&entry).is_err(),
            "isolated store must not purge a foreign entry"
        );
        assert_eq!(
            fs::read_to_string(&entry.trashed_path).unwrap(),
            "keep me",
            "foreign data must survive untouched"
        );
        assert!(entry.info_path.exists(), "foreign sidecar must survive");
        // The owning store can still purge its own entry.
        store_a.purge_resolved(&entry).unwrap();
        assert!(!entry.trashed_path.exists());
    }

    // Regression (#409): a selected entry that cannot be deleted must be
    // reported as a failure, not silently swallowed into a success count. A
    // vanished entry is different: the requested end state was reached.
    #[test]
    fn empty_entries_reports_undeletable_entries() {
        let (store, _data, work, _lock) = test_store();
        // A real entry whose root no longer passes validation (a
        // group-readable info/, which root cannot defeat by permissions):
        // nothing in it is deleted. Purge acts only through the root's own
        // validated directories, so an entry whose paths lie elsewhere is
        // never deleted either (security-1).
        let source = create_file(work.path(), "stuck", "data");
        store.trash(&source, None).unwrap();
        let stuck = store.find_entry("stuck").unwrap();
        fs::set_permissions(store.home.join("info"), fs::Permissions::from_mode(0o755)).unwrap();
        let (purged, failed) = store.empty_entries_reporting(std::slice::from_ref(&stuck), None);
        fs::set_permissions(store.home.join("info"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!((purged, failed), (0, 1), "an undeletable entry fails");
        assert!(stuck.trashed_path.exists());
        let vanished = TrashEntry {
            identity: None,
            sidecar_version: None,
            id: "vanished".into(),
            info: TrashInfo::new(work.path().join("vanished")),
            trashed_path: work.path().join("nowhere/vanished"),
            info_path: work.path().join("vanished.trashinfo"),
            trash_root: store.home.clone(),
            orphaned: false,
        };
        let (purged, failed) = store.empty_entries_reporting(&[vanished], None);
        assert_eq!((purged, failed), (0, 0), "a vanished entry does not fail");
    }

    // Regression (store-core-6, cli-5): an entry compressed or otherwise
    // changed between `trash empty`'s listing and its purge was counted as
    // already vanished, so `trash empty` reported success while the entry
    // the user confirmed stayed in the trash.
    #[test]
    fn empty_counts_entries_changed_since_selection_as_failures() {
        let (store, _data, work, _lock) = test_store();
        let doomed = create_file(work.path(), "changed.txt", &"x".repeat(4096));
        store.trash(&doomed, None).unwrap();
        let selected = store.list(None).unwrap();
        // A compressor rewrites the sidecar's marker after the listing.
        set_compression_marker(&selected[0].info_path, Some("zstd")).unwrap();
        let (purged, failed) = store.empty_entries_reporting(&selected, None);
        assert_eq!((purged, failed), (0, 1), "a changed entry is not gone");
        assert_eq!(
            store.list(None).unwrap().len(),
            1,
            "it is kept, not deleted"
        );

        // The selected entry vanished and a different one reused its ID:
        // the confirmed entry is gone, which is what was asked for.
        let stale = store.list(None).unwrap();
        store.purge_entry(&stale[0]).unwrap();
        fs::create_dir(work.path().join("sub")).unwrap();
        let other = create_file(&work.path().join("sub"), "changed.txt", "other");
        let id = store.trash(&other, None).unwrap();
        assert_eq!(id, stale[0].id, "the fixture must reuse the ID");
        let (purged, failed) = store.empty_entries_reporting(&stale, None);
        assert_eq!((purged, failed), (0, 0));
        assert_eq!(
            store.list(None).unwrap()[0].info.original_path,
            other,
            "the new entry survives"
        );
    }

    // Isolation boundary (#428) through empty: an isolated store must not
    // delete an entry resolved in another store's root.
    #[test]
    fn isolated_store_refuses_foreign_entries_in_empty() {
        let (store_a, _data, work, _lock) = test_store();
        let doomed = create_file(work.path(), "foreign-empty.txt", "keep me");
        let id = store_a.trash(&doomed, None).unwrap();
        let entry = store_a.find_entry(&id).unwrap();

        let other_root = tempfile::tempdir().unwrap();
        let store_b =
            TrashStore::open_isolated(&other_root.path().join("Trash"), Config::default()).unwrap();
        let (purged, failed) = store_b.empty_entries_reporting(std::slice::from_ref(&entry), None);
        assert_eq!((purged, failed), (0, 1));
        assert_eq!(
            fs::read_to_string(&entry.trashed_path).unwrap(),
            "keep me",
            "foreign data must survive untouched"
        );
    }

    // Regression (#429): a tree nested deeper than the old survey depth cap
    // was recorded with the truncated (zero) partial total, hiding its real
    // size from status and retention. The worklist survey has no cap.
    #[test]
    fn deep_trees_record_their_real_size() {
        let (store, _data, work, _lock) = test_store();
        let mut deep = work.path().join("deep");
        for _ in 0..105 {
            deep = deep.join("d");
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("payload"), vec![b'x'; 4096]).unwrap();

        let root = work.path().join("deep");
        let id = store.trash(&root, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        assert_eq!(
            entry.info.size,
            Some(4096),
            "payload beyond the old cap must be counted"
        );
    }

    // Regression (#403): a trash root with data but NO info/ directory must
    // surface its stranded files as orphans, not read as an empty store —
    // list and empty would otherwise strand the data forever.
    #[test]
    fn missing_info_dir_still_reports_orphans() {
        let (store, _data, _work, _lock) = test_store();
        let root = store.home.clone();
        fs::create_dir_all(root.join("files")).unwrap();
        fs::write(root.join("files/stranded"), b"data").unwrap();
        // Simulate the damaged/foreign root: the store itself creates info/
        // at open time, so remove it after the fact.
        fs::remove_dir_all(root.join("info")).unwrap();
        assert!(!root.join("info").exists());

        let mut entries = Vec::new();
        store.list_in_dir(&root, None, &mut entries).unwrap();
        assert_eq!(entries.len(), 1, "stranded data must be listed");
        assert!(entries[0].orphaned);
        assert_eq!(entries[0].id, "stranded");
        assert_eq!(fs::read(root.join("files/stranded")).unwrap(), b"data");

        // store-metadata-4: and it can be removed. The root lock validates
        // info/ too and refused the root, so `empty` reported nothing
        // deleted and left the data, on every run.
        assert_eq!(store.empty(None).unwrap(), 1);
        assert!(!root.join("files/stranded").exists());
        let info = fs::symlink_metadata(root.join("info")).unwrap();
        assert!(info.is_dir());
        assert_eq!(info.mode() & 0o7777, 0o700);
        assert!(store.list(None).unwrap().is_empty());
    }

    // store-metadata-4: only a missing info/ is put back for a purge. One
    // that is there but is not this user's private directory keeps the root
    // refused, and a purge never creates a root or its files/.
    #[test]
    fn purge_repairs_nothing_but_a_missing_info_dir() {
        let (store, _data, work, _lock) = test_store();
        let root = store.home.clone();
        fs::write(root.join("files/stranded"), b"data").unwrap();
        let mut entries = Vec::new();
        fs::remove_dir(root.join("info")).unwrap();
        store.list_in_dir(&root, None, &mut entries).unwrap();
        assert_eq!(entries.len(), 1);
        // A symlink where info/ was: nothing is created through it.
        let elsewhere = work.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("info")).unwrap();
        assert!(matches!(
            store.purge_entry(&entries[0]),
            Err(TrashError::Refused(_))
        ));
        assert_eq!(fs::read(root.join("files/stranded")).unwrap(), b"data");
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        fs::remove_file(root.join("info")).unwrap();
        // files/ open to others: the root is not private, and stays as it is.
        fs::set_permissions(root.join("files"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            store.purge_entry(&entries[0]),
            Err(TrashError::Refused(_))
        ));
        assert!(!root.join("info").exists());
        assert_eq!(fs::read(root.join("files/stranded")).unwrap(), b"data");
        fs::set_permissions(root.join("files"), fs::Permissions::from_mode(0o700)).unwrap();
        store.purge_entry(&entries[0]).unwrap();
        assert!(!root.join("files/stranded").exists());
    }

    // Regression (#404): orphans must age. A synthetic "now" deletion date
    // kept them forever outside age-based retention. Their age starts when
    // the data arrived in files/ (rename and copy both set its ctime), not
    // at its content's last edit: an old file trashed just now was purged
    // at once as a long-deleted orphan (store-metadata-1, store-core-5).
    #[test]
    fn orphan_deletion_date_is_when_its_data_arrived() {
        use std::fs::FileTimes;

        let (store, _data, _work, _lock) = test_store();
        let root = store.home.clone();
        fs::create_dir_all(root.join("files")).unwrap();
        let data_path = root.join("files/aged");
        fs::write(&data_path, b"data").unwrap();
        let ten_days_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 86400);
        fs::OpenOptions::new()
            .append(true)
            .open(&data_path)
            .unwrap()
            .set_times(
                FileTimes::new()
                    .set_accessed(ten_days_ago)
                    .set_modified(ten_days_ago),
            )
            .unwrap();

        let mut entries = Vec::new();
        store.list_in_dir(&root, None, &mut entries).unwrap();
        assert_eq!(entries.len(), 1);
        // A fixed instant from the inode, so the orphan keeps aging.
        let metadata = fs::symlink_metadata(&data_path).unwrap();
        let arrived =
            chrono::DateTime::from_timestamp(metadata.ctime(), metadata.ctime_nsec() as u32)
                .unwrap();
        assert_eq!(entries[0].info.deletion_date, arrived);
        let age = chrono::Local::now() - entries[0].info.deletion_date;
        assert!(
            age < chrono::Duration::days(1),
            "orphan aged by its content mtime: {age:?}"
        );
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
        // Its stamp is that same instant: entries are ordered by it.
        other_info.deletion_ns = other_info
            .deletion_date
            .timestamp_nanos_opt()
            .and_then(|ns| u64::try_from(ns).ok());
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
        let restored = store
            .restore_resolved(&mut chosen, RestoreTarget::Recorded, true)
            .unwrap();
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
        let (mut store, _data, _work, _) = test_store();
        store.config.retention.auto_compress = true;
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
        let (mut store, _data, _work, _) = test_store();
        store.config.retention.auto_compress = true;
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
            // limit; the complete foreign tree plus the new file is above
            // it. The tree alone still fits: an entry larger than the whole
            // cap is never size-trimmed (store-core-2).
            store.config.retention.max_size_gb = (size + 2) as f64 / (1024.0 * 1024.0 * 1024.0);
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
        assert_eq!(directory_accounted_size(&tree, None, false), 12);
        assert_eq!(directory_accounted_size(&tree, Some(u64::MAX), false), 12);
        assert_eq!(directory_accounted_size(&tree, Some(5), false), 5);
        assert_eq!(directory_accounted_size(&tree, Some(0), false), 0);
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
                let measured = directory_accounted_size(&tree, None, false);
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

    // ---- WS-A: retention must never destroy live or legitimate entries ----

    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    /// Set a path's mtime `age` into the past. Its ctime stays "now".
    fn backdate_mtime(path: &Path, age: std::time::Duration) {
        fs::File::options()
            .append(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - age)
            .unwrap();
    }

    /// Rewrite an entry's sidecar as if it had been trashed `age` ago.
    fn backdate_entry(store: &TrashStore, id: &str, age: chrono::Duration) {
        let entry = store.find_entry(id).unwrap();
        let mut info = entry.info.clone();
        info.deletion_date -= age;
        info.deletion_ns = info
            .deletion_date
            .timestamp_nanos_opt()
            .and_then(|ns| u64::try_from(ns).ok());
        fs::write(&entry.info_path, info.to_trashinfo_string()).unwrap();
    }

    fn retention_off() -> Config {
        let mut config = Config::default();
        config.retention.max_age_days = 0;
        config.retention.max_size_gb = 0.0;
        config.retention.disk_pressure_percent = 0;
        config
    }

    // store-metadata-1 / store-core-1: an entry published between the info/
    // and files/ passes of an unlocked listing was synthesized as an orphan
    // dated by its data's old mtime, and retention then deleted its data and
    // its valid sidecar.
    #[test]
    fn entry_published_between_listing_passes_survives_retention() {
        for via_empty in [false, true] {
            let (mut store, _data, work, _) = test_store();
            store.config.retention.max_age_days = 30;
            let source = create_file(work.path(), "report-2023.pdf", "old report");
            backdate_mtime(&source, std::time::Duration::from_secs(60 * 86400));
            let root = store.home.clone();
            let (published_tx, published_rx) = std::sync::mpsc::channel();
            *store.between_scan_passes.borrow_mut() = Some(Box::new(move || {
                let writer = TrashStore::open_isolated(&root, retention_off()).unwrap();
                writer.defer_maintenance();
                published_tx
                    .send(writer.trash(&source, None).unwrap())
                    .unwrap();
            }));
            if via_empty {
                let selected = store.entries_older_than(Some(30)).unwrap();
                assert!(
                    selected.iter().all(|entry| !entry.orphaned),
                    "a live entry was selected as an aged orphan"
                );
                store.empty_entries(&selected, Some(30));
            } else {
                let listed = store.list(None).unwrap();
                assert!(
                    listed.iter().all(|entry| !entry.orphaned),
                    "a live entry was listed as an orphan"
                );
                store.auto_purge_in_roots(&[store.home.clone()]).unwrap();
            }
            let id = published_rx.recv().unwrap();
            let entry = store.find_entry(&id).unwrap();
            assert!(!entry.orphaned, "via_empty={via_empty}");
            assert_eq!(fs::read(&entry.trashed_path).unwrap(), b"old report");
            assert!(entry.info_path.exists());
        }
    }

    // store-core-1: the purge revalidates an orphan snapshot under the root
    // lock. Writers publish under that lock, so a sidecar that now parses
    // means the snapshot came from a racing listing: the entry is live.
    #[test]
    fn orphan_snapshot_is_not_purged_once_its_sidecar_parses() {
        let (store, _data, work, _) = test_store();
        let data = store.home.join("files/X");
        fs::write(&data, b"live").unwrap();
        let mut entry = store.find_entry("X").unwrap();
        assert!(entry.orphaned);
        let info_path = store.home.join("info/X.trashinfo");
        fs::write(
            &info_path,
            TrashInfo::new(work.path().join("X")).to_trashinfo_string(),
        )
        .unwrap();
        // The snapshot a listing records after the writer has finished.
        entry.sidecar_version = sidecar_snapshot(&info_path);
        entry.info.deletion_date = chrono::Local::now() - chrono::Duration::days(60);
        assert!(matches!(
            store.purge_resolved(&entry),
            Err(TrashError::EntryNotFound(_))
        ));
        assert_eq!(
            store.empty_entries_reporting(std::slice::from_ref(&entry), Some(30)),
            (0, 0)
        );
        assert_eq!(fs::read(&data).unwrap(), b"live");
        assert!(info_path.exists());
        assert!(!store.find_entry("X").unwrap().orphaned);
    }

    // store-metadata-1 / store-core-5: a sidecar that exists but cannot be
    // parsed (a claim torn by a crash, a corrupt file) leaves the data's age
    // unknown. Age-based retention keeps it, as fsck does; an explicit purge
    // of that one entry still works (the spec's emergency case).
    #[test]
    fn age_based_retention_never_purges_data_whose_sidecar_cannot_be_parsed() {
        let (store, _data, _work, _) = test_store();
        let data = store.home.join("files/torn");
        fs::write(&data, b"recoverable").unwrap();
        let info = store.home.join("info/torn.trashinfo");
        fs::write(&info, b"").unwrap();
        let mut entry = store.find_entry("torn").unwrap();
        assert!(entry.orphaned);
        assert!(
            store.entries_older_than(Some(0)).unwrap().is_empty(),
            "data with an unparseable sidecar was selected by age"
        );
        entry.info.deletion_date = chrono::Local::now() - chrono::Duration::days(60);
        assert_eq!(
            store.empty_entries_reporting(std::slice::from_ref(&entry), Some(30)),
            (0, 0)
        );
        assert_eq!(fs::read(&data).unwrap(), b"recoverable");
        assert!(info.exists());
        store.purge_resolved(&entry).unwrap();
        assert!(data.symlink_metadata().is_err());
        assert!(info.symlink_metadata().is_err());
    }

    // store-core-5: after a crash the new sidecar can be empty while the data
    // rename is durable. That orphan arrived just now (ctime), whatever its
    // content's mtime says, and must not expire by age.
    #[test]
    fn torn_sidecar_after_a_crash_does_not_expire_old_data() {
        let (mut store, _data, _work, _) = test_store();
        store.config.retention.max_age_days = 30;
        let data = store.home.join("files/old.pdf");
        fs::write(&data, b"report").unwrap();
        backdate_mtime(&data, std::time::Duration::from_secs(60 * 86400));
        fs::write(store.home.join("info/old.pdf.trashinfo"), b"").unwrap();
        store.auto_purge_in_roots(&[store.home.clone()]).unwrap();
        assert_eq!(fs::read(&data).unwrap(), b"report");
        let entry = store.find_entry("old.pdf").unwrap();
        assert!(entry.orphaned);
        assert!(chrono::Local::now() - entry.info.deletion_date < chrono::Duration::days(30));
    }

    // store-metadata-2: a legacy sidecar over the 64 KiB read cap (the full
    // argv of a large `rm`) was treated as missing, so its data became an
    // orphan dated by mtime and retention deleted both.
    #[test]
    fn legacy_oversized_sidecar_survives_retention_and_restores() {
        let (mut store, _data, work, _) = test_store();
        store.config.retention.max_age_days = 30;
        let original = work.path().join("IMG_0001.jpg");
        let data = store.home.join("files/IMG_0001.jpg");
        fs::write(&data, b"photo").unwrap();
        backdate_mtime(&data, std::time::Duration::from_secs(60 * 86400));
        let mut info = TrashInfo::new(original.clone());
        info.pid = Some(1);
        let sidecar = info.to_trashinfo_string()
            + &format!("X-Trashd-Command=rm {}\n", "IMG_9999.jpg ".repeat(8_000));
        assert!(sidecar.len() > 100 * 1024);
        fs::write(store.home.join("info/IMG_0001.jpg.trashinfo"), sidecar).unwrap();
        store.auto_purge_in_roots(&[store.home.clone()]).unwrap();
        assert!(store.entries_older_than(Some(30)).unwrap().is_empty());
        let entry = store.find_entry("IMG_0001.jpg").unwrap();
        assert!(!entry.orphaned);
        assert_eq!(entry.info.original_path, original);
        assert!(chrono::Local::now() - entry.info.deletion_date < chrono::Duration::hours(1));
        let restored = store.restore("IMG_0001.jpg", None).unwrap();
        assert_eq!(restored, original);
        assert_eq!(fs::read(&original).unwrap(), b"photo");
    }

    // store-core-2: an operand larger than the retention size cap was trashed
    // and then purged by the same rm's retention pass, taking every older
    // entry with it. Caps are refusals: nothing moves.
    #[test]
    fn operand_larger_than_the_retention_cap_is_refused_before_moving() {
        let (mut store, _data, work, _) = test_store();
        let old = create_file(work.path(), "old", &"x".repeat(100));
        let old_id = store.trash(&old, None).unwrap();
        store.config.retention.max_size_gb = 4096.0 / GIB;
        store.config.auto_purge_interval_secs = 0;
        let tree = work.path().join("big");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("payload"), vec![b'x'; 8192]).unwrap();
        let file = create_file(work.path(), "bigfile", &"y".repeat(8192));
        let parent = fs::File::open(work.path()).unwrap();
        for operand in [&tree, &file] {
            assert!(
                matches!(store.trash(operand, None), Err(TrashError::TooLarge { .. })),
                "{operand:?}"
            );
            assert!(
                matches!(
                    store.trash_at(
                        parent.as_raw_fd(),
                        operand.file_name().unwrap(),
                        operand,
                        None
                    ),
                    Err(TrashError::TooLarge { .. })
                ),
                "{operand:?}"
            );
        }
        assert_eq!(fs::read(tree.join("payload")).unwrap().len(), 8192);
        assert_eq!(fs::read(&file).unwrap().len(), 8192);
        let kept = store.find_entry(&old_id).unwrap();
        assert_eq!(fs::read(kept.trashed_path).unwrap().len(), 100);
        let small = create_file(work.path(), "small", "fits");
        store.trash(&small, None).unwrap();
        assert_eq!(store.list(None).unwrap().len(), 2);
    }

    // store-core-2: like disk pressure (#201), size trimming must never turn
    // the delete that just happened into a permanent one.
    #[test]
    fn size_trimming_never_purges_just_trashed_entries() {
        let (mut store, _data, work, _) = test_store();
        let ids: Vec<String> = ["first", "second"]
            .iter()
            .map(|name| {
                let file = create_file(work.path(), name, &"x".repeat(100));
                store.trash(&file, None).unwrap()
            })
            .collect();
        store.config.retention.max_size_gb = 150.0 / GIB;
        store.auto_purge_in_roots(&[store.home.clone()]).unwrap();
        for id in &ids {
            assert!(store.find_entry(id).is_ok(), "{id} was purged by size");
        }
        // Once old enough, the oldest is trimmed as before.
        backdate_entry(&store, &ids[0], chrono::Duration::hours(3));
        backdate_entry(&store, &ids[1], chrono::Duration::hours(2));
        store.auto_purge_in_roots(&[store.home.clone()]).unwrap();
        assert!(store.find_entry(&ids[0]).is_err());
        assert!(store.find_entry(&ids[1]).is_ok());
    }

    // store-core-2: an entry larger than the whole cap made the excess larger
    // than every older entry together, so trimming purged all of them and
    // then the oversized entry too.
    #[test]
    fn an_entry_larger_than_the_size_cap_never_drives_other_purges() {
        let (mut store, _data, work, _) = test_store();
        let mut ids = Vec::new();
        for name in ["old", "mid"] {
            let file = create_file(work.path(), name, &"x".repeat(100));
            ids.push(store.trash(&file, None).unwrap());
        }
        let tree = work.path().join("big");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("payload"), vec![b'x'; 8192]).unwrap();
        ids.push(store.trash(&tree, None).unwrap());
        for (id, hours) in ids.iter().zip([4, 3, 2]) {
            backdate_entry(&store, id, chrono::Duration::hours(hours));
        }
        // The cap was lowered after the tree was trashed.
        store.config.retention.max_size_gb = 4096.0 / GIB;
        store.auto_purge_in_roots(&[store.home.clone()]).unwrap();
        for id in &ids {
            assert!(store.find_entry(id).is_ok(), "{id} was purged by size");
        }
    }

    // store-core-3: a foreign (topdir) root on the home filesystem was
    // measured by apparent size, so sparse files there made the size cap
    // purge the home trash.
    #[test]
    fn sparse_foreign_entries_cannot_make_the_size_cap_purge_the_home_trash() {
        let (mut store, _data, work, _) = test_store();
        let mut ids = Vec::new();
        for (name, days) in [("older", 10), ("newer", 1)] {
            let file = create_file(work.path(), name, &"h".repeat(20 * 1024));
            let id = store.trash(&file, None).unwrap();
            backdate_entry(&store, &id, chrono::Duration::days(days));
            ids.push(id);
        }
        let foreign =
            TrashStore::open_isolated(&work.path().join("foreign-trash"), retention_off()).unwrap();
        for name in ["a", "b"] {
            let file = fs::File::create(foreign.home.join("files").join(name)).unwrap();
            file.set_len(30 * 1024).unwrap();
            fs::write(
                foreign.home.join("info").join(format!("{name}.trashinfo")),
                format!("[Trash Info]\nPath={name}\nDeletionDate=2099-01-01T00:00:00\n"),
            )
            .unwrap();
        }
        store.config.retention.max_size_gb = (64 * 1024) as f64 / GIB;
        store
            .auto_purge_in_roots(&[store.home.clone(), foreign.home.clone()])
            .unwrap();
        for id in &ids {
            let entry = store.find_entry(id).unwrap();
            assert_eq!(fs::read(entry.trashed_path).unwrap().len(), 20 * 1024);
        }
    }

    // store-core-3: bytes in a root on another filesystem (removable media,
    // whose author controls sizes and dates) never justify purging the home
    // trash. That root's entries are not size-capped at all.
    #[test]
    fn foreign_filesystem_roots_never_drive_size_purges_in_the_home_trash() {
        let Some(dir) = cross_device_dir("foreign-root") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let (mut store, _data, work, _) = test_store();
        let mut ids = Vec::new();
        for (name, days) in [("older", 10), ("newer", 1)] {
            let file = create_file(work.path(), name, &"h".repeat(20 * 1024));
            let id = store.trash(&file, None).unwrap();
            backdate_entry(&store, &id, chrono::Duration::days(days));
            ids.push(id);
        }
        let foreign = dir.join(".Trash-1000");
        for sub in ["files", "info"] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(foreign.join(sub))
                .unwrap();
        }
        fs::write(foreign.join("files/a"), vec![b'f'; 30 * 1024]).unwrap();
        fs::write(
            foreign.join("info/a.trashinfo"),
            "[Trash Info]\nPath=a\nDeletionDate=2099-01-01T00:00:00\n",
        )
        .unwrap();
        // An orphan dated by an mtime the media author chose (2099).
        let orphan = foreign.join("files/b");
        fs::write(&orphan, vec![b'f'; 30 * 1024]).unwrap();
        fs::File::options()
            .append(true)
            .open(&orphan)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_070_908_800))
            .unwrap();
        store.config.retention.max_size_gb = (64 * 1024) as f64 / GIB;
        let result = store.auto_purge_in_roots(&[store.home.clone(), foreign.clone()]);
        let survivors: Vec<bool> = ids.iter().map(|id| store.find_entry(id).is_ok()).collect();
        let _ = fs::remove_dir_all(&dir);
        result.unwrap();
        assert_eq!(survivors, [true, true], "home entries were purged");
    }

    // store-core-5: on the cross-device path the trash copy becomes the only
    // copy once the source is retired, so its sidecar and info/ must be
    // durable first. Same-device renames stay unsynced.
    #[test]
    fn cross_device_trash_makes_the_sidecar_durable_before_retiring_the_source() {
        let Some(dir) = cross_device_dir("durable-sidecar") else {
            eprintln!("SKIP: no tmpfs on another device");
            return;
        };
        let (store, _data) = cross_device_store();
        fs::write(dir.join("file"), "payload").unwrap();
        fs::create_dir(dir.join("tree")).unwrap();
        fs::write(dir.join("tree/inner"), "payload").unwrap();
        fs::write(dir.join("pinned"), "payload").unwrap();
        let parent = fs::File::open(&dir).unwrap();
        let mut outcomes = Vec::new();
        for (name, pinned) in [("file", false), ("tree", false), ("pinned", true)] {
            store.durability_events.borrow_mut().clear();
            let result = if pinned {
                store.trash_at(parent.as_raw_fd(), OsStr::new(name), &dir.join(name), None)
            } else {
                store.trash(&dir.join(name), None)
            };
            let events = store.durability_events.borrow().clone();
            outcomes.push((name, result.is_ok(), events));
        }
        let same_device = {
            let (store, _data, work, _) = test_store();
            let file = create_file(work.path(), "local", "payload");
            store.trash(&file, None).unwrap();
            store.durability_events.borrow().clone()
        };
        let _ = fs::remove_dir_all(&dir);
        for (name, ok, events) in outcomes {
            assert!(ok, "{name}");
            assert_eq!(events, ["files", "sidecar", "info", "retire"], "{name}");
        }
        assert!(same_device.is_empty(), "{same_device:?}");
    }

    // store-metadata-5: automatic compression rewrote trashd's entries to
    // zstd in place, and other file managers restore those bytes verbatim.
    // It is opt-in; explicit `trash compress` is unaffected.
    #[test]
    fn retention_compresses_only_when_auto_compress_is_enabled() {
        for enabled in [false, true] {
            let (mut store, _data, work, _) = test_store();
            store.config.retention.auto_compress = enabled;
            let text = "a line of ordinary text\n".repeat(200);
            let file = create_file(work.path(), "notes.txt", &text);
            let id = store.trash(&file, None).unwrap();
            backdate_entry(&store, &id, chrono::Duration::days(8));
            store.auto_purge_in_roots(&[store.home.clone()]).unwrap();
            let entry = store.find_entry(&id).unwrap();
            let stored = fs::read(&entry.trashed_path).unwrap();
            let sidecar = fs::read_to_string(&entry.info_path).unwrap();
            assert_eq!(stored == text.as_bytes(), !enabled, "enabled={enabled}");
            assert_eq!(
                sidecar.contains("X-Trashd-Compressed=zstd"),
                enabled,
                "enabled={enabled}"
            );
        }
    }

    /// Run `operation` on its own thread and fail the test if it has not
    /// returned within `limit`. A blocked operation stays behind on its
    /// thread; the caller releases whatever blocks it.
    fn returns_within<T: Send + 'static>(
        name: &str,
        limit: std::time::Duration,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(operation());
        });
        receiver
            .recv_timeout(limit)
            .unwrap_or_else(|_| panic!("{name} did not return within {limit:?}"))
    }

    // store-core-9 / cli-8: a process that flock()ed a file before it was
    // deleted keeps that lock on the inode now in files/. Purge, empty,
    // restore and retention blocked on it forever (in the supervisor, the
    // whole session's deletes with them). They give up after a bounded wait:
    // explicit commands report the entry busy, never already gone, and
    // retention skips it. The entry stays intact.
    #[test]
    fn entry_flocks_held_by_other_processes_never_block_forever() {
        let (store, _data, work, _) = test_store();
        let content = "x".repeat(4096);
        let source = create_file(work.path(), "state.dat", &content);
        let id = store.trash(&source, None).unwrap();
        backdate_entry(&store, &id, chrono::Duration::days(10));
        let entry = store.find_entry(&id).unwrap();
        let sidecar = fs::read(&entry.info_path).unwrap();
        let holder = fs::File::open(&entry.trashed_path).unwrap();
        holder.lock().unwrap();

        // TrashStore is !Sync: each operation opens its own instance.
        let home = store.home.clone();
        let open = move |configure: fn(&mut Config)| {
            let home = home.clone();
            move || {
                let mut config = retention_off();
                configure(&mut config);
                let mut store = TrashStore::open_isolated(&home, config).unwrap();
                store.entry_lock_wait = std::time::Duration::from_millis(300);
                store
            }
        };
        let limit = std::time::Duration::from_secs(20);
        let busy = |result: Result<(), TrashError>| match result {
            Err(TrashError::Io(error)) => error.kind() == io::ErrorKind::WouldBlock,
            _ => false,
        };

        let (snapshot, store) = (entry.clone(), open(|_| {}));
        let purged = returns_within("purge", limit, move || store().purge_resolved(&snapshot));
        assert!(busy(purged), "purge must report the entry busy");

        let (snapshot, store) = (entry.clone(), open(|_| {}));
        let emptied = returns_within("empty", limit, move || {
            store().empty_entries_reporting(&[snapshot], None)
        });
        assert_eq!(emptied, (0, 1), "empty must count the busy entry failed");

        let (mut snapshot, store) = (entry.clone(), open(|_| {}));
        let restored = returns_within("restore", limit, move || {
            store().restore_entry(&mut snapshot, None).map(|_| ())
        });
        assert!(busy(restored), "restore must report the entry busy");

        let roots = [entry.trash_root.clone()];
        let store = open(|config| {
            config.retention.max_age_days = 1;
            config.retention.auto_compress = true;
        });
        let retained = returns_within("retention", limit, move || {
            store().auto_purge_in_roots(&roots).is_ok()
        });
        assert!(retained, "retention must skip the busy entry");

        drop(holder);
        assert!(!source.exists(), "the busy entry was restored");
        assert_eq!(fs::read_to_string(&entry.trashed_path).unwrap(), content);
        assert_eq!(fs::read(&entry.info_path).unwrap(), sidecar);
    }

    /// Run `operation`, recording each store-internal unlink it issues while
    /// `root`'s mutation lock is held.
    fn unlinks_under_root_lock<T>(root: &Path, operation: impl FnOnce() -> T) -> (T, Vec<String>) {
        let lock = root.join(".trashd/store.lock");
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let record = seen.clone();
        UNLINK_PROBE.set(Some(Box::new(move |name: &CStr| {
            // A new open file description conflicts with the store's own.
            let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(&lock) else {
                return;
            };
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                record
                    .borrow_mut()
                    .push(name.to_string_lossy().into_owned());
            }
        })));
        let result = operation();
        UNLINK_PROBE.set(None);
        let seen = seen.borrow().clone();
        (result, seen)
    }

    // store-core-4: purge, restore and the copy fallbacks' source retirement
    // unlinked while holding the root lock. Under trashd-exec every unlink
    // traps into the single-threaded supervisor, which may itself be waiting
    // for that lock on another process's delete, and the whole session hung.
    // No store-internal unlink may run under the root lock.
    #[test]
    fn no_store_unlink_runs_under_the_root_lock() {
        let mut violations = Vec::new();
        let (store, _data, work, _) = test_store();
        let root = store.home.clone();
        let tree = work.path().join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("sub/inner"), "payload").unwrap();
        let sources = [
            create_file(work.path(), "file", "payload"),
            tree,
            create_file(work.path(), "emptied", "payload"),
            create_file(work.path(), "restored", "payload"),
        ];
        let ids: Vec<String> = sources
            .iter()
            .map(|source| store.trash(source, None).unwrap())
            .collect();
        for id in &ids[..2] {
            let entry = store.find_entry(id).unwrap();
            let (result, seen) = unlinks_under_root_lock(&root, || store.purge_resolved(&entry));
            result.unwrap();
            violations.push(("purge", seen));
        }
        let entry = store.find_entry(&ids[2]).unwrap();
        let (counts, seen) =
            unlinks_under_root_lock(&root, || store.empty_entries_reporting(&[entry], None));
        assert_eq!(counts, (1, 0));
        violations.push(("empty", seen));
        let mut entry = store.find_entry(&ids[3]).unwrap();
        let (result, seen) =
            unlinks_under_root_lock(&root, || store.restore_entry(&mut entry, None));
        result.unwrap();
        violations.push(("restore", seen));
        // An orphan occupying the natural id makes the claim move on.
        fs::write(root.join("files/occupied"), "orphan").unwrap();
        let occupied = create_file(work.path(), "occupied", "payload");
        let (result, seen) = unlinks_under_root_lock(&root, || store.trash(&occupied, None));
        assert_ne!(result.unwrap(), "occupied");
        violations.push(("id claim", seen));

        // Cross-device: both copy fallbacks retire their source, and restore
        // retires the trash copy.
        if let Some(dir) = cross_device_dir("unlock-unlinks") {
            let (store, _data) = cross_device_store();
            let root = store.home.clone();
            fs::write(dir.join("pinned"), "payload").unwrap();
            fs::create_dir(dir.join("tree")).unwrap();
            fs::write(dir.join("tree/inner"), "payload").unwrap();
            fs::write(dir.join("moved"), "payload").unwrap();
            let parent = fs::File::open(&dir).unwrap();
            let mut results = Vec::new();
            for name in ["pinned", "tree"] {
                let (result, seen) = unlinks_under_root_lock(&root, || {
                    store.trash_at(parent.as_raw_fd(), OsStr::new(name), &dir.join(name), None)
                });
                results.push(result.is_ok());
                violations.push(("cross-device trash_at", seen));
                if let Ok(id) = result {
                    let mut entry = store.find_entry(&id).unwrap();
                    let (result, seen) =
                        unlinks_under_root_lock(&root, || store.restore_entry(&mut entry, None));
                    results.push(result.is_ok());
                    violations.push(("cross-device restore", seen));
                }
            }
            let (result, seen) =
                unlinks_under_root_lock(&root, || store.trash(&dir.join("moved"), None));
            results.push(result.is_ok());
            violations.push(("cross-device trash", seen));
            let restored = ["pinned", "tree/inner"].map(|name| dir.join(name).exists());
            let _ = fs::remove_dir_all(&dir);
            assert_eq!(results, [true; 5]);
            assert_eq!(restored, [true; 2]);
        } else {
            eprintln!("SKIP: no tmpfs on another device for the cross-device cases");
        }
        violations.retain(|(_, seen)| !seen.is_empty());
        assert!(
            violations.is_empty(),
            "unlinked while holding the root lock: {violations:#?}"
        );
    }

    // ---- WS-C: untrusted topdir trashes act only through pinned descriptors ----

    /// A private trash root (files/, info/, .trashd/) at `root`.
    fn private_root(root: &Path) -> PathBuf {
        for dir in [root.to_path_buf(), root.join("files"), root.join("info")] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root.to_path_buf()
    }

    /// The names in `dir`.
    fn names_in(dir: &Path) -> Vec<std::ffi::OsString> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }

    // security-1: retention acts on a root only through the descriptors its
    // lock validated. A FUSE server can answer `files` with a private
    // directory for the lock and with a symlink to /etc for every other
    // lookup, plus a sidecar dated long ago named after a file there: root's
    // routine retention then purged /etc/shadow. Covered for a topdir root
    // (listed through pinned descriptors) and the home root (listed by path,
    // purged through the lock's descriptors).
    #[test]
    fn retention_never_purges_through_a_swapped_files_directory() {
        use crate::store_lock::validation_probe;
        for topdir in [true, false] {
            let (mut store, _data, work, _) = test_store();
            store.config.retention.max_age_days = 30;
            let root = if topdir {
                private_root(&work.path().join("top/.Trash-1000"))
            } else {
                store.home.clone()
            };
            let victim = work.path().join("etc");
            fs::create_dir(&victim).unwrap();
            fs::write(victim.join("shadow"), b"root:secret").unwrap();
            let mut info = TrashInfo::new(PathBuf::from("shadow"));
            info.deletion_date -= chrono::Duration::days(60);
            fs::write(
                root.join("info/shadow.trashinfo"),
                info.to_trashinfo_string(),
            )
            .unwrap();
            validation_probe::serve_files_as_symlink(&root, &victim);
            let _ = store.auto_purge_in_roots(std::slice::from_ref(&root));
            validation_probe::set(None);
            assert_eq!(
                fs::read(victim.join("shadow")).ok().as_deref(),
                Some(&b"root:secret"[..]),
                "retention purged through the symlink (topdir root: {topdir})"
            );
            assert_eq!(names_in(&victim), ["shadow"]);
        }
    }

    // security-2: a new entry is claimed, published and verified through the
    // descriptors the lock validated. Renamed into `root/files/<id>` by
    // path, it landed wherever a FUSE server pointed `files` after the
    // check (/etc/sudoers.d as root).
    #[test]
    fn trash_never_publishes_through_a_swapped_files_directory() {
        use crate::store_lock::validation_probe;
        let (store, _data, work, _) = test_store();
        let victim = work.path().join("sudoers.d");
        fs::create_dir(&victim).unwrap();
        let source = create_file(work.path(), "zz-alice", "alice ALL=(ALL) NOPASSWD: ALL");
        validation_probe::serve_files_as_symlink(&store.home, &victim);
        let trashed = store.trash(&source, None);
        validation_probe::set(None);
        assert!(
            names_in(&victim).is_empty(),
            "published through the symlink: {:?}",
            names_in(&victim)
        );
        let id = trashed.unwrap();
        let real = validation_probe::real_files(&store.home);
        assert_eq!(
            fs::read(real.join(&id)).unwrap(),
            b"alice ALL=(ALL) NOPASSWD: ALL"
        );
        assert!(
            store
                .home
                .join("info")
                .join(format!("{id}.trashinfo"))
                .is_file()
        );
    }

    // security-1: a topdir root is listed through descriptors that follow
    // no symlink, so a symlinked files/ or info/ lists nothing instead of
    // whatever it points at, which were synthesized as orphans.
    #[test]
    fn topdir_listing_never_follows_a_symlinked_store_directory() {
        for child in ["files", "info"] {
            let (store, _data, work, _) = test_store();
            let root = private_root(&work.path().join("top/.Trash-1000"));
            let victim = work.path().join("etc");
            fs::create_dir(&victim).unwrap();
            fs::write(victim.join("passwd"), b"root:x:0:0").unwrap();
            fs::write(
                victim.join("passwd.trashinfo"),
                TrashInfo::new(PathBuf::from("passwd")).to_trashinfo_string(),
            )
            .unwrap();
            fs::remove_dir(root.join(child)).unwrap();
            std::os::unix::fs::symlink(&victim, root.join(child)).unwrap();
            let mut entries = Vec::new();
            let _ = store.list_in_dir(&root, None, &mut entries);
            assert!(
                entries.is_empty(),
                "listed through a symlinked {child}/: {entries:?}"
            );
        }
    }

    // security-2 (defense in depth): a regular file copied from a nosuid
    // filesystem keeps no set-id bits or file capabilities. There they mean
    // nothing, and on a FUSE mount the server, not the kernel, reports owner
    // and mode: copied out by root, it became a setuid-root binary of
    // another user's choosing in root's trash.
    #[test]
    fn copies_from_nosuid_filesystems_drop_set_id_bits() {
        let (store, _data, workdir, _lock) = test_store();
        let mount = workdir.path().join("nosuid");
        fs::create_dir(&mount).unwrap();
        let verdict = crate::mounts::in_private_mounts(
            "store::tests::copies_from_nosuid_filesystems_drop_set_id_bits",
            || {
                let target = CString::new(mount.as_os_str().as_bytes()).unwrap();
                if unsafe {
                    libc::mount(
                        c"none".as_ptr(),
                        target.as_ptr(),
                        c"tmpfs".as_ptr(),
                        libc::MS_NOSUID,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return false;
                }
                let tool = mount.join("tool");
                let kept = fs::write(&tool, b"#!/bin/sh\n").is_ok()
                    && fs::set_permissions(&tool, fs::Permissions::from_mode(0o6755)).is_ok()
                    && store.trash(&tool, None).is_ok_and(|id| {
                        let mode = fs::symlink_metadata(store.home.join("files").join(&id))
                            .map(|copy| copy.mode() & 0o7777);
                        eprintln!("copied mode: {mode:?}");
                        mode.is_ok_and(|mode| mode == 0o755)
                    });
                unmount(&mount);
                kept
            },
        );
        assert_ne!(verdict, Some(false));
    }

    // store-fs-2: a directory without u+rwx is opened up through a
    // descriptor of the directory just statted. A process that kept a
    // descriptor inside a group-writable directory of a trashed tree can
    // still swap entries there; one swapped for a symlink between the status
    // read and the chmod made the purger's path-following retry chmod the
    // symlink's target (/etc/passwd, /usr/bin/sudo) to 0700.
    #[test]
    fn tree_removal_never_chmods_through_a_swapped_symlink() {
        let fixture = TempDir::new().unwrap();
        let sentinel = fixture.path().join("sentinel");
        fs::write(&sentinel, b"keep").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o644)).unwrap();
        let job = fixture.path().join("job");
        fs::create_dir_all(job.join("locked")).unwrap();
        fs::set_permissions(job.join("locked"), fs::Permissions::from_mode(0o500)).unwrap();
        let (raced, victim) = (job.clone(), sentinel.clone());
        TREE_STATUS_PROBE.set(Some(Box::new(move |name: &CStr| {
            if name.to_bytes() == b"locked" {
                fs::rename(raced.join("locked"), raced.join("aside")).unwrap();
                std::os::unix::fs::symlink(&victim, raced.join("locked")).unwrap();
            }
        })));
        let parent = fs::File::open(fixture.path()).unwrap();
        let removed = remove_tree_at(parent.as_raw_fd(), c"job", 0);
        TREE_STATUS_PROBE.set(None);
        assert_eq!(
            fs::metadata(&sentinel).unwrap().mode() & 0o7777,
            0o644,
            "the purge chmodded the symlink's target"
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
        assert!(
            removed.is_err(),
            "a swapped directory must not pass as removed"
        );
        // The next sweep finishes the job: the symlink is unlinked, the
        // directory it replaced removed.
        remove_tree_at(parent.as_raw_fd(), c"job", 0).unwrap();
        assert!(!job.exists());
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
    }

    // store-metadata-10: the unlocked sweep of detached jobs can walk a tree
    // that a live purge is still removing. A directory the other remover
    // deleted between this walk's status read and its chmod or open was
    // recorded as a failure, so the job counted as pending and `trash empty`
    // failed although the tree was gone.
    #[test]
    fn a_concurrent_remover_never_leaves_a_detached_job_pending() {
        let (store, _data, _work, _) = test_store();
        let job = store.home.join(".trashd/purging-raced");
        fs::create_dir_all(job.join("writable")).unwrap();
        fs::write(job.join("writable/file"), "payload").unwrap();
        fs::create_dir(job.join("read-only")).unwrap();
        fs::set_permissions(job.join("read-only"), fs::Permissions::from_mode(0o555)).unwrap();
        let raced = job.clone();
        TREE_STATUS_PROBE.set(Some(Box::new(move |name: &CStr| {
            if matches!(name.to_bytes(), b"writable" | b"read-only") {
                fs::remove_dir_all(raced.join(OsStr::from_bytes(name.to_bytes()))).unwrap();
            }
        })));
        let report = store.cleanup_unfinished_in_roots(std::slice::from_ref(&store.home));
        TREE_STATUS_PROBE.set(None);
        let report = report.unwrap();
        assert_eq!(report.pending, 0, "{report:?}");
        assert!(!job.exists(), "the detached job was not finished");
    }

    /// Lower this process's soft descriptor limit to `soft`, returning the
    /// limit to restore.
    fn lower_descriptor_limit(soft: libc::rlim_t) -> libc::rlimit {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let lowered = libc::rlimit {
            rlim_cur: soft.min(limit.rlim_max),
            rlim_max: limit.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        limit
    }

    // store-fs-1: the survey opened every subdirectory of a directory before
    // it descended into the first, so a directory with more subdirectories
    // than the descriptor limit (a cargo registry, a photo library) was
    // sized without most of them: X-Trashd-Size and the directorysizes row
    // recorded that undercount for the life of the entry. Run in a child:
    // the limit is the whole process's.
    #[test]
    fn wide_trees_are_sized_whole_under_a_low_descriptor_limit() {
        const TEST: &str = "store::tests::wide_trees_are_sized_whole_under_a_low_descriptor_limit";
        const CHILD: &str = "TRASHD_TEST_WIDE_SURVEY";
        if !mounts::is_rerun_child(TEST, CHILD) {
            assert_ne!(mounts::rerun_test(TEST, CHILD), Some(false));
            return;
        }
        const DIRECTORIES: u64 = 2000;
        let (store, _data, work, _) = test_store();
        let tree = work.path().join("wide");
        fs::create_dir(&tree).unwrap();
        for index in 0..DIRECTORIES {
            let directory = tree.join(format!("d{index}"));
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("file"), [b'x'; 1024]).unwrap();
        }
        let parent = fs::File::open(work.path()).unwrap();
        lower_descriptor_limit(256);
        let surveyed = tree_sizes_at(parent.as_raw_fd(), c"wide");
        let recorded = store.trash(&tree, None).map(|id| {
            let size = store.find_entry(&id).unwrap().info.size;
            let row = crate::directorysizes::read_cache(&store.home)
                .get(id.as_bytes())
                .map(|row| row.size);
            (size, row)
        });
        let whole = DIRECTORIES * 1024;
        let surveyed = (surveyed.apparent, surveyed.allocated);
        eprintln!("surveyed {surveyed:?}, recorded {recorded:?}");
        let _ = mounts::report_test_verdict(Some(
            surveyed.0 == Some(whole)
                && surveyed.1.is_some_and(|allocated| allocated >= whole)
                && matches!(recorded, Ok((Some(size), Some(row))) if size == whole && row >= whole),
        ));
    }

    // store-fs-1: a chain of directories is walked with one descriptor
    // however deep, but a tree that is deep and branches at every level
    // still needs one per level and can run out. Its partial size (the
    // survey used to drop whichever subdirectories it could not open) is
    // not recorded as the entry's size: without one, accounting measures
    // the tree itself.
    #[test]
    fn a_tree_too_deep_to_survey_records_no_partial_size() {
        const TEST: &str = "store::tests::a_tree_too_deep_to_survey_records_no_partial_size";
        const CHILD: &str = "TRASHD_TEST_DEEP_SURVEY";
        if !mounts::is_rerun_child(TEST, CHILD) {
            assert_ne!(mounts::rerun_test(TEST, CHILD), Some(false));
            return;
        }
        const PAYLOAD: u64 = 1024 * 1024;
        const SIDE: u64 = 8192;
        const LEVELS: u64 = 200;
        let (store, _data, work, _) = test_store();
        let trash_deep = |name: &str, branching: bool| {
            let tree = work.path().join(name);
            let mut bottom = tree.clone();
            fs::create_dir(&bottom).unwrap();
            for _ in 0..LEVELS {
                fs::create_dir(bottom.join("a")).unwrap();
                if branching {
                    fs::create_dir(bottom.join("b")).unwrap();
                }
                // The walk goes down the subdirectory listed first, so a
                // branching level keeps its descriptor for the other one,
                // which holds a file of its own.
                let mut listed = fs::read_dir(&bottom)
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name());
                let first = listed.next().unwrap();
                if let Some(other) = listed.next() {
                    fs::write(bottom.join(other).join("side"), vec![b'y'; SIDE as usize]).unwrap();
                }
                bottom.push(first);
            }
            fs::write(bottom.join("payload"), vec![b'x'; PAYLOAD as usize]).unwrap();
            let limit = lower_descriptor_limit(64);
            let id = store.trash(&tree, None);
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
            id.map(|id| store.find_entry(&id).unwrap().info.size)
        };
        let chain = trash_deep("chain", false);
        let branching = trash_deep("branching", true);
        let status = store.status().unwrap();
        eprintln!("chain {chain:?}, branching {branching:?}, status {status:?}");
        let _ = mounts::report_test_verdict(Some(
            matches!(chain, Ok(Some(PAYLOAD)))
                && matches!(branching, Ok(None))
                && status == (2 * PAYLOAD + LEVELS * SIDE, 2),
        ));
    }

    /// Trash `victim` through `trash_at` (`pinned`) or `trash`, replacing it
    /// with `replacement` right before the move; the entry that landed and
    /// its directorysizes row.
    fn trash_replaced_operand(
        store: &TrashStore,
        victim: &Path,
        replacement: &Path,
        pinned: bool,
    ) -> (TrashEntry, Option<u64>) {
        let (raced, replacement) = (victim.to_path_buf(), replacement.to_path_buf());
        *store.before_move.borrow_mut() = Some(Box::new(move || {
            let aside = raced.with_extension("aside");
            fs::rename(&raced, aside).unwrap();
            fs::rename(&replacement, &raced).unwrap();
        }));
        let id = if pinned {
            let parent = fs::File::open(victim.parent().unwrap()).unwrap();
            store.trash_at(
                parent.as_raw_fd(),
                victim.file_name().unwrap(),
                victim,
                None,
            )
        } else {
            store.trash(victim, None)
        }
        .unwrap();
        let row = crate::directorysizes::read_cache(&store.home)
            .get(id.as_bytes())
            .map(|row| row.size);
        (store.find_entry(&id).unwrap(), row)
    }

    // recent-changes-9: an operand replaced by one of another type between
    // its sizing and the move was sized by the type it had before. A file
    // replaced by a tree recorded the directory inode's own size (#414
    // again) and got no directorysizes row; a directory replaced by a file
    // recorded the size 0.
    #[test]
    fn a_raced_type_change_records_what_landed() {
        const PAYLOAD: u64 = 1024 * 1024;
        for pinned in [true, false] {
            let (store, _data, work, _) = test_store();
            let victim = create_file(work.path(), "victim", "small");
            let tree = work.path().join("tree");
            fs::create_dir(&tree).unwrap();
            fs::write(tree.join("payload"), vec![b'x'; PAYLOAD as usize]).unwrap();
            let (entry, row) = trash_replaced_operand(&store, &victim, &tree, pinned);
            assert!(entry.trashed_path.join("payload").exists());
            assert_eq!(entry.info.size, Some(PAYLOAD), "pinned={pinned}");
            assert!(
                row.is_some_and(|size| size >= PAYLOAD),
                "pinned={pinned}: {row:?}"
            );
        }
        for pinned in [true, false] {
            let (store, _data, work, _) = test_store();
            let victim = work.path().join("victim");
            fs::create_dir(&victim).unwrap();
            fs::write(victim.join("payload"), vec![b'x'; PAYLOAD as usize]).unwrap();
            let file = create_file(work.path(), "file", &"y".repeat(3000));
            let (entry, row) = trash_replaced_operand(&store, &victim, &file, pinned);
            assert!(fs::symlink_metadata(&entry.trashed_path).unwrap().is_file());
            assert_eq!(entry.info.size, Some(3000), "pinned={pinned}");
            assert_eq!(row, None, "pinned={pinned}");
        }
    }

    // store-metadata-9: a directorysizes rebuild measured each directory
    // with a walk of its own that stopped 100 levels down, and neither it
    // nor the survey counted a directory's own blocks. The spec's size is
    // `du -B1`, and KDE trusts a row whose sidecar mtime matches.
    #[test]
    fn directorysizes_rows_measure_whole_trees_like_du() {
        /// `du -B1`: the blocks of the directory and everything below it.
        fn disk_usage(path: &Path) -> u64 {
            let metadata = fs::symlink_metadata(path).unwrap();
            let below: u64 = if metadata.is_dir() {
                fs::read_dir(path)
                    .unwrap()
                    .map(|entry| disk_usage(&entry.unwrap().path()))
                    .sum()
            } else {
                0
            };
            metadata.blocks() * 512 + below
        }
        let (store, _data, work, _) = test_store();
        let root = work.path().join("deep");
        let mut bottom = root.clone();
        for _ in 0..105 {
            bottom.push("d");
        }
        fs::create_dir_all(&bottom).unwrap();
        fs::write(bottom.join("payload"), vec![b'x'; 4096]).unwrap();
        let expected = disk_usage(&root);
        let id = store.trash(&root, None).unwrap();
        let row = || {
            crate::directorysizes::read_cache(&store.home)
                .get(id.as_bytes())
                .map(|row| row.size)
        };
        assert_eq!(row(), Some(expected), "the row recorded with the entry");
        fs::remove_file(store.home.join("directorysizes")).unwrap();
        crate::directorysizes::write_cache(&store.home).unwrap();
        assert_eq!(row(), Some(expected), "the row a rebuild measured");
    }

    /// Names in `dir` a copy staged and left behind.
    fn leftover_copy_stages(dir: &Path) -> Vec<std::ffi::OsString> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.as_bytes().starts_with(COPY_STAGE_PREFIX.as_bytes()))
            .collect()
    }

    // store-fs-3: where RENAME_NOREPLACE is unsupported (NFS, 9p, FUSE
    // without rename2) the move into the trash falls back to a copy, whose
    // publication into files/ used the same flag and then refused every
    // directory. No directory could be trashed on such a home, each attempt
    // after a full copy. The private files/ takes it under an exclusively
    // created name; a restore into the user's tree stays refused.
    #[test]
    fn directories_reach_a_trash_without_rename_noreplace() {
        for errno in [libc::EINVAL, libc::ENOSYS, libc::EOPNOTSUPP] {
            for pinned in [false, true] {
                let (store, _data, work, _) = test_store();
                let tree = work.path().join("tree");
                fs::create_dir_all(tree.join("sub")).unwrap();
                fs::write(tree.join("sub/payload"), b"recoverable bytes").unwrap();
                fs::set_permissions(&tree, fs::Permissions::from_mode(0o750)).unwrap();
                NOREPLACE_ERRNO.set(Some(errno));
                let trashed = if pinned {
                    let parent = fs::File::open(work.path()).unwrap();
                    store.trash_at(parent.as_raw_fd(), OsStr::new("tree"), &tree, None)
                } else {
                    store.trash(&tree, None)
                };
                NOREPLACE_ERRNO.set(None);
                let id = trashed.unwrap_or_else(|error| panic!("{errno} pinned={pinned}: {error}"));
                assert!(!tree.exists(), "the source was left behind");
                let entry = store.find_entry(&id).unwrap();
                assert_eq!(
                    fs::read(entry.trashed_path.join("sub/payload")).unwrap(),
                    b"recoverable bytes"
                );
                let landed = fs::symlink_metadata(&entry.trashed_path).unwrap();
                assert_eq!(landed.mode() & 0o7777, 0o750);
                assert_eq!(entry.info.original_path, tree);
                assert_eq!(
                    leftover_copy_stages(&store.home.join(".trashd")),
                    Vec::<std::ffi::OsString>::new()
                );
                // Out of the trash nothing changes: a directory is published
                // into the user's tree only without replacing anything.
                NOREPLACE_ERRNO.set(Some(errno));
                let restored = store.restore(&id, None);
                NOREPLACE_ERRNO.set(None);
                assert!(restored.is_err(), "{restored:?}");
                assert!(!tree.exists());
                assert_eq!(
                    fs::read(entry.trashed_path.join("sub/payload")).unwrap(),
                    b"recoverable bytes"
                );
                assert!(entry.info_path.exists());
            }
        }
    }

    // store-fs-3: the name in files/ is taken with an exclusive mkdir, so
    // even something that appeared there against every guarantee (the claim
    // in info/, the root lock, the private mode) is never replaced.
    #[test]
    fn private_root_publication_never_replaces_a_competitor() {
        for (competitor, kept) in [("directory", true), ("file", true), ("nothing", false)] {
            let (store, _data, work, _) = test_store();
            let tree = work.path().join("tree");
            fs::create_dir(&tree).unwrap();
            fs::write(tree.join("payload"), b"recoverable bytes").unwrap();
            let parent = fs::File::open(work.path()).unwrap();
            let files = fs::File::open(store.home.join("files")).unwrap();
            let staging = fs::File::open(store.home.join(".trashd")).unwrap();
            let source = stat_at(parent.as_raw_fd(), c"tree", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            let destination = store.home.join("files/tree");
            let result = copy_staged_at_with_rename(
                parent.as_raw_fd(),
                c"tree",
                files.as_raw_fd(),
                c"tree",
                staging.as_raw_fd(),
                &source,
                Publication::PrivateRoot,
                |_, _, _, _| {
                    match competitor {
                        "directory" => fs::create_dir(&destination).unwrap(),
                        "file" => fs::write(&destination, b"competing").unwrap(),
                        _ => {}
                    }
                    Err(io::Error::from_raw_os_error(libc::EINVAL))
                },
            );
            assert_eq!(result.is_ok(), !kept, "{competitor}: {result:?}");
            assert_eq!(
                fs::read(tree.join("payload")).unwrap(),
                b"recoverable bytes",
                "the copy never touches its source"
            );
            assert_eq!(
                leftover_copy_stages(&store.home.join(".trashd")),
                Vec::<std::ffi::OsString>::new(),
                "{competitor}"
            );
            match competitor {
                "directory" => assert_eq!(fs::read_dir(&destination).unwrap().count(), 0),
                "file" => assert_eq!(fs::read(&destination).unwrap(), b"competing"),
                _ => {
                    assert_eq!(
                        fs::read(destination.join("payload")).unwrap(),
                        b"recoverable bytes"
                    );
                    let landed = fs::symlink_metadata(&destination).unwrap();
                    assert_eq!(result.unwrap(), (landed.dev(), landed.ino()));
                }
            }
        }
    }

    /// Replace an entry's data with its zstd encoding and mark the sidecar,
    /// as a compressor does.
    fn compress_in_place(entry: &TrashEntry, plaintext: &[u8]) {
        fs::write(&entry.trashed_path, zstd::encode_all(plaintext, 3).unwrap()).unwrap();
        set_compression_marker(&entry.info_path, Some("zstd")).unwrap();
    }

    // store-core-7, store-fs-8, cli-4: restore bounded a compressed entry's
    // output by max_file_size_mb as configured at restore time, which only
    // says what may enter the trash. Lowering it left every larger entry
    // compressed before unrestorable ("decompressed entry exceeds N bytes").
    #[test]
    fn compressed_entries_restore_after_the_file_size_limit_is_lowered() {
        let (mut store, _data, work, _) = test_store();
        let original = b"compressible ".repeat(200_000);
        let file = work.path().join("app.log");
        fs::write(&file, &original).unwrap();
        let id = store.trash(&file, None).unwrap();
        let entry = store.find_entry(&id).unwrap();
        assert_eq!(entry.info.size, Some(original.len() as u64));
        compress_in_place(&entry, &original);
        store.config.max_file_size_mb = 1;
        let restored = store.restore(&id, None).unwrap();
        assert_eq!(fs::read(restored).unwrap(), original);
    }

    // store-core-7: automatic compression takes entries up to its own cap
    // whatever max_file_size_mb says, so with a limit below that cap it
    // made an entry unrestorable without the user changing anything.
    #[test]
    fn automatic_compression_keeps_entries_over_the_file_size_limit_restorable() {
        let (mut store, _data, work, _) = test_store();
        store.config.retention.auto_compress = true;
        let original = b"compressible ".repeat(200_000);
        let file = work.path().join("old.log");
        fs::write(&file, &original).unwrap();
        let id = store.trash(&file, None).unwrap();
        store.config.max_file_size_mb = 1;
        backdate_entry(&store, &id, chrono::Duration::days(8));
        store.auto_purge().unwrap();
        let entry = store.find_entry(&id).unwrap();
        assert!(
            zstd_magic(&entry.trashed_path),
            "the entry was not compressed"
        );
        let restored = store.restore(&id, None).unwrap();
        assert_eq!(fs::read(restored).unwrap(), original);
    }

    // store-core-7: the bound is the entry's recorded size, never less than
    // what automatic compression accepts and never over the hard cap; the
    // file size limit can only widen it, as it did before.
    #[test]
    fn decompression_is_bounded_by_the_recorded_size() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(decompress_limit(None), COMPRESS_MAX_BYTES);
        assert_eq!(decompress_limit(Some(MIB)), COMPRESS_MAX_BYTES);
        assert_eq!(decompress_limit(Some(300 * MIB)), 300 * MIB);
        assert_eq!(decompress_limit(Some(u64::MAX)), HARD_DECOMPRESS_LIMIT);
        let (mut store, _data, _work, _) = test_store();
        for (limit_mb, recorded, expected) in [
            (1, Some(300 * MIB), 300 * MIB),
            (1, None, COMPRESS_MAX_BYTES),
            (1024, Some(MIB), 1024 * MIB),
            (1024, None, 1024 * MIB),
            (0, None, HARD_DECOMPRESS_LIMIT),
            (u64::MAX, Some(MIB), HARD_DECOMPRESS_LIMIT),
        ] {
            store.config.max_file_size_mb = limit_mb;
            assert_eq!(
                store.restore_decompress_limit(recorded),
                expected,
                "max_file_size_mb={limit_mb} recorded={recorded:?}"
            );
        }
    }

    /// Restore `entry` to its recorded path with `--force`, as
    /// `restore --all --force` (`batch`) or a single `restore --force` does.
    fn restore_forced(
        store: &TrashStore,
        entry: &TrashEntry,
        batch: bool,
    ) -> Result<PathBuf, TrashError> {
        if batch {
            store
                .restore_batch(std::slice::from_ref(entry), None, true)
                .remove(0)
        } else {
            store.restore_entry_renamed(&mut entry.clone(), None)
        }
    }

    // store-core-8, cli-6: a `--force` retry passed the `.N` name it derived
    // from the recorded path back as a destination the user chose, so the
    // retry was not kept below the topdir. An empty `Path=` names the topdir
    // itself: it conflicts, and the retry restored planted data to
    // `<topdir>.1`, beside the mount point.
    #[test]
    fn forced_restore_keeps_a_recorded_path_below_its_topdir() {
        let (mut store, _data, work, _) = test_store();
        // Take entries of other roots, as a production store does.
        store.isolated = false;
        let top = work.path().join("mnt");
        let root = top.join(format!(".Trash-{}", unsafe { libc::geteuid() }));
        let external = TrashStore::open_isolated(&root, retention_off()).unwrap();
        fs::write(root.join("files/planted"), b"planted").unwrap();
        fs::write(
            root.join("info/planted.trashinfo"),
            "[Trash Info]\nPath=\nDeletionDate=2026-01-01T00:00:00\n",
        )
        .unwrap();
        let entries = external.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].orphaned);
        for batch in [true, false] {
            let result = restore_forced(&store, &entries[0], batch);
            assert!(
                matches!(result, Err(TrashError::RestoreTraversal(_))),
                "batch={batch}: {result:?}"
            );
            assert!(
                fs::symlink_metadata(work.path().join("mnt.1")).is_err(),
                "batch={batch}: restored beside the topdir"
            );
            assert_eq!(fs::read(root.join("files/planted")).unwrap(), b"planted");
        }
        // A path below the topdir still gets its `.N` name there.
        fs::write(
            root.join("info/planted.trashinfo"),
            "[Trash Info]\nPath=taken\nDeletionDate=2026-01-01T00:00:00\n",
        )
        .unwrap();
        fs::write(top.join("taken"), b"in the way").unwrap();
        let entries = external.list(None).unwrap();
        let restored = restore_forced(&store, &entries[0], true).unwrap();
        assert_eq!(restored, top.join("taken.1"));
        assert_eq!(fs::read(restored).unwrap(), b"planted");
    }

    // store-core-8, cli-6: the first attempt walks the recorded path through
    // no symlink, and its `--force` retry followed them: a directory of the
    // path swapped for a symlink between the two sent the entry wherever
    // the link pointed. A destination the user names may still be reached
    // through one, retry included.
    #[test]
    fn forced_restore_retry_follows_no_symlink_in_a_recorded_path() {
        for batch in [true, false] {
            let (store, _data, work, _) = test_store();
            let recorded_parent = work.path().join("recorded-parent");
            let outside = work.path().join("outside");
            fs::create_dir(&recorded_parent).unwrap();
            fs::create_dir(&outside).unwrap();
            let original = create_file(&recorded_parent, "payload", "trashed");
            let id = store.trash(&original, None).unwrap();
            create_file(&recorded_parent, "payload", "in the way");
            let entry = store.find_entry(&id).unwrap();
            let (swapped, link_target) = (recorded_parent.clone(), outside.clone());
            *store.before_forced_retry.borrow_mut() = Some(Box::new(move || {
                fs::rename(&swapped, swapped.with_extension("moved")).unwrap();
                std::os::unix::fs::symlink(&link_target, &swapped).unwrap();
            }));
            let result = restore_forced(&store, &entry, batch);
            assert!(
                matches!(result, Err(TrashError::RestoreTraversal(_))),
                "batch={batch}: {result:?}"
            );
            assert_eq!(
                fs::read_dir(&outside).unwrap().count(),
                0,
                "batch={batch}: restored through the symlink"
            );
            assert_eq!(fs::read(&entry.trashed_path).unwrap(), b"trashed");

            create_file(&outside, "payload", "in the way too");
            let chosen = recorded_parent.join("payload");
            let restored = store
                .restore_entry_renamed(&mut entry.clone(), Some(&chosen))
                .unwrap();
            assert_eq!(restored, recorded_parent.join("payload.1"));
            assert_eq!(fs::read(outside.join("payload.1")).unwrap(), b"trashed");
        }
    }

    /// The value of the extended attribute `name` of `path` itself.
    fn xattr_of(path: &Path, name: &CStr) -> Option<Vec<u8>> {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut value = [0u8; 16];
        let size = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        (size >= 0).then(|| value[..size as usize].to_vec())
    }

    // store-fs-5: a copy got its source's mode before its extended
    // attributes. `user.*` attributes need write permission on the inode
    // whatever the descriptor was opened for, so a read-only file or
    // directory (0444, 0555) lost them on every cross-device move, silently.
    // Root may write anyway: the case runs unprivileged.
    #[test]
    fn copies_of_read_only_nodes_keep_their_user_xattrs() {
        const TEST: &str = "store::tests::copies_of_read_only_nodes_keep_their_user_xattrs";
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: unprivileged fixture setup requires root");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let (source, copies) = (base.path().join("source"), base.path().join("copies"));
        fs::create_dir(&source).unwrap();
        fs::create_dir(&copies).unwrap();
        fs::write(source.join("file"), b"data").unwrap();
        fs::create_dir(source.join("dir")).unwrap();
        fs::write(source.join("dir/inner"), b"inner").unwrap();
        for (name, value, mode) in [("file", b"1", 0o444), ("dir", b"2", 0o555)] {
            let path = CString::new(source.join(name).as_os_str().as_bytes()).unwrap();
            if unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    c"user.test".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            } != 0
            {
                eprintln!("SKIP: no user extended attributes here");
                return;
            }
            fs::set_permissions(source.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        for path in [
            &source,
            &copies,
            &source.join("file"),
            &source.join("dir"),
            &source.join("dir/inner"),
        ] {
            std::os::unix::fs::lchown(path, Some(65534), Some(65534)).unwrap();
        }
        let outcome = as_unprivileged(TEST, move || {
            let from = fs::File::open(&source).unwrap();
            let to = fs::File::open(&copies).unwrap();
            let stat = |name| stat_at(from.as_raw_fd(), name, libc::AT_SYMLINK_NOFOLLOW).unwrap();
            copy_regular_at(
                from.as_raw_fd(),
                c"file",
                to.as_raw_fd(),
                c"file",
                &stat(c"file"),
            )
            .unwrap();
            copy_directory_at(
                from.as_raw_fd(),
                c"dir",
                to.as_raw_fd(),
                c"dir",
                &stat(c"dir"),
                0,
                &mut TreeCopy::new(to.as_raw_fd()),
                b"dir",
            )
            .unwrap();
            let mode = |name: &str| fs::metadata(copies.join(name)).unwrap().mode() & 0o7777;
            let kept = (
                xattr_of(&copies.join("file"), c"user.test"),
                xattr_of(&copies.join("dir"), c"user.test"),
            );
            eprintln!("xattrs of the copies: {kept:?}");
            kept == (Some(b"1".to_vec()), Some(b"2".to_vec()))
                && mode("file") == 0o444
                && mode("dir") == 0o555
                && fs::read(copies.join("dir/inner")).unwrap() == b"inner"
        });
        assert_ne!(outcome, Some(false));
    }

    // store-fs-4: a copied directory has its source's mode as soon as its
    // own children are done, so the rollback of a copy that failed later
    // could not unlink anything in a read-only one (0555: a Go module cache,
    // Nix and Bazel trees) and gave up at the first such error. A restore
    // stages its copy beside the destination, where no sweep ever looks:
    // every failed attempt left a hidden `.trashd-copy-*` tree there. Root
    // may unlink anyway: the case runs unprivileged.
    #[test]
    fn failed_restore_copy_removes_its_read_only_directories() {
        const TEST: &str = "store::tests::failed_restore_copy_removes_its_read_only_directories";
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: unprivileged fixture setup requires root");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let (trash, destination) = (base.path().join("trash"), base.path().join("destination"));
        let vendor = trash.join("tree/vendor/pkg@v1");
        fs::create_dir_all(&vendor).unwrap();
        fs::write(vendor.join("mod.go"), b"package pkg").unwrap();
        // Something took the name while the tree was being copied.
        fs::create_dir_all(destination.join("tree")).unwrap();
        for path in [
            &trash,
            &destination,
            &trash.join("tree"),
            &trash.join("tree/vendor"),
            &vendor,
            &vendor.join("mod.go"),
        ] {
            std::os::unix::fs::lchown(path, Some(65534), Some(65534)).unwrap();
        }
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(trash.join("tree/vendor"), fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = as_unprivileged(TEST, move || {
            let from = fs::File::open(&trash).unwrap();
            let to = fs::File::open(&destination).unwrap();
            let entry = stat_at(from.as_raw_fd(), c"tree", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            let result = publish_copy_noreplace(
                from.as_raw_fd(),
                c"tree",
                to.as_raw_fd(),
                c"tree",
                stat_identity(&entry),
            );
            let left = leftover_copy_stages(&destination);
            eprintln!("restore: {result:?}; left behind: {left:?}");
            result.is_err_and(|error| is_conflict_error(&error))
                && left.is_empty()
                && fs::read(vendor.join("mod.go")).unwrap() == b"package pkg"
                && fs::read_dir(destination.join("tree")).unwrap().count() == 0
        });
        assert_ne!(outcome, Some(false));
    }

    /// Restore `source/item` (a `kind` of node) to `destination/item` by
    /// copy, as a restore onto another filesystem does.
    fn restore_by_copy(base: &Path, kind: &str) -> io::Result<()> {
        let (source, destination) = (base.join("source"), base.join("destination"));
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        let item = source.join("item");
        match kind {
            "file" => fs::write(&item, b"payload").unwrap(),
            "symlink" => std::os::unix::fs::symlink("missing-target", &item).unwrap(),
            "fifo" => {
                let name = CString::new(item.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            _ => {
                fs::create_dir_all(item.join("sub")).unwrap();
                fs::write(item.join("sub/file"), b"payload").unwrap();
            }
        }
        // O_PATH, as restore pins a destination's parent.
        let from = open_directory_path(&source, true).unwrap();
        let to = open_directory_path(&destination, true).unwrap();
        let entry = stat_at(from.as_raw_fd(), c"item", libc::AT_SYMLINK_NOFOLLOW).unwrap();
        publish_copy_noreplace(
            from.as_raw_fd(),
            c"item",
            to.as_raw_fd(),
            c"item",
            stat_identity(&entry),
        )
    }

    // store-fs-7: a restore by copy removed the trash copy without making
    // the destination's directory entry durable. The copy's data is synced
    // under its staging name; the rename to its final name was not, and the
    // trash is on another filesystem, which commits on its own: a crash
    // could keep the unlink and lose the rename. The destination is synced
    // first (a tree with its filesystem, for the entries inside it), and
    // while that fails the trash copy stays.
    #[test]
    fn restore_by_copy_syncs_the_destination_before_retiring_the_trash_copy() {
        for kind in ["file", "symlink", "fifo", "directory"] {
            let base = tempfile::tempdir().unwrap();
            RESTORE_COPY_EVENTS.take();
            restore_by_copy(base.path(), kind).unwrap();
            assert_eq!(RESTORE_COPY_EVENTS.take(), ["sync", "retire"], "{kind}");
            assert!(fs::symlink_metadata(base.path().join("source/item")).is_err());
            assert!(fs::symlink_metadata(base.path().join("destination/item")).is_ok());

            let base = tempfile::tempdir().unwrap();
            DESTINATION_SYNC_ERRNO.set(Some(libc::EIO));
            let result = restore_by_copy(base.path(), kind);
            DESTINATION_SYNC_ERRNO.set(None);
            assert_eq!(
                result.as_ref().map_err(io::Error::raw_os_error),
                Err(Some(libc::EIO)),
                "{kind}"
            );
            assert_eq!(RESTORE_COPY_EVENTS.take(), [""; 0], "{kind}");
            assert!(
                fs::symlink_metadata(base.path().join("source/item")).is_ok(),
                "{kind}: the trash copy was retired"
            );
            assert_eq!(
                fs::read_dir(base.path().join("destination"))
                    .unwrap()
                    .count(),
                0,
                "{kind}: the copy that could not be made durable was left"
            );

            // A filesystem that syncs no directories at all (EINVAL) is
            // not a failed sync: the restore goes on, as it always did.
            let base = tempfile::tempdir().unwrap();
            DESTINATION_SYNC_ERRNO.set(Some(libc::EINVAL));
            let result = restore_by_copy(base.path(), kind);
            DESTINATION_SYNC_ERRNO.set(None);
            assert!(result.is_ok(), "{kind}: {result:?}");
            assert_eq!(RESTORE_COPY_EVENTS.take(), ["retire"], "{kind}");
            assert!(fs::symlink_metadata(base.path().join("destination/item")).is_ok());
        }
    }

    /// Seed the entry `id` with its sidecar's text after the `Path=` line.
    fn seed_entry(store: &TrashStore, original: &Path, id: &str, rest: &str) {
        fs::write(store.home.join("files").join(id), id).unwrap();
        fs::write(
            store.home.join(format!("info/{id}.trashinfo")),
            format!("[Trash Info]\nPath={}\n{rest}", original.display()),
        )
        .unwrap();
    }

    // store-metadata-7: DeletionDate is local time without an offset. In
    // the hour a DST fall-back repeats, both readings resolve to the later
    // one, so a file deleted at 01:50 EDT sorted after one deleted twenty
    // minutes later, at 01:10 EST, and `undo` restored the wrong one. The
    // exact instant both writers record, X-Trashd-DeletedNs, only broke
    // ties within a second. Re-exec'd: the zone is the whole process's.
    #[test]
    fn newest_first_orders_by_the_recorded_instant_across_a_dst_fold() {
        const TEST: &str =
            "store::tests::newest_first_orders_by_the_recorded_instant_across_a_dst_fold";
        const CHILD: &str = "TRASHD_TEST_DST_FOLD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env(CHILD, "1")
                .env("TZ", "America/New_York")
                .env("TRASH_BYPASS", "1")
                .status()
                .unwrap();
            assert!(status.success(), "the America/New_York child failed");
            return;
        }
        use chrono::TimeZone;
        let (store, _data, work, _) = test_store();
        let instant = |hour, minute| {
            chrono::Utc
                .with_ymd_and_hms(2026, 11, 1, hour, minute, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap()
        };
        for (id, local, stamp) in [
            ("deleted-first", "2026-11-01T01:50:00", instant(5, 50)),
            ("deleted-last", "2026-11-01T01:10:00", instant(6, 10)),
        ] {
            seed_entry(
                &store,
                &work.path().join(id),
                id,
                &format!("DeletionDate={local}\nX-Trashd-DeletedNs={stamp}\n"),
            );
        }
        let listed: Vec<String> = store
            .list(None)
            .unwrap()
            .into_iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(listed, ["deleted-last", "deleted-first"]);
        assert_eq!(store.undo().unwrap(), work.path().join("deleted-last"));
    }

    // store-metadata-7: the stamp orders entries only where it agrees with
    // the DeletionDate it was written with (time zones are at most 26 hours
    // apart). A sidecar whose date another tool rewrote, or a forged stamp,
    // sorts by its date, as an entry without a stamp does.
    #[test]
    fn a_deletion_stamp_far_from_its_date_does_not_order_an_entry() {
        let (store, _data, work, _) = test_store();
        let stamp = |date: &str| {
            TrashInfo::from_trashinfo(&format!(
                "[Trash Info]\nPath=/original\nDeletionDate={date}\n"
            ))
            .unwrap()
            .deletion_date
            .timestamp_nanos_opt()
            .unwrap()
        };
        let far = stamp("2030-01-01T00:00:00");
        let near = stamp("2026-03-01T12:00:00") + 999_999_999;
        for (id, rest) in [
            (
                "forged",
                format!("DeletionDate=2026-01-01T12:00:00\nX-Trashd-DeletedNs={far}\n"),
            ),
            (
                "unstamped",
                "DeletionDate=2026-02-01T12:00:00\n".to_string(),
            ),
            ("early", "DeletionDate=2026-03-01T12:00:00\n".to_string()),
            (
                "late",
                format!("DeletionDate=2026-03-01T12:00:00\nX-Trashd-DeletedNs={near}\n"),
            ),
        ] {
            seed_entry(&store, &work.path().join(id), id, &rest);
        }
        let listed: Vec<String> = store
            .list(None)
            .unwrap()
            .into_iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(listed, ["late", "early", "unstamped", "forged"]);
    }

    // store-fs-7: a destination directory its user may write but not read
    // cannot be opened to be synced. A restore into it still goes through,
    // as it did before. Root may read anything: the case runs unprivileged.
    #[test]
    fn restore_by_copy_into_a_write_only_directory_still_succeeds() {
        const TEST: &str =
            "store::tests::restore_by_copy_into_a_write_only_directory_still_succeeds";
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: unprivileged fixture setup requires root");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let (source, destination) = (base.path().join("source"), base.path().join("drop-box"));
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("item"), b"payload").unwrap();
        for path in [&source, &destination, &source.join("item")] {
            std::os::unix::fs::lchown(path, Some(65534), Some(65534)).unwrap();
        }
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o300)).unwrap();
        let outcome = as_unprivileged(TEST, move || {
            let from = open_directory_path(&source, true).unwrap();
            let to = open_directory_path(&destination, true).unwrap();
            let entry = stat_at(from.as_raw_fd(), c"item", libc::AT_SYMLINK_NOFOLLOW).unwrap();
            RESTORE_COPY_EVENTS.take();
            let result = publish_copy_noreplace(
                from.as_raw_fd(),
                c"item",
                to.as_raw_fd(),
                c"item",
                stat_identity(&entry),
            );
            let events = RESTORE_COPY_EVENTS.take();
            eprintln!("restore: {result:?}; {events:?}");
            result.is_ok()
                && events == ["retire"]
                && fs::symlink_metadata(source.join("item")).is_err()
                && fs::read(destination.join("item")).is_ok_and(|data| data == b"payload")
        });
        assert_ne!(outcome, Some(false));
    }
}
