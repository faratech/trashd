use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// A mounted filesystem.
#[derive(Debug, Clone)]
pub struct MountPoint {
    pub device: String,
    pub path: PathBuf,
    pub fstype: String,
}

/// Get the device ID (st_dev) for a path.
///
/// symlink_metadata: the device decision must reflect the INODE being moved.
/// A symlink classified by its TARGET could route the move to the wrong
/// filesystem's trash (#46).
pub fn device_id(path: &Path) -> Option<u64> {
    fs::symlink_metadata(path).ok().map(|m| m.dev())
}

/// Get the device ID for a path, following through to the parent if needed.
pub fn device_id_or_parent(path: &Path) -> Option<u64> {
    if let Some(dev) = device_id(path) {
        return Some(dev);
    }
    // File might not exist yet; check parent
    path.parent().and_then(device_id)
}

/// Parse /proc/mounts to get all mount points.
///
/// Parsed as raw bytes: the kernel octal-escapes only space/tab/newline/
/// backslash (all ASCII) in mount paths, so any other raw byte ≥ 0x80
/// survives verbatim — a UTF-8 read of the whole file would fail on a single
/// such mount point and silently empty the entire mount list.
pub fn list_mounts() -> Vec<MountPoint> {
    let content = match read_mount_table() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_mounts(&content)
}

/// /proc/mounts reports size 0, so fs::read grew its buffer from 32 bytes:
/// about ten reads for a typical table (#353). It returns at most a page per
/// read even when more follows, so only an empty read ends it (#354).
/// This thread's table: a thread can unshare(2) a mount namespace of its
/// own, which /proc/mounts (the main thread's) does not show (#368).
fn read_mount_table() -> io::Result<Vec<u8>> {
    read_mount_table_at("/proc/thread-self/mounts").or_else(|_| read_mount_table_at("/proc/mounts"))
}

fn read_mount_table_at(path: &str) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut table = Vec::with_capacity(16 * 1024);
    loop {
        let filled = table.len();
        if table.capacity() - filled < 4096 {
            table.reserve(16 * 1024);
        }
        let spare = table.capacity() - filled;
        table.resize(filled + spare, 0);
        match file.read(&mut table[filled..]) {
            Ok(0) => {
                table.truncate(filled);
                return Ok(table);
            }
            Ok(n) => table.truncate(filled + n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => table.truncate(filled),
            Err(e) => return Err(e),
        }
    }
}

/// Parse mounted-filesystems content (`/proc/mounts` format).
fn parse_mounts(content: &[u8]) -> Vec<MountPoint> {
    parse_mount_table(content, false)
}

/// `parse_mounts`, kernel pseudo-filesystems included when `virtual_too`.
fn parse_mount_table(content: &[u8], virtual_too: bool) -> Vec<MountPoint> {
    let mut mounts = Vec::new();
    for line in content.split(|&b| b == b'\n') {
        // fields are separated by space/tab (both kernel-escaped in paths),
        // so ASCII splitting is exact
        let mut parts = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());
        // strip a trailing \r defensively (getmntent format has none, but a
        // trailing CR would otherwise corrupt every field)
        let device = parts
            .next()
            .map(|f| {
                String::from_utf8_lossy(f)
                    .trim_end_matches('\r')
                    .to_string()
            })
            .unwrap_or_default();
        let path = match parts.next() {
            Some(p) => PathBuf::from(OsString::from_vec(unescape_octal(p))),
            None => continue,
        };
        let fstype = match parts.next() {
            Some(f) => String::from_utf8_lossy(f).to_string(),
            None => continue,
        };

        // Skip virtual filesystems
        if !virtual_too
            && matches!(
                fstype.as_str(),
                "proc"
                    | "sysfs"
                    | "devtmpfs"
                    | "devpts"
                    | "cgroup"
                    | "cgroup2"
                    | "pstore"
                    | "securityfs"
                    | "debugfs"
                    | "tracefs"
                    | "hugetlbfs"
                    | "mqueue"
                    | "configfs"
                    | "fusectl"
                    | "binfmt_misc"
                    | "autofs"
                    | "efivarfs"
                    | "bpf"
                    | "nsfs"
            )
        {
            continue;
        }

        mounts.push(MountPoint {
            device,
            path,
            fstype,
        });
    }

    // Sort by path length descending so longer (more specific) mounts come first
    mounts.sort_by_key(|b| std::cmp::Reverse(b.path.as_os_str().len()));
    mounts
}

/// Find the mount point that contains a given path.
pub fn find_mount_point(path: &Path) -> Option<MountPoint> {
    let mounts = list_mounts();
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };

    // Already sorted longest-first, so first match is most specific
    for mount in &mounts {
        if abs.starts_with(&mount.path) {
            return Some(mount.clone());
        }
    }
    None
}

/// Select the trash directory for an inode identified by DEVICE ID rather
/// than by re-statting a (possibly raced) path — used by the seccomp
/// supervisor's fd-based interception, where `display_path` is best-effort
/// context and `file_dev` is authoritative.
///
/// Falls back to the home trash whenever the device can't be matched to a
/// known mount. Pinned callers surface a resulting cross-device rename so the
/// original process can execute its syscall in its own mount namespace.
///
/// None for a mount root, which cannot move (and whose topdir store would be
/// inside it): rename(2) answers EBUSY for it.
pub fn trash_dir_for_device(
    file_dev: u64,
    display_path: &Path,
    home_trash: &Path,
) -> Option<PathBuf> {
    if device_id_or_parent(home_trash) == Some(file_dev) {
        return Some(home_trash.to_path_buf());
    }
    let uid = unsafe { libc::geteuid() };
    if let Some(mount) = find_mount_point(display_path)
        && device_id(&mount.path) == Some(file_dev)
    {
        if mount.path == display_path && is_mount_root(&mount.path) {
            return None;
        }
        // Spec §1.2.2a: shared .Trash/$UID (created on demand — we're about
        // to write), else §1.2.2b .Trash-$UID.
        if let Some(shared) = check_shared_trash(&mount.path, uid, true) {
            return Some(shared);
        }
        if let Some(private) = check_private_topdir_trash(&mount.path, uid, true) {
            return Some(private);
        }
    }
    Some(home_trash.to_path_buf())
}

/// Whether `path`, which the mount table names as a mount point, still is
/// one: a later mount over its parent can hide it. Where neither statx nor
/// mount IDs can tell, the table is trusted. A mount root operand never
/// gets its topdir store prepared, which would be inside it: that left a
/// .Trash-$UID on the mounted filesystem (#368).
fn is_mount_root(path: &Path) -> bool {
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    match entry_info_at(libc::AT_FDCWD, &name, libc::STATX_TYPE) {
        Err(_) => false,
        Ok(EntryInfo {
            mount_root: Some(root),
            ..
        }) => root,
        Ok(_) => {
            let parent = path
                .parent()
                .and_then(|parent| std::ffi::CString::new(parent.as_os_str().as_bytes()).ok());
            match (
                mount_id_at(libc::AT_FDCWD, &name, 0),
                parent.and_then(|parent| {
                    mount_id_at(libc::AT_FDCWD, &parent, libc::AT_SYMLINK_FOLLOW)
                }),
            ) {
                (Some(own), Some(above)) => own != above,
                _ => true,
            }
        }
    }
}

/// The first mount point strictly below `path`, relative to it, from the
/// mount table: for a tree that could not be walked whole (#370).
/// Every kind counts, a chroot's proc, sys and devpts included. A table
/// entry stands unless the path is shown not to be a mount root there now:
/// a mount over its parent can hide one (#370).
pub(crate) fn mount_below(path: &Path) -> Option<PathBuf> {
    let table = read_mount_table().ok()?;
    parse_mount_table(&table, true)
        .into_iter()
        .find_map(|mount| {
            let inside = mount.path.strip_prefix(path).ok()?;
            if inside.as_os_str().is_empty() || is_not_mount_root(&mount.path) {
                return None;
            }
            Some(inside.to_path_buf())
        })
}

/// Whether `path` is shown not to be a mount root (statx's attribute, else
/// mount IDs, or no such path from here); false whenever that cannot be
/// told.
fn is_not_mount_root(path: &Path) -> bool {
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    match entry_info_at(libc::AT_FDCWD, &name, libc::STATX_TYPE) {
        Ok(EntryInfo {
            mount_root: Some(root),
            ..
        }) => !root,
        Ok(_) => {
            let parent = path
                .parent()
                .and_then(|parent| std::ffi::CString::new(parent.as_os_str().as_bytes()).ok());
            matches!(
                (
                    mount_id_at(libc::AT_FDCWD, &name, 0),
                    parent.and_then(|parent| mount_id_at(libc::AT_FDCWD, &parent, libc::AT_SYMLINK_FOLLOW)),
                ),
                (Some(own), Some(above)) if own == above
            )
        }
        Err(error) => matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)),
    }
}

/// Whether a known device is the filesystem of `path`.
fn same_device(device: Option<u64>, path: &Path) -> bool {
    matches!((device, device_id_or_parent(path)), (Some(a), Some(b)) if a == b)
}

/// Check if two paths are on the same filesystem.
pub fn same_filesystem(a: &Path, b: &Path) -> bool {
    match (device_id_or_parent(a), device_id_or_parent(b)) {
        (Some(da), Some(db)) => da == db,
        _ => false,
    }
}

/// Get the trash directory for a given file path.
/// Per FreeDesktop Trash spec §1.2:
/// - Same filesystem as `$HOME` → `~/.local/share/Trash/`
/// - Different filesystem → check `$topdir/.Trash/$UID/` (sticky-bit), fallback to `$topdir/.Trash-$UID/`
pub fn trash_dir_for_path(path: &Path, home_trash: &Path) -> PathBuf {
    trash_dir_for_path_on(path, None, home_trash).unwrap_or_else(|| home_trash.to_path_buf())
}

/// `trash_dir_for_path` for an operand whose device the caller already
/// knows (`None` looks it up like `same_filesystem`). None for a mount
/// root (see `trash_dir_for_device`).
pub(crate) fn trash_dir_for_path_on(
    path: &Path,
    device: Option<u64>,
    home_trash: &Path,
) -> Option<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return Some(home_trash.to_path_buf()),
        }
    };

    // If on the same filesystem as home trash, use home trash
    if same_device(device.or_else(|| device_id_or_parent(&abs)), home_trash) {
        return Some(home_trash.to_path_buf());
    }

    let uid = unsafe { libc::geteuid() };
    if let Some(mount) = find_mount_point(&abs) {
        if mount.path == abs && is_mount_root(&mount.path) {
            return None;
        }
        // Spec §1.2.2a: check $topdir/.Trash/ (creating our uid dir is fine —
        // we're about to write into it)
        if let Some(shared) = check_shared_trash(&mount.path, uid, true) {
            return Some(shared);
        }
        // Spec §1.2.2b: use $topdir/.Trash-$UID/. Refuse a pre-existing
        // symlink, foreign-owned directory, or directory that cannot be made
        // private; copying to the authenticated home trash is safer.
        if let Some(private) = check_private_topdir_trash(&mount.path, uid, true) {
            return Some(private);
        }
    }

    // Fallback to home trash (will do cross-device copy)
    Some(home_trash.to_path_buf())
}

/// Read-only selection used by preflight; it never prepares a store.
/// `device` is the operand's, when the caller already knows it.
pub(crate) fn existing_trash_dir_for_path_on(
    path: &Path,
    device: Option<u64>,
    home: &Path,
) -> PathBuf {
    if same_device(device.or_else(|| device_id_or_parent(path)), home) {
        return home.to_path_buf();
    }
    let uid = unsafe { libc::geteuid() };
    if let Some(mount) = find_mount_point(path) {
        if let Some(root) = check_shared_trash(&mount.path, uid, false)
            .or_else(|| check_private_topdir_trash(&mount.path, uid, false))
        {
            return root;
        }
        // A future same-device private store would be inside a mount-root
        // operand. Preserve the existing trash-self refusal before traversal.
        if trusted_topdir(&mount.path, uid) && !mount.path.join(format!(".Trash-{uid}")).exists() {
            return mount.path.join(format!(".Trash-{uid}"));
        }
    }
    home.to_path_buf()
}

/// Check if $topdir/.Trash/ exists, is a real directory (not symlink),
/// has the sticky bit, and is usable. If so, return $topdir/.Trash/$UID/.
///
/// `create=false` turns this into a pure PROBE for enumeration
/// (all_trash_dirs): a read-only `trash ls`/`status` must not scatter
/// `.Trash/$UID` directories across every mounted filesystem (#38).
fn check_shared_trash(topdir: &Path, uid: u32, create: bool) -> Option<PathBuf> {
    if !trusted_topdir(topdir, uid) {
        return None;
    }
    shared_trash_in(topdir, uid, create)
}

/// `check_shared_trash` for a topdir already found trusted.
fn shared_trash_in(topdir: &Path, uid: u32, create: bool) -> Option<PathBuf> {
    let trash_dir = topdir.join(".Trash");

    // Must not be a symlink
    let meta = fs::symlink_metadata(&trash_dir).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    if !meta.is_dir() || (meta.uid() != 0 && meta.uid() != uid) {
        return None;
    }

    // Must have sticky bit set (mode & S_ISVTX)
    let mode = meta.permissions().mode();
    if mode & 0o1000 == 0 {
        return None;
    }

    // Must be writable by us (check by trying to create the uid subdir)
    let uid_dir = trash_dir.join(uid.to_string());
    if !uid_dir.exists() {
        if !create {
            return None;
        }
        if fs::DirBuilder::new().mode(0o700).create(&uid_dir).is_err() {
            return None;
        }
    }

    // Verify the uid subdir is owned by us (FreeDesktop spec §1.2.2a).
    // A malicious user could pre-create this directory with different ownership.
    if let Ok(m) = fs::symlink_metadata(&uid_dir) {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != uid || m.file_type().is_symlink() || !m.is_dir() {
            return None;
        }
        // Re-enforce privacy on reuse: an older version could have left the
        // dir group/other-readable.
        if create && m.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(&uid_dir, fs::Permissions::from_mode(0o700)).ok()?;
            let after = fs::symlink_metadata(&uid_dir).ok()?;
            if after.uid() != uid
                || !after.is_dir()
                || after.file_type().is_symlink()
                || after.permissions().mode() & 0o777 != 0o700
            {
                return None;
            }
        } else if m.permissions().mode() & 0o777 != 0o700 {
            return None;
        }
        return Some(uid_dir);
    }

    None
}

/// Verify (and optionally create) the private per-user fallback described by
/// FreeDesktop §1.2.2b. The mount root must itself be a stable directory: it
/// may be owned by root or by the caller, and a writable mount root must have
/// the sticky bit so another user cannot replace our entry.
fn check_private_topdir_trash(topdir: &Path, uid: u32, create: bool) -> Option<PathBuf> {
    if !trusted_topdir(topdir, uid) {
        return None;
    }
    private_trash_in(topdir, uid, create)
}

/// `check_private_topdir_trash` for a topdir already found trusted.
fn private_trash_in(topdir: &Path, uid: u32, create: bool) -> Option<PathBuf> {
    let path = topdir.join(format!(".Trash-{uid}"));
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            fs::DirBuilder::new().mode(0o700).create(&path).ok()?;
        }
        Err(_) => return None,
    }
    validate_private_dir(&path, uid, create).then_some(path)
}

fn trusted_topdir(topdir: &Path, uid: u32) -> bool {
    fs::symlink_metadata(topdir).is_ok_and(|parent| trusted_topdir_metadata(&parent, uid))
}

fn trusted_topdir_metadata(parent: &fs::Metadata, uid: u32) -> bool {
    let mode = parent.permissions().mode();
    parent.is_dir()
        && !parent.file_type().is_symlink()
        && (parent.uid() == 0 || parent.uid() == uid)
        && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}

/// A trusted trash root and each of its writable children must be a real,
/// current-user-owned directory with no group/other access. This invariant is
/// what makes subsequent entry names safe to enumerate and permanently purge.
pub(crate) fn validate_private_dir(path: &Path, uid: u32, repair_mode: bool) -> bool {
    private_dir_metadata(path, uid, repair_mode).is_some()
}

/// Keep the validated identity and permissions in the same metadata snapshot.
fn private_dir_metadata(path: &Path, uid: u32, repair_mode: bool) -> Option<fs::Metadata> {
    let mut meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
        return None;
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        if !repair_mode || fs::set_permissions(path, fs::Permissions::from_mode(0o700)).is_err() {
            return None;
        }
        meta = fs::symlink_metadata(path).ok()?;
    }
    (meta.is_dir()
        && !meta.file_type().is_symlink()
        && meta.uid() == uid
        && meta.permissions().mode() & 0o777 == 0o700)
        .then_some(meta)
}

/// Validate an existing trash root for read/destructive enumeration. Unlike
/// selection this never creates or chmods anything.
pub(crate) fn is_safe_trash_root(path: &Path, uid: u32) -> bool {
    validate_private_dir(path, uid, false)
        && validate_private_dir(&path.join("files"), uid, false)
        && validate_private_dir(&path.join("info"), uid, false)
}

/// Classify authenticated stores without creating or repairing directories.
/// Remember each authenticated root's identity so removing files/info during
/// cleanup does not invalidate it, and a replacement inode cannot inherit it.
///
/// Identities only, no descriptors: a held descriptor pinned removable media
/// so `umount` failed for as long as the process ran, and the lock is never
/// held across syscalls, since a fork in another thread would otherwise leave
/// it locked forever in the child (#206). The root itself is re-validated as
/// a private directory of this user on every call.
#[allow(dead_code)]
pub(crate) fn is_trash_internal(path: &Path, home: &Path, trusted_home: bool) -> bool {
    use std::sync::{Mutex, OnceLock};
    let home_candidate = trusted_home && path.starts_with(home);
    // A mounted trash root must have one of these complete path components.
    // This is only a negative filter: candidates still undergo every trust
    // check below. Ordinary paths need no mount discovery or UID lookup.
    if !home_candidate
        && !path.components().any(|component| {
            let name = component.as_os_str().as_bytes();
            name == b".Trash" || name.starts_with(b".Trash-")
        })
    {
        return false;
    }
    static ROOTS: OnceLock<Mutex<HashMap<PathBuf, (u64, u64)>>> = OnceLock::new();
    let roots = ROOTS.get_or_init(|| Mutex::new(HashMap::new()));
    let uid = unsafe { libc::geteuid() };
    let forget = |root: &Path| {
        with_lock_bounded(roots, |map| map.remove(root));
    };
    let authenticated = |root: &Path| {
        let Some(meta) = private_dir_metadata(root, uid, false) else {
            forget(root);
            return false;
        };
        let identity = (meta.dev(), meta.ino());
        // Never hold this lock over filesystem calls or retain descriptors.
        let remembered = with_lock_bounded(roots, |map| map.get(root).copied()).flatten();
        if let Some(remembered) = remembered {
            if remembered == identity {
                return true;
            }
            forget(root);
        }
        if !is_safe_trash_root(root, uid) {
            return false;
        }
        with_lock_bounded(roots, |map| map.insert(root.to_path_buf(), identity));
        true
    };
    // Home is already the first candidate. Authenticate it before consulting
    // the mount table, including cached cleanup after files/info are removed.
    if home_candidate && authenticated(home) {
        return true;
    }
    for mount in list_mounts() {
        if !path.starts_with(&mount.path) {
            continue;
        }
        for root in [
            check_shared_trash(&mount.path, uid, false),
            check_private_topdir_trash(&mount.path, uid, false),
        ]
        .into_iter()
        .flatten()
        {
            if path.starts_with(&root) && authenticated(&root) {
                return true;
            }
        }
    }
    false
}

/// Run `operation` under `mutex` without blocking indefinitely. Plain
/// `try_lock` dropped the operation whenever another thread held the lock
/// for its single map access, losing remembered roots (#309). Waiting a few
/// milliseconds outlasts a holder that was merely preempted, while a lock
/// left held by a thread that did not survive `fork` still cannot deadlock
/// the child (#206).
fn with_lock_bounded<T, R>(
    mutex: &std::sync::Mutex<T>,
    operation: impl FnOnce(&mut T) -> R,
) -> Option<R> {
    use std::sync::TryLockError;
    use std::time::{Duration, Instant};
    let mut spins = 0u32;
    let mut deadline = None;
    loop {
        match mutex.try_lock() {
            Ok(mut guard) => return Some(operation(&mut guard)),
            Err(TryLockError::Poisoned(poisoned)) => {
                return Some(operation(&mut poisoned.into_inner()));
            }
            Err(TryLockError::WouldBlock) => {}
        }
        if spins < 64 {
            spins += 1;
            std::hint::spin_loop();
            continue;
        }
        let now = Instant::now();
        if now >= *deadline.get_or_insert(now + Duration::from_millis(10)) {
            return None;
        }
        std::thread::yield_now();
    }
}

/// The ID of the mount an open descriptor is on, from /proc/self/fdinfo
/// (Linux 3.15+): works on every filesystem, unlike file handles.
pub fn fd_mount_id(fd: std::os::fd::RawFd) -> Option<i32> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|id| id.trim().parse().ok())
}

/// Mode, (device, inode) and mount-root status of `name` in `parent`
/// without following a symlink, in one statx. The mount status is None
/// where statx does not report it (before Linux 5.8); `mount_id_at`
/// answers then.
pub fn entry_status_at(
    parent: std::os::fd::RawFd,
    name: &std::ffi::CStr,
) -> io::Result<(u32, (u64, u64), Option<bool>)> {
    let entry = entry_info_at(
        parent,
        name,
        libc::STATX_TYPE | libc::STATX_MODE | libc::STATX_INO,
    )?;
    Ok((entry.mode, (entry.dev, entry.ino), entry.mount_root))
}

/// What one statx of an entry reports (`entry_info_at`).
pub struct EntryInfo {
    pub mode: u32,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    /// 512-byte blocks allocated.
    pub blocks: u64,
    pub uid: u32,
    /// Modification and inode-change timestamps, when requested.
    pub modified: (libc::time_t, libc::c_long),
    pub changed: (libc::time_t, libc::c_long),
    /// Whether it is the root of a mount; None where statx does not say
    /// (before Linux 5.8, or statx refused).
    pub mount_root: Option<bool>,
    /// Whether it is immutable or append-only (nothing in it can be
    /// unlinked); false where statx does not say.
    pub pinned: bool,
    /// Whether statx reported both immutable and append-only attributes.
    /// Retirement checks use `entry_pinned_at` when this is false.
    pub pinned_known: bool,
}

/// `name` in `parent`, without following a symlink, from one statx asking
/// for `mask`, or fstatat where statx is unavailable. An empty `name` is
/// `parent` itself.
pub fn entry_info_at(
    parent: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    mask: u32,
) -> io::Result<EntryInfo> {
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // statx(2), unlike fstatat, triggers an automount at the last component
    // unless told not to (#371).
    let flags = libc::AT_SYMLINK_NOFOLLOW
        | libc::AT_NO_AUTOMOUNT
        | if name.is_empty() {
            libc::AT_EMPTY_PATH
        } else {
            0
        };
    // The raw syscall: glibc's wrapper turns ENOSYS into a silent fstatat.
    // A failure on this path alone (a FUSE getattr's EPERM) falls back for
    // this entry only; statx is given up only when the probe agrees it is
    // refused everywhere (#365).
    let statx_ok = !statx_refused()
        && (unsafe {
            libc::syscall(
                libc::SYS_statx,
                parent,
                name.as_ptr(),
                flags,
                mask,
                &mut stx as *mut libc::statx,
            )
        } == 0
            || {
                if matches!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EPERM | libc::ENOSYS)
                ) {
                    probe_statx();
                }
                false
            });
    complete_entry_info(parent, name, mask, flags, statx_ok.then_some(&stx))
}

fn complete_entry_info(
    parent: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    mask: u32,
    flags: libc::c_int,
    stx: Option<&libc::statx>,
) -> io::Result<EntryInfo> {
    // A successful statx can omit fields a filesystem cannot supply. A
    // snapshot needs every requested version field, so do not accept zero
    // timestamps or identities in place of missing metadata (#379).
    if let Some(stx) = stx.filter(|stx| stx.stx_mask & mask == mask) {
        let root = libc::STATX_ATTR_MOUNT_ROOT as u64;
        let pinned = (libc::STATX_ATTR_IMMUTABLE | libc::STATX_ATTR_APPEND) as u64;
        return Ok(EntryInfo {
            mode: u32::from(stx.stx_mode),
            dev: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
            ino: stx.stx_ino,
            size: stx.stx_size,
            blocks: stx.stx_blocks,
            uid: stx.stx_uid,
            modified: (stx.stx_mtime.tv_sec as _, stx.stx_mtime.tv_nsec as _),
            changed: (stx.stx_ctime.tv_sec as _, stx.stx_ctime.tv_nsec as _),
            mount_root: (stx.stx_attributes_mask & root != 0)
                .then_some(stx.stx_attributes & root != 0),
            pinned: stx.stx_attributes & stx.stx_attributes_mask & pinned != 0,
            pinned_known: stx.stx_attributes_mask & pinned == pinned,
        });
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(EntryInfo {
        mode: stat.st_mode,
        dev: stat.st_dev,
        ino: stat.st_ino,
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        uid: stat.st_uid,
        modified: (stat.st_mtime, stat.st_mtime_nsec),
        changed: (stat.st_ctime, stat.st_ctime_nsec),
        mount_root: None,
        pinned: false,
        pinned_known: false,
    })
}

/// Whether this entry is immutable or append-only before a copy whose
/// source must subsequently be unlinked. `entry` must include TYPE and INO.
/// Ordinary surveys and purge do not need this ioctl fallback per entry.
///
/// Unlike statx, FS_IOC_GETFLAGS needs a readable descriptor. An O_PATH
/// parent without read permission can legitimately permit removal, but
/// cannot be examined this way: leave that as an I/O failure rather than
/// copying a source that might be impossible to retire.
pub(crate) fn entry_pinned_at(
    parent: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    entry: &EntryInfo,
) -> io::Result<bool> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if entry.pinned || entry.pinned_known {
        return Ok(entry.pinned);
    }
    // Pin without opening a replacement device or following a symlink.
    let name = if name.is_empty() { c"." } else { name };
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
    // Raw fstat: Rust's File::metadata may itself use statx and fail with
    // EPERM under the very profile this fallback is handling (#379).
    let inspect = |fd| -> io::Result<libc::stat> {
        let mut stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stat)
    };
    let agrees = |stat: &libc::stat| {
        (stat.st_dev, stat.st_ino, stat.st_mode & libc::S_IFMT)
            == (entry.dev, entry.ino, entry.mode & libc::S_IFMT)
    };
    let stat = inspect(pinned.as_raw_fd())?;
    if !agrees(&stat) {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    let kind = stat.st_mode & libc::S_IFMT;
    // Linux inode flag ioctls do not operate on a symlink itself.
    if kind == libc::S_IFLNK {
        return Ok(false);
    }
    if !matches!(kind, libc::S_IFREG | libc::S_IFDIR | libc::S_IFIFO) {
        // Device nodes and sockets cannot be copied either. Never open a
        // device just to ask about flags: its open can have side effects.
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let readable = if kind == libc::S_IFDIR {
        unsafe {
            libc::openat(
                pinned.as_raw_fd(),
                c".".as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        }
    } else {
        // This magic link reopens our pinned inode, not the source's name.
        // A FIFO is nonblocking and is never read.
        let path = std::ffi::CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
        unsafe { libc::open(path.as_ptr(), flags) }
    };
    if readable < 0 {
        return Err(io::Error::last_os_error());
    }
    let readable = unsafe { fs::File::from_raw_fd(readable) };
    if !agrees(&inspect(readable.as_raw_fd())?) {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
    const PINNED: libc::c_int = 0x10 | 0x20; // FS_IMMUTABLE_FL | FS_APPEND_FL
    let mut inode_flags: libc::c_int = 0;
    if unsafe { libc::ioctl(readable.as_raw_fd(), FS_IOC_GETFLAGS, &mut inode_flags) } == 0 {
        return Ok(inode_flags & PINNED != 0);
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENOTTY | libc::EOPNOTSUPP)) {
        Ok(false) // This filesystem does not provide inode flags.
    } else {
        Err(error)
    }
}

/// Whether statx was found refused everywhere (`probe_statx`).
static STATX_REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn statx_refused() -> bool {
    STATX_REFUSED.load(std::sync::atomic::Ordering::Relaxed)
}

/// After a statx failed with EPERM or ENOSYS, ask whether that is statx
/// itself, the way Rust's std does: a NULL buffer makes a usable statx fail
/// with EFAULT, while a seccomp profile refuses it with EPERM and old
/// kernels with ENOSYS (#365).
fn probe_statx() {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_statx,
            0,
            std::ptr::null::<libc::c_char>(),
            0,
            libc::STATX_ALL,
            std::ptr::null_mut::<libc::statx>(),
        )
    };
    if ret == -1
        && matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM | libc::ENOSYS)
        )
    {
        STATX_REFUSED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The ID of the mount `name` (relative to `dir`) is on: from
/// name_to_handle_at, which needs no /proc, else from fdinfo; None when
/// neither can tell.
pub fn mount_id_at(
    dir: std::os::fd::RawFd,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> Option<i32> {
    #[repr(C)]
    struct Handle {
        bytes: u32,
        kind: i32,
        data: [u8; 128], // MAX_HANDLE_SZ
    }
    let mut handle = Handle {
        bytes: 128,
        kind: 0,
        data: [0; 128],
    };
    let mut id: libc::c_int = 0;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            dir,
            name.as_ptr(),
            &mut handle as *mut Handle,
            &mut id as *mut libc::c_int,
            flags,
        )
    };
    // EOVERFLOW still reports the mount.
    if ret == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EOVERFLOW) {
        return Some(id);
    }
    // Filesystems that encode no handles (ramfs, overlayfs, 9p, CIFS):
    // fdinfo names the mount of any descriptor (#362).
    if flags & libc::AT_EMPTY_PATH != 0 {
        return fd_mount_id(dir);
    }
    let nofollow = if flags & libc::AT_SYMLINK_FOLLOW != 0 {
        0
    } else {
        libc::O_NOFOLLOW
    };
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | nofollow,
        )
    };
    if fd < 0 {
        return None;
    }
    let id = fd_mount_id(fd);
    unsafe { libc::close(fd) };
    id
}

/// Filesystem types that never hold user files.
const PSEUDO_FILESYSTEMS: &[&str] = &[
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "proc",
    "pstore",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "sysfs",
    "tracefs",
];

/// Discover all trash directories across all mount points.
/// Returns (trash_dir, mount_description) pairs.
pub fn all_trash_dirs(home_trash: &Path) -> Vec<(PathBuf, String)> {
    let uid = unsafe { libc::geteuid() };
    let mut dirs: HashMap<PathBuf, String> = HashMap::new();
    // A filesystem mounted at two paths (a bind mount) exposes the same trash
    // root twice; it was double-counted by retention and made every ID in it
    // ambiguous. Roots are identified by device and inode (#219).
    let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    let mut first_sighting =
        |root: &Path| fs::metadata(root).is_ok_and(|meta| seen.insert((meta.dev(), meta.ino())));

    // Always include home trash
    if is_safe_trash_root(home_trash, uid) && first_sighting(home_trash) {
        dirs.insert(home_trash.to_path_buf(), "home".into());
    }

    // One enumeration uses one observed home device instead of re-statting
    // the same path for each mount. Every discovered root is still validated.
    let home_device = device_id_or_parent(home_trash);
    // Scan all mount points for trash directories
    for mount in list_mounts() {
        // Kernel pseudo-filesystems hold no user files, so no topdir trash;
        // statting an autofs point could even trigger a mount (#354).
        if PSEUDO_FILESYSTEMS.contains(&mount.fstype.as_str()) {
            continue;
        }
        // One lstat of the mount point serves the home-device skip and both
        // topdir trust checks, which statted it twice more (#353). A mount
        // point that cannot be examined holds no usable topdir trash.
        let Ok(top) = fs::symlink_metadata(&mount.path) else {
            continue;
        };
        // Skip if same filesystem as home
        if home_device == Some(top.dev()) || !trusted_topdir_metadata(&top, uid) {
            continue;
        }

        let label = format!("{} ({})", mount.path.display(), mount.fstype);

        // Check shared .Trash/$UID first (spec §1.2.2a) — PROBE only: a
        // read-only enumeration must not create trash dirs on every mount (#38).
        if let Some(shared) = shared_trash_in(&mount.path, uid, false)
            && is_safe_trash_root(&shared, uid)
            && first_sighting(&shared)
        {
            dirs.entry(shared).or_insert(label.clone());
        }

        // Also check .Trash-$UID (spec §1.2.2b)
        let topdir = mount.path.join(format!(".Trash-{uid}"));
        if private_trash_in(&mount.path, uid, false)
            .is_some_and(|path| is_safe_trash_root(&path, uid))
            && first_sighting(&topdir)
        {
            dirs.entry(topdir).or_insert(label);
        }
    }

    dirs.into_iter().collect()
}

/// A mount path field of /proc/mounts or /proc/self/mountinfo, unescaped.
pub fn unescape_mount_path(field: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(unescape_octal(field)))
}

/// Unescape octal sequences in mount paths (e.g. \040 for space).
///
/// Operates on raw bytes and preserves every unescaped byte verbatim: mount
/// points may contain arbitrary non-UTF-8 bytes (the kernel only escapes
/// space/tab/newline/backslash).
fn unescape_octal(field: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        // the kernel emits exactly %03o (three octal digits 0-7)
        if field[i] == b'\\'
            && i + 4 <= field.len()
            && field[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let o = &field[i + 1..i + 4];
            result.push(((o[0] - b'0') << 6) | ((o[1] - b'0') << 3) | (o[2] - b'0'));
            i += 4;
        } else {
            result.push(field[i]);
            i += 1;
        }
    }
    result
}

/// Marker line a re-run test child prints with its verdict.
#[cfg(test)]
const TEST_VERDICT: &str = "trashd-test-verdict:";

/// Run the named test again in a child process whose environment sets
/// `variable` to that name, and read the verdict it prints: forking inside
/// the multi-threaded harness can deadlock the child. A child that never
/// reports (a renamed test) fails. None when the child could not isolate.
#[cfg(test)]
pub(crate) fn rerun_test(test: &str, variable: &str) -> Option<bool> {
    let output = std::process::Command::new(std::env::current_exe().ok()?)
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(variable, test)
        .env("TRASH_BYPASS", "1")
        .stderr(std::process::Stdio::inherit())
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // libtest prints its own "test ... " ahead of the case's output.
    let verdict = stdout
        .split(TEST_VERDICT)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next());
    match verdict {
        Some("skip") => None,
        Some("pass") if output.status.success() => Some(true),
        Some(_) => Some(false),
        None => {
            eprintln!("the child never ran {test}:\n{stdout}");
            Some(false)
        }
    }
}

/// Inside a re-run child: report `verdict` for the parent and return it, so
/// the test body finishes and drops its temporaries.
#[cfg(test)]
pub(crate) fn report_test_verdict(verdict: Option<bool>) -> Option<bool> {
    let word = match verdict {
        Some(true) => "pass",
        Some(false) => "fail",
        None => "skip",
    };
    println!("{TEST_VERDICT}{word}");
    verdict
}

/// Whether this process is the re-run child for `test`.
#[cfg(test)]
pub(crate) fn is_rerun_child(test: &str, variable: &str) -> bool {
    std::env::var(variable).is_ok_and(|named| named == test)
}

/// Run `case` in a private mount namespace, as root (see `rerun_test`).
/// The case must unmount what it mounts.
#[cfg(test)]
pub(crate) fn in_private_mounts(test: &str, case: impl FnOnce() -> bool) -> Option<bool> {
    const CHILD: &str = "TRASHD_TEST_PRIVATE_MOUNTS";
    if is_rerun_child(test, CHILD) {
        let isolated = unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0
            && unsafe {
                libc::mount(
                    c"none".as_ptr(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            } == 0;
        return report_test_verdict(isolated.then(case));
    }
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    rerun_test(test, CHILD)
}

#[cfg(test)]
mod tests {
    use super::in_private_mounts;

    // #365: the fdinfo fallback tells a mount from a plain directory, and
    // statx's availability is probed once.
    #[test]
    fn mount_fallback_tells_mounts_from_directories() {
        use std::os::fd::AsRawFd;
        let root = std::fs::File::open("/").unwrap();
        let Some(id) = super::mount_id_at(root.as_raw_fd(), c"", libc::AT_EMPTY_PATH) else {
            return; // neither file handles nor /proc: nothing to compare
        };
        if std::fs::metadata("/proc/self").is_ok() {
            assert_ne!(super::mount_id_at(root.as_raw_fd(), c"proc", 0), Some(id));
        }
        // A directory just made is on its parent's mount.
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(base.path().join("plain")).unwrap();
        let dir = std::fs::File::open(base.path()).unwrap();
        let above = super::mount_id_at(dir.as_raw_fd(), c"", libc::AT_EMPTY_PATH);
        assert!(above.is_some());
        assert_eq!(super::mount_id_at(dir.as_raw_fd(), c"plain", 0), above);
    }

    // #354: /proc/mounts hands out a page per read; the whole table counts.
    // A child in a private mount namespace grows it past a page (root only).
    #[test]
    fn mount_table_is_read_past_its_first_page() {
        let base = tempfile::tempdir().unwrap();
        let verdict = in_private_mounts(
            "mounts::tests::mount_table_is_read_past_its_first_page",
            || {
                for i in 0..80 {
                    let dir = base
                        .path()
                        .join(format!("mount-{i:02}-padding-to-grow-the-table"));
                    if std::fs::create_dir(&dir).is_err() {
                        return false;
                    }
                    let target =
                        std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
                    if unsafe {
                        libc::mount(
                            c"none".as_ptr(),
                            target.as_ptr(),
                            c"tmpfs".as_ptr(),
                            0,
                            std::ptr::null(),
                        )
                    } != 0
                    {
                        return false;
                    }
                }
                // The namespace is this thread's (the harness runs tests on
                // their own threads); /proc/mounts names the main thread's.
                let table = "/proc/thread-self/mounts";
                let whole = std::fs::read(table).unwrap_or_default();
                let read = super::read_mount_table_at(table);
                for i in 0..80 {
                    let dir = base
                        .path()
                        .join(format!("mount-{i:02}-padding-to-grow-the-table"));
                    let target =
                        std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
                    unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
                }
                whole.len() > 4096 && read.is_ok_and(|read| read == whole)
            },
        );
        assert_ne!(verdict, Some(false));
    }

    use super::*;

    // #379: a successful but partial statx must not fabricate a snapshot
    // version from zero or missing fields. Re-stat it in full, without
    // carrying attributes from an inode the name may no longer identify.
    #[test]
    fn partial_statx_falls_back_to_complete_version_metadata() {
        use std::os::fd::AsRawFd;
        let work = tempfile::tempdir().unwrap();
        let file = fs::File::create(work.path().join("file")).unwrap();
        file.set_len(123).unwrap();
        file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::new(1_234_567, 987_654_321))
            .unwrap();
        let metadata = file.metadata().unwrap();
        let parent = fs::File::open(work.path()).unwrap();
        let mask = libc::STATX_TYPE
            | libc::STATX_MODE
            | libc::STATX_INO
            | libc::STATX_UID
            | libc::STATX_SIZE
            | libc::STATX_MTIME
            | libc::STATX_CTIME;
        let mut partial: libc::statx = unsafe { std::mem::zeroed() };
        partial.stx_mask = mask & !libc::STATX_CTIME;
        partial.stx_attributes_mask = u64::MAX;
        partial.stx_attributes = u64::MAX;
        let entry = complete_entry_info(
            parent.as_raw_fd(),
            c"file",
            mask,
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            Some(&partial),
        )
        .unwrap();
        assert_eq!((entry.dev, entry.ino), (metadata.dev(), metadata.ino()));
        assert_eq!((entry.mode, entry.uid), (metadata.mode(), metadata.uid()));
        assert_eq!(entry.size, metadata.len());
        assert_eq!(entry.modified, (metadata.mtime(), metadata.mtime_nsec()));
        assert_eq!(entry.changed, (metadata.ctime(), metadata.ctime_nsec()));
        assert!(!entry.pinned && !entry.pinned_known);
        assert_eq!(entry.mount_root, None);
        let normal = entry_info_at(parent.as_raw_fd(), c"file", mask).unwrap();
        assert_eq!(normal.modified, entry.modified);
        assert_eq!(normal.changed, entry.changed);
    }

    // The process-wide statx probe must be changed only in a re-run child.
    // Inode flags are still examined when statx is unavailable, or when it
    // returned attributes without describing immutable/append-only flags.
    #[test]
    fn pinned_flags_fallback_without_statx() {
        use std::ffi::OsStr;
        use std::os::fd::AsRawFd;
        const TEST: &str = "mounts::tests::pinned_flags_fallback_without_statx";
        const CHILD: &str = "TRASHD_TEST_PINNED_FALLBACK";
        if !is_rerun_child(TEST, CHILD) {
            assert_ne!(rerun_test(TEST, CHILD), Some(false));
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let parent = fs::File::open(base.path()).unwrap();
        fs::write(base.path().join("file"), b"keep").unwrap();
        fs::create_dir(base.path().join("directory")).unwrap();
        std::os::unix::fs::symlink("file", base.path().join("link")).unwrap();
        assert_eq!(
            unsafe { libc::mkfifoat(parent.as_raw_fd(), c"fifo".as_ptr(), 0o600) },
            0
        );
        let mask = libc::STATX_TYPE | libc::STATX_INO;
        // Force only the attribute-unknown branch first, before disabling
        // statx; the known fast path never needs to reopen an entry.
        let mut unknown = entry_info_at(parent.as_raw_fd(), c"file", mask).unwrap();
        unknown.pinned = false;
        unknown.pinned_known = true;
        assert!(!entry_pinned_at(-1, c"missing", &unknown).unwrap());
        unknown.pinned = true;
        assert!(entry_pinned_at(-1, c"missing", &unknown).unwrap());
        unknown.pinned = false;
        unknown.pinned_known = false;
        assert!(!entry_pinned_at(parent.as_raw_fd(), c"file", &unknown).unwrap());

        STATX_REFUSED.store(true, std::sync::atomic::Ordering::Relaxed);
        for name in [c"file", c"directory", c"link", c"fifo"] {
            let entry = entry_info_at(parent.as_raw_fd(), name, mask).unwrap();
            assert!(!entry.pinned_known);
            assert!(!entry_pinned_at(parent.as_raw_fd(), name, &entry).unwrap());
        }

        const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
        const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
        struct RestoreFlags(fs::File, libc::c_int);
        impl Drop for RestoreFlags {
            fn drop(&mut self) {
                assert_eq!(
                    unsafe { libc::ioctl(self.0.as_raw_fd(), FS_IOC_SETFLAGS, &self.1) },
                    0
                );
            }
        }
        let mut checked = 0;
        for name in [c"file", c"directory"] {
            let file =
                fs::File::open(base.path().join(OsStr::from_bytes(name.to_bytes()))).unwrap();
            let mut original: libc::c_int = 0;
            if unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut original) } != 0 {
                continue;
            }
            let reset = RestoreFlags(file, original);
            for flag in [0x10, 0x20] {
                let flags = original | flag;
                if unsafe { libc::ioctl(reset.0.as_raw_fd(), FS_IOC_SETFLAGS, &flags) } != 0 {
                    continue;
                }
                let entry = entry_info_at(parent.as_raw_fd(), name, mask).unwrap();
                assert!(!entry.pinned && !entry.pinned_known);
                assert!(entry_pinned_at(parent.as_raw_fd(), name, &entry).unwrap());
                checked += 1;
                assert_eq!(
                    unsafe { libc::ioctl(reset.0.as_raw_fd(), FS_IOC_SETFLAGS, &original) },
                    0
                );
            }
        }
        if checked < 4 {
            eprintln!(
                "SKIP: checked {checked}/4 immutable/append-only cases (privilege/filesystem)"
            );
        }
        // A replaced entry must never inherit the original inode's verdict.
        let before = entry_info_at(parent.as_raw_fd(), c"file", mask).unwrap();
        fs::rename(base.path().join("file"), base.path().join("old")).unwrap();
        fs::write(base.path().join("file"), b"replacement").unwrap();
        assert!(
            entry_pinned_at(parent.as_raw_fd(), c"file", &before)
                .is_err_and(|error| error.raw_os_error() == Some(libc::ENOENT))
        );
        report_test_verdict(Some(true));
    }

    // Without statx, an unreadable O_PATH parent cannot be queried with
    // FS_IOC_GETFLAGS. That is an examination failure, never "unpinned".
    #[test]
    fn pinned_flags_fallback_preserves_read_errors() {
        use std::os::fd::{AsRawFd, FromRawFd};
        const TEST: &str = "mounts::tests::pinned_flags_fallback_preserves_read_errors";
        const CHILD: &str = "TRASHD_TEST_PINNED_READ_ERROR";
        if !is_rerun_child(TEST, CHILD) {
            if unsafe { libc::geteuid() } == 0 {
                assert_ne!(rerun_test(TEST, CHILD), Some(false));
            }
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let name = std::ffi::CString::new(base.path().as_os_str().as_bytes()).unwrap();
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let parent = unsafe { fs::File::from_raw_fd(fd) };
        std::os::unix::fs::chown(base.path(), Some(65534), Some(65534)).unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o300)).unwrap();
        STATX_REFUSED.store(true, std::sync::atomic::Ordering::Relaxed);
        let entry = entry_info_at(fd, c"", libc::STATX_TYPE | libc::STATX_INO).unwrap();
        struct RestoreUid;
        impl Drop for RestoreUid {
            fn drop(&mut self) {
                assert_eq!(unsafe { libc::seteuid(0) }, 0);
            }
        }
        assert_eq!(unsafe { libc::seteuid(65534) }, 0);
        let restore = RestoreUid;
        let result = entry_pinned_at(parent.as_raw_fd(), c"", &entry);
        drop(restore);
        assert!(result.is_err_and(|error| error.raw_os_error() == Some(libc::EACCES)));
        report_test_verdict(Some(true));
    }

    // #368: a mount root that is itself the operand has no trash: its topdir
    // store would be inside it, and is never created; an entry inside still
    // gets it.
    #[test]
    fn a_mount_root_operand_prepares_no_trash_inside_it() {
        let base = tempfile::tempdir().unwrap();
        let home = base.path().join("home/Trash");
        let mounted = base.path().join("mounted");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir(&mounted).unwrap();
        let verdict = in_private_mounts(
            "mounts::tests::a_mount_root_operand_prepares_no_trash_inside_it",
            || {
                let target =
                    std::ffi::CString::new(mounted.as_os_str().as_encoded_bytes()).unwrap();
                if unsafe {
                    libc::mount(
                        c"none".as_ptr(),
                        target.as_ptr(),
                        c"tmpfs".as_ptr(),
                        0,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return false;
                }
                let own = mounted.join(format!(".Trash-{}", unsafe { libc::geteuid() }));
                let chosen = trash_dir_for_path_on(&mounted, None, &home);
                let by_device =
                    device_id(&mounted).map(|device| trash_dir_for_device(device, &mounted, &home));
                let untouched = fs::read_dir(&mounted).is_ok_and(|mut dir| dir.next().is_none());
                let inside = fs::write(mounted.join("f"), b"x").is_ok()
                    && trash_dir_for_path_on(&mounted.join("f"), None, &home) == Some(own.clone())
                    && own.is_dir();
                unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
                chosen.is_none() && by_device == Some(None) && untouched && inside
            },
        );
        assert_ne!(verdict, Some(false));
    }

    // Regression (#206): authenticated trash roots were pinned with O_PATH
    // descriptors that were never closed, so every long-running process that
    // once deleted inside /media/usb/.Trash-1000 kept that mount busy.
    #[test]
    fn trash_root_classification_holds_no_descriptors() {
        use std::os::unix::fs::DirBuilderExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Trash");
        for sub in ["", "files", "info"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(sub))
                .unwrap();
        }
        let canonical = fs::canonicalize(&root).unwrap();
        assert!(is_trash_internal(&root.join("files/x"), &root, true));
        let held: Vec<PathBuf> = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|fd| fs::read_link(fd.ok()?.path()).ok())
            .filter(|target| *target == canonical || *target == root)
            .collect();
        assert!(
            held.is_empty(),
            "descriptors still pin the trash root: {held:?}"
        );
        // The classification survives without a descriptor.
        assert!(is_trash_internal(&root.join("info/y"), &root, true));
    }

    #[test]
    fn bounded_lock_outlasts_short_holders_and_gives_up_on_stale_ones() {
        use std::sync::{Arc, Barrier, Mutex};
        // A holder that releases within the bound never loses the operation.
        let value = Arc::new(Mutex::new(0u32));
        let barrier = Arc::new(Barrier::new(2));
        let holder = {
            let (value, barrier) = (Arc::clone(&value), Arc::clone(&barrier));
            std::thread::spawn(move || {
                let _guard = value.lock().unwrap();
                barrier.wait();
                std::thread::sleep(std::time::Duration::from_millis(2));
            })
        };
        barrier.wait();
        assert_eq!(with_lock_bounded(&value, |v| *v += 1), Some(()));
        holder.join().unwrap();
        assert_eq!(*value.lock().unwrap(), 1);

        // A poisoned map stays usable.
        let clone = Arc::clone(&value);
        let _ = std::thread::spawn(move || {
            let _guard = clone.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(with_lock_bounded(&value, |v| *v), Some(1));

        // A lock that is never released gives up instead of blocking.
        let held = Mutex::new(());
        let _guard = held.lock().unwrap();
        let started = std::time::Instant::now();
        assert_eq!(with_lock_bounded(&held, |_| ()), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn authenticated_cleanup_cache_is_readonly_and_inode_bound() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("Trash");
        for path in [&home, &home.join("files"), &home.join("info")] {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
        assert!(is_trash_internal(&home.join("files/item"), &home, true));
        fs::remove_dir(home.join("files")).unwrap();
        assert!(is_trash_internal(&home.join("info"), &home, true));
        fs::remove_dir(home.join("info")).unwrap();
        assert!(is_trash_internal(&home, &home, true));
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!is_trash_internal(&home, &home, true));
        assert_eq!(home.symlink_metadata().unwrap().mode() & 0o777, 0o755);
        assert!(!home.join("files").exists());
        assert!(!home.join("info").exists());
        let lookalike = fixture.path().join("project/.Trash");
        assert!(!is_trash_internal(&lookalike.join("item"), &home, true));
        assert!(!lookalike.exists());
    }

    #[test]
    fn home_authentication_keeps_raw_paths_and_rejects_replacement_roots() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture
            .path()
            .join(OsString::from_vec(b"custom-\xff-home".to_vec()));
        let prepare = || {
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        };
        prepare();
        for child in ["files", "info"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(home.join(child))
                .unwrap();
        }
        let item = home.join("files/item");
        assert!(is_trash_internal(&item, &home, true));
        assert!(!is_trash_internal(&item, &home, false));

        // A private directory at the same path cannot inherit the old inode's
        // cleanup authorization without its own authenticated files/info.
        fs::rename(&home, fixture.path().join("retired")).unwrap();
        prepare();
        assert!(!is_trash_internal(&item, &home, true));
        assert!(!home.join("files").exists());
        assert!(!home.join("info").exists());
        for child in ["files", "info"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(home.join(child))
                .unwrap();
        }
        assert!(is_trash_internal(&item, &home, true));
        fs::remove_dir(home.join("files")).unwrap();
        fs::remove_dir(home.join("info")).unwrap();
        assert!(is_trash_internal(&home, &home, true));
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!is_trash_internal(&home, &home, true));
    }

    #[test]
    fn private_topdir_trash_is_created_private_and_probe_rejects_open_mode() {
        let topdir = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let trash = check_private_topdir_trash(topdir.path(), uid, true).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(trash.join("files"))
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(trash.join("info"))
            .unwrap();
        assert!(is_safe_trash_root(&trash, uid));

        fs::set_permissions(&trash, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_private_topdir_trash(topdir.path(), uid, false).is_none());
        assert!(!is_safe_trash_root(&trash, uid));
        assert!(check_private_topdir_trash(topdir.path(), uid, true).is_some());
        assert!(is_safe_trash_root(&trash, uid));
    }

    #[test]
    fn private_topdir_trash_rejects_symlink() {
        let topdir = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        std::os::unix::fs::symlink(target.path(), topdir.path().join(format!(".Trash-{uid}")))
            .unwrap();
        assert!(check_private_topdir_trash(topdir.path(), uid, true).is_none());
    }

    #[test]
    fn parse_mounts_survives_non_utf8_mount_point() {
        // The kernel octal-escapes only space/tab/newline/backslash; a raw
        // byte ≥ 0x80 in a mount point must not zero out the whole list.
        let content = b"/dev/sda1 /mnt/\xffdata ext4 rw 0 0\n/proc /proc proc rw 0 0\n";
        let mounts = parse_mounts(content);
        assert_eq!(mounts.len(), 1);
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            mounts[0].path.as_os_str().as_bytes(),
            b"/mnt/\xffdata".as_slice()
        );
    }

    #[test]
    fn parse_mounts_unescapes_whitespace_and_keeps_sort_order() {
        let content = b"/dev/sdb1 /mnt/with\\040space ext4 rw 0 0\n\
                        /dev/sdc1 /mnt/nested/deep vfat rw 0 0\n";
        let mounts = parse_mounts(content);
        assert_eq!(mounts.len(), 2);
        // longest (most specific) first
        assert_eq!(mounts[0].path, PathBuf::from("/mnt/nested/deep"));
        assert_eq!(mounts[1].path, PathBuf::from("/mnt/with space"));
        assert_eq!(mounts[1].device, "/dev/sdb1");
        assert_eq!(mounts[1].fstype, "ext4");
    }

    #[test]
    fn unescape_octal_round_trips_kernel_escapes() {
        // the kernel escapes exactly space, tab, newline, backslash
        for (raw, expected) in [
            (b"\\040".as_slice(), b" ".as_slice()),
            (b"\\011".as_slice(), b"\t".as_slice()),
            (b"\\012".as_slice(), b"\n".as_slice()),
            (b"\\134".as_slice(), b"\\".as_slice()),
            (b"a\\040b".as_slice(), b"a b".as_slice()),
            // non-UTF-8 payload bytes pass through verbatim
            (b"/m\xff/x".as_slice(), b"/m\xff/x".as_slice()),
        ] {
            assert_eq!(unescape_octal(raw), expected, "input {raw:?}");
        }
    }
}
