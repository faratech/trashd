use std::collections::HashMap;
use std::fs;
use std::io;
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
pub fn list_mounts() -> Vec<MountPoint> {
    let content = match fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut mounts = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let device = parts[0].to_string();
        let path = PathBuf::from(unescape_octal(parts[1]));
        let fstype = parts[2].to_string();

        // Skip virtual filesystems
        if matches!(
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
        ) {
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
pub fn trash_dir_for_device(file_dev: u64, display_path: &Path, home_trash: &Path) -> PathBuf {
    if device_id_or_parent(home_trash) == Some(file_dev) {
        return home_trash.to_path_buf();
    }
    let uid = unsafe { libc::geteuid() };
    if let Some(mount) = find_mount_point(display_path)
        && device_id(&mount.path) == Some(file_dev)
    {
        // Spec §1.2.2a: shared .Trash/$UID (created on demand — we're about
        // to write), else §1.2.2b .Trash-$UID.
        if let Some(shared) = check_shared_trash(&mount.path, uid, true) {
            return shared;
        }
        if let Some(private) = check_private_topdir_trash(&mount.path, uid, true) {
            return private;
        }
    }
    home_trash.to_path_buf()
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
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return home_trash.to_path_buf(),
        }
    };

    // If on the same filesystem as home trash, use home trash
    if same_filesystem(&abs, home_trash) {
        return home_trash.to_path_buf();
    }

    let uid = unsafe { libc::geteuid() };
    if let Some(mount) = find_mount_point(&abs) {
        // Spec §1.2.2a: check $topdir/.Trash/ (creating our uid dir is fine —
        // we're about to write into it)
        if let Some(shared) = check_shared_trash(&mount.path, uid, true) {
            return shared;
        }
        // Spec §1.2.2b: use $topdir/.Trash-$UID/. Refuse a pre-existing
        // symlink, foreign-owned directory, or directory that cannot be made
        // private; copying to the authenticated home trash is safer.
        if let Some(private) = check_private_topdir_trash(&mount.path, uid, true) {
            return private;
        }
    }

    // Fallback to home trash (will do cross-device copy)
    home_trash.to_path_buf()
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
    fs::symlink_metadata(topdir).is_ok_and(|parent| {
        let mode = parent.permissions().mode();
        parent.is_dir()
            && !parent.file_type().is_symlink()
            && (parent.uid() == 0 || parent.uid() == uid)
            && (mode & 0o022 == 0 || mode & 0o1000 != 0)
    })
}

/// A trusted trash root and each of its writable children must be a real,
/// current-user-owned directory with no group/other access. This invariant is
/// what makes subsequent entry names safe to enumerate and permanently purge.
pub(crate) fn validate_private_dir(path: &Path, uid: u32, repair_mode: bool) -> bool {
    let mut meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(_) => return false,
    };
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != uid {
        return false;
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        if !repair_mode || fs::set_permissions(path, fs::Permissions::from_mode(0o700)).is_err() {
            return false;
        }
        meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(_) => return false,
        };
    }
    meta.is_dir()
        && !meta.file_type().is_symlink()
        && meta.uid() == uid
        && meta.permissions().mode() & 0o777 == 0o700
}

/// Validate an existing trash root for read/destructive enumeration. Unlike
/// selection this never creates or chmods anything.
pub(crate) fn is_safe_trash_root(path: &Path, uid: u32) -> bool {
    validate_private_dir(path, uid, false)
        && validate_private_dir(&path.join("files"), uid, false)
        && validate_private_dir(&path.join("info"), uid, false)
}

/// Discover all trash directories across all mount points.
/// Returns (trash_dir, mount_description) pairs.
pub fn all_trash_dirs(home_trash: &Path) -> Vec<(PathBuf, String)> {
    let uid = unsafe { libc::geteuid() };
    let mut dirs: HashMap<PathBuf, String> = HashMap::new();

    // Always include home trash
    if is_safe_trash_root(home_trash, uid) {
        dirs.insert(home_trash.to_path_buf(), "home".into());
    }

    // Scan all mount points for trash directories
    for mount in list_mounts() {
        // Skip if same filesystem as home
        if same_filesystem(home_trash, &mount.path) {
            continue;
        }

        let label = format!("{} ({})", mount.path.display(), mount.fstype);

        // Check shared .Trash/$UID first (spec §1.2.2a) — PROBE only: a
        // read-only enumeration must not create trash dirs on every mount (#38).
        if let Some(shared) = check_shared_trash(&mount.path, uid, false)
            && is_safe_trash_root(&shared, uid)
        {
            dirs.entry(shared).or_insert(label.clone());
        }

        // Also check .Trash-$UID (spec §1.2.2b)
        let topdir = mount.path.join(format!(".Trash-{uid}"));
        if check_private_topdir_trash(&mount.path, uid, false)
            .is_some_and(|path| is_safe_trash_root(&path, uid))
        {
            dirs.entry(topdir).or_insert(label);
        }
    }

    dirs.into_iter().collect()
}

/// Unescape octal sequences in mount paths (e.g. \040 for space).
fn unescape_octal(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let oct: String = chars.by_ref().take(3).collect();
            if oct.len() == 3
                && let Ok(val) = u8::from_str_radix(&oct, 8)
            {
                result.push(val as char);
                continue;
            }
            result.push('\\');
            result.push_str(&oct);
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
