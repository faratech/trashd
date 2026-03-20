use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// A mounted filesystem.
#[derive(Debug, Clone)]
pub struct MountPoint {
    pub device: String,
    pub path: PathBuf,
    pub fstype: String,
}

/// Get the device ID (st_dev) for a path.
pub fn device_id(path: &Path) -> Option<u64> {
    fs::metadata(path).ok().map(|m| m.dev())
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
    mounts.sort_by(|a, b| b.path.as_os_str().len().cmp(&a.path.as_os_str().len()));
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

    let uid = unsafe { libc::getuid() };
    if let Some(mount) = find_mount_point(&abs) {
        // Spec §1.2.2a: check $topdir/.Trash/
        if let Some(shared) = check_shared_trash(&mount.path, uid) {
            return shared;
        }
        // Spec §1.2.2b: use $topdir/.Trash-$UID/
        return mount.path.join(format!(".Trash-{uid}"));
    }

    // Fallback to home trash (will do cross-device copy)
    home_trash.to_path_buf()
}

/// Check if $topdir/.Trash/ exists, is a real directory (not symlink),
/// has the sticky bit, and is writable. If so, return $topdir/.Trash/$UID/.
fn check_shared_trash(topdir: &Path, uid: u32) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let trash_dir = topdir.join(".Trash");

    // Must not be a symlink
    let meta = fs::symlink_metadata(&trash_dir).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    if !meta.is_dir() {
        return None;
    }

    // Must have sticky bit set (mode & S_ISVTX)
    let mode = meta.permissions().mode();
    if mode & 0o1000 == 0 {
        return None;
    }

    // Must be writable by us (check by trying to create the uid subdir)
    let uid_dir = trash_dir.join(uid.to_string());
    if uid_dir.exists() || fs::create_dir_all(&uid_dir).is_ok() {
        return Some(uid_dir);
    }

    None
}

/// Discover all trash directories across all mount points.
/// Returns (trash_dir, mount_description) pairs.
pub fn all_trash_dirs(home_trash: &Path) -> Vec<(PathBuf, String)> {
    let uid = unsafe { libc::getuid() };
    let mut dirs: HashMap<PathBuf, String> = HashMap::new();

    // Always include home trash
    dirs.insert(home_trash.to_path_buf(), "home".into());

    // Scan all mount points for trash directories
    for mount in list_mounts() {
        // Skip if same filesystem as home
        if same_filesystem(home_trash, &mount.path) {
            continue;
        }

        let label = format!("{} ({})", mount.path.display(), mount.fstype);

        // Check shared .Trash/$UID first (spec §1.2.2a)
        if let Some(shared) = check_shared_trash(&mount.path, uid) {
            if shared.exists() && shared.is_dir() {
                dirs.entry(shared).or_insert(label.clone());
            }
        }

        // Also check .Trash-$UID (spec §1.2.2b)
        let topdir = mount.path.join(format!(".Trash-{uid}"));
        if topdir.exists() && topdir.is_dir() {
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
            if oct.len() == 3 {
                if let Ok(val) = u8::from_str_radix(&oct, 8) {
                    result.push(val as char);
                    continue;
                }
            }
            result.push('\\');
            result.push_str(&oct);
        } else {
            result.push(c);
        }
    }
    result
}
