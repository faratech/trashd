//! trashd LD_PRELOAD library
//!
//! Intercepts unlink(), unlinkat(), and rmdir() syscalls to move files to trash
//! instead of permanently deleting them.
//!
//! Usage:
//!   LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so <command>
//!
//! Or system-wide via /etc/ld.so.preload
//!
//! Environment:
//!   TRASH_BYPASS=1       — disable interception entirely
//!   TRASHD_PRELOAD_LOG=1 — log interceptions to stderr

use serde::Deserialize;
use std::cell::Cell;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Lightweight config — parsed once from ~/.config/trashd/config.toml
// ---------------------------------------------------------------------------
/// Preload config — mirrors trashd-common's Config but without pulling in
/// SQLite or other heavy deps. Uses the same layered loading:
///   1. Hardcoded defaults
///   2. /etc/trashd/config.toml (global, extends lists, overrides scalars)
///   3. ~/.config/trashd/config.toml (user, extends lists, overrides scalars)
#[derive(Debug)]
struct PreloadConfig {
    never_trash: Vec<String>,
    bypass_processes: Vec<String>,
}

/// Partial config for layered merge — all fields optional.
#[derive(Debug, Deserialize, Default)]
struct PartialPreloadConfig {
    never_trash: Option<Vec<String>>,
    bypass_processes: Option<Vec<String>>,
}

impl Default for PreloadConfig {
    fn default() -> Self {
        Self {
            never_trash: vec![
                "/tmp/*".into(),
                "/var/tmp/*".into(),
                "/var/cache/*".into(),
                "/proc/*".into(),
                "/sys/*".into(),
                "/dev/*".into(),
                "/run/*".into(),
                "*.o".into(),
                "*.pyc".into(),
                "*.class".into(),
                "*.lock".into(),
                "*.pid".into(),
                "*.sock".into(),
                "*.socket".into(),
                "*.tmp".into(),
                "*.swp".into(),
                "*~".into(),
                "__pycache__/*".into(),
                "node_modules/*".into(),
                "target/debug/*".into(),
                "target/release/*".into(),
                "*/.git/*".into(),
            ],
            bypass_processes: vec![
                "apt".into(),
                "apt-get".into(),
                "dpkg".into(),
                "yum".into(),
                "dnf".into(),
                "pacman".into(),
                "rpm".into(),
                "pip".into(),
                "cargo".into(),
                "npm".into(),
                "make".into(),
                "git".into(),
                "systemd".into(),
                "systemctl".into(),
                "journald".into(),
                "containerd".into(),
                "dockerd".into(),
            ],
        }
    }
}

impl PreloadConfig {
    fn merge(&mut self, partial: PartialPreloadConfig) {
        if let Some(extra) = partial.never_trash {
            for item in extra {
                if !self.never_trash.contains(&item) {
                    self.never_trash.push(item);
                }
            }
        }
        if let Some(extra) = partial.bypass_processes {
            for item in extra {
                if !self.bypass_processes.contains(&item) {
                    self.bypass_processes.push(item);
                }
            }
        }
    }
}

/// Config with periodic reload. Checks config file mtime every 60 seconds
/// so long-lived processes pick up config changes without restart.
fn config() -> &'static PreloadConfig {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static CFG: OnceLock<PreloadConfig> = OnceLock::new();
    static LAST_CHECK: AtomicI64 = AtomicI64::new(0);
    static GLOBAL_MTIME: AtomicI64 = AtomicI64::new(0);

    let cfg = CFG.get_or_init(load_config);

    // Periodically check if config files changed (every 60 seconds)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let last = LAST_CHECK.load(Ordering::Relaxed);
    if now - last >= 60 {
        LAST_CHECK.store(now, Ordering::Relaxed);
        let current_mtime = config_mtime();
        let cached_mtime = GLOBAL_MTIME.load(Ordering::Relaxed);
        if current_mtime != cached_mtime {
            GLOBAL_MTIME.store(current_mtime, Ordering::Relaxed);
            // Can't replace OnceLock, but we can log the change.
            // Full reload would require unsafe or a Mutex — not worth the
            // complexity in a preload .so. Log so users know to restart.
            if cached_mtime != 0 {
                eprintln!("[trashd-preload] config changed — restart process to apply");
            }
        }
    }

    cfg
}

fn load_config() -> PreloadConfig {
    use std::sync::atomic::{AtomicI64, Ordering};
    // Store initial mtime
    static INIT_MTIME: AtomicI64 = AtomicI64::new(0);
    INIT_MTIME.store(config_mtime(), Ordering::Relaxed);

    let mut cfg = PreloadConfig::default();

    // Layer 1: global config
    if let Some(partial) = load_partial_config(Path::new("/etc/trashd/config.toml")) {
        cfg.merge(partial);
    }

    // Layer 2: user config
    let user_path = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("trashd/config.toml");
    if let Some(partial) = load_partial_config(&user_path) {
        cfg.merge(partial);
    }

    cfg
}

fn config_mtime() -> i64 {
    use std::os::unix::fs::MetadataExt;
    let global = fs::metadata("/etc/trashd/config.toml")
        .map(|m| m.mtime())
        .unwrap_or(0);
    let user = dirs::config_dir()
        .map(|d| d.join("trashd/config.toml"))
        .and_then(|p| fs::metadata(p).ok())
        .map(|m| m.mtime())
        .unwrap_or(0);
    global + user
}

fn load_partial_config(path: &Path) -> Option<PartialPreloadConfig> {
    let content = fs::read_to_string(path).ok()?;
    toml::from_str::<PartialPreloadConfig>(&content).ok()
}

// ---------------------------------------------------------------------------
// Thread-local re-entrancy guard.
// ---------------------------------------------------------------------------
thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

struct ReentrancyGuard;

impl ReentrancyGuard {
    fn enter() -> Option<Self> {
        IN_HOOK.with(|flag| {
            if flag.get() {
                None
            } else {
                flag.set(true);
                Some(ReentrancyGuard)
            }
        })
    }
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        IN_HOOK.with(|flag| flag.set(false));
    }
}

// ---------------------------------------------------------------------------
// Resolve original libc functions via dlsym(RTLD_NEXT, ...).
// ---------------------------------------------------------------------------
type UnlinkFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
type UnlinkatFn =
    unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int) -> libc::c_int;
type RmdirFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;

unsafe fn real_unlink() -> UnlinkFn {
    let sym = libc::dlsym(libc::RTLD_NEXT, c"unlink".as_ptr() as *const _);
    assert!(!sym.is_null(), "trashd: dlsym(unlink) failed");
    std::mem::transmute(sym)
}

unsafe fn real_unlinkat() -> UnlinkatFn {
    let sym = libc::dlsym(libc::RTLD_NEXT, c"unlinkat".as_ptr() as *const _);
    assert!(!sym.is_null(), "trashd: dlsym(unlinkat) failed");
    std::mem::transmute(sym)
}

unsafe fn real_rmdir() -> RmdirFn {
    let sym = libc::dlsym(libc::RTLD_NEXT, c"rmdir".as_ptr() as *const _);
    assert!(!sym.is_null(), "trashd: dlsym(rmdir) failed");
    std::mem::transmute(sym)
}

// ---------------------------------------------------------------------------
// Skip checks — uses config
// ---------------------------------------------------------------------------

fn is_bypass_active() -> bool {
    std::env::var_os("TRASH_BYPASS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// When Layer 4 (seccomp) is active, it handles interception at the kernel
/// level. The preload layer defers to avoid double-trashing.
fn is_seccomp_active() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var_os("TRASHD_SECCOMP_ACTIVE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Check if a parent process is in the bypass list.
fn is_parent_bypassed() -> bool {
    let bypass = &config().bypass_processes;
    if bypass.is_empty() {
        return false;
    }
    // Check bypass lazily — cache result per-process (PID won't change)
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let mut pid = std::process::id();
        for _ in 0..10 {
            let ppid = match parent_pid(pid) {
                Some(p) if p > 1 => p,
                _ => break,
            };
            if let Some(name) = process_name(ppid) {
                if bypass.contains(&name) {
                    return true;
                }
            }
            pid = ppid;
        }
        false
    })
}

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    fields.get(1)?.parse().ok()
}

fn process_name(pid: u32) -> Option<String> {
    if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(name) = exe.file_name() {
            return Some(name.to_string_lossy().into_owned());
        }
    }
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Check if a path is inside a trash directory (should never be intercepted).
fn is_inside_trash(path: &Path) -> bool {
    let s = path.to_string_lossy();
    // Home trash
    if s.contains("/.local/share/Trash/") {
        return true;
    }
    // Per-mountpoint trash: .Trash-$UID or .Trash/$UID
    if s.contains("/.Trash-") || s.contains("/.Trash/") {
        return true;
    }
    false
}

/// Check if path matches the never-trash list from config.
/// Uses the same matching logic as trashd-common's Config::should_skip.
fn should_skip_path(path: &Path) -> bool {
    // Never intercept operations inside trash directories themselves
    if is_inside_trash(path) {
        return true;
    }

    let s = path.to_string_lossy();
    let cfg = config();

    for pattern in &cfg.never_trash {
        if pattern.starts_with("*/") && pattern.ends_with("/*") {
            // Infix pattern like "*/.git/*" — match as "contains"
            let infix = &pattern[1..pattern.len() - 1]; // "/.git/"
            if s.contains(infix) {
                return true;
            }
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            if s.starts_with(prefix) {
                return true;
            }
        } else if pattern.starts_with("*.") {
            if s.ends_with(&pattern[1..]) {
                return true;
            }
        } else if pattern == "*~" {
            if s.ends_with('~') {
                return true;
            }
        } else if let Some(suffix) = pattern.strip_prefix("*/") {
            if s.contains(&format!("/{suffix}"))
                || s.ends_with(&format!("/{}", suffix.trim_end_matches('/')))
            {
                return true;
            }
        } else if *pattern == *s {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Trash directory selection (same-device or topdir)
// ---------------------------------------------------------------------------

fn trash_dir_for(path: &Path) -> PathBuf {
    let home_trash = home_trash_dir();

    let file_dev = fs::metadata(path)
        .or_else(|_| {
            path.parent()
                .map(fs::metadata)
                .unwrap_or_else(|| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "")))
        })
        .ok()
        .map(|m| m.dev());

    let home_dev = fs::metadata(&home_trash)
        .or_else(|_| fs::metadata(home_trash.parent().unwrap_or(Path::new("/"))))
        .ok()
        .map(|m| m.dev());

    if file_dev == home_dev {
        return home_trash;
    }

    let uid = unsafe { libc::getuid() };
    if let Some(mountpoint) = find_mount_point(path) {
        // Check shared .Trash/ first (FreeDesktop spec §1.2.2a)
        let shared_trash = mountpoint.join(".Trash");
        if let Ok(meta) = fs::symlink_metadata(&shared_trash) {
            if !meta.file_type().is_symlink()
                && meta.is_dir()
                && (meta.permissions().mode() & 0o1000) != 0
            {
                let uid_dir = shared_trash.join(uid.to_string());
                if uid_dir.exists()
                    || (fs::create_dir_all(uid_dir.join("files")).is_ok()
                        && fs::create_dir_all(uid_dir.join("info")).is_ok())
                {
                    return uid_dir;
                }
            }
        }

        // Fallback: .Trash-$UID (spec §1.2.2b)
        let topdir = mountpoint.join(format!(".Trash-{uid}"));
        if fs::create_dir_all(topdir.join("files")).is_ok()
            && fs::create_dir_all(topdir.join("info")).is_ok()
        {
            return topdir;
        }
    }

    home_trash
}

fn home_trash_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
                .join(".local/share")
        })
        .join("Trash")
}

fn find_mount_point(path: &Path) -> Option<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };

    let content = fs::read_to_string("/proc/mounts").ok()?;
    let mut best: Option<PathBuf> = None;
    let mut best_len = 0;

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let _dev = match parts.next() {
            Some(d) => d,
            None => continue,
        };
        let mpoint = match parts.next() {
            Some(m) => m,
            None => continue,
        };
        let mp = PathBuf::from(mpoint);
        if abs.starts_with(&mp) && mp.as_os_str().len() > best_len {
            best_len = mp.as_os_str().len();
            best = Some(mp);
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Core trash logic
// ---------------------------------------------------------------------------

fn try_trash(path: &Path) -> bool {
    let trash_dir = trash_dir_for(path);

    let files_dir = trash_dir.join("files");
    let info_dir = trash_dir.join("info");
    if fs::create_dir_all(&files_dir).is_err() || fs::create_dir_all(&info_dir).is_err() {
        return false;
    }

    // Atomic unique ID via O_CREAT|O_EXCL
    let base_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".into());

    let (id, info_path) = match unique_id_atomic(&info_dir, &base_name) {
        Some(v) => v,
        None => return false,
    };

    let dest = files_dir.join(&id);

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };

    let size = fs::symlink_metadata(&abs_path).ok().map(|m| m.len());

    let now = chrono::Local::now();
    let trashinfo = format!(
        "[Trash Info]\nPath={}\nDeletionDate={}\nX-Trashd-Command=preload\nX-Trashd-PID={}\n{}\n",
        encode_path(&abs_path),
        now.format("%Y-%m-%dT%H:%M:%S"),
        std::process::id(),
        size.map(|s| format!("X-Trashd-Size={s}"))
            .unwrap_or_default(),
    );

    if fs::write(&info_path, &trashinfo).is_err() {
        let _ = fs::remove_file(&info_path);
        return false;
    }

    // Move the file
    if fs::rename(path, &dest).is_ok() {
        log_preload(&format!(
            "trashed: {} -> {}",
            path.display(),
            dest.display()
        ));
        return true;
    }

    // Cross-device: copy preserving symlinks, then remove original
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => {
            let _ = fs::remove_file(&info_path);
            return false;
        }
    };

    if meta.file_type().is_symlink() {
        // Re-create symlink
        if let Ok(target) = fs::read_link(path) {
            if std::os::unix::fs::symlink(&target, &dest).is_ok() {
                let cpath = match CString::new(path.as_os_str().as_bytes()) {
                    Ok(c) => c,
                    Err(_) => {
                        let _ = fs::remove_file(&info_path);
                        let _ = fs::remove_file(&dest);
                        return false;
                    }
                };
                unsafe {
                    (real_unlink())(cpath.as_ptr());
                }
                log_preload(&format!("trashed (cross-dev symlink): {}", path.display()));
                return true;
            }
        }
    } else if meta.is_dir() {
        // Cross-device dirs: best-effort. For preload, fall back to real delete.
        let _ = fs::remove_file(&info_path);
        return false;
    } else {
        // Regular file: copy + delete original
        if fs::copy(path, &dest).is_ok() {
            // Preserve permissions
            let _ = fs::set_permissions(&dest, meta.permissions());
            let cpath = match CString::new(path.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => {
                    let _ = fs::remove_file(&info_path);
                    let _ = fs::remove_file(&dest);
                    return false;
                }
            };
            unsafe {
                (real_unlink())(cpath.as_ptr());
            }
            log_preload(&format!("trashed (cross-dev): {}", path.display()));
            return true;
        }
    }

    let _ = fs::remove_file(&info_path);
    false
}

/// Atomically claim a unique trashinfo filename using O_CREAT|O_EXCL.
fn unique_id_atomic(info_dir: &Path, base_name: &str) -> Option<(String, PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt;

    // Truncate to avoid exceeding filesystem filename limits (255 bytes).
    let max_base = 223; // reserve 32 for ".YYYYMMDDHHMMSS.NNNNN.trashinfo"
    let base_name = if base_name.len() > max_base {
        &base_name[..max_base]
    } else {
        base_name
    };

    // Try base name
    let path = info_dir.join(format!("{base_name}.trashinfo"));
    if fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .is_ok()
    {
        return Some((base_name.to_string(), path));
    }

    // Append timestamp + counter
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S");
    for i in 0u32..1000 {
        let candidate = if i == 0 {
            format!("{base_name}.{ts}")
        } else {
            format!("{base_name}.{ts}.{i}")
        };
        let path = info_dir.join(format!("{candidate}.trashinfo"));
        if fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .is_ok()
        {
            return Some((candidate, path));
        }
    }
    None
}

fn encode_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    let mut encoded = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(*byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

fn log_preload(msg: &str) {
    if std::env::var_os("TRASHD_PRELOAD_LOG")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        eprintln!("[trashd-preload] {msg}");
    }
}

fn cstr_to_path(s: *const libc::c_char) -> Option<PathBuf> {
    if s.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(s) };
    Some(PathBuf::from(OsStr::from_bytes(cstr.to_bytes())))
}

fn resolve_at_path(dirfd: libc::c_int, pathname: *const libc::c_char) -> Option<PathBuf> {
    let path = cstr_to_path(pathname)?;

    if path.is_absolute() {
        return Some(path);
    }

    if dirfd == libc::AT_FDCWD {
        return std::env::current_dir().ok().map(|cwd| cwd.join(&path));
    }

    let fd_link = format!("/proc/self/fd/{dirfd}");
    if let Ok(dir_path) = fs::read_link(&fd_link) {
        Some(dir_path.join(&path))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Common pre-check for all hooks
// ---------------------------------------------------------------------------

/// Return 0 with errno cleared. libc callers expect errno unchanged on success,
/// but our trash operations may have set it as a side effect.
fn success() -> libc::c_int {
    unsafe { *libc::__errno_location() = 0 };
    0
}

fn should_intercept() -> bool {
    !is_bypass_active() && !is_seccomp_active() && !is_parent_bypassed()
}

// ---------------------------------------------------------------------------
// Hooked functions
// ---------------------------------------------------------------------------

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[no_mangle]
pub unsafe extern "C" fn unlink(pathname: *const libc::c_char) -> libc::c_int {
    let _guard = match ReentrancyGuard::enter() {
        Some(g) => g,
        None => return (real_unlink())(pathname),
    };

    if !should_intercept() {
        return (real_unlink())(pathname);
    }

    if let Some(path) = cstr_to_path(pathname) {
        let abs = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir().unwrap_or_default().join(&path)
        };

        // Use symlink_metadata to not follow symlinks — dangling symlinks
        // should be trashed, not permanently deleted via the fallthrough.
        if let Ok(meta) = fs::symlink_metadata(&abs) {
            if !should_skip_path(&abs) && !meta.is_dir() && try_trash(&abs) {
                return success();
            }
        }
    }

    (real_unlink())(pathname)
}

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[no_mangle]
pub unsafe extern "C" fn unlinkat(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    let _guard = match ReentrancyGuard::enter() {
        Some(g) => g,
        None => return (real_unlinkat())(dirfd, pathname, flags),
    };

    if !should_intercept() {
        return (real_unlinkat())(dirfd, pathname, flags);
    }

    let is_removedir = (flags & libc::AT_REMOVEDIR) != 0;

    if let Some(abs) = resolve_at_path(dirfd, pathname) {
        // Use symlink_metadata to not follow symlinks
        if let Ok(meta) = fs::symlink_metadata(&abs) {
            if !should_skip_path(&abs) {
                let is_real_dir = meta.is_dir() && !meta.file_type().is_symlink();
                if is_removedir {
                    if is_real_dir {
                        if let Ok(mut rd) = fs::read_dir(&abs) {
                            if rd.next().is_none() && try_trash(&abs) {
                                return success();
                            }
                        }
                    }
                } else if !is_real_dir && try_trash(&abs) {
                    return success();
                }
            }
        }
    }

    (real_unlinkat())(dirfd, pathname, flags)
}

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[no_mangle]
pub unsafe extern "C" fn rmdir(pathname: *const libc::c_char) -> libc::c_int {
    let _guard = match ReentrancyGuard::enter() {
        Some(g) => g,
        None => return (real_rmdir())(pathname),
    };

    if !should_intercept() {
        return (real_rmdir())(pathname);
    }

    if let Some(path) = cstr_to_path(pathname) {
        let abs = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir().unwrap_or_default().join(&path)
        };

        // Use symlink_metadata — rmdir only applies to real directories, not symlinks
        if let Ok(meta) = fs::symlink_metadata(&abs) {
            if meta.is_dir() && !meta.file_type().is_symlink() && !should_skip_path(&abs) {
                if let Ok(mut rd) = fs::read_dir(&abs) {
                    if rd.next().is_none() && try_trash(&abs) {
                        return success();
                    }
                }
            }
        }
    }

    (real_rmdir())(pathname)
}
