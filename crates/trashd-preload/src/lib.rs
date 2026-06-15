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
    /// Whitelist mode: if non-empty, ONLY matching paths are trashed; every
    /// other path is real-deleted (never_trash still wins). Mirrors
    /// trashd-common so the preload makes the same decision as the other
    /// layers for a given config.
    only_trash: Vec<String>,
    bypass_processes: Vec<String>,
}

/// Partial config for layered merge — all fields optional.
#[derive(Debug, Deserialize, Default)]
struct PartialPreloadConfig {
    never_trash: Option<Vec<String>>,
    only_trash: Option<Vec<String>>,
    bypass_processes: Option<Vec<String>>,
}

/// Per-directory `.trashd.toml` overrides (mirrors trashd-common's LocalConfig)
/// so the preload makes the same decision as the CLI/seccomp layers.
#[derive(Debug, Deserialize, Default)]
struct LocalConfig {
    #[serde(default)]
    never_trash: Vec<String>,
    #[serde(default)]
    only_trash: Vec<String>,
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
            only_trash: Vec::new(),
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
        // only_trash is a whitelist, not additive: a later layer replaces it
        // (matches trashd-common's Config::merge semantics).
        if let Some(list) = partial.only_trash {
            self.only_trash = list;
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
    // Avoid collisions from simple addition (e.g., global=100+user=200 == global=200+user=100).
    // Shift one value to make the pair distinguishable.
    global.wrapping_mul(1000003) ^ user
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
    // Use .get() rather than slicing: a truncated /proc/<pid>/stat (the process
    // died mid-read) can end at ')', making after_comm > len — slicing would
    // PANIC, which in this LD_PRELOAD library would abort the host process.
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat.get(after_comm..)?.split_whitespace().collect();
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
///
/// Matches on whole path COMPONENTS, not raw substrings: a user file such as
/// `~/my.Trash-backup/x` or `~/foo.local/share/Trash-notes` must NOT be
/// misclassified as trash-internal (which would make the hook permanently
/// `rm` it instead of trashing it).
fn is_inside_trash(path: &Path) -> bool {
    use std::path::Component;

    // Inside the home trash directory tree?
    if path.starts_with(home_trash_dir()) {
        return true;
    }

    // Inside a per-mount trash: some ancestor component is exactly ".Trash"
    // (the shared spec dir) or ".Trash-<uid>" (numeric uid).
    path.components().any(|comp| {
        if let Component::Normal(name) = comp {
            let n = name.to_string_lossy();
            n == ".Trash"
                || n.strip_prefix(".Trash-")
                    .is_some_and(|uid| !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()))
        } else {
            false
        }
    })
}

/// Match a single never_trash/only_trash pattern against a path string.
/// Mirrors trashd-common's `pattern_matches_any` so every layer agrees.
fn pattern_matches(pattern: &str, s: &str) -> bool {
    if pattern.starts_with("*/") && pattern.ends_with("/*") {
        // Infix pattern like "*/.git/*" — match as "contains"
        let infix = &pattern[1..pattern.len() - 1]; // "/.git/"
        s.contains(infix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        // "node_modules/*" → match anywhere in path (no leading /)
        if prefix.starts_with('/') {
            s.starts_with(prefix)
        } else {
            s.starts_with(prefix) || s.contains(&format!("/{prefix}"))
        }
    } else if pattern.starts_with("*.") {
        s.ends_with(&pattern[1..])
    } else if pattern == "*~" {
        s.ends_with('~')
    } else if let Some(suffix) = pattern.strip_prefix("*/") {
        s.contains(&format!("/{suffix}"))
            || s.ends_with(&format!("/{}", suffix.trim_end_matches('/')))
    } else {
        *pattern == *s
    }
}

/// Find the nearest `.trashd.toml` walking up from `path` (≤5 levels), matching
/// trashd-common's Config::load_local_config.
fn load_local_config(path: &Path) -> Option<LocalConfig> {
    let mut dir = path.parent()?;
    for _ in 0..5 {
        let cfg_path = dir.join(".trashd.toml");
        if cfg_path.is_file() {
            if let Ok(content) = fs::read_to_string(&cfg_path) {
                if let Ok(local) = toml::from_str::<LocalConfig>(&content) {
                    return Some(local);
                }
            }
        }
        dir = dir.parent()?;
    }
    None
}

/// Check if path should skip trash (real-delete instead).
/// Uses the same matching logic and precedence as trashd-common's
/// Config::should_skip: per-directory .trashd.toml first, then never_trash
/// wins, then only_trash narrows.
fn should_skip_path(path: &Path) -> bool {
    // Never intercept operations inside trash directories themselves
    if is_inside_trash(path) {
        return true;
    }

    let s = path.to_string_lossy();
    let cfg = config();

    // Per-directory .trashd.toml overrides (same precedence as trashd-common).
    if let Some(local) = load_local_config(path) {
        if !local.never_trash.is_empty() && local.never_trash.iter().any(|p| pattern_matches(p, &s))
        {
            return true;
        }
        if !local.only_trash.is_empty() {
            if !local.only_trash.iter().any(|p| pattern_matches(p, &s)) {
                return true; // doesn't match local whitelist → real-delete
            }
            // Matched local whitelist — global never_trash can still veto.
            if cfg.never_trash.iter().any(|p| pattern_matches(p, &s)) {
                return true;
            }
            return false;
        }
    }

    // never_trash always wins
    if cfg.never_trash.iter().any(|p| pattern_matches(p, &s)) {
        return true;
    }

    // only_trash whitelist: if set and the path doesn't match, skip it so the
    // preload real-deletes it — same as the seccomp/CLI/store layers.
    if !cfg.only_trash.is_empty() && !cfg.only_trash.iter().any(|p| pattern_matches(p, &s)) {
        return true;
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
                if !uid_dir.exists() {
                    if fs::create_dir_all(uid_dir.join("files")).is_err()
                        || fs::create_dir_all(uid_dir.join("info")).is_err()
                    {
                        // Fall through to .Trash-$UID
                    } else {
                        // Keep it private (0700) — the parent .Trash is sticky
                        // and shared by all users.
                        let priv700 = fs::Permissions::from_mode(0o700);
                        let _ = fs::set_permissions(&uid_dir, priv700.clone());
                        let _ = fs::set_permissions(uid_dir.join("files"), priv700.clone());
                        let _ = fs::set_permissions(uid_dir.join("info"), priv700);
                        return uid_dir;
                    }
                } else {
                    // Verify ownership — don't use a dir pre-created by another user
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(m) = fs::symlink_metadata(&uid_dir) {
                        if m.uid() == uid && !m.file_type().is_symlink() {
                            return uid_dir;
                        }
                    }
                    // Ownership mismatch or symlink — fall through to .Trash-$UID
                }
            }
        }

        // Fallback: .Trash-$UID (spec §1.2.2b)
        let topdir = mountpoint.join(format!(".Trash-{uid}"));
        if fs::create_dir_all(topdir.join("files")).is_ok()
            && fs::create_dir_all(topdir.join("info")).is_ok()
        {
            // Private (0700): on a shared mount other users must not be able to
            // read our deleted files or their original-path metadata.
            let priv700 = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(&topdir, priv700.clone());
            let _ = fs::set_permissions(topdir.join("files"), priv700.clone());
            let _ = fs::set_permissions(topdir.join("info"), priv700);
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

    let (id, info_path) = match unique_id_atomic(&info_dir, &files_dir, &base_name) {
        Some(v) => v,
        None => return false,
    };

    let dest = files_dir.join(&id);

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return false,
        }
    };

    let size = fs::symlink_metadata(&abs_path).ok().map(|m| m.len());

    // Per FreeDesktop spec, topdir trash stores relative paths from the mount point.
    let home_trash = home_trash_dir();
    let trashinfo_path = if trash_dir == home_trash {
        abs_path.clone()
    } else {
        // Topdir: strip the mount point prefix to get a relative path.
        // .Trash-$uid -> parent is the topdir
        // .Trash/$uid -> grandparent is the topdir
        let topdir = trash_dir
            .parent()
            .and_then(|p| {
                let name = p.file_name()?.to_string_lossy();
                if name == ".Trash" {
                    p.parent()
                } else {
                    Some(p)
                }
            })
            .unwrap_or(&trash_dir);
        abs_path
            .strip_prefix(topdir)
            .map(|rel| rel.to_path_buf())
            .unwrap_or_else(|_| abs_path.clone())
    };

    let now = chrono::Local::now();
    let trashinfo = format!(
        "[Trash Info]\nPath={}\nDeletionDate={}\nX-Trashd-Command=preload\nX-Trashd-PID={}\n{}\n",
        encode_path(&trashinfo_path),
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
                let ret = unsafe { (real_unlink())(cpath.as_ptr()) };
                if ret != 0 {
                    // Couldn't remove the original symlink — don't report a
                    // false success (which would leave the original on disk and
                    // a duplicate in the trash). Roll back and fall through to
                    // the real unlink. Matches the regular-file branch below.
                    let _ = fs::remove_file(&info_path);
                    let _ = fs::remove_file(&dest);
                    return false;
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
            let ret = unsafe { (real_unlink())(cpath.as_ptr()) };
            if ret != 0 {
                // Unlink of original failed — clean up the copy to avoid orphan
                let _ = fs::remove_file(&info_path);
                let _ = fs::remove_file(&dest);
                return false;
            }
            log_preload(&format!("trashed (cross-dev): {}", path.display()));
            return true;
        }
    }

    let _ = fs::remove_file(&info_path);
    false
}

/// Atomically claim a unique trashinfo filename using O_CREAT|O_EXCL.
///
/// The id is unique against BOTH `info_dir` and `files_dir`: an orphaned data
/// file (in `files/` with no matching `.trashinfo`) is recoverable, so reusing
/// its name would silently overwrite the user's data on the move into `files/`.
fn unique_id_atomic(
    info_dir: &Path,
    files_dir: &Path,
    base_name: &str,
) -> Option<(String, PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt;

    // Truncate to avoid exceeding filesystem filename limits (255 bytes).
    let max_base = 223; // reserve 32 for ".YYYYMMDDHHMMSS.NNNNN.trashinfo"
    let base_name = if base_name.len() > max_base {
        &base_name[..base_name.floor_char_boundary(max_base)]
    } else {
        base_name
    };

    // Claim `candidate`: O_EXCL the .trashinfo AND ensure files/<candidate> is
    // free. Some(path) = claimed; None = taken (try another) or fatal IO error.
    let try_claim = |candidate: &str| -> Result<Option<PathBuf>, ()> {
        let path = info_dir.join(format!("{candidate}.trashinfo"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => {
                if fs::symlink_metadata(files_dir.join(candidate)).is_ok() {
                    // info name free but an orphaned data file occupies files/.
                    let _ = fs::remove_file(&path);
                    Ok(None)
                } else {
                    Ok(Some(path))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(_) => Err(()), // real I/O error (disk full, permission denied)
        }
    };

    // Try base name
    match try_claim(base_name) {
        Ok(Some(path)) => return Some((base_name.to_string(), path)),
        Ok(None) => {}
        Err(()) => return None,
    }

    // Append timestamp + counter
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S");
    for i in 0u32..1000 {
        let candidate = if i == 0 {
            format!("{base_name}.{ts}")
        } else {
            format!("{base_name}.{ts}.{i}")
        };
        match try_claim(&candidate) {
            Ok(Some(path)) => return Some((candidate, path)),
            Ok(None) => continue,
            Err(()) => return None,
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
    match fs::read_link(&fd_link) {
        Ok(dir_path) => Some(dir_path.join(&path)),
        Err(_) => {
            // Can't resolve the dirfd (e.g. /proc not mounted). We fall through
            // to the real syscall — a permanent delete with no trashing. Log it
            // so operators know interception was silently bypassed here.
            log_preload(&format!(
                "could not resolve dirfd {dirfd} via /proc; not intercepting {}",
                path.display()
            ));
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Common pre-check for all hooks
// ---------------------------------------------------------------------------

/// Return 0 with errno preserved from before the intercept.
/// Our trash operations may set errno as a side effect — restore the
/// caller's original errno so they see a clean success.
fn success_with_errno(saved_errno: libc::c_int) -> libc::c_int {
    unsafe { *libc::__errno_location() = saved_errno };
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
    // Capture the caller's errno FIRST — before the guard, should_intercept()
    // (/proc walks), or path resolution can perturb it — so the success path
    // restores the caller's true pre-call errno.
    let saved_errno = *libc::__errno_location();

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = match ReentrancyGuard::enter() {
            Some(g) => g,
            None => return None,
        };

        if !should_intercept() {
            return None;
        }

        if let Some(path) = cstr_to_path(pathname) {
            let abs = if path.is_absolute() {
                path.clone()
            } else {
                match std::env::current_dir() {
                    Ok(cwd) => cwd.join(&path),
                    Err(_) => return None,
                }
            };

            // Use symlink_metadata to not follow symlinks — dangling symlinks
            // should be trashed, not permanently deleted via the fallthrough.
            if let Ok(meta) = fs::symlink_metadata(&abs) {
                if !should_skip_path(&abs) && !meta.is_dir() && try_trash(&abs) {
                    return Some(success_with_errno(saved_errno));
                }
            }
        }
        None
    }));

    match res {
        Ok(Some(ret)) => ret,
        _ => (real_unlink())(pathname),
    }
}

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[no_mangle]
pub unsafe extern "C" fn unlinkat(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    // Capture the caller's errno first (see unlink()).
    let saved_errno = *libc::__errno_location();

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = match ReentrancyGuard::enter() {
            Some(g) => g,
            None => return None,
        };

        if !should_intercept() {
            return None;
        }

        let is_removedir = (flags & libc::AT_REMOVEDIR) != 0;

        if let Some(abs) = resolve_at_path(dirfd, pathname) {
            // Use symlink_metadata to not follow symlinks
            if let Ok(meta) = fs::symlink_metadata(&abs) {
                if !should_skip_path(&abs) {
                    let is_real_dir = meta.is_dir() && !meta.file_type().is_symlink();
                    if is_removedir {
                        // NOTE: emptiness here then rename in try_trash is a small
                        // TOCTOU — a sibling could repopulate the dir in between.
                        // The result is still recoverable from the trash (residual
                        // L8), so we accept it rather than add fragile locking.
                        if is_real_dir {
                            if let Ok(mut rd) = fs::read_dir(&abs) {
                                if rd.next().is_none() && try_trash(&abs) {
                                    return Some(success_with_errno(saved_errno));
                                }
                            }
                        }
                    } else if !is_real_dir && try_trash(&abs) {
                        return Some(success_with_errno(saved_errno));
                    }
                }
            }
        }
        None
    }));

    match res {
        Ok(Some(ret)) => ret,
        _ => (real_unlinkat())(dirfd, pathname, flags),
    }
}

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[no_mangle]
pub unsafe extern "C" fn rmdir(pathname: *const libc::c_char) -> libc::c_int {
    // Capture the caller's errno first (see unlink()).
    let saved_errno = *libc::__errno_location();

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = match ReentrancyGuard::enter() {
            Some(g) => g,
            None => return None,
        };

        if !should_intercept() {
            return None;
        }

        if let Some(path) = cstr_to_path(pathname) {
            let abs = if path.is_absolute() {
                path.clone()
            } else {
                match std::env::current_dir() {
                    Ok(cwd) => cwd.join(&path),
                    Err(_) => return None,
                }
            };

            // Use symlink_metadata — rmdir only applies to real directories, not symlinks
            if let Ok(meta) = fs::symlink_metadata(&abs) {
                if meta.is_dir() && !meta.file_type().is_symlink() && !should_skip_path(&abs) {
                    if let Ok(mut rd) = fs::read_dir(&abs) {
                        if rd.next().is_none() && try_trash(&abs) {
                            return Some(success_with_errno(saved_errno));
                        }
                    }
                }
            }
        }
        None
    }));

    match res {
        Ok(Some(ret)) => ret,
        _ => (real_rmdir())(pathname),
    }
}
