//! trashd LD_PRELOAD library
//!
//! Intercepts unlink(), unlinkat(), rmdir(), and remove() (glibc's remove()
//! calls hidden __unlink/__rmdir aliases that PLT interposition cannot reach,
//! so it must be hooked directly) to move files to trash instead of
//! permanently deleting them.
//!
//! Usage:
//!   LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so <command>
//!
//! Or system-wide via /etc/ld.so.preload
//!
//! Environment:
//!   TRASH_BYPASS=1       — disable interception entirely
//!   TRASHD_PRELOAD_LOG=1 — log interceptions to stderr

#[allow(dead_code)]
#[path = "../../trashd-common/src/config_file.rs"]
mod config_file;
#[allow(dead_code)]
#[path = "../../trashd-common/src/fdops.rs"]
mod fdops;
#[path = "../../trashd-common/src/legacy_config.rs"]
mod legacy_config;
#[allow(dead_code)]
#[path = "../../trashd-common/src/local_trust.rs"]
mod local_trust;
#[allow(dead_code)]
#[path = "../../trashd-common/src/mounts.rs"]
mod mounts;
#[allow(dead_code)]
#[path = "../../trashd-common/src/pattern_policy.rs"]
mod pattern_policy;
#[allow(dead_code)]
#[path = "../../trashd-common/src/proc_stat.rs"]
mod proc_stat;
#[path = "../../trashd-common/src/seccomp_identity.rs"]
mod seccomp_identity;
#[allow(dead_code)]
#[path = "../../trashd-common/src/store_lock.rs"]
mod store_lock;
#[path = "../../trashd-common/src/trash_id.rs"]
mod trash_id;

use serde::Deserialize;
use std::cell::Cell;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Lightweight config — parsed once from ~/.config/trashd/config.toml
// ---------------------------------------------------------------------------
/// Preload config — mirrors trashd-common's Config without pulling in the
/// shared store's dependencies. Uses the same layered loading:
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
    bypass_paths: Vec<String>,
    /// Maximum regular-file size in MiB. Zero disables the limit.
    max_file_size_mb: u64,
    /// Maximum directory-tree size in MiB. Zero disables the limit (#118).
    max_dir_size_mb: u64,
    /// `config_mtime()` of the files this config was loaded from.
    mtime_key: i64,
}

/// Partial config for layered merge — all fields optional.
#[derive(Debug, Deserialize, Default)]
struct PartialPreloadConfig {
    never_trash: Option<Vec<String>>,
    only_trash: Option<Vec<String>>,
    bypass_processes: Option<Vec<String>>,
    bypass_paths: Option<Vec<String>>,
    max_file_size_mb: Option<u64>,
    max_dir_size_mb: Option<u64>,
    // Validate this table even though the preload does not run retention.
    // A misplaced root policy key must not be silently ignored (#63).
    #[serde(rename = "retention")]
    _retention: Option<RetentionConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionConfig {
    #[serde(rename = "max_age_days")]
    _max_age_days: Option<u32>,
    #[serde(rename = "max_size_gb")]
    _max_size_gb: Option<f64>,
    #[serde(rename = "disk_pressure_percent")]
    _disk_pressure_percent: Option<u8>,
    #[serde(rename = "auto_compress")]
    _auto_compress: Option<bool>,
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
                "rustup".into(),
                "rustup-init".into(),
                "npm".into(),
                "make".into(),
                "git".into(),
                // No "systemd"/"systemctl": the ancestor walk matches ANY
                // ancestor by name, and systemd-launched sessions would have
                // the whole layer silently disabled (#22). Use precise
                // bypass_paths for services instead.
                "journald".into(),
                "containerd".into(),
                "dockerd".into(),
            ],
            bypass_paths: Vec::new(),
            max_file_size_mb: 1024,
            max_dir_size_mb: 0,
            mtime_key: 0,
        }
    }
}

impl PreloadConfig {
    fn merge(&mut self, partial: PartialPreloadConfig) {
        if let Some(extra) = partial.never_trash {
            for item in sanitize_patterns(extra, "never_trash") {
                if !self.never_trash.contains(&item) {
                    self.never_trash.push(item);
                }
            }
        }
        // only_trash is a whitelist, not additive: a later layer replaces it
        // (matches trashd-common's Config::merge semantics). Sanitize first —
        // an unsupported pattern would make the whitelist real-delete all (#4).
        if let Some(list) = partial.only_trash {
            self.only_trash = sanitize_patterns(list, "only_trash");
        }
        if let Some(extra) = partial.bypass_processes {
            for item in extra {
                if !self.bypass_processes.contains(&item) {
                    self.bypass_processes.push(item);
                }
            }
        }
        if let Some(extra) = partial.bypass_paths {
            for item in extra {
                if !self.bypass_paths.contains(&item) {
                    self.bypass_paths.push(item);
                }
            }
        }
        if let Some(limit) = partial.max_file_size_mb {
            self.max_file_size_mb = limit;
        }
        if let Some(limit) = partial.max_dir_size_mb {
            self.max_dir_size_mb = limit;
        }
    }
}

/// Immutable config; the hook's existing time sample drives change notices.
fn config() -> &'static PreloadConfig {
    static CFG: OnceLock<PreloadConfig> = OnceLock::new();
    CFG.get_or_init(load_config)
}

/// Check file mtimes every 60 seconds and report restart-required changes.
/// Reuse the bypass cache's time sample rather than reading the clock on
/// every config lookup within the same deletion (#283).
fn check_config_changed(now: i64) {
    use std::sync::atomic::{AtomicI64, Ordering};

    static LAST_CHECK: AtomicI64 = AtomicI64::new(0);
    static GLOBAL_MTIME: AtomicI64 = AtomicI64::new(0);

    let last = LAST_CHECK.load(Ordering::Relaxed);
    if now - last >= 60
        && LAST_CHECK
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        // The first check adopts the metadata observed while loading, so no
        // hook stats the configs only to establish a baseline (#308).
        if last == 0 {
            GLOBAL_MTIME.store(config().mtime_key, Ordering::Relaxed);
            return;
        }
        let current_mtime = config_mtime();
        let cached_mtime = GLOBAL_MTIME.load(Ordering::Relaxed);
        if current_mtime != cached_mtime {
            GLOBAL_MTIME.store(current_mtime, Ordering::Relaxed);
            // Can't replace OnceLock, but we can log the change.
            // Full reload would require unsafe or a Mutex — not worth the
            // complexity in a preload .so. Log so users know to restart.
            log_preload("config changed — restart process to apply");
        }
    }
}

fn load_config() -> PreloadConfig {
    let mut cfg = PreloadConfig::default();

    // Layer 1: global config
    let (global, global_mtime) = load_partial_config_with_mtime(Path::new(GLOBAL_CONFIG));
    if let Some(partial) = global {
        cfg.merge(partial);
    }

    // Layer 2: user config
    let (user, user_mtime) = load_partial_config_with_mtime(&user_config_path());
    if let Some(partial) = user {
        cfg.merge(partial);
    }

    cfg.mtime_key = mtime_key(global_mtime, user_mtime);
    cfg
}

const GLOBAL_CONFIG: &str = "/etc/trashd/config.toml";

fn user_config_path() -> PathBuf {
    config_dir()
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("trashd/config.toml")
}

fn config_mtime() -> i64 {
    let mtime = |path: &Path| fs::metadata(path).map(|m| m.mtime()).unwrap_or(0);
    mtime_key(mtime(Path::new(GLOBAL_CONFIG)), mtime(&user_config_path()))
}

fn mtime_key(global: i64, user: i64) -> i64 {
    // Avoid collisions from simple addition (e.g., global=100+user=200 == global=200+user=100).
    // Shift one value to make the pair distinguishable.
    global.wrapping_mul(1000003) ^ user
}

#[cfg(test)]
fn load_partial_config(path: &Path) -> Option<PartialPreloadConfig> {
    load_partial_config_with_mtime(path).0
}

/// A config layer and the mtime `config_mtime()` would observe for it.
fn load_partial_config_with_mtime(path: &Path) -> (Option<PartialPreloadConfig>, i64) {
    let content = match config_file::read_with_metadata(path) {
        Ok((content, metadata)) => (content, metadata.mtime()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return (None, 0),
        // Present but unusable (a FIFO, invalid UTF-8): still tracked.
        Err(_) => return (None, fs::metadata(path).map(|m| m.mtime()).unwrap_or(0)),
    };
    (parse_partial_config(path, &content.0), content.1)
}

fn parse_partial_config(path: &Path, content: &str) -> Option<PartialPreloadConfig> {
    let dropped = |key: &str, error: &toml::de::Error| {
        host_stderr(&format!(
            "trashd-preload: bad config {}: ignoring '{key}': {}",
            path.display(),
            error.message()
        ));
    };
    match legacy_config::normalize(content)
        .and_then(|value| legacy_config::layer::<PartialPreloadConfig>(value, dropped))
    {
        Ok(partial) => Some(partial),
        Err(error) => {
            host_stderr(&format!(
                "trashd-preload: bad config {}: {error}",
                path.display()
            ));
            None
        }
    }
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

// dlsym(RTLD_NEXT) results are cached: resolving on EVERY passthrough call
// walks the whole link map each time and dominates latency for programs that
// delete in a loop.
unsafe fn real_unlink() -> UnlinkFn {
    static F: OnceLock<UnlinkFn> = OnceLock::new();
    *F.get_or_init(|| {
        let sym = unsafe { libc::dlsym(libc::RTLD_NEXT, c"unlink".as_ptr() as *const _) };
        assert!(!sym.is_null(), "trashd: dlsym(unlink) failed");
        unsafe { std::mem::transmute(sym) }
    })
}

unsafe fn real_unlinkat() -> UnlinkatFn {
    static F: OnceLock<UnlinkatFn> = OnceLock::new();
    *F.get_or_init(|| {
        let sym = unsafe { libc::dlsym(libc::RTLD_NEXT, c"unlinkat".as_ptr() as *const _) };
        assert!(!sym.is_null(), "trashd: dlsym(unlinkat) failed");
        unsafe { std::mem::transmute(sym) }
    })
}

unsafe fn real_rmdir() -> RmdirFn {
    static F: OnceLock<RmdirFn> = OnceLock::new();
    *F.get_or_init(|| {
        let sym = unsafe { libc::dlsym(libc::RTLD_NEXT, c"rmdir".as_ptr() as *const _) };
        assert!(!sym.is_null(), "trashd: dlsym(rmdir) failed");
        unsafe { std::mem::transmute(sym) }
    })
}

// Same C signature as unlink: int remove(const char *).
unsafe fn real_remove() -> UnlinkFn {
    static F: OnceLock<UnlinkFn> = OnceLock::new();
    *F.get_or_init(|| {
        // remove() must be interposed DIRECTLY: glibc implements it with the
        // hidden internal aliases __unlink/__rmdir, which PLT interposition of
        // unlink/rmdir cannot see — a program deleting via remove() would
        // otherwise bypass the trash entirely.
        let sym = unsafe { libc::dlsym(libc::RTLD_NEXT, c"remove".as_ptr() as *const _) };
        assert!(!sym.is_null(), "trashd: dlsym(remove) failed");
        unsafe { std::mem::transmute(sym) }
    })
}

// ---------------------------------------------------------------------------
// Skip checks — uses config
// ---------------------------------------------------------------------------

fn is_bypass_active() -> bool {
    std::env::var_os("TRASH_BYPASS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Defer only to a cookie-identified trashd filter after completed startup.
fn is_seccomp_active() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let claimed = std::env::var_os("TRASHD_SECCOMP_ACTIVE").is_some_and(|v| v == "1");
        let verified = std::env::var(seccomp_identity::COOKIE_ENV)
            .ok()
            .and_then(|s| seccomp_identity::parse(&s))
            .is_some_and(seccomp_identity::verified);
        seccomp_deferred(claimed, verified)
    })
}

fn seccomp_deferred(claimed: bool, verified: bool) -> bool {
    claimed && verified
}

/// Cache key for the bypass verdict: PID, parent PID, and the verdict.
/// Including the parent makes a reparented process re-evaluate its tree.
fn bypass_cache_key(pid: u32, ppid: u32, bypassed: bool) -> u64 {
    (u64::from(pid) << 32) | (u64::from(ppid) << 1) | u64::from(bypassed)
}

fn bypass_cache_hit(cached: u64, pid: u32, ppid: u32) -> Option<bool> {
    if cached >> 32 == u64::from(pid) && (cached >> 1) & 0x7fff_ffff == u64::from(ppid) {
        Some(cached & 1 != 0)
    } else {
        None
    }
}

/// Cache by PID and parent PID, so children of a fork - and processes whose
/// bypass ancestor died and left them reparented - re-evaluate their tree.
/// Caching by PID alone kept the verdict for the process's whole lifetime,
/// so a long-lived worker spawned by git/make/cargo deleted permanently
/// forever after that ancestor exited (#249).
/// The last bypass verdict (`bypass_cache_key`) and when it was reached.
static BYPASS_VERDICT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BYPASS_VERDICT_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A fresh cached verdict that this process is bypassed, consulted before
/// any path work: bypassed processes (make, git, package managers) delete
/// in bulk, and resolving every path first cost them 58% more syscalls
/// (#354). Without such a verdict this costs nothing.
fn known_bypassed() -> bool {
    use std::sync::atomic::Ordering;
    let cached = BYPASS_VERDICT.load(Ordering::Relaxed);
    if cached & 1 == 0 {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(BYPASS_VERDICT_AT.load(Ordering::Relaxed)) <= 5
        && bypass_cache_hit(cached, std::process::id(), unsafe { libc::getppid() }
            as u32)
            == Some(true)
}

fn is_process_bypassed(pid: u32, now: u64) -> bool {
    use std::sync::atomic::Ordering;
    // This runs on every hook, even while the verdict is cached. A direct
    // getppid preserves reparenting detection without opening, reading and
    // parsing /proc/self/stat for each deletion.
    let ppid = unsafe { libc::getppid() } as u32;
    // A grandparent's death does not change this process's PPID, so the
    // verdict also expires: re-walk the tree at least every few seconds.
    check_config_changed(now as i64);
    let fresh = now.saturating_sub(BYPASS_VERDICT_AT.load(Ordering::Relaxed)) <= 5;
    if fresh && let Some(hit) = bypass_cache_hit(BYPASS_VERDICT.load(Ordering::Relaxed), pid, ppid)
    {
        return hit;
    }
    let bypassed = process_is_bypassed(config(), pid);
    BYPASS_VERDICT.store(bypass_cache_key(pid, ppid, bypassed), Ordering::Relaxed);
    BYPASS_VERDICT_AT.store(now, Ordering::Relaxed);
    bypassed
}

/// Executable prefixes apply to the deleting process. Name rules apply to
/// that process itself and up to ten ancestors, excluding init/session PID 1.
/// Each level costs one exe readlink and one stat read, which yields both the
/// kernel comm and the next parent (#302).
fn process_is_bypassed(cfg: &PreloadConfig, mut pid: u32) -> bool {
    if cfg.bypass_paths.is_empty() && cfg.bypass_processes.is_empty() {
        return false;
    }
    for depth in 0..=10 {
        let exe = fs::read_link(format!("/proc/{pid}/exe")).ok();
        if depth == 0
            && let Some(exe) = &exe
            && cfg
                .bypass_paths
                .iter()
                .any(|prefix| exe.as_os_str().as_bytes().starts_with(prefix.as_bytes()))
        {
            return true;
        }
        if cfg.bypass_processes.is_empty() {
            return false;
        }
        let stat = proc_stat::comm_and_parent(pid);
        if process_names(exe.as_deref(), stat.as_ref().map(|(comm, _)| comm.as_str()))
            .any(|name| cfg.bypass_processes.iter().any(|bypass| *bypass == name))
        {
            return true;
        }
        pid = match stat {
            Some((_, parent)) if parent > 1 && parent != pid => parent,
            _ => break,
        };
    }
    false
}

/// Both the executable's basename and the kernel's comm: for a script,
/// comm is the script's own name (pip, npm) while the executable is its
/// interpreter, so bypass entries for script tools never matched (#224).
fn process_names<'a>(
    exe: Option<&'a Path>,
    comm: Option<&'a str>,
) -> impl Iterator<Item = std::borrow::Cow<'a, str>> {
    exe.and_then(Path::file_name)
        .map(OsStr::to_string_lossy)
        .into_iter()
        .chain(comm.map(std::borrow::Cow::Borrowed))
}

/// Check if a path is inside a trash directory (should never be intercepted).
///
/// Matches on whole path COMPONENTS, not raw substrings: a user file such as
/// `~/my.Trash-backup/x` or `~/foo.local/share/Trash-notes` must NOT be
/// misclassified as trash-internal (which would make the hook permanently
/// `rm` it instead of trashing it).
fn is_inside_trash(path: &Path) -> bool {
    let mut home = home_trash_dir();
    // A physical home trash still ends in Trash: the root itself may not
    // be a symlink. Other paths cannot need home-ancestor authentication.
    if !path.starts_with(&home)
        && !path
            .components()
            .any(|component| component.as_os_str() == "Trash")
    {
        return mounts::is_trash_internal(path, &home, false);
    }
    let uid = unsafe { libc::geteuid() };
    let mut trusted_home = ensure_trusted_parent(&home, uid).is_ok();
    if !trusted_home
        && let Some(parent) = home.parent()
        && ensure_trusted_ancestors_with(parent, uid, false).is_ok()
        && let Ok(physical_parent) = fs::canonicalize(parent)
        && let Some(name) = home.file_name()
    {
        // Resolve only after authenticating logical symlinks and their
        // targets. Keep the final root unresolved so the classifier still
        // rejects a Trash symlink and validates UID/mode/inode (#289).
        home = physical_parent.join(name);
        trusted_home = true;
    }
    mounts::is_trash_internal(path, &home, trusted_home)
}

/// Bounded directory-tree size walk mirroring trashd-common's dir_size_capped.
fn dir_size_capped(path: &Path) -> (u64, bool) {
    const MAX_FILES: u64 = 10_000;
    let mut total = 0u64;
    let mut count = 0u64;
    // One entry past the cap is visited, so a tree of exactly the cap is not
    // mistaken for an oversized one (same rule as trashd-common, #223).
    fn walk(path: &Path, total: &mut u64, count: &mut u64, max: u64) {
        if *count > max {
            return;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if *count > max {
                    return;
                }
                *count += 1;
                let Ok(meta) = entry.path().symlink_metadata() else {
                    continue;
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    walk(&entry.path(), total, count, max);
                } else {
                    *total = total.saturating_add(meta.len());
                }
            }
        }
    }
    walk(path, &mut total, &mut count, MAX_FILES);
    (total, count > MAX_FILES)
}

/// Match a single never_trash/only_trash pattern against a path string.
/// Mirrors trashd-common's `pattern_matches_any` so every layer agrees.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let Some(rest) = pattern.strip_prefix("~/") else {
        return expanded_pattern_matches(pattern, path);
    };
    let Some(home) = home_dir() else {
        return false;
    };
    // The canonical home too: policy paths are canonical (common-policy-6).
    let (raw, canonical) = pattern_policy::expand_home(rest, &home);
    expanded_pattern_matches(&raw, path)
        || canonical.is_some_and(|canonical| expanded_pattern_matches(&canonical, path))
}

/// `pattern_matches` for a pattern whose `~/` is already expanded.
fn expanded_pattern_matches(pattern: &str, path: &str) -> bool {
    // Keep common literal prefix/suffix rules allocation-free, but only
    // after excluding interior wildcard syntax (#4).
    if let Some(prefix) = pattern.strip_suffix('*')
        && !prefix.contains(['*', '?', '[', '\\'])
    {
        return path.starts_with(prefix)
            || (!prefix.starts_with('/')
                && path
                    .match_indices('/')
                    .any(|(index, _)| path[index + 1..].starts_with(prefix)));
    }
    if let Some(component) = pattern.strip_prefix("*/")
        && !component.is_empty()
        && !component.contains(['/', '*', '?', '[', '\\'])
    {
        return path.split('/').any(|part| part == component);
    }
    if let Some(suffix) = pattern.strip_prefix('*')
        && !suffix.contains(['*', '?', '[', '\\'])
    {
        return path.ends_with(suffix);
    }
    if glob_match(pattern, path) {
        return true;
    }
    !pattern.starts_with(['/', '*'])
        && path
            .match_indices('/')
            .any(|(index, _)| glob_match(pattern, &path[index + 1..]))
}

/// Glob matcher (`*`, `?`, `[...]`, `**`) — same semantics as trashd-common's
/// `simple_glob_match`; duplicated by design (the preload does not link
/// trashd-common). Iterative with star backtracking; cannot panic.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
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
        if pi == p.len() && ti == t.len() {
            return true;
        }
        if star_pi != usize::MAX && star_ti < t.len() {
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

/// Match one char against a `[...]` class at `p[start]`.
fn class_match(p: &[char], start: usize, c: char) -> ClassMatch {
    let mut i = start + 1;
    let mut negate = false;
    if i < p.len() && (p[i] == '!' || p[i] == '^') {
        negate = true;
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
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

/// Normalize patterns by the rules trashd-common applies, dropping what the
/// matcher cannot honour with a warning: in an only_trash whitelist a
/// never-matching pattern real-deletes everything (#4). The preload kept
/// its own copy of these rules, and it missed the empty pattern (#402,
/// cross-layer-2).
fn sanitize_patterns(list: Vec<String>, what: &str) -> Vec<String> {
    pattern_policy::sanitize_patterns(&list, what, |warning| {
        host_stderr(&format!("trashd-preload: WARNING: {warning}"));
    })
}

/// Find the nearest `.trashd.toml` walking up from `path` to the filesystem
/// root, matching trashd-common's Config::load_local_config (a fixed 5-level
/// cap silently dropped deep project whitelists, #9). A PRESENT local policy
/// that cannot be read or parsed stops the walk with a warning — inheriting
/// an ancestor's narrower whitelist would turn "trash it" into a REAL delete
/// (#136), and the preload protects exactly the daemon/cron processes that
/// have no other layer.
fn load_local_config(path: &Path) -> Option<LocalConfig> {
    // The walk runs on EVERY hooked call (the common crate loads config once
    // at store open; the preload has no such cache), so the warning must be
    // once-per-process: a broken config in a hot path would otherwise print
    // a line for every single unlink (#165).
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let warn = |msg: String| {
        if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            host_stderr(&format!("trashd-preload: warning: {msg}"));
        }
    };
    let mut dir = path.parent()?;
    loop {
        // Only a regular file the deleting user (or root) owns and nobody
        // else can write is policy; it is read without following symlinks
        // or blocking, and diagnostics never echo its content (#198, #207).
        let cfg_path = dir.join(".trashd.toml");
        match local_trust::read_local_config(dir) {
            local_trust::LocalConfigFile::Absent => {}
            local_trust::LocalConfigFile::Ignored(reason) => {
                warn(format!("ignoring {}: it {reason}", cfg_path.display()));
                return None;
            }
            local_trust::LocalConfigFile::Content(content) => {
                let mut local = match toml::from_str::<LocalConfig>(&content) {
                    Ok(local) => local,
                    Err(e) => {
                        warn(format!(
                            "ignoring broken {}: {}",
                            cfg_path.display(),
                            e.message()
                        ));
                        return None;
                    }
                };
                local.never_trash = sanitize_patterns(local.never_trash, "never_trash");
                local.only_trash = sanitize_patterns(local.only_trash, "only_trash");
                return Some(local);
            }
        }
        dir = dir.parent()?; // None at the filesystem root
    }
}

/// Global exclusions always win, even over local whitelists. Check them
/// before inode metadata, trash-root or local-policy walks (#285).
fn globally_excluded(path: &Path) -> bool {
    let s = path.to_string_lossy();
    config().never_trash.iter().any(|p| pattern_matches(p, &s))
}

/// Check remaining policy after the hook has ruled out global exclusions,
/// trash internals and bypassed processes. Keep the nearest local policy
/// fresh on every call, including local whitelist precedence over the
/// global whitelist.
fn policy_skips(path: &Path) -> bool {
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
            return false;
        }
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

/// Why no trash directory could be used for a delete.
#[derive(Debug)]
enum StoreError {
    /// It cannot be created or reached (no usable home, read-only, full).
    /// The real delete runs, exactly as without trashd (#194).
    Unavailable,
    /// A path another user could control: refuse instead of writing there.
    Unsafe,
    /// The selected store was prepared but cannot be locked. Final: no
    /// other store is tried.
    Lock(io::Error),
}

/// The store a delete goes to, already locked.
struct SelectedStore {
    root: PathBuf,
    guard: store_lock::RootMutationGuard,
    /// Home trash entries record absolute paths, topdir entries relative ones.
    home: bool,
}

impl From<io::Error> for StoreError {
    /// OS failures mean "unavailable"; violations found by our own ownership
    /// and type checks are constructed errors without an OS code.
    fn from(error: io::Error) -> Self {
        if error.raw_os_error().is_some() {
            StoreError::Unavailable
        } else {
            StoreError::Unsafe
        }
    }
}

/// Prepare and lock the HOME-derived trash; when it lies in a tree another
/// user controls (root with a user's HOME via `sudo -E` or a setuid tool),
/// use the effective user's own passwd home instead of refusing the delete
/// (#194).
fn prepared_home_trash(
    home_trash: PathBuf,
    uid: u32,
    now: u64,
) -> Result<SelectedStore, StoreError> {
    let (root, guard) = match prepare_home_trash(&home_trash, uid, now) {
        Err(StoreError::Unsafe) => {
            let own = cached_passwd_home(uid)
                .map(|home| home.join(".local/share/Trash"))
                .filter(|own| *own != home_trash)
                .ok_or(StoreError::Unsafe)?;
            let guard = prepare_home_trash(&own, uid, now)?;
            (own, guard)
        }
        Err(error) => return Err(error),
        Ok(guard) => (home_trash, guard),
    };
    Ok(SelectedStore {
        root,
        guard,
        home: true,
    })
}

/// The home directory of `uid`, read from /etc/passwd directly: NSS can load
/// modules and contact daemons from inside a hooked unlink (#303). Only a
/// user /etc/passwd does not list (LDAP, sssd, systemd-homed) asks NSS, like
/// the store does, so both pick the same home trash (#346). The result is
/// cached per process, so that lookup happens once.
fn passwd_home(uid: u32) -> Option<PathBuf> {
    fs::read("/etc/passwd")
        .ok()
        .and_then(|passwd| passwd_home_in(&passwd, uid))
        .or_else(|| nss_home_cached(uid))
}

/// `nss_home`, remembered without a lock: the per-UID home cache is only
/// try-locked (a fork child must never wait on it), so a failed try would
/// otherwise repeat the NSS lookup inside the hook (#352). A replaced value
/// is leaked, since a concurrent reader may still hold it; the UID changes
/// rarely, if ever.
fn nss_home_cached(uid: u32) -> Option<PathBuf> {
    use std::sync::atomic::{AtomicPtr, Ordering};
    static CACHE: AtomicPtr<(u32, Option<PathBuf>)> = AtomicPtr::new(std::ptr::null_mut());
    let cached = CACHE.load(Ordering::Acquire);
    if let Some((cached_uid, home)) = unsafe { cached.as_ref() }
        && *cached_uid == uid
    {
        return home.clone();
    }
    let home = nss_home(uid);
    let fresh = Box::into_raw(Box::new((uid, home.clone())));
    if CACHE
        .compare_exchange(cached, fresh, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        drop(unsafe { Box::from_raw(fresh) });
    }
    home
}

fn nss_home(uid: u32) -> Option<PathBuf> {
    let mut buffer = vec![0 as libc::c_char; 1024];
    loop {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || found.is_null() || entry.pw_dir.is_null() {
            return None;
        }
        let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes();
        return home
            .starts_with(b"/")
            .then(|| PathBuf::from(OsStr::from_bytes(home)));
    }
}

fn passwd_home_in(passwd: &[u8], uid: u32) -> Option<PathBuf> {
    let uid = uid.to_string();
    passwd.split(|&b| b == b'\n').find_map(|line| {
        let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
        (fields.len() >= 7 && fields[2] == uid.as_bytes() && fields[5].starts_with(b"/"))
            .then(|| PathBuf::from(OsStr::from_bytes(fields[5])))
    })
}

/// Device of `path`, or of its nearest existing ancestor (the home trash is
/// only created once it is actually selected).
fn existing_device(path: &Path) -> Option<u64> {
    path.ancestors()
        .find_map(|ancestor| fs::metadata(ancestor).ok())
        .map(|meta| meta.dev())
}

fn trash_dir_for(
    path: &Path,
    file_dev: u64,
    uid: u32,
    now: u64,
) -> Result<SelectedStore, StoreError> {
    let home_trash = home_trash_dir();

    // The hook just stat'ed this inode; its device cannot change. The
    // pre-move identity recheck still detects replacement (#297).
    if Some(file_dev) == existing_device(&home_trash) {
        return prepared_home_trash(home_trash, uid, now);
    }

    if let Some(mountpoint) = find_mount_point(path) {
        // A mount root cannot move, and its topdir store would be inside
        // it: preparing one left a .Trash-$UID on the mounted filesystem
        // before the real call failed busy anyway (#368).
        if mountpoint == path && is_mount_root(path) {
            return Err(StoreError::Unavailable);
        }
        // Only the mount the file is on: a nested subvolume's file went to a
        // store on its mount root, which listing skips when that root shares
        // the home trash's device (cross-layer-3).
        if fs::metadata(&mountpoint).map(|meta| meta.dev()).ok() != Some(file_dev) {
            return prepared_home_trash(home_trash, uid, now);
        }
        let topdir = |root: PathBuf| match lock_store(&root, uid) {
            Ok(guard) => Ok(Some(SelectedStore {
                root,
                guard,
                home: false,
            })),
            Err(StoreError::Lock(error)) => Err(StoreError::Lock(error)),
            // Unusable here: try the next candidate, as the spec orders.
            Err(_) => Ok(None),
        };
        // Check shared .Trash/ first (FreeDesktop spec §1.2.2a)
        let shared_trash = mountpoint.join(".Trash");
        if trusted_topdir(&mountpoint, uid)
            && let Ok(meta) = fs::symlink_metadata(&shared_trash)
            && !meta.file_type().is_symlink()
            && meta.is_dir()
            && (meta.uid() == 0 || meta.uid() == uid)
            && (meta.permissions().mode() & 0o1000) != 0
            && let Some(selected) = topdir(shared_trash.join(uid.to_string()))?
        {
            return Ok(selected);
        }

        // Fallback: .Trash-$UID (spec §1.2.2b)
        if trusted_topdir(&mountpoint, uid)
            && let Some(selected) = topdir(mountpoint.join(format!(".Trash-{uid}")))?
        {
            return Ok(selected);
        }
    }

    prepared_home_trash(home_trash, uid, now)
}

/// Lock `root`, creating or repairing its private directories only when the
/// lock reports one missing or not private. The lock validates the store
/// through descriptors, so path checks first only repeated it (#305). The
/// path checks still decide every rejection exactly as before, and a store
/// that passes them but cannot be locked is a final error.
fn lock_store(root: &Path, uid: u32) -> Result<store_lock::RootMutationGuard, StoreError> {
    match store_lock::RootMutationGuard::acquire_as(root, uid) {
        Ok(guard) => return Ok(guard),
        Err(error)
            if !matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::EACCES | libc::ELOOP | libc::ENOTDIR)
            ) =>
        {
            return Err(StoreError::Lock(error));
        }
        Err(_) => {}
    }
    ensure_private_dir(root, uid, true)?;
    ensure_private_dir(&root.join("files"), uid, true)?;
    ensure_private_dir(&root.join("info"), uid, true)?;
    store_lock::RootMutationGuard::acquire_as(root, uid).map_err(StoreError::Lock)
}

fn trusted_topdir(path: &Path, uid: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| {
        let mode = meta.permissions().mode();
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && (meta.uid() == 0 || meta.uid() == uid)
            && (mode & 0o022 == 0 || mode & 0o1000 != 0)
    })
}

fn prepare_home_trash(
    home: &Path,
    uid: u32,
    now: u64,
) -> Result<store_lock::RootMutationGuard, StoreError> {
    let fallback = PathBuf::from(format!("/tmp/trashd-home-{uid}"));
    if home == fallback.join("Trash") {
        ensure_trusted_parent(&fallback, uid)?;
        ensure_private_dir(&fallback, uid, true)?;
        return lock_store(home, uid);
    }
    let Some(parent) = home.parent() else {
        return lock_store(home, uid);
    };
    let reused = TrustedAncestry::recent(parent, uid, now);
    if !reused {
        ensure_trusted_ancestors(parent, uid)?;
        TrustedAncestry::remember(parent, uid, now);
    }
    match lock_store(home, uid) {
        // The reused chain may have lost a directory since; preparing it
        // again recreates missing ancestors exactly as an unreused call does.
        Err(StoreError::Unavailable) if reused => {
            TrustedAncestry::forget();
            ensure_trusted_ancestors(parent, uid)?;
            TrustedAncestry::remember(parent, uid, now);
            lock_store(home, uid)
        }
        result => result,
    }
}

/// The home trash ancestry this process validated last. Only root or the
/// user can change a validated chain (every component is theirs and not
/// writable by others), so validating it on every delete repeated one lstat
/// per component (#305). Like the bypass verdict, it expires after a few
/// seconds. The lock is only tried: losing the record costs a revalidation.
struct TrustedAncestry;

impl TrustedAncestry {
    const REUSE_SECS: u64 = 5;

    fn slot() -> &'static std::sync::Mutex<Option<(PathBuf, u32, u64)>> {
        static SLOT: std::sync::Mutex<Option<(PathBuf, u32, u64)>> = std::sync::Mutex::new(None);
        &SLOT
    }

    fn recent(directory: &Path, uid: u32, now: u64) -> bool {
        Self::slot().try_lock().is_ok_and(|slot| {
            slot.as_ref().is_some_and(|(path, owner, at)| {
                path == directory
                    && *owner == uid
                    && now
                        .checked_sub(*at)
                        .is_some_and(|age| age <= Self::REUSE_SECS)
            })
        })
    }

    fn remember(directory: &Path, uid: u32, now: u64) {
        if let Ok(mut slot) = Self::slot().try_lock() {
            *slot = Some((directory.to_path_buf(), uid, now));
        }
    }

    fn forget() {
        if let Ok(mut slot) = Self::slot().try_lock() {
            *slot = None;
        }
    }
}

fn ensure_private_dir(path: &Path, uid: u32, create: bool) -> io::Result<()> {
    let mut meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
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
            "unsafe trash directory ownership or type",
        ));
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        #[cfg(test)]
        crate::fdops::repair_probe::run(path);
        // Through the directory just checked, never by path: chmod(2)
        // follows a symlink that a FUSE or NFS server can answer for the
        // next lookup, which made the caller chmod any file (security-3).
        fdops::fchmod_pinned_dir(
            libc::AT_FDCWD,
            &CString::new(path.as_os_str().as_bytes())?,
            (meta.dev(), meta.ino()),
            0o700,
        )?;
        meta = fs::symlink_metadata(path)?;
    }
    if meta.uid() != uid
        || !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trash directory is not private",
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
                "trash ancestor can be replaced by another user",
            ));
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }
    Ok(())
}

fn ensure_trusted_ancestors(directory: &Path, uid: u32) -> io::Result<()> {
    ensure_trusted_ancestors_with(directory, uid, true)
}

fn ensure_trusted_ancestors_with(directory: &Path, uid: u32, create: bool) -> io::Result<()> {
    let directory = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()?.join(directory)
    };
    ensure_trusted_ancestors_from(&directory, uid, 0, create)
}

/// Same rule as trashd-common: a symlinked ancestor owned by root or this
/// user (ostree's /home, a stowed ~/.local) is followed and its target
/// validated from the root; anyone else's link is refused (#222).
fn ensure_trusted_ancestors_from(
    directory: &Path,
    uid: u32,
    hops: u32,
    create: bool,
) -> io::Result<()> {
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
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
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
            return ensure_trusted_ancestors_from(&resolved, uid, hops + 1, create);
        }
        let mode = metadata.permissions().mode();
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trash ancestor can be replaced by another user",
            ));
        }
    }
    Ok(())
}

/// Resolve `.` and `..` textually; only applied to a symlink target joined
/// to a directory the walk already validated.
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

/// Unescape /proc/mounts octal sequences (the kernel escapes only whitespace
/// and backslash, e.g. "\040" for space) so mount paths with spaces resolve.
///
/// Operates on raw bytes and preserves every unescaped byte verbatim: mount
/// points may contain arbitrary non-UTF-8 bytes.
fn unescape_octal(field: &[u8]) -> OsString {
    let mut out: Vec<u8> = Vec::with_capacity(field.len());
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
            out.push(((o[0] - b'0') << 6) | ((o[1] - b'0') << 3) | (o[2] - b'0'));
            i += 4;
        } else {
            out.push(field[i]);
            i += 1;
        }
    }
    OsString::from_vec(out)
}

fn home_trash_dir() -> PathBuf {
    // No shared /tmp fallback: without XDG or HOME the trash would land in a
    // world-readable, periodically purged directory (#35). A uid-suffixed
    // path keeps it out of other users' reach.
    data_dir()
        .unwrap_or_else(|| {
            PathBuf::from(format!("/tmp/trashd-home-{}", unsafe { libc::geteuid() }))
        })
        .join("Trash")
}

/// The dirs crate's rules (non-empty `$HOME`, absolute `$XDG_*_HOME`), but
/// without its NSS fallback: getpwuid_r inside a hooked unlink stats
/// nsswitch.conf, rereads /etc/passwd, may contact nscd and can load NSS
/// modules such as libnss_systemd (#303). The fallback is this effective
/// user's /etc/passwd entry, the user every ownership check expects.
fn home_dir() -> Option<PathBuf> {
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => Some(PathBuf::from(home)),
        _ => cached_passwd_home(unsafe { libc::geteuid() }),
    }
}

fn data_dir() -> Option<PathBuf> {
    xdg_dir("XDG_DATA_HOME").or_else(|| home_dir().map(|home| home.join(".local/share")))
}

fn config_dir() -> Option<PathBuf> {
    xdg_dir("XDG_CONFIG_HOME").or_else(|| home_dir().map(|home| home.join(".config")))
}

fn xdg_dir(variable: &str) -> Option<PathBuf> {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// passwd_home, remembered per effective UID. The lock is only tried, and
/// never held across syscalls: a fork from another thread must not leave a
/// child locked out, and it then merely loses the cache (#206).
fn cached_passwd_home(uid: u32) -> Option<PathBuf> {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(u32, Option<PathBuf>)>> = Mutex::new(None);
    if let Ok(cache) = CACHE.try_lock()
        && let Some((cached_uid, home)) = cache.as_ref()
        && *cached_uid == uid
    {
        return home.clone();
    }
    let home = passwd_home(uid);
    if let Ok(mut cache) = CACHE.try_lock() {
        *cache = Some((uid, home.clone()));
    }
    home
}

/// Whether `path`, which the mount table names as a mount point, still is
/// one (a later mount over its parent can hide it), from statx's mount-root
/// attribute, else from mount IDs (before Linux 5.8, or statx refused).
/// Where neither can tell, it is trashed as any path: a real mount root
/// then fails to move, while giving up made a hidden entry's delete
/// permanent (#370).
fn is_mount_root(path: &Path) -> bool {
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let root = libc::STATX_ATTR_MOUNT_ROOT as u64;
    if unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            name.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            libc::STATX_TYPE,
            &mut stx as *mut libc::statx,
        )
    } != 0
        || stx.stx_attributes_mask & root == 0
    {
        let parent = path
            .parent()
            .and_then(|parent| std::ffi::CString::new(parent.as_os_str().as_bytes()).ok());
        return matches!(
            (
                mount_id(&name, 0),
                parent.and_then(|parent| mount_id(&parent, libc::AT_SYMLINK_FOLLOW)),
            ),
            (Some(own), Some(above)) if own != above
        );
    }
    stx.stx_attributes & root != 0
}

/// The ID of the mount `path` is on, from its file handle.
fn mount_id(path: &std::ffi::CStr, flags: libc::c_int) -> Option<libc::c_int> {
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
            libc::AT_FDCWD,
            path.as_ptr(),
            &mut handle as *mut Handle,
            &mut id as *mut libc::c_int,
            flags,
        )
    };
    // EOVERFLOW still reports the mount.
    (ret == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EOVERFLOW)).then_some(id)
}

fn find_mount_point(path: &Path) -> Option<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };

    // Parsed as raw bytes: the kernel octal-escapes only space/tab/newline/
    // backslash in mount paths, so any other raw byte ≥ 0x80 survives
    // verbatim and a UTF-8 read would fail on a single such mount point —
    // silently losing the trash location for EVERY filesystem.
    // This thread's table: a thread can have a mount namespace of its own.
    let content = fs::read("/proc/thread-self/mounts")
        .or_else(|_| fs::read("/proc/mounts"))
        .ok()?;
    let mut best: Option<PathBuf> = None;
    let mut best_len = 0;

    for line in content.split(|&b| b == b'\n') {
        let mut parts = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());
        let _dev = match parts.next() {
            Some(d) => d,
            None => continue,
        };
        let mpoint = match parts.next() {
            Some(m) => m,
            None => continue,
        };
        // /proc/mounts octal-escapes whitespace and backslash in mount paths
        // (e.g. "\040" for space); unescape so those paths resolve (#47).
        let mp = PathBuf::from(unescape_octal(mpoint));
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

/// Copy a regular file with a race-hardened source open (see try_trash's
/// cross-device branch). The destination is created exclusively.
///
/// Mirrors trashd-common's copy_regular_at (store.rs): sparse-aware extents,
/// a source-version check, then ownership/mode, xattrs and timestamps on the
/// still-open destination, and a sync before the source is retired (#405).
fn copy_regular_verified(
    src: &Path,
    dst: &Path,
    expect_dev: u64,
    expect_ino: u64,
    created: &mut Option<(u64, u64)>,
) -> io::Result<fs::Metadata> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(src)?;
    let m = input.metadata()?;
    if !m.is_file() || m.dev() != expect_dev || m.ino() != expect_ino {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(dst)?;
    let metadata = output.metadata()?;
    *created = Some((metadata.dev(), metadata.ino()));
    copy_checked_contents(&mut input, &mut output, &m)?;
    apply_copy_metadata(&output, &m)?;
    copy_xattrs(&input, &output);
    apply_copy_times(&output, &m)?;
    output.sync_all()?;
    Ok(m)
}

/// Copy the selected version's bytes and refuse a source that changed while
/// being copied. A growing source must not keep the hook copying indefinitely:
/// extents past the selected size are never read, and the version check —
/// which also compares lengths and nanosecond timestamps — reports the rest.
fn copy_checked_contents(
    input: &mut fs::File,
    output: &mut fs::File,
    source: &fs::Metadata,
) -> io::Result<()> {
    copy_extents(input, output, source.len())?;
    if !same_copy_source(source, &input.metadata()?) {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    Ok(())
}

/// Copy a file's data extents only, leaving its holes as holes: a plain copy
/// expanded an 8-block sparse file to one block per written position (#405),
/// which can fail with ENOSPC where `mv` succeeds. Mirrors trashd-common's
/// copy_extents (store.rs): filesystems without SEEK_DATA get a plain copy.
fn copy_extents(source: &mut fs::File, destination: &mut fs::File, len: u64) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
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

/// Mode and ownership of the copy, mirroring trashd-common's
/// apply_fd_metadata: chown may clear set-id bits, so permissions are always
/// applied last, and a set-id copy owned by someone else would grant that
/// owner's privileges (#203).
fn apply_copy_metadata(destination: &fs::File, source: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut mode = (source.permissions().mode() & 0o7777) as libc::mode_t;
    if unsafe { libc::fchown(destination.as_raw_fd(), source.uid(), source.gid()) } != 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
            || unsafe { libc::geteuid() } == 0
        {
            return Err(error);
        }
        mode &= !0o6000;
    }
    if unsafe { libc::fchmod(destination.as_raw_fd(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Timestamps through the descriptor we created, before it is closed — the
/// destination otherwise gets the deletion instant for both (#405). Mirrors
/// trashd-common's apply_fd_times.
fn apply_copy_times(destination: &fs::File, source: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let times = [
        libc::timespec {
            tv_sec: source.atime() as libc::time_t,
            tv_nsec: source.atime_nsec() as libc::c_long,
        },
        libc::timespec {
            tv_sec: source.mtime() as libc::time_t,
            tv_nsec: source.mtime_nsec() as libc::c_long,
        },
    ];
    if unsafe { libc::futimens(destination.as_raw_fd(), times.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Best-effort extended-attribute copy, mirroring trashd-common's
/// copy_xattrs_fd: every namespace listxattr reports is carried over, and a
/// failure (unsupported filesystem, permissions) never fails the move (#405).
fn copy_xattrs(source: &fs::File, destination: &fs::File) {
    let src = source.as_raw_fd();
    let size = unsafe { libc::flistxattr(src, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return;
    }
    let mut names = vec![0u8; size as usize];
    if unsafe { libc::flistxattr(src, names.as_mut_ptr().cast(), names.len()) } < 0 {
        return;
    }
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let Ok(cname) = CString::new(name) else {
            continue;
        };
        let vsize = unsafe { libc::fgetxattr(src, cname.as_ptr(), std::ptr::null_mut(), 0) };
        if vsize < 0 {
            continue;
        }
        let mut value = vec![0u8; vsize as usize];
        if unsafe { libc::fgetxattr(src, cname.as_ptr(), value.as_mut_ptr().cast(), value.len()) }
            < 0
        {
            continue;
        }
        unsafe {
            libc::fsetxattr(
                destination.as_raw_fd(),
                cname.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            );
        }
    }
}

/// A copied source must still name the exact version we opened. Nanosecond
/// timestamps also detect same-inode, same-length rewrites during the copy.
fn same_copy_source(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.file_type() == after.file_type()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn remove_owned_copy(dest: &Path, created: Option<(u64, u64)>) {
    if created.is_some() && fs::symlink_metadata(dest).ok().map(|m| (m.dev(), m.ino())) == created {
        let _ = fs::remove_file(dest);
    }
}

/// Consume the guard so publication stays locked through source retirement
/// and rollback (#382). A changed source must return an error: NotTrashed
/// would ask the hook to permanently delete the replacement.
fn retire_copied_source(
    path: &Path,
    dest: &Path,
    info_path: &Path,
    copied: (&fs::Metadata, Option<(u64, u64)>),
    _guard: store_lock::RootMutationGuard,
    unlink: impl FnOnce() -> io::Result<()>,
) -> TrashAttempt {
    let (source, created) = copied;
    let current = fs::symlink_metadata(path);
    let result = match current {
        Ok(current) if same_copy_source(source, &current) => unlink(),
        _ => Err(io::Error::from_raw_os_error(libc::EBUSY)),
    };
    match result {
        Ok(()) => TrashAttempt::Trashed,
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(libc::EIO);
            remove_owned_copy(dest, created);
            let _ = fs::remove_file(info_path);
            TrashAttempt::Error(errno)
        }
    }
}

/// Whether a trashed item exceeds a configured size cap. Mirrors trashd-common
/// store.rs's limits (prepare_source and trash_at_display): every knob is an
/// EXACT-byte comparison — `len > mb.saturating_mul(1 MiB)`, which whole-MiB
/// truncation let ~1 MiB slip past (#245) — and a zero value disables the
/// knob. max_file_size_mb bounds a regular file; max_dir_size_mb bounds a
/// directory, through the bounded walk in `trash_entry`. Applying the tree
/// cap to every file (#412) made a standalone file between the two caps a
/// permanent delete here while every other layer trashed it
/// (cross-layer-1). The hook cannot tell a file inside an `rm -rf` from a
/// standalone one, so an oversized tree removed through the preload is
/// trashed file by file (preload-8).
fn exceeds_size_limit(cfg: &PreloadConfig, meta: &fs::Metadata) -> bool {
    exceeds_size_limit_mb(cfg, meta.is_file(), meta.len())
}

fn exceeds_size_limit_mb(cfg: &PreloadConfig, is_file: bool, len: u64) -> bool {
    is_file && over_size_cap(cfg.max_file_size_mb, len)
}

fn over_size_cap(cap_mb: u64, len: u64) -> bool {
    cap_mb != 0 && len > cap_mb.saturating_mul(1024 * 1024)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrashAttempt {
    Trashed,
    NotTrashed,
    /// The selected store failed its ownership/type/privacy checks. Falling
    /// through to libc here would turn an attack on the store into permanent
    /// deletion, so hooks return EACCES instead.
    UnsafeStore,
    Error(i32),
}

/// Move `path` into the appropriate trash. `expect_dev`/`expect_ino` are the
/// identity captured by the hook's eligibility stat: re-stat immediately
/// before the move and bail out if the file was REPLACED in between (#44) —
/// trashing the new inode would capture content the caller never asked to
/// delete, and then report success for it.
/// Fresh ids to claim when another writer takes `files/<id>` first.
const MAX_CLAIM_ATTEMPTS: u32 = 8;

fn try_trash(path: &Path, meta: &fs::Metadata, pid: u32, now: u64) -> TrashAttempt {
    remembered(trash_entry(path, meta, pid, now)).0
}

/// The trash roots this process moved entries into: (PID, roots). A
/// recursive removal of an ancestor of the trash (`rm -rf ~/.local/share`)
/// first trashed what it met into the trash, then reached the trash and
/// deleted every entry for real, the ones it had just moved there too
/// (cross-layer-5). While a process has trashed into a root, it may not
/// delete anything in that root for real: the hooks answer EBUSY. Emptying
/// tools run as processes of their own and are unaffected. The PID drops a
/// forked child's inherited record; the lock is only tried and never held
/// across a syscall, so a fork cannot leave a child waiting on it.
static TRASHED_ROOTS: std::sync::Mutex<(u32, Vec<TrashedRoot>)> =
    std::sync::Mutex::new((0, Vec::new()));
/// The PID of the last record, so a hook of a process that trashed nothing
/// skips the check without a lock or a syscall.
static TRASHED_ROOTS_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// Roots one process keeps a record of: one per filesystem it trashed on.
const MAX_TRASHED_ROOTS: usize = 16;

struct TrashedRoot {
    /// As selected, to find it again without resolving it.
    selected: PathBuf,
    /// Resolved, as the hooks' canonical paths name it.
    canonical: PathBuf,
    identity: (u64, u64),
}

/// Record the root of an entry this process just trashed.
fn remembered(
    trashed: (TrashAttempt, Option<(PathBuf, PathBuf)>),
) -> (TrashAttempt, Option<(PathBuf, PathBuf)>) {
    if let (TrashAttempt::Trashed, Some((dest, _))) = &trashed
        && let Some(root) = dest.parent().and_then(Path::parent)
    {
        remember_trashed_root(root);
    }
    trashed
}

fn remember_trashed_root(root: &Path) {
    use std::sync::atomic::Ordering;
    let pid = std::process::id();
    let known = TRASHED_ROOTS
        .try_lock()
        .is_ok_and(|record| record.0 == pid && record.1.iter().any(|known| known.selected == root));
    if known {
        return;
    }
    let Ok(canonical) = fs::canonicalize(root) else {
        return;
    };
    let Ok(meta) = fs::metadata(&canonical) else {
        return;
    };
    let Ok(mut record) = TRASHED_ROOTS.try_lock() else {
        return;
    };
    if record.0 != pid {
        *record = (pid, Vec::new());
    }
    if record.1.len() < MAX_TRASHED_ROOTS {
        record.1.push(TrashedRoot {
            selected: root.to_path_buf(),
            canonical,
            identity: (meta.dev(), meta.ino()),
        });
    }
    TRASHED_ROOTS_PID.store(pid, Ordering::Release);
}

/// Whether `abs` (a hook's canonical path) is in, or is, a trash root this
/// process trashed into.
fn in_trashed_root(abs: &Path) -> bool {
    use std::sync::atomic::Ordering;
    let recorded = TRASHED_ROOTS_PID.load(Ordering::Acquire);
    if recorded == 0 || recorded != std::process::id() {
        return false;
    }
    // The record is this process's own, so its lock was free when this
    // process last took it: only another thread's brief update can hold it
    // (a fork child, whose copy may be held forever, returned above).
    let roots: Vec<(PathBuf, (u64, u64))> = TRASHED_ROOTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .1
        .iter()
        .filter(|root| abs.starts_with(&root.canonical))
        .map(|root| (root.canonical.clone(), root.identity))
        .collect();
    roots.into_iter().any(|(root, identity)| {
        fs::symlink_metadata(&root).is_ok_and(|meta| (meta.dev(), meta.ino()) == identity)
    })
}

/// A hook's answer for a real delete inside a trash this process filled:
/// EBUSY, as the shim refuses to remove a trash (cross-layer-5).
fn keep_trashed_root(abs: &Path) -> Option<libc::c_int> {
    if !in_trashed_root(abs) {
        return None;
    }
    unsafe { *libc::__errno_location() = libc::EBUSY };
    Some(-1)
}

/// `try_trash`, plus the published entry's data and sidecar paths: an rmdir
/// that cannot verify emptiness before the move verifies it at the destination
/// instead (#410). `Some` only accompanies `TrashAttempt::Trashed`.
fn trash_entry(
    path: &Path,
    meta: &fs::Metadata,
    pid: u32,
    now: u64,
) -> (TrashAttempt, Option<(PathBuf, PathBuf)>) {
    // The hook's own lstat of `path` supplies the identity; the pre-move
    // recheck below detects a replacement (#44) without a second stat here.
    let (expect_dev, expect_ino) = (meta.dev(), meta.ino());
    if exceeds_size_limit(config(), meta) {
        return (TrashAttempt::NotTrashed, None);
    }
    // Directory size cap (#118): the other layers refuse oversized trees, so
    // trashing one here file-by-file would gut it where the user asked for a
    // refusal. Bounded walk, same 10k-entry cap as trashd-common.
    if meta.is_dir() && !meta.file_type().is_symlink() {
        let cfg = config();
        if cfg.max_dir_size_mb > 0 {
            let (bytes, capped) = dir_size_capped(path);
            // Exact bytes, as the store compares them (#245).
            if capped || bytes > cfg.max_dir_size_mb.saturating_mul(1024 * 1024) {
                return (TrashAttempt::NotTrashed, None);
            }
        }
    }
    let uid = unsafe { libc::geteuid() };
    let SelectedStore {
        root: trash_dir,
        guard,
        home,
    } = match trash_dir_for(path, expect_dev, uid, now) {
        Ok(selected) => selected,
        Err(StoreError::Unavailable) => return (TrashAttempt::NotTrashed, None),
        Err(StoreError::Unsafe) => return (TrashAttempt::UnsafeStore, None),
        Err(StoreError::Lock(e))
            if matches!(
                e.raw_os_error(),
                Some(libc::EACCES | libc::ELOOP | libc::ENOTDIR)
            ) =>
        {
            return (TrashAttempt::UnsafeStore, None);
        }
        Err(StoreError::Lock(e)) => {
            return (
                TrashAttempt::Error(e.raw_os_error().unwrap_or(libc::EIO)),
                None,
            );
        }
    };

    let files_dir = trash_dir.join("files");
    let info_dir = trash_dir.join("info");
    let base_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".into());

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return (TrashAttempt::NotTrashed, None),
        }
    };

    let size = meta.len();

    // Per FreeDesktop spec, topdir trash stores relative paths from the mount
    // point; every home trash (including the passwd-home fallback) stores
    // absolute ones.
    let trashinfo_path = if home {
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

    // The deletion instant to the nanosecond orders entries trashed within
    // one second, which DeletionDate and coarse sidecar mtimes cannot
    // (#345). The clock read is a vDSO call, not a syscall.
    let Ok(stamp) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return (TrashAttempt::NotTrashed, None);
    };
    let Some(date) = local_time(stamp.as_secs()) else {
        return (TrashAttempt::NotTrashed, None);
    };
    let trashinfo = format!(
        "[Trash Info]\nPath={}\nDeletionDate={:04}-{:02}-{:02}T{:02}:{:02}:{:02}\nX-Trashd-Command=preload\nX-Trashd-PID={}\nX-Trashd-Size={size}\nX-Trashd-DeletedNs={}\n",
        encode_path(&trashinfo_path),
        date.tm_year + 1900,
        date.tm_mon + 1,
        date.tm_mday,
        date.tm_hour,
        date.tm_min,
        date.tm_sec,
        pid,
        stamp.as_nanos(),
    );

    let source = match CString::new(path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return (TrashAttempt::Error(libc::EINVAL), None),
    };

    // Atomic unique ID via O_CREAT|O_EXCL. A FreeDesktop tool that ignores our
    // lock can still take files/<id> between the claim and the move; claim a
    // fresh id then, since unlink never fails with EEXIST (#225).
    let mut attempts = 0;
    let (info_path, dest, rename_error) = loop {
        let (id, info_path, mut info_file) =
            match unique_id_atomic(&info_dir, &files_dir, &base_name, &date) {
                Some(v) => v,
                None => return (TrashAttempt::NotTrashed, None),
            };
        let dest = files_dir.join(&id);

        // Write through the descriptor that claimed the name: reopening it
        // with O_TRUNC cost two syscalls (#305).
        let written = io::Write::write_all(&mut info_file, trashinfo.as_bytes());
        drop(info_file);
        if written.is_err() {
            let _ = fs::remove_file(&info_path);
            return (TrashAttempt::NotTrashed, None);
        }

        // TOCTOU re-check just before the move (#44)
        match fs::symlink_metadata(path) {
            Ok(now) if now.dev() == expect_dev && now.ino() == expect_ino => {}
            Ok(_) => {
                let _ = fs::remove_file(&info_path);
                return (TrashAttempt::NotTrashed, None); // replaced — let the real unlink handle the path
            }
            Err(_) => {} // vanished; rename below fails cleanly
        }

        // Move the file
        let target = match CString::new(dest.as_os_str().as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                let _ = fs::remove_file(&info_path);
                return (TrashAttempt::Error(libc::EINVAL), None);
            }
        };
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0
        {
            // A concurrent purge may have stripped the sidecar while the data was
            // absent mid-move; a completed move must never land as an orphan (#169).
            log_preload(&format!(
                "trashed: {} -> {}",
                path.display(),
                dest.display()
            ));
            return (
                TrashAttempt::Trashed,
                Some((dest.clone(), info_path.clone())),
            );
        }
        let rename_error = io::Error::last_os_error().raw_os_error();
        if rename_error == Some(libc::EEXIST) || dest.symlink_metadata().is_ok() {
            let _ = fs::remove_file(&info_path);
            attempts += 1;
            if attempts < MAX_CLAIM_ATTEMPTS {
                continue;
            }
            return (TrashAttempt::NotTrashed, None);
        }
        break (info_path, dest, rename_error);
    };
    // Only a cross-device move (or an unsupported RENAME_NOREPLACE) calls for
    // copying. Any other error (EACCES, EPERM, EROFS) makes the real unlink
    // fail as well; copying first only stranded duplicates in the trash (#205).
    if !matches!(
        rename_error,
        Some(libc::EXDEV) | Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
    ) {
        let _ = fs::remove_file(&info_path);
        return (TrashAttempt::NotTrashed, None);
    }
    // Cross-device: copy preserving symlinks, then remove original
    let meta = match fs::symlink_metadata(path) {
        Ok(m) if m.dev() == expect_dev && m.ino() == expect_ino => m,
        Ok(_) => {
            let _ = fs::remove_file(&info_path);
            return (TrashAttempt::Error(libc::EBUSY), None);
        }
        Err(_) => {
            let _ = fs::remove_file(&info_path);
            return (TrashAttempt::NotTrashed, None);
        }
    };

    if meta.file_type().is_symlink() {
        // Re-create symlink
        if let Ok(target) = fs::read_link(path)
            && std::os::unix::fs::symlink(&target, &dest).is_ok()
        {
            let created = fs::symlink_metadata(&dest).ok().map(|m| (m.dev(), m.ino()));
            let result = retire_copied_source(
                path,
                &dest,
                &info_path,
                (&meta, created),
                guard,
                || unsafe { seccomp_identity::retire_unlink(source.as_ptr()) },
            );
            if result == TrashAttempt::Trashed {
                log_preload(&format!("trashed (cross-dev symlink): {}", path.display()));
            }
            return located(result, &dest, &info_path);
        }
    } else if meta.is_dir() {
        // Cross-device dirs: best-effort. For preload, fall back to real delete.
        let _ = fs::remove_file(&info_path);
        return (TrashAttempt::NotTrashed, None);
    } else if meta.file_type().is_fifo() || meta.file_type().is_socket() {
        // fs::copy on a FIFO blocks forever waiting for a writer (#11);
        // sockets have no persistent data. Let the real unlink proceed.
        let _ = fs::remove_file(&info_path);
        return (TrashAttempt::NotTrashed, None);
    } else if meta.file_type().is_char_device() || meta.file_type().is_block_device() {
        // Copying a device node would read unbounded data from it.
        let _ = fs::remove_file(&info_path);
        return (TrashAttempt::NotTrashed, None);
    } else {
        // Regular file: copy + delete original. The copy opens the source
        // with O_NOFOLLOW|O_NONBLOCK and re-verifies dev/ino first: a racer
        // swapping the file for a FIFO must not block the copy forever, and
        // a symlink swap must not be read through (#111).
        let mut created = None;
        // Losing the files/<id> race on the O_EXCL create falls back like any
        // other copy failure; unlink never fails with EEXIST (#225).
        let copied = match copy_regular_verified(path, &dest, expect_dev, expect_ino, &mut created)
        {
            Ok(source) => source,
            Err(error) => {
                remove_owned_copy(&dest, created);
                let _ = fs::remove_file(&info_path);
                if error.raw_os_error() == Some(libc::EBUSY)
                    || fs::symlink_metadata(path).is_ok_and(|now| !same_copy_source(&meta, &now))
                {
                    return (TrashAttempt::Error(libc::EBUSY), None);
                }
                return (TrashAttempt::NotTrashed, None);
            }
        };
        let result = retire_copied_source(
            path,
            &dest,
            &info_path,
            (&copied, created),
            guard,
            || unsafe { seccomp_identity::retire_unlink(source.as_ptr()) },
        );
        if result == TrashAttempt::Trashed {
            log_preload(&format!("trashed (cross-dev): {}", path.display()));
        }
        return located(result, &dest, &info_path);
    }

    let _ = fs::remove_file(&info_path);
    (TrashAttempt::NotTrashed, None)
}

/// Pair a cross-device retirement result with where its entry landed.
fn located(
    result: TrashAttempt,
    dest: &Path,
    info_path: &Path,
) -> (TrashAttempt, Option<(PathBuf, PathBuf)>) {
    (
        result,
        (result == TrashAttempt::Trashed).then(|| (dest.to_path_buf(), info_path.to_path_buf())),
    )
}

/// The rmdir family's emptiness verdict for a directory, decided before
/// anything moves: a caller must be able to POSITIVELY confirm emptiness
/// before it emulates a successful rmdir.
enum Emptiness {
    /// No entries besides `.` and `..`: trash it as today.
    Empty,
    /// Populated, or unreadable in a way the kernel will answer for itself.
    Populated,
    /// This user cannot read it, yet the kernel's rmdir only needs the
    /// PARENT's write permission — such a directory would be removed for real
    /// where today's read-based emptiness gate must decline (#410).
    Unreadable,
}

fn emptiness(path: &Path) -> Emptiness {
    match fs::read_dir(path) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                Emptiness::Populated
            } else {
                Emptiness::Empty
            }
        }
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            Emptiness::Unreadable
        }
        // Vanished, or otherwise unreportable: the real syscall produces the
        // exact errno.
        Err(_) => Emptiness::Populated,
    }
}

/// The rmdir/unlinkat(AT_REMOVEDIR)/remove(directory) decision for a real
/// directory. `None` lets the real syscall run and answer for itself.
fn rmdir_attempt(abs: &Path, meta: &fs::Metadata, pid: u32, now: u64) -> Option<TrashAttempt> {
    match emptiness(abs) {
        Emptiness::Empty => Some(try_trash(abs, meta, pid, now)),
        Emptiness::Populated => None,
        Emptiness::Unreadable => rmdir_unreadable(abs, meta, pid, now),
    }
}

/// #410: an unreadable directory is scanned under a temporary read and write
/// grant instead of being left to the kernel's rmdir, which removes it for
/// real. The grant is needed for the move too: renaming a directory OUT of
/// its parent requires the directory's OWN write permission (a 0300
/// directory renames across parents, a 0500 one fails EACCES), and the scan
/// needs read. The entry's own mode goes back on whichever copy it ends up
/// as, and a populated directory is answered with the kernel's own ENOTEMPTY
/// without trashing anything.
fn rmdir_unreadable(abs: &Path, meta: &fs::Metadata, pid: u32, now: u64) -> Option<TrashAttempt> {
    // Only the entry's owner can grant and restore its mode.
    if meta.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    let mode = meta.permissions().mode() & 0o7777;
    let path = match CString::new(abs.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return None,
    };
    let set_mode = |granted: bool, target: &CString| {
        let value = if granted {
            mode | libc::S_IRUSR | libc::S_IWUSR
        } else {
            mode
        };
        unsafe { libc::chmod(target.as_ptr(), value as libc::mode_t) == 0 }
    };
    if !set_mode(true, &path) {
        return None;
    }
    let scanned = fs::read_dir(abs).map(|mut entries| entries.next().is_none());
    let empty = match scanned {
        Ok(empty) => empty,
        Err(error) => {
            // Even the grant does not make it scannable: decline as before.
            if !set_mode(false, &path) {
                log_preload(&format!(
                    "unreadable rmdir: could not restore the mode of {}: {error}",
                    abs.display()
                ));
            }
            return None;
        }
    };
    if !empty {
        // The kernel would have answered ENOTEMPTY: nothing is trashed and
        // the victim's own mode is restored.
        if !set_mode(false, &path) {
            log_preload(&format!(
                "unreadable rmdir: could not restore the mode of {}",
                abs.display()
            ));
        }
        return Some(TrashAttempt::Error(libc::ENOTEMPTY));
    }
    let (attempt, located) = remembered(trash_entry(abs, meta, pid, now));
    match located {
        // The entry moved under the granted mode: put its own mode back on
        // the copy in the trash.
        Some((dest, _info)) => {
            if let Ok(dest) = CString::new(dest.as_os_str().as_bytes())
                && !set_mode(false, &dest)
            {
                log_preload(&format!(
                    "unreadable rmdir: could not restore the mode of the trashed copy of {}",
                    abs.display()
                ));
            }
        }
        // Not moved (store failure, another device, a size cap): put the
        // original's mode back before the real syscall runs.
        None => {
            if !set_mode(false, &path) {
                log_preload(&format!(
                    "unreadable rmdir: could not restore the mode of {}",
                    abs.display()
                ));
            }
        }
    }
    Some(attempt)
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
    date: &libc::tm,
) -> Option<(String, PathBuf, fs::File)> {
    let name_max = trash_id::name_max(info_dir);
    unique_id_atomic_within(info_dir, files_dir, base_name, date, name_max)
}

/// `unique_id_atomic` with ids sized for a NAME_MAX of `name_max`. A name
/// the filesystem refuses as too long made the delete permanent; it is
/// claimed again shorter (cross-layer-6).
fn unique_id_atomic_within(
    info_dir: &Path,
    files_dir: &Path,
    base_name: &str,
    date: &libc::tm,
    mut name_max: usize,
) -> Option<(String, PathBuf, fs::File)> {
    loop {
        match claim_unique_id(info_dir, files_dir, base_name, date, name_max) {
            Err(error) if error.raw_os_error() == Some(libc::ENAMETOOLONG) => {
                name_max = trash_id::smaller_name_max(name_max)?;
            }
            claimed => return claimed.ok(),
        }
    }
}

fn claim_unique_id(
    info_dir: &Path,
    files_dir: &Path,
    base_name: &str,
    date: &libc::tm,
    name_max: usize,
) -> io::Result<(String, PathBuf, fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;

    // Room for ".trashinfo" and a collision suffix within NAME_MAX.
    let base_name = trash_id::base_within(base_name, name_max);

    // Claim `candidate`: O_EXCL the .trashinfo AND ensure files/<candidate> is
    // free. Some(path) = claimed; None = taken (try another); Err = an I/O
    // error (disk full, permission denied, a name too long).
    let try_claim = |candidate: &str| -> io::Result<Option<(PathBuf, fs::File)>> {
        let path = info_dir.join(format!("{candidate}.trashinfo"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                if fs::symlink_metadata(files_dir.join(candidate)).is_ok() {
                    // info name free but an orphaned data file occupies files/.
                    let _ = fs::remove_file(&path);
                    Ok(None)
                } else {
                    Ok(Some((path, file)))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e),
        }
    };

    // Try base name
    if let Some((path, file)) = try_claim(base_name)? {
        return Ok((base_name.to_string(), path, file));
    }

    // Keep the first timestamped ID, then advance without rescanning the
    // existing counter range or exhausting a fixed naming namespace (#399).
    let ts = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        date.tm_year + 1900,
        date.tm_mon + 1,
        date.tm_mday,
        date.tm_hour,
        date.tm_min,
        date.tm_sec
    );
    let mut names = trash_id::CollisionNames::new(base_name, &ts, name_max);
    loop {
        let candidate = names.next();
        if let Some((path, file)) = try_claim(&candidate)? {
            return Ok((candidate, path, file));
        }
    }
}

/// Local broken-down time for the hook's sample. glibc keeps its zone after
/// the first conversion, so dating a sidecar needs no further clock read or
/// timezone-file check, unlike chrono's Local::now() (#305).
fn local_time(now: u64) -> Option<libc::tm> {
    let time = libc::time_t::try_from(now).ok()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    (!unsafe { libc::localtime_r(&time, &mut tm) }.is_null()).then_some(tm)
}

fn encode_path(path: &Path) -> String {
    let bytes = path.as_os_str().as_bytes();
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
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
        host_stderr(&format!("[trashd-preload] {msg}"));
    }
}

/// Write one diagnostic line to the HOST process's stderr. It must never hurt
/// the host: `eprintln!` panics when the write fails, which aborts the host
/// from inside an extern "C" hook, and writing to a closed pipe raises
/// SIGPIPE in a program that may never write to stderr itself (#208). So
/// SIGPIPE is blocked around the write and a SIGPIPE caused by it is
/// consumed; errors are ignored and the caller's errno is preserved.
fn host_stderr(msg: &str) {
    let mut line = msg.as_bytes().to_vec();
    line.push(b'\n');
    unsafe {
        let saved_errno = *libc::__errno_location();
        let mut pipe: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut pipe);
        libc::sigaddset(&mut pipe, libc::SIGPIPE);
        let mut pending: libc::sigset_t = std::mem::zeroed();
        libc::sigpending(&mut pending);
        let already_pending = libc::sigismember(&pending, libc::SIGPIPE) == 1;
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, &pipe, &mut previous);
        let written = libc::write(2, line.as_ptr().cast(), line.len());
        if written < 0 && *libc::__errno_location() == libc::EPIPE && !already_pending {
            let immediately = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            libc::sigtimedwait(&pipe, std::ptr::null_mut(), &immediately);
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        *libc::__errno_location() = saved_errno;
    }
}

/// Diagnostics of modules shared with trashd-common (`#[path]` includes).
pub(crate) fn report_note(msg: &str) {
    host_stderr(msg);
}

fn cstr_to_path(s: *const libc::c_char) -> Option<PathBuf> {
    if s.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(s) };
    Some(PathBuf::from(OsStr::from_bytes(cstr.to_bytes())))
}

/// Absolute path for a hooked `(dirfd, pathname)` with a canonical parent,
/// plus, for dirfd-relative names, the identity of the inode the caller
/// named. Only components that may still be symlinks are resolved (#304):
/// `getcwd` and a descriptor's /proc link are already canonical, so a bare
/// name costs one syscall instead of a readlink for every directory above it.
fn resolve_at_path(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
) -> Option<(PathBuf, Option<(u64, u64)>)> {
    let raw = cstr_to_path(pathname)?;
    let bytes = raw.as_os_str().as_bytes();
    let end = bytes.iter().rposition(|b| *b != b'/')? + 1;
    let final_bytes = bytes[..end].rsplit(|b| *b == b'/').next()?;
    if final_bytes.is_empty() || final_bytes == b"." || final_bytes == b".." {
        return None;
    }
    // Everything above the final component; empty for a bare name. Its
    // trailing slashes are dropped (keeping a lone "/"): realpath checks a
    // slash-terminated name with an extra access() call.
    let above = &bytes[..end - final_bytes.len()];
    let directories = OsStr::from_bytes(match above.iter().rposition(|b| *b != b'/') {
        Some(last) => &above[..=last],
        None => &above[..above.len().min(1)],
    });
    let mut identity = None;
    let parent = if bytes[0] == b'/' {
        fs::canonicalize(directories).ok()?
    } else if dirfd == libc::AT_FDCWD {
        if directories.is_empty() {
            std::env::current_dir().ok()?
        } else {
            // realpath of a relative path starts from getcwd and checks only
            // the relative components.
            fs::canonicalize(directories).ok()?
        }
    } else {
        // The /proc link is a path string: under a chroot, or after a rename,
        // it can name a different file than the descriptor. The hook only
        // proceeds when the resolved path still names this inode.
        identity = Some(identity_at(dirfd, &bytes[..end])?);
        let base = fs::read_link(format!("/proc/self/fd/{dirfd}")).ok()?;
        // Sockets and anonymous inodes have no path.
        if !base.is_absolute() {
            return None;
        }
        if directories.is_empty() {
            base
        } else {
            fs::canonicalize(base.join(directories)).ok()?
        }
    };
    let resolved = parent.join(OsStr::from_bytes(final_bytes));
    if end != bytes.len() {
        let meta = fs::symlink_metadata(&resolved).ok()?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return None;
        }
    }
    Some((resolved, identity))
}

/// Device and inode of `name` relative to `dirfd`, without following a
/// final symlink.
fn identity_at(dirfd: libc::c_int, name: &[u8]) -> Option<(u64, u64)> {
    let name = CString::new(name).ok()?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0)
        .then_some((stat.st_dev, stat.st_ino))
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

fn finish_attempt(attempt: TrashAttempt, saved_errno: libc::c_int) -> Option<libc::c_int> {
    match attempt {
        TrashAttempt::Trashed => Some(success_with_errno(saved_errno)),
        TrashAttempt::NotTrashed => None,
        TrashAttempt::Error(e) => {
            unsafe { *libc::__errno_location() = e };
            Some(-1)
        }
        TrashAttempt::UnsafeStore => {
            unsafe { *libc::__errno_location() = libc::EACCES };
            Some(-1)
        }
    }
}

/// The libc deletion entry point being handed to the supervisor. Keep its
/// native syscall family: an existing application filter may allow unlink
/// or rmdir on x86-64 while rejecting unlinkat.
enum DeletionCall {
    Unlink,
    UnlinkAt(libc::c_int, libc::c_int),
    Rmdir,
}

/// Hand a deletion to the trashd supervisor filtering this process: it
/// trashes the entry or answers with the deletion's real result. `None`
/// when it declined (ENOSYS: it will not act with its own credentials for
/// this process, or its listener is gone); the hook then trashes the entry
/// in-process (#349).
fn defer_to_supervisor(
    call: DeletionCall,
    pathname: *const libc::c_char,
    saved_errno: libc::c_int,
) -> Option<libc::c_int> {
    if is_bypass_active() || !is_seccomp_active() {
        return None;
    }
    let ret = unsafe {
        match call {
            #[cfg(target_arch = "x86_64")]
            DeletionCall::Unlink | DeletionCall::Rmdir => libc::syscall(
                if matches!(call, DeletionCall::Unlink) {
                    libc::SYS_unlink
                } else {
                    libc::SYS_rmdir
                },
                pathname,
                0 as libc::c_long,
                0 as libc::c_long,
                seccomp_identity::DEFER_MARK as libc::c_long,
            ),
            call => {
                let (dirfd, flags) = match call {
                    DeletionCall::Unlink => (libc::AT_FDCWD, 0),
                    DeletionCall::Rmdir => (libc::AT_FDCWD, libc::AT_REMOVEDIR),
                    DeletionCall::UnlinkAt(dirfd, flags) => (dirfd, flags),
                };
                libc::syscall(
                    libc::SYS_unlinkat,
                    dirfd as libc::c_long,
                    pathname,
                    flags as libc::c_long,
                    seccomp_identity::DEFER_MARK as libc::c_long,
                )
            }
        }
    } as libc::c_int;
    match ret {
        0 => Some(success_with_errno(saved_errno)),
        _ if unsafe { *libc::__errno_location() } == libc::ENOSYS => None,
        _ => Some(-1),
    }
}

/// `remove()` handed to the supervisor the way glibc implements it: unlink,
/// then rmdir only when unlink said EISDIR (an EPERM retry turned a sticky
/// or immutable file's EPERM into rmdir's ENOTDIR, #355).
fn defer_remove_to_supervisor(
    pathname: *const libc::c_char,
    saved_errno: libc::c_int,
) -> Option<libc::c_int> {
    let ret = defer_to_supervisor(DeletionCall::Unlink, pathname, saved_errno)?;
    if ret == 0 || unsafe { *libc::__errno_location() } != libc::EISDIR {
        return Some(ret);
    }
    defer_to_supervisor(DeletionCall::Rmdir, pathname, saved_errno)
}

/// PID and time sample for a hook about to trash, unless its process is
/// bypassed. Hooks call it only after the cheap path checks: the ancestor
/// walk it may run cost every excluded, missing or trash-internal deletion
/// ~50 syscalls first (#353).
fn intercepted() -> Option<(u32, u64)> {
    if is_bypass_active() {
        return None;
    }
    // One fresh PID per hook preserves fork detection and also identifies
    // any sidecar this operation publishes, without a second syscall (#298).
    let pid = std::process::id();
    // One clock read per hook: it expires the bypass verdict and config
    // notices, bounds trusted-ancestry reuse and dates the sidecar.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (!is_process_bypassed(pid, now)).then_some((pid, now))
}

// ---------------------------------------------------------------------------
// Hooked functions
//
// ASYNC-SIGNAL-SAFETY CAVEAT (#36): these hooks do heap allocation, file IO
// and locks, so unlink()/unlinkat()/rmdir() are NOT async-signal-safe while
// this library is loaded. A program that deletes files from WITHIN a signal
// handler takes the real-syscall path (the re-entrancy guard makes the nested
// hook a no-op) — the deletion still happens, just without trashing. This is
// the least-bad behavior for an interposer; glibc's own printf-family has the
// same caveat and programs are expected not to delete from handlers.
// ---------------------------------------------------------------------------

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(pathname: *const libc::c_char) -> libc::c_int {
    unsafe {
        // Capture the caller's errno FIRST — before the guard, intercepted_pid()
        // (/proc walks), or path resolution can perturb it — so the success path
        // restores the caller's true pre-call errno.
        let saved_errno = *libc::__errno_location();

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = match ReentrancyGuard::enter() {
                Some(g) => g,
                None => return None,
            };

            if is_bypass_active() || known_bypassed() {
                return None;
            }
            if let Some(ret) = defer_to_supervisor(DeletionCall::Unlink, pathname, saved_errno) {
                return Some(ret);
            }

            let resolved = resolve_at_path(libc::AT_FDCWD, pathname);
            if let Some((abs, _)) = &resolved
                && let Some(refused) = keep_trashed_root(abs)
            {
                return Some(refused);
            }
            if let Some((abs, _)) = resolved
                && !globally_excluded(&abs)
            {
                // Use symlink_metadata to not follow symlinks — dangling symlinks
                // should be trashed, not permanently deleted via the fallthrough.
                if let Ok(meta) = fs::symlink_metadata(&abs)
                    && !meta.is_dir()
                    && !is_inside_trash(&abs)
                    && let Some((pid, now)) = intercepted()
                    && !policy_skips(&abs)
                    && let Some(result) =
                        finish_attempt(try_trash(&abs, &meta, pid, now), saved_errno)
                {
                    return Some(result);
                }
            }
            None
        }));

        match res {
            Ok(Some(ret)) => ret,
            _ => (real_unlink())(pathname),
        }
    }
}

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlinkat(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe {
        // Capture the caller's errno first (see unlink()).
        let saved_errno = *libc::__errno_location();

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = match ReentrancyGuard::enter() {
                Some(g) => g,
                None => return None,
            };

            if flags & !libc::AT_REMOVEDIR != 0 || is_bypass_active() || known_bypassed() {
                return None;
            }
            if let Some(ret) =
                defer_to_supervisor(DeletionCall::UnlinkAt(dirfd, flags), pathname, saved_errno)
            {
                return Some(ret);
            }
            let is_removedir = (flags & libc::AT_REMOVEDIR) != 0;

            let resolved = resolve_at_path(dirfd, pathname);
            if let Some((abs, _)) = &resolved
                && let Some(refused) = keep_trashed_root(abs)
            {
                return Some(refused);
            }
            if let Some((abs, identity)) = resolved
                && !globally_excluded(&abs)
            {
                // Use symlink_metadata to not follow symlinks
                if let Ok(meta) = fs::symlink_metadata(&abs)
                    && identity.is_none_or(|named| named == (meta.dev(), meta.ino()))
                    && !is_inside_trash(&abs)
                    && let Some((pid, now)) = intercepted()
                    && !policy_skips(&abs)
                {
                    let is_real_dir = meta.is_dir() && !meta.file_type().is_symlink();
                    if is_removedir {
                        // NOTE: emptiness here then rename in try_trash is a small
                        // TOCTOU — a sibling could repopulate the dir in between.
                        // The result is still recoverable from the trash (residual
                        // L8), so we accept it rather than add fragile locking.
                        // (#410) settles the unreadable case at the destination,
                        // where a non-empty entry is moved back.
                        if is_real_dir
                            && let Some(result) = rmdir_attempt(&abs, &meta, pid, now)
                            && let Some(result) = finish_attempt(result, saved_errno)
                        {
                            return Some(result);
                        }
                    } else if !is_real_dir
                        && let Some(result) =
                            finish_attempt(try_trash(&abs, &meta, pid, now), saved_errno)
                    {
                        return Some(result);
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
}

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(pathname: *const libc::c_char) -> libc::c_int {
    unsafe {
        // Capture the caller's errno first (see unlink()).
        let saved_errno = *libc::__errno_location();

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = match ReentrancyGuard::enter() {
                Some(g) => g,
                None => return None,
            };

            if is_bypass_active() || known_bypassed() {
                return None;
            }
            if let Some(ret) = defer_to_supervisor(DeletionCall::Rmdir, pathname, saved_errno) {
                return Some(ret);
            }

            let resolved = resolve_at_path(libc::AT_FDCWD, pathname);
            if let Some((abs, _)) = &resolved
                && let Some(refused) = keep_trashed_root(abs)
            {
                return Some(refused);
            }
            if let Some((abs, _)) = resolved
                && !globally_excluded(&abs)
            {
                // Use symlink_metadata — rmdir only applies to real directories, not symlinks
                if let Ok(meta) = fs::symlink_metadata(&abs)
                    && meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && !is_inside_trash(&abs)
                    && let Some((pid, now)) = intercepted()
                    && !policy_skips(&abs)
                    && let Some(result) = rmdir_attempt(&abs, &meta, pid, now)
                    && let Some(result) = finish_attempt(result, saved_errno)
                {
                    return Some(result);
                }
            }
            None
        }));

        match res {
            Ok(Some(ret)) => ret,
            _ => (real_rmdir())(pathname),
        }
    }
}

/// # Safety
/// Called by the dynamic linker as a libc hook. `pathname` must be a valid C string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn remove(pathname: *const libc::c_char) -> libc::c_int {
    unsafe {
        // Capture the caller's errno first (see unlink()).
        let saved_errno = *libc::__errno_location();

        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = match ReentrancyGuard::enter() {
                Some(g) => g,
                None => return None,
            };

            if is_bypass_active() || known_bypassed() {
                return None;
            }
            if let Some(ret) = defer_remove_to_supervisor(pathname, saved_errno) {
                return Some(ret);
            }

            let resolved = resolve_at_path(libc::AT_FDCWD, pathname);
            if let Some((abs, _)) = &resolved
                && let Some(refused) = keep_trashed_root(abs)
            {
                return Some(refused);
            }
            if let Some((abs, _)) = resolved
                && !globally_excluded(&abs)
            {
                // remove() == unlink() for non-directories and rmdir() for
                // (empty) directories; symlink_metadata never follows links.
                if let Ok(meta) = fs::symlink_metadata(&abs)
                    && !is_inside_trash(&abs)
                    && let Some((pid, now)) = intercepted()
                    && !policy_skips(&abs)
                {
                    let is_real_dir = meta.is_dir() && !meta.file_type().is_symlink();
                    // remove() == unlink() for non-directories and rmdir() for
                    // (empty) directories; an unreadable directory follows the
                    // rmdir decision, not a permanent delete (#410).
                    let attempt = if is_real_dir {
                        rmdir_attempt(&abs, &meta, pid, now)
                    } else {
                        Some(try_trash(&abs, &meta, pid, now))
                    };
                    if let Some(result) = attempt
                        && let Some(result) = finish_attempt(result, saved_errno)
                    {
                        return Some(result);
                    }
                }
            }
            None
        }));

        match res {
            Ok(Some(ret)) => ret,
            _ => (real_remove())(pathname),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // security-3: the preload's store repair never chmods through a symlink
    // swapped in after its check, as a FUSE server answers the next lookup.
    #[test]
    fn private_dir_repair_never_follows_a_swapped_symlink() {
        let fixture = tempfile::tempdir().unwrap();
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
        fs::remove_file(&dir).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir, uid, false).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o7777, 0o700);
    }

    #[test]
    fn occupied_legacy_id_range_still_claims_recoverable_entries() {
        let fixture = tempfile::tempdir().unwrap();
        let info = fixture.path().join("info");
        let files = fixture.path().join("files");
        fs::create_dir(&info).unwrap();
        fs::create_dir(&files).unwrap();
        let date = libc::tm {
            tm_year: 126,
            tm_mon: 0,
            tm_mday: 2,
            tm_hour: 3,
            tm_min: 4,
            tm_sec: 5,
            ..unsafe { std::mem::zeroed() }
        };
        // Every ID the previous implementation knew is already occupied.
        // Each remains intact; a free extended ID still permits trashing.
        fs::write(info.join("same.trashinfo"), b"existing").unwrap();
        for index in 0..1000 {
            let id = if index == 0 {
                "same.20260102030405".to_string()
            } else {
                format!("same.20260102030405.{index}")
            };
            fs::write(info.join(format!("{id}.trashinfo")), b"existing").unwrap();
        }
        let (id, path, claim) = unique_id_atomic(&info, &files, "same", &date)
            .expect("occupied old IDs must not turn unlink into a permanent delete");
        assert!(id.starts_with("same.20260102030405."));
        assert!(path.exists());
        assert_eq!(claim.metadata().unwrap().len(), 0);
        assert_eq!(fs::read_dir(&info).unwrap().count(), 1002);
        for entry in fs::read_dir(&info).unwrap() {
            let entry = entry.unwrap();
            if entry.path() != path {
                assert_eq!(fs::read(entry.path()).unwrap(), b"existing");
            }
        }
    }

    #[test]
    fn collision_claims_preserve_orphans_and_long_unicode_names() {
        let fixture = tempfile::tempdir().unwrap();
        let info = fixture.path().join("info");
        let files = fixture.path().join("files");
        fs::create_dir(&info).unwrap();
        fs::create_dir(&files).unwrap();
        let date = libc::tm {
            tm_year: 126,
            tm_mon: 0,
            tm_mday: 2,
            ..unsafe { std::mem::zeroed() }
        };
        let name = "é".repeat(120);
        let truncated = &name[..name.floor_char_boundary(223)];
        fs::write(files.join(truncated), b"orphan").unwrap();
        let (first, _, _) = unique_id_atomic(&info, &files, &name, &date).unwrap();
        let (second, _, _) = unique_id_atomic(&info, &files, &name, &date).unwrap();
        assert_ne!(first, second);
        assert!(first.len() + 10 <= 255);
        assert!(second.len() + 10 <= 255);
        assert_eq!(fs::read(files.join(truncated)).unwrap(), b"orphan");
        assert!(!info.join(format!("{truncated}.trashinfo")).exists());
    }

    // cross-layer-5: once a process trashed into a root, its hooks refuse
    // to delete anything in that root for real, so `rm -rf ~/.local/share`
    // cannot destroy the entries it just moved there.
    #[test]
    fn a_trash_this_process_filled_is_kept_whole() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("Trash");
        fs::create_dir_all(root.join("files")).unwrap();
        fs::create_dir_all(root.join("info")).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        let inside = [
            canonical.clone(),
            canonical.join("files"),
            canonical.join("files/dir/y"),
            canonical.join("info/x.trashinfo"),
        ];
        assert!(inside.iter().all(|path| !in_trashed_root(path)));
        remember_trashed_root(&root);
        assert!(inside.iter().all(|path| in_trashed_root(path)));
        let beside = canonical.parent().unwrap().join("Trash-notes/x");
        assert!(!in_trashed_root(&beside));
        assert_eq!(keep_trashed_root(&canonical.join("files/x")), Some(-1));
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBUSY));
        assert_eq!(keep_trashed_root(&beside), None);
    }

    // cross-layer-6: a sidecar name the filesystem refuses as too long made
    // the delete permanent; a shorter id is claimed instead. The budget is
    // above what the filesystem takes, as a filesystem may report one.
    #[test]
    fn ids_shrink_to_what_the_filesystem_takes() {
        let fixture = tempfile::tempdir().unwrap();
        let info = fixture.path().join("info");
        let files = fixture.path().join("files");
        fs::create_dir(&info).unwrap();
        fs::create_dir(&files).unwrap();
        let date = libc::tm {
            tm_year: 126,
            tm_mon: 0,
            tm_mday: 2,
            ..unsafe { std::mem::zeroed() }
        };
        let name = "n".repeat(254);
        let (first, path, _) = unique_id_atomic_within(&info, &files, &name, &date, 400)
            .expect("a long name is never a reason for a permanent delete");
        let (second, _, _) = unique_id_atomic_within(&info, &files, &name, &date, 400).unwrap();
        assert_ne!(first, second);
        assert!(path.exists());
        for id in [first, second] {
            assert!(id.len() + ".trashinfo".len() <= 255, "{}", id.len());
        }
    }

    // #405: the copy reads exactly the selected version. Data appended past
    // the captured EOF is never read, and a source that grew or shrank while
    // being copied is refused with EBUSY like any other rewrite.
    #[test]
    fn copied_source_growth_is_bounded_and_shrink_is_detected_during_copy() {
        use std::io::Write as _;
        for grow in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            fs::write(&source, b"original bytes").unwrap();
            let mut input = fs::File::open(&source).unwrap();
            let selected = input.metadata().unwrap();
            let destination = fixture.path().join("copy");
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .unwrap();
            if grow {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&source)
                    .unwrap()
                    .write_all(&[b'x'; 16 * 1024])
                    .unwrap();
            } else {
                fs::File::options()
                    .write(true)
                    .open(&source)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
            }
            let error = copy_checked_contents(&mut input, &mut output, &selected).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EBUSY));
            let copied = output.metadata().unwrap().len();
            if grow {
                assert_eq!(copied, selected.len(), "the append is not ours to copy");
            } else {
                assert_eq!(copied, selected.len(), "the hole is sized, not written");
            }
            assert_eq!(
                fs::metadata(&source).unwrap().len(),
                if grow { selected.len() + 16 * 1024 } else { 0 }
            );
        }
    }

    // #405: a cross-device trash copy must mirror trashd-common's
    // copy_regular_at — holes stay holes, timestamps and extended attributes
    // survive, and the block count proves neither expanded.
    #[test]
    fn cross_device_copy_preserves_sparse_holes_times_and_xattrs() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("sparse");
        // Two 8-byte data extents around holes: [0,8), [1 MiB, 1 MiB+8), len
        // 2 MiB. The gap spans whole pages so sparseness survives the copy on
        // any page-granular filesystem.
        const GAP: u64 = 1024 * 1024;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)
            .unwrap();
        use std::io::{Seek, SeekFrom, Write as _};
        file.write_all(b"extent0").unwrap();
        file.seek(SeekFrom::Start(GAP)).unwrap();
        file.write_all(b"extent1").unwrap();
        file.set_len(2 * GAP).unwrap();
        let (seconds, nanos) = (1_000_000_000i64, 123_456_789i64);
        let stamp = std::time::UNIX_EPOCH + std::time::Duration::new(seconds as u64, nanos as u32);
        file.set_times(fs::FileTimes::new().set_accessed(stamp).set_modified(stamp))
            .unwrap();
        drop(file);

        // user.* may be unsupported on the fixture's filesystem (a tmpfs
        // without user xattrs): probe it before asserting anything about it.
        let cname = c"user.trashd.test";
        let set_xattr = |path: &Path, value: &[u8]| {
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            unsafe {
                libc::setxattr(
                    name.as_ptr(),
                    cname.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            }
        };
        let xattr_set = set_xattr(&source, b"kept") == 0;

        let original = fs::symlink_metadata(&source).unwrap();
        let root = fixture.path().join("Trash");
        lock_store(&root, unsafe { libc::geteuid() }).unwrap();
        let dest = root.join("files/sparse");
        let mut created = None;
        let copied =
            copy_regular_verified(&source, &dest, original.dev(), original.ino(), &mut created)
                .unwrap();
        assert_eq!(copied.len(), 2 * GAP);
        // Stat BEFORE reading: a read updates the copy's own atime.
        let copy_meta = fs::symlink_metadata(&dest).unwrap();
        use std::io::Read as _;
        let mut copy = fs::File::open(&dest).unwrap();
        let mut hole = vec![0u8; 2 * GAP as usize];
        copy.read_exact(&mut hole).unwrap();
        assert_eq!(&hole[0..7], b"extent0");
        assert_eq!(&hole[GAP as usize..GAP as usize + 7], b"extent1");
        assert!(hole[8..GAP as usize].iter().all(|b| *b == 0));
        // The same block-count probe the issue used: holes must not be written.
        // A plain io::copy lands 4096 blocks for 2 MiB; the two page-backed
        // extents need a small multiple of 8 blocks.
        assert!(
            copy_meta.blocks() < (2 * GAP) / 512 / 8,
            "sparse copy expanded to {} blocks",
            copy_meta.blocks()
        );
        assert_eq!(copy_meta.mtime(), seconds);
        assert_eq!(copy_meta.mtime_nsec(), nanos);
        assert_eq!(copy_meta.atime(), seconds, "access time preserved too");
        let name = CString::new(dest.as_os_str().as_bytes()).unwrap();
        let mut value = [0u8; 16];
        let got = unsafe {
            libc::getxattr(
                name.as_ptr(),
                cname.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if xattr_set {
            // Whatever the probe wrote must have travelled to the copy.
            let source_name = CString::new(source.as_os_str().as_bytes()).unwrap();
            let mut expected = [0u8; 16];
            let want = unsafe {
                libc::getxattr(
                    source_name.as_ptr(),
                    cname.as_ptr(),
                    expected.as_mut_ptr().cast(),
                    expected.len(),
                )
            };
            assert_eq!(got, want, "xattr length");
            assert_eq!(&value[..got as usize], &expected[..want as usize]);
        } else {
            eprintln!(
                "SKIP: user.* xattrs unsupported on {}",
                fixture.path().display()
            );
        }

        // A file without xattrs still copies, and mode travels with it.
        let plain = fixture.path().join("plain");
        fs::write(&plain, b"no xattrs").unwrap();
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o640)).unwrap();
        let meta = fs::symlink_metadata(&plain).unwrap();
        let dest = root.join("files/plain");
        let mut created = None;
        let copied =
            copy_regular_verified(&plain, &dest, meta.dev(), meta.ino(), &mut created).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"no xattrs");
        let copy_meta = fs::symlink_metadata(&dest).unwrap();
        assert_eq!(copy_meta.permissions().mode() & 0o7777, 0o640);
        assert_eq!(
            copied.dev(),
            meta.dev(),
            "the return is the source's identity"
        );
    }

    // #382: exercise the production retirement helper after deterministic
    // copy/replace and copy/rewrite races, without touching a real trash.
    #[test]
    fn copied_source_changes_refuse_retirement_and_remove_the_duplicate() {
        for replace in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            fs::write(&source, b"older").unwrap();
            let root = fixture.path().join("Trash");
            let guard = lock_store(&root, unsafe { libc::geteuid() }).unwrap();
            let dest = root.join("files/copy");
            let info = root.join("info/copy.trashinfo");
            fs::write(&info, b"claimed").unwrap();
            let original = fs::symlink_metadata(&source).unwrap();
            let mut created = None;
            let copied =
                copy_regular_verified(&source, &dest, original.dev(), original.ino(), &mut created)
                    .unwrap();
            assert_eq!(fs::read(&dest).unwrap(), b"older");
            if replace {
                fs::rename(&source, fixture.path().join("old-source")).unwrap();
            }
            fs::write(&source, b"NEWER").unwrap();
            if !replace {
                // Keep the same second and size: nanoseconds must count too.
                let modified = std::time::UNIX_EPOCH
                    + std::time::Duration::new(
                        copied.mtime() as u64,
                        (copied.mtime_nsec() as u32 + 1) % 1_000_000_000,
                    );
                fs::File::options()
                    .write(true)
                    .open(&source)
                    .unwrap()
                    .set_times(fs::FileTimes::new().set_modified(modified))
                    .unwrap();
                let current = fs::symlink_metadata(&source).unwrap();
                assert_eq!(current.ino(), copied.ino());
                assert_eq!(current.len(), copied.len());
                assert_eq!(current.mtime(), copied.mtime());
                assert_ne!(current.mtime_nsec(), copied.mtime_nsec());
            }
            let result =
                retire_copied_source(&source, &dest, &info, (&copied, created), guard, || {
                    panic!("a changed source must never reach unlink")
                });
            assert_eq!(result, TrashAttempt::Error(libc::EBUSY));
            assert_eq!(fs::read(&source).unwrap(), b"NEWER");
            assert!(!dest.exists());
            assert!(!info.exists());
        }
    }

    #[test]
    fn copied_source_requires_original_identity_and_cleans_only_its_own_copy() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().join("source");
        fs::write(&source, b"older").unwrap();
        let original = fs::symlink_metadata(&source).unwrap();
        fs::rename(&source, fixture.path().join("old-source")).unwrap();
        fs::write(&source, b"NEWER").unwrap();
        let root = fixture.path().join("Trash");
        let guard = lock_store(&root, unsafe { libc::geteuid() }).unwrap();
        let dest = root.join("files/copy");
        let info = root.join("info/copy.trashinfo");
        let mut created = None;
        let error =
            copy_regular_verified(&source, &dest, original.dev(), original.ino(), &mut created)
                .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBUSY));
        assert_eq!(created, None);
        assert!(!dest.exists());

        let current = fs::symlink_metadata(&source).unwrap();
        let copied =
            copy_regular_verified(&source, &dest, current.dev(), current.ino(), &mut created)
                .unwrap();
        fs::write(&info, b"claimed").unwrap();
        fs::rename(&dest, fixture.path().join("our-copy")).unwrap();
        fs::write(&dest, b"someone else's entry").unwrap();
        fs::write(&source, b"latest").unwrap();
        assert_eq!(
            retire_copied_source(&source, &dest, &info, (&copied, created), guard, || {
                panic!("a changed source must never reach unlink")
            }),
            TrashAttempt::Error(libc::EBUSY)
        );
        assert_eq!(fs::read(&source).unwrap(), b"latest");
        assert_eq!(fs::read(&dest).unwrap(), b"someone else's entry");
        assert!(!info.exists());
    }

    #[test]
    fn copied_source_retirement_holds_store_lock_and_preserves_unlink_errno() {
        use std::os::fd::AsRawFd;
        for errno in [None, Some(libc::EACCES)] {
            let fixture = tempfile::tempdir().unwrap();
            let source = fixture.path().join("source");
            fs::write(&source, b"recoverable").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
            let root = fixture.path().join("Trash");
            let guard = lock_store(&root, unsafe { libc::geteuid() }).unwrap();
            let contender = fs::File::open(root.join(".trashd/store.lock")).unwrap();
            let dest = root.join("files/copy");
            let info = root.join("info/copy.trashinfo");
            fs::write(&info, b"claimed").unwrap();
            let original = fs::symlink_metadata(&source).unwrap();
            let mut created = None;
            let copied =
                copy_regular_verified(&source, &dest, original.dev(), original.ino(), &mut created)
                    .unwrap();
            assert_eq!(fs::metadata(&dest).unwrap().mode() & 0o777, 0o640);
            let result =
                retire_copied_source(&source, &dest, &info, (&copied, created), guard, || {
                    assert_eq!(
                        unsafe {
                            libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
                        },
                        -1
                    );
                    assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                    if let Some(errno) = errno {
                        return Err(io::Error::from_raw_os_error(errno));
                    }
                    let path = CString::new(source.as_os_str().as_bytes()).unwrap();
                    if unsafe { (real_unlink())(path.as_ptr()) } == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error())
                    }
                });
            assert_eq!(
                unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0,
                "retirement must release the guard on every return"
            );
            if let Some(errno) = errno {
                assert_eq!(result, TrashAttempt::Error(errno));
                assert_eq!(fs::read(&source).unwrap(), b"recoverable");
                assert!(!dest.exists());
                assert!(!info.exists());
            } else {
                assert_eq!(result, TrashAttempt::Trashed);
                assert!(!source.exists());
                assert_eq!(fs::read(&dest).unwrap(), b"recoverable");
                assert!(info.exists());
            }
        }
    }

    // Regression (#249): the bypass verdict was cached by PID alone for the
    // process's whole lifetime. A new parent (reparenting after the bypass
    // ancestor died) must miss the cache and force a re-walk.
    #[test]
    fn bypass_cache_misses_after_reparenting() {
        let key = bypass_cache_key(4242, 100, true);
        assert_eq!(bypass_cache_hit(key, 4242, 100), Some(true));
        assert_eq!(bypass_cache_hit(key, 4242, 1), None);
        assert_eq!(bypass_cache_hit(key, 4243, 100), None);
        assert_eq!(
            bypass_cache_hit(bypass_cache_key(7, 1, false), 7, 1),
            Some(false)
        );
    }

    // #349: the kernel ignores unlinkat's fourth argument, so a deferral the
    // supervisor leaves to the kernel deletes exactly like an unmarked call.
    #[test]
    fn marked_unlinkat_behaves_like_unlinkat() {
        let dir = std::env::temp_dir().join(format!("trashd-mark-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file"), b"x").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        for (name, flags) in [("file", 0), ("sub", libc::AT_REMOVEDIR)] {
            let path = CString::new(dir.join(name).as_os_str().as_bytes()).unwrap();
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_unlinkat,
                    libc::AT_FDCWD as libc::c_long,
                    path.as_ptr(),
                    flags as libc::c_long,
                    seccomp_identity::DEFER_MARK as libc::c_long,
                )
            };
            assert_eq!(ret, 0, "{name}: {}", io::Error::last_os_error());
            assert!(fs::symlink_metadata(dir.join(name)).is_err());
        }
        let path = CString::new(dir.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path.as_ptr(), 1024, 0) },
            -1
        );
        // Raw: this test binary exports the hooks themselves.
        let removed = unsafe {
            libc::syscall(
                libc::SYS_unlinkat,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
        assert_eq!(removed, 0);
    }

    #[test]
    fn policy_globs_match_complete_patterns() {
        let home = home_dir().expect("test user has a home directory");
        assert!(pattern_matches(
            "~/docs/*",
            &home.join("docs/report.txt").to_string_lossy()
        ));
        let cases = [
            ("*.py*", "/home/user/main.py", true),
            ("*.py*", "/home/user/main.py.txt", true),
            ("*.py*", "/home/user/main.rs", false),
            ("*.[ch]", "/home/user/main.c", true),
            ("*.[ch]", "/home/user/main.rs", false),
            ("/home/*/docs/*", "/home/alice/docs/report.pdf", true),
            ("/home/*/docs/*", "/home/alice/pics/report.pdf", false),
            (
                "*/project?/docs/*",
                "/home/alice/project1/docs/report",
                true,
            ),
            ("src/**/*.rs", "/home/user/project/src/nested/main.rs", true),
            ("src/file?.[ch]", "/home/user/project/src/file1.c", true),
            ("src/file?.[ch]", "/home/user/project/notsrc/file1.c", false),
            (
                "node_modules/*",
                "/home/user/project/node_modules/pkg/index.js",
                true,
            ),
            (
                "target/debug/*",
                "/home/user/project/target/debug/deps/bin",
                true,
            ),
            ("*/.git/*", "/home/user/project/.git/HEAD", true),
            ("*/name", "/home/user/name/file", true),
            ("*/name", "/home/user/name-x/file", false),
            ("*~", "/home/user/backup~", true),
            ("[a-z]?*.txt", "/home/user/report.txt", true),
            // #337: fnmatch(3) rules, identical to trashd-common.
            ("*[draft*", "/home/user/x[draft1", true),
            ("a[1", "/home/user/a[1", true),
            ("draft\\*", "/home/user/draft*", true),
            ("draft\\*", "/home/user/draft1", false),
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(
                pattern_matches(pattern, path),
                expected,
                "{pattern}: {path}"
            );
        }
    }

    // cross-layer-2 (#402): the preload kept an empty only_trash pattern,
    // which matches nothing, so every delete it handled became permanent
    // while the other layers trashed. common-policy-5: `dir/` and `./dir/*`
    // matched nothing either. Both layers now share one rule set.
    #[test]
    fn patterns_follow_the_rules_shared_with_trashd_common() {
        let mut cfg = PreloadConfig::default();
        cfg.merge(toml::from_str::<PartialPreloadConfig>("only_trash = [\"\"]").unwrap());
        assert!(cfg.only_trash.is_empty(), "{:?}", cfg.only_trash);
        let local: LocalConfig = toml::from_str("only_trash = [\"\"]\n").unwrap();
        assert!(sanitize_patterns(local.only_trash, "only_trash").is_empty());
        cfg.merge(
            toml::from_str::<PartialPreloadConfig>("only_trash = [\"src/\", \"./build/*\"]")
                .unwrap(),
        );
        for path in ["/h/p/src/x", "/h/p/build/y"] {
            assert!(
                cfg.only_trash.iter().any(|p| pattern_matches(p, path)),
                "{path}: {:?}",
                cfg.only_trash
            );
        }
    }

    // common-policy-6: policy paths are canonical, so a HOME reached
    // through a symlink never matched its `~/` patterns.
    #[test]
    fn home_patterns_match_through_a_symlinked_home() {
        const CHILD: &str = "TRASHD_PRELOAD_SYMLINKED_HOME";
        const TEST: &str = "tests::home_patterns_match_through_a_symlinked_home";
        if mounts::is_rerun_child(TEST, CHILD) {
            let base = tempfile::tempdir().unwrap();
            let real = base.path().join("real");
            fs::create_dir_all(real.join("docs")).unwrap();
            let link = base.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            // Safety: the re-run child runs this one test on its own.
            unsafe { std::env::set_var("HOME", &link) };
            let canonical = fs::canonicalize(&real).unwrap();
            let verdict = pattern_matches("~/docs/*", &canonical.join("docs/x").to_string_lossy())
                && pattern_matches("~/docs/*", &link.join("docs/x").to_string_lossy());
            mounts::report_test_verdict(Some(verdict));
            return;
        }
        assert_eq!(mounts::rerun_test(TEST, CHILD), Some(true));
    }

    // cross-layer-3: like trashd-common, a topdir store only on the file's
    // own filesystem: a nested subvolume's file went to a store on its mount
    // root, which listing skips when that root shares the home device.
    #[test]
    fn topdir_store_needs_the_files_own_device() {
        let base = tempfile::tempdir().unwrap();
        let verdict =
            mounts::in_private_mounts("tests::topdir_store_needs_the_files_own_device", || {
                let mount = base.path().join("m");
                let target = CString::new(mount.as_os_str().as_bytes()).unwrap();
                if fs::create_dir(&mount).is_err()
                    || unsafe {
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
                // Safety: the re-run child runs this one test on its own.
                unsafe { std::env::set_var("XDG_DATA_HOME", base.path().join("data")) };
                let file = mount.join("file");
                let uid = unsafe { libc::geteuid() };
                // Each selection holds its store's lock: drop it before the
                // next one.
                let home =
                    |dev| matches!(trash_dir_for(&file, dev, uid, 0), Ok(store) if store.home);
                let checked = fs::write(&file, b"x").is_ok()
                    && fs::metadata(&mount)
                        .is_ok_and(|own| home(own.dev().wrapping_add(1)) && !home(own.dev()));
                unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
                checked
            });
        assert_ne!(verdict, Some(false));
    }

    // cross-layer-7: one mistyped key drops only itself, in both loaders, so
    // they apply the same layer.
    #[test]
    fn a_mistyped_key_drops_only_itself() {
        let path = Path::new("/nonexistent/config.toml");
        let partial = parse_partial_config(
            path,
            "only_trash = [\"*.rs\"]\nmax_file_size_mb = \"big\"\nmax_dir_size_mb = 4\n",
        )
        .expect("the valid keys still load");
        assert_eq!(
            partial.only_trash.as_deref(),
            Some(&["*.rs".to_string()][..])
        );
        assert_eq!(partial.max_file_size_mb, None);
        assert_eq!(partial.max_dir_size_mb, Some(4));
        assert!(parse_partial_config(path, "only_trash = [\"*.rs\"\n").is_none());
    }

    #[test]
    fn shipped_template_loads_preload_policy() {
        let edited = include_str!("../../../config/trashd.toml")
            .replace("max_file_size_mb = 1024", "max_file_size_mb = 5")
            .replace("only_trash = []", "only_trash = [\"*.py\"]")
            .replace("bypass_paths = []", "bypass_paths = [\"/opt/test/\"]");
        let mut cfg = PreloadConfig::default();
        cfg.merge(toml::from_str(&edited).unwrap());
        assert_eq!(cfg.max_file_size_mb, 5);
        assert_eq!(cfg.only_trash, ["*.py"]);
        assert_eq!(cfg.bypass_paths, ["/opt/test/"]);
        assert!(
            !cfg.bypass_processes
                .iter()
                .any(|p| p == "systemd" || p == "systemctl")
        );
    }

    #[test]
    fn loader_preserves_policy_from_legacy_retention_table() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "[retention]\nmax_age_days = 7\nonly_trash = [\"*.txt\"]\nmax_file_size_mb = 9\nauto_purge_interval_secs = 123\n").unwrap();
        let mut config = PreloadConfig::default();
        config.merge(load_partial_config(&path).expect("legacy config must load"));
        assert_eq!(config.only_trash, ["*.txt"]);
        assert_eq!(config.max_file_size_mb, 9);
    }

    // store-metadata-5: `retention.auto_compress` is a valid key. Rejecting
    // it as unknown dropped the whole file, and with it the user's policy.
    #[test]
    fn loader_accepts_every_retention_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "max_file_size_mb = 9\n[retention]\nmax_age_days = 7\nmax_size_gb = 1.5\n\
             disk_pressure_percent = 80\nauto_compress = true\n",
        )
        .unwrap();
        let partial = load_partial_config(&path).expect("retention keys must load");
        assert_eq!(partial.max_file_size_mb, Some(9));
    }

    #[test]
    fn loader_accepts_symlinked_config_and_ignores_fifo() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("dotfiles.toml");
        std::fs::write(&target, "max_file_size_mb = 17\n").unwrap();
        let path = directory.path().join("config.toml");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            load_partial_config(&path).unwrap().max_file_size_mb,
            Some(17)
        );

        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(load_partial_config(&path).is_none());
    }

    #[test]
    fn misplaced_policy_in_retention_is_rejected() {
        for key in [
            "only_trash = [\"*.py\"]",
            "max_file_size_mb = 5",
            "bypass_paths = []",
        ] {
            assert!(
                toml::from_str::<PartialPreloadConfig>(&format!("[retention]\n{key}\n")).is_err()
            );
        }
    }

    #[test]
    fn process_bypass_includes_self_and_executable_path() {
        let pid = std::process::id();
        let mut cfg = PreloadConfig::default();
        cfg.bypass_processes.clear();
        assert!(!process_is_bypassed(&cfg, pid));
        let exe = fs::read_link("/proc/self/exe").unwrap();
        cfg.bypass_processes
            .push(exe.file_name().unwrap().to_string_lossy().into_owned());
        assert!(process_is_bypassed(&cfg, pid));
        cfg.bypass_processes.clear();
        cfg.bypass_paths.push(
            fs::read_link("/proc/self/exe")
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        assert!(process_is_bypassed(&cfg, pid));
    }

    #[test]
    fn passwd_home_matches_the_exact_uid_and_needs_an_absolute_home() {
        let passwd = b"root:x:0:0:root:/root:/bin/sh\n\
            short:x:1000\n\
            rel:x:1001:1001::home/rel:/bin/sh\n\
            alice:x:10000:10000::/home/alice:/bin/sh\n\
            bob:x:1000:1000::/home/\xffbob:/bin/sh";
        assert_eq!(passwd_home_in(passwd, 0), Some(PathBuf::from("/root")));
        assert_eq!(
            passwd_home_in(passwd, 1000),
            Some(PathBuf::from(OsStr::from_bytes(b"/home/\xffbob")))
        );
        assert_eq!(passwd_home_in(passwd, 1001), None);
        assert_eq!(passwd_home_in(passwd, 100), None);
        // The cache answers repeated lookups for one UID consistently.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(cached_passwd_home(uid), passwd_home(uid));
        assert_eq!(cached_passwd_home(uid), passwd_home(uid));
        // #346: NSS answers for users /etc/passwd does not list, as it does
        // for the store; an unknown UID has no home.
        assert_eq!(nss_home(0), Some(PathBuf::from("/root")));
        assert_eq!(nss_home(u32::MAX - 7), None);
        assert_eq!(nss_home_cached(0), Some(PathBuf::from("/root")));
        assert_eq!(nss_home_cached(0), Some(PathBuf::from("/root")));
        assert_eq!(nss_home_cached(u32::MAX - 7), None);
    }

    #[test]
    fn resolve_at_path_keeps_canonical_prefixes_and_names_the_inode() {
        use std::os::fd::AsRawFd;
        let resolve = |dirfd: libc::c_int, name: &[u8]| {
            let name = CString::new(name).unwrap();
            resolve_at_path(dirfd, name.as_ptr())
        };
        let base = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(base.path()).unwrap();
        fs::create_dir(root.join("real")).unwrap();
        fs::write(root.join("real/f"), b"x").unwrap();
        std::os::unix::fs::symlink("real", root.join("link")).unwrap();
        let identity = |path: &Path| {
            let meta = fs::symlink_metadata(path).unwrap();
            Some((meta.dev(), meta.ino()))
        };

        // Bare names join the canonical cwd; nothing needs to exist.
        assert_eq!(
            resolve(libc::AT_FDCWD, b"no-such-name"),
            Some((std::env::current_dir().unwrap().join("no-such-name"), None))
        );
        // Absolute parents resolve symlinked components.
        let absolute = root.join("link/f");
        assert_eq!(
            resolve(libc::AT_FDCWD, absolute.as_os_str().as_bytes()),
            Some((root.join("real/f"), None))
        );

        let dir = fs::File::open(&root).unwrap();
        let fd = dir.as_raw_fd();
        assert_eq!(
            resolve(fd, b"real/f"),
            Some((root.join("real/f"), identity(&root.join("real/f"))))
        );
        assert_eq!(
            resolve(fd, b"link/f"),
            Some((root.join("real/f"), identity(&root.join("real/f"))))
        );
        // A symlink is named itself, never its target.
        assert_eq!(
            resolve(fd, b"link"),
            Some((root.join("link"), identity(&root.join("link"))))
        );
        // Trailing slashes are accepted for real directories only.
        assert_eq!(
            resolve(fd, b"real//"),
            Some((root.join("real"), identity(&root.join("real"))))
        );
        assert_eq!(resolve(fd, b"link/"), None);
        // Missing names, dot names and pathless descriptors fall through.
        for name in [&b"missing"[..], b"", b".", b"..", b"real/..", b"/"] {
            assert_eq!(resolve(fd, name), None, "{name:?}");
        }
        let file = fs::File::open(root.join("real/f")).unwrap();
        assert_eq!(resolve(file.as_raw_fd(), b"f"), None);
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(resolve(socket.as_raw_fd(), b"f"), None);
        // A removed directory's descriptor names nothing that can be trashed.
        fs::create_dir(root.join("gone")).unwrap();
        let gone = fs::File::open(root.join("gone")).unwrap();
        fs::remove_dir(root.join("gone")).unwrap();
        assert_eq!(resolve(gone.as_raw_fd(), b"f"), None);
    }

    #[test]
    fn optimistic_store_lock_creates_repairs_and_still_rejects() {
        let base = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let mode = |path: &Path| fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777;

        // Missing store: created private, then locked.
        let fresh = base.path().join("fresh");
        lock_store(&fresh, uid).expect("missing store is created");
        for dir in [&fresh, &fresh.join("files"), &fresh.join("info")] {
            assert_eq!(mode(dir), 0o700, "{}", dir.display());
        }
        // An existing store is locked without changes.
        lock_store(&fresh, uid).expect("existing store locks");

        // Group/world access is repaired, as the path checks always did.
        fs::set_permissions(fresh.join("info"), fs::Permissions::from_mode(0o755)).unwrap();
        lock_store(&fresh, uid).expect("mode is repaired");
        assert_eq!(mode(&fresh.join("info")), 0o700);

        // Symlinked roots and children are still refused, not followed.
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&fresh, &link).unwrap();
        assert!(matches!(lock_store(&link, uid), Err(StoreError::Unsafe)));
        let child = base.path().join("child");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(fresh.join("files"), child.join("files")).unwrap();
        assert!(matches!(lock_store(&child, uid), Err(StoreError::Unsafe)));
        assert!(!fresh.join("files/.trashd").exists());

        if uid == 0 {
            let foreign = base.path().join("foreign");
            fs::create_dir(&foreign).unwrap();
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o700)).unwrap();
            std::os::unix::fs::lchown(&foreign, Some(65534), Some(65534)).unwrap();
            assert!(matches!(lock_store(&foreign, uid), Err(StoreError::Unsafe)));
            assert!(!foreign.join("files").exists());
        }
    }

    #[test]
    fn dir_size_cap_merges_from_config() {
        let mut cfg = PreloadConfig::default();
        assert_eq!(cfg.max_dir_size_mb, 0, "default is disabled");
        cfg.merge(toml::from_str::<PartialPreloadConfig>("max_dir_size_mb = 5").unwrap());
        assert_eq!(cfg.max_dir_size_mb, 5);
    }

    // #245: the caps compare exact bytes. cross-layer-1: a file is limited by
    // max_file_size_mb alone, as in every other layer; the tree cap applying
    // to each file made a standalone file between the two caps a permanent
    // delete here while the shim and the supervisor trashed it.
    #[test]
    fn size_limits_compare_exact_bytes_and_bind_files_by_the_file_cap() {
        const MIB: u64 = 1024 * 1024;
        let mut cfg = PreloadConfig::default();
        assert_eq!(cfg.max_file_size_mb, 1024);
        assert_eq!(cfg.max_dir_size_mb, 0, "default is unlimited");

        // Whole-MiB truncation used to admit these (#245).
        assert!(exceeds_size_limit_mb(
            &cfg,
            true,
            cfg.max_file_size_mb * MIB + 1
        ));
        assert!(!exceeds_size_limit_mb(
            &cfg,
            true,
            cfg.max_file_size_mb * MIB
        ));
        // Zero never binds, whatever the size.
        assert!(!over_size_cap(0, u64::MAX));
        // The default dir cap is unlimited, so only the file cap can refuse.
        assert!(!exceeds_size_limit_mb(&cfg, true, 2 * MIB));
        // The tree cap never binds a file: a 2 MiB file with
        // max_dir_size_mb = 1 is trashed, as the shim and supervisor trash
        // it. An oversized tree removed through the preload is therefore
        // trashed file by file (preload-8).
        cfg.max_dir_size_mb = 1;
        assert!(!exceeds_size_limit_mb(&cfg, true, 2 * MIB));
        assert!(exceeds_size_limit_mb(
            &cfg,
            true,
            cfg.max_file_size_mb * MIB + 1
        ));
        cfg.max_file_size_mb = 0;
        assert!(!exceeds_size_limit_mb(&cfg, true, 2 * MIB));
        // Both disabled: unlimited.
        cfg.max_dir_size_mb = 0;
        assert!(!exceeds_size_limit_mb(&cfg, true, u64::MAX));
        // Directories take the bounded walk instead, never the size compare.
        assert!(!exceeds_size_limit_mb(&cfg, false, u64::MAX));
    }

    // Regression (#108): lookalike .Trash-<other-uid> directories are user
    // data, not trash — the hook must intercept them (not skip, which would
    // permanently delete).
    #[test]
    fn is_inside_trash_matches_only_own_uid_suffix() {
        let own_dir = format!("/mnt/usb/.Trash-{}", unsafe { libc::geteuid() });
        let own = Path::new(&own_dir).join("files/x");
        assert!(!is_inside_trash(&own));

        let other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let foreign_dir = format!("/home/u/proj/.Trash-{other_uid}/out.bin");
        assert!(!is_inside_trash(Path::new(&foreign_dir)));

        let lookalike = Path::new("/home/u/proj/.Trash-backup/x");
        assert!(!is_inside_trash(lookalike));
    }

    // The gating logic as a pure function so the test needs no environment
    // mutation (libtest runs tests in parallel; mutating environ under the
    // harness races other tests' env reads — round-4 review).
    #[test]
    fn seccomp_deferral_gates_claim_on_filter_presence() {
        assert!(
            !seccomp_deferred(false, true),
            "no claim, nothing to defer to"
        );
        assert!(!seccomp_deferred(false, false));
        // The whole point of #125: a claim without a real filter must NOT defer.
        assert!(!seccomp_deferred(true, false));
        // Claim + real filter: defer to the seccomp layer.
        assert!(seccomp_deferred(true, true));
    }

    #[test]
    fn encode_path_preserves_non_utf8_bytes() {
        let path = Path::new(OsStr::from_bytes(b"/home/user/name-\xff \n%?#"));
        assert_eq!(encode_path(path), "/home/user/name-%FF%20%0A%25%3F%23");
    }

    #[test]
    fn private_trash_directory_rejects_symlink_and_repairs_mode() {
        let base = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let private = base.path().join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&private, uid, true).unwrap();
        assert_eq!(
            fs::symlink_metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let link = base.path().join("link");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        // The trash directory itself is never a symlink.
        assert!(ensure_private_dir(&link, uid, true).is_err());
        // Classification accepts trusted existing ancestry but must never
        // prepare missing directories while deciding whether to bypass.
        assert!(ensure_trusted_ancestors_with(&link, uid, false).is_ok());
        assert!(ensure_trusted_ancestors_with(&link.join("new"), uid, false).is_err());
        assert!(!private.join("new").exists());
        // Ancestors may be links the user or root owns (#222); a link owned
        // by anyone else is refused and nothing is created through it.
        if uid == 0 {
            std::os::unix::fs::lchown(&link, Some(65534), Some(65534)).unwrap();
            assert!(ensure_trusted_ancestors_with(&link, uid, false).is_err());
            assert!(ensure_trusted_ancestors(&link.join("new"), uid).is_err());
            assert!(!private.join("new").exists());
        }
    }

    // #410: rmdir of an unreadable directory must never decline into a
    // permanent deletion. The scenarios need a dedicated child: a redirected
    // trash root and policy (no ambient /tmp exclusion, no bypassed ancestor —
    // this harness runs under cargo, which every default bypass list names),
    // and an owner that cannot read the directory, which root never can.
    #[test]
    fn rmdir_of_unreadable_directory_is_never_a_permanent_deletion() {
        const MARKER: &str = "TRASHD_PRELOAD_RMDIR_CHILD";
        const TEST: &str = "tests::rmdir_of_unreadable_directory_is_never_a_permanent_deletion";
        match std::env::var_os(MARKER).as_deref().and_then(OsStr::to_str) {
            None => {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .stderr(std::process::Stdio::inherit())
                    .env(MARKER, "fork")
                    .status()
                    .expect("spawn hook child");
                assert!(status.success(), "hook child failed: {status}");
            }
            Some("fork") => run_reparented_scenarios(MARKER),
            _ => run_unreadable_rmdir_scenarios(),
        }
    }

    /// The fork helper of the #410 test: raw-fork the scenario process and
    /// exit so it reparents away from this harness's bypassed ancestry. The
    /// pipe carries the scenario's verdict back to the helper.
    fn run_reparented_scenarios(marker: &str) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let forked = unsafe { libc::fork() };
        assert!(forked >= 0);
        if forked == 0 {
            unsafe { libc::close(fds[0]) };
            let middle = unsafe { libc::fork() };
            if middle == 0 {
                // The scenario process. Its verdict travels the pipe; panics
                // are reported raw (the harness's stderr may hold no lock a
                // forked child could deadlock on).
                unsafe { libc::alarm(120) };
                std::panic::set_hook(Box::new(|info| {
                    let message = info.to_string();
                    unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
                }));
                let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    // Safety: the scenario process is single-threaded.
                    unsafe { std::env::remove_var(marker) };
                    run_unreadable_rmdir_scenarios();
                }))
                .is_ok();
                let byte = [u8::from(ok)];
                let _ = unsafe { libc::write(fds[1], byte.as_ptr().cast(), 1) };
                unsafe {
                    libc::close(fds[1]);
                    libc::_exit(if ok { 0 } else { 3 });
                }
            }
            // Leaving now reparents the scenario process to init, so its
            // ancestor walk never reaches this harness's process names.
            unsafe { libc::close(fds[1]) };
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(fds[1]) };
        let mut verdict = [0u8; 1];
        let read = unsafe { libc::read(fds[0], verdict.as_mut_ptr().cast(), 1) };
        unsafe { libc::close(fds[0]) };
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(forked, &mut status, 0) }, forked);
        let ok = read == 1
            && verdict[0] == 1
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0;
        std::process::exit(i32::from(!ok));
    }

    /// The #410 scenarios, in a process that owns its environment, mount
    /// namespace and (as root) drops to an unprivileged user for real EACCES.
    fn run_unreadable_rmdir_scenarios() {
        // The host global config's never_trash and bypass lists must not
        // decide this test: a private mount namespace with an empty
        // /etc/trashd leaves only the defaults and this child's user config.
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            eprintln!("SKIP: a private mount namespace is unavailable");
            return;
        }
        let shadowed = c"/etc/trashd";
        if unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                shadowed.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        } != 0
        {
            eprintln!("SKIP: /etc/trashd cannot be shadowed");
            return;
        }
        // /tmp itself is in every default never_trash list; /var/lib is not.
        let Ok(base) = tempfile::Builder::new()
            .prefix("trashd-preload-rmdir-")
            .tempdir_in("/var/lib")
        else {
            eprintln!("SKIP: no writable /var/lib for a non-excluded fixture");
            return;
        };
        let (home, data, config_dir, work) = (
            base.path().join("home"),
            base.path().join("data"),
            base.path().join("config"),
            base.path().join("work"),
        );
        for dir in [&home, &data, &config_dir, &work] {
            fs::create_dir(dir).unwrap();
        }
        fs::create_dir_all(config_dir.join("trashd")).unwrap();
        fs::write(config_dir.join("trashd/config.toml"), "never_trash = []\n").unwrap();
        let uid = 65534;
        let dropping = unsafe { libc::geteuid() } == 0;
        if dropping {
            for dir in [base.path(), &home, &data, &config_dir, &work] {
                use std::os::unix::fs::MetadataExt;
                assert!(std::os::unix::fs::chown(dir, Some(uid), Some(uid)).is_ok());
                assert_eq!(
                    fs::symlink_metadata(dir).unwrap().uid(),
                    uid,
                    "{}",
                    dir.display()
                );
            }
            assert!(
                std::os::unix::fs::chown(
                    config_dir.join("trashd/config.toml"),
                    Some(uid),
                    Some(uid)
                )
                .is_ok()
            );
            assert_eq!(unsafe { libc::setgid(uid) }, 0);
            assert_eq!(unsafe { libc::setuid(uid) }, 0);
        }
        // Safety: the scenario process is single-threaded.
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_DATA_HOME", &data);
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
            std::env::remove_var("TRASH_BYPASS");
            std::env::remove_var("TRASHD_SECCOMP_ACTIVE");
        }
        // Reparenting escapes cargo, but any other bypassed ancestor (an
        // init named systemd, per the host config) would make the hooks
        // decline and the scenarios assert against the wrong behavior.
        if process_is_bypassed(config(), std::process::id()) {
            eprintln!("SKIP: the scenario process is bypassed by policy");
            return;
        }

        let files = data.join("Trash/files");
        let infos = data.join("Trash/info");
        let errno = || unsafe { *libc::__errno_location() };
        let remove_dir = |name: &Path| {
            let path = CString::new(name.as_os_str().as_bytes()).unwrap();
            unsafe { unlinkat(libc::AT_FDCWD, path.as_ptr(), libc::AT_REMOVEDIR) }
        };
        let entries = |dir: &Path| {
            fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>()
        };
        let owner = unsafe { libc::geteuid() };

        // (1) Empty and unreadable: the caller's rmdir succeeds and the entry
        // lands in the trash whole, with its own mode restored after the scan.
        let locked = work.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o300)).unwrap();
        assert_eq!(
            remove_dir(&locked),
            0,
            "empty unreadable rmdir: {}",
            io::Error::last_os_error()
        );
        assert!(!locked.exists(), "removed from its directory");
        let mut trashed = entries(&files);
        assert_eq!(trashed.len(), 1, "kept recoverable in the trash");
        let trashed = trashed.pop().unwrap();
        let meta = fs::symlink_metadata(&trashed).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.uid(), owner);
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o300,
            "the scan's read grant was undone"
        );
        assert_eq!(entries(&infos).len(), 1, "sidecar present");
        // Scan the copy the way the hook scanned the origin: grant, read,
        // restore.
        let copy = CString::new(trashed.as_os_str().as_bytes()).unwrap();
        let chmod = |granted: bool| unsafe {
            libc::chmod(
                copy.as_ptr(),
                if granted { 0o700 } else { 0o300 } as libc::mode_t,
            )
        };
        assert_eq!(chmod(true), 0);
        let scanned = fs::read_dir(&trashed)
            .map(|mut entries| entries.next().is_none())
            .unwrap();
        assert_eq!(chmod(false), 0);
        assert!(scanned, "the copy is verifiably empty");

        // (2) Unreadable and populated: the kernel's own ENOTEMPTY, nothing
        // trashed, the entry and its contents untouched at the origin.
        let full = work.join("full");
        fs::create_dir(&full).unwrap();
        fs::write(full.join("kept"), b"inside").unwrap();
        fs::set_permissions(&full, fs::Permissions::from_mode(0o300)).unwrap();
        assert_eq!(remove_dir(&full), -1);
        assert_eq!(errno(), libc::ENOTEMPTY);
        assert!(full.exists());
        assert_eq!(
            fs::symlink_metadata(&full).unwrap().permissions().mode() & 0o7777,
            0o300,
            "the victim's mode is never modified"
        );
        assert_eq!(fs::read(full.join("kept")).unwrap(), b"inside");
        // Scenario (1)'s entry is still there; nothing new was added.
        assert_eq!(entries(&files).len(), 1, "nothing new stays trashed");
        let sidecars = entries(&infos);
        if sidecars.len() != 1 {
            panic!("no sidecar stays behind: {sidecars:?}");
        }

        // (3) A readable empty directory still trashes the ordinary way.
        let open = work.join("open");
        fs::create_dir(&open).unwrap();
        assert_eq!(remove_dir(&open), 0);
        assert!(!open.exists());
        assert_eq!(entries(&files).len(), 2, "scenario (1)'s entry is joined");
        assert_eq!(entries(&infos).len(), 2);
    }
}
