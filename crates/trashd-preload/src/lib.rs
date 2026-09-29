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

#[path = "../../trashd-common/src/legacy_config.rs"]
mod legacy_config;

use serde::Deserialize;
use std::cell::Cell;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
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
    bypass_paths: Vec<String>,
    /// Maximum regular-file size in MiB. Zero disables the limit.
    max_file_size_mb: u64,
    /// Maximum directory-tree size in MiB. Zero disables the limit (#118).
    max_dir_size_mb: u64,
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
    match legacy_config::normalize(&content)
        .and_then(|value| value.try_into::<PartialPreloadConfig>())
    {
        Ok(partial) => Some(partial),
        Err(error) => {
            eprintln!("trashd-preload: bad config {}: {error}", path.display());
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
///
/// The env var alone once sufficed — but ANY process inheriting or exporting
/// `TRASHD_SECCOMP_ACTIVE=1` (a leaked export, a copied Environment= line)
/// then silently lost ALL preload protection: every intercepted delete
/// became permanent (#125). Defer only when BOTH hold: the wrapper claims
/// the handshake AND this process really runs under a seccomp filter
/// (`Seccomp: 2` in /proc/self/status).
fn is_seccomp_active() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let claimed = std::env::var_os("TRASHD_SECCOMP_ACTIVE")
            .map(|v| v == "1")
            .unwrap_or(false);
        seccomp_deferred(claimed, seccomp_filter_installed())
    })
}

/// Pure gating logic: a claim must be backed by a real filter.
fn seccomp_deferred(claimed: bool, filter_installed: bool) -> bool {
    claimed && filter_installed
}

/// True when this process runs in seccomp filter mode (value 2 of the
/// `Seccomp:` field in /proc/self/status). Unreadable status → not verified.
///
/// KNOWN RESIDUAL: this accepts ANY seccomp filter, not trashd's — container
/// runtimes (Docker's default profile), LXC, firejail, or systemd
/// SystemCallFilter= all set Seccomp: 2 for every process, so on such hosts a
/// leaked env var still silences the preload. The child closes its
/// notification fd before exec, so no in-process signal can distinguish
/// trashd's filter; the residual requires the operator to leak the var
/// themselves and is accepted rather than complicate the hot path further.
fn seccomp_filter_installed() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => status.lines().any(|line| {
            line.strip_prefix("Seccomp:")
                .is_some_and(|value| value.trim() == "2")
        }),
        Err(_) => false,
    }
}

/// Cache by PID, so children of a fork re-evaluate their own process tree.
fn is_process_bypassed() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CACHED: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let cached = CACHED.load(Ordering::Relaxed);
    if cached >> 1 == u64::from(pid) {
        return cached & 1 != 0;
    }
    let bypassed = process_is_bypassed(config(), pid);
    CACHED.store(
        (u64::from(pid) << 1) | u64::from(bypassed),
        Ordering::Relaxed,
    );
    bypassed
}

/// Executable prefixes apply to the deleting process. Name rules apply to
/// that process itself and up to ten ancestors, excluding init/session PID 1.
fn process_is_bypassed(cfg: &PreloadConfig, mut pid: u32) -> bool {
    if !cfg.bypass_paths.is_empty()
        && let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe"))
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
    for _ in 0..=10 {
        if let Some(name) = process_name(pid)
            && cfg.bypass_processes.contains(&name)
        {
            return true;
        }
        pid = match parent_pid(pid) {
            Some(parent) if parent > 1 && parent != pid => parent,
            _ => break,
        };
    }
    false
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
    if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe"))
        && let Some(name) = exe.file_name()
    {
        return Some(name.to_string_lossy().into_owned());
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
    // (the shared spec dir) or ".Trash-<uid>". The uid must be THIS caller's
    // effective uid: a lookalike directory like ~/proj/.Trash-1001 (another
    // user's uid, or any name with digits) is ordinary user data, and
    // skipping interception here would PERMANENTLY DELETE it while the
    // shim/seccomp layers trash it (#108).
    path.components().any(|comp| {
        if let Component::Normal(name) = comp {
            let n = name.to_string_lossy();
            n == ".Trash" || n == format!(".Trash-{}", unsafe { libc::geteuid() })
        } else {
            false
        }
    })
}

/// Bounded directory-tree size walk mirroring trashd-common's dir_size_capped.
fn dir_size_capped(path: &Path) -> (u64, bool) {
    const MAX_FILES: u64 = 10_000;
    let mut total = 0u64;
    let mut count = 0u64;
    fn walk(path: &Path, total: &mut u64, count: &mut u64, max: u64) {
        if *count >= max {
            return;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if *count >= max {
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
    (total, count >= MAX_FILES)
}

/// Match a single never_trash/only_trash pattern against a path string.
/// Mirrors trashd-common's `pattern_matches_any` so every layer agrees.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let expanded;
    let pattern = if let Some(rest) = pattern.strip_prefix("~/") {
        let Some(home) = dirs::home_dir() else {
            return false;
        };
        expanded = home.join(rest).to_string_lossy().into_owned();
        expanded.as_str()
    } else {
        pattern
    };
    // Keep common literal prefix/suffix rules allocation-free, but only
    // after excluding interior wildcard syntax (#4).
    if let Some(prefix) = pattern.strip_suffix('*')
        && !prefix.contains(['*', '?', '['])
    {
        return path.starts_with(prefix)
            || (!prefix.starts_with('/')
                && path
                    .match_indices('/')
                    .any(|(index, _)| path[index + 1..].starts_with(prefix)));
    }
    if let Some(component) = pattern.strip_prefix("*/")
        && !component.is_empty()
        && !component.contains(['/', '*', '?', '['])
    {
        return path.split('/').any(|part| part == component);
    }
    if let Some(suffix) = pattern.strip_prefix('*')
        && !suffix.contains(['*', '?', '['])
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
                '[' if ti < t.len() => {
                    if let Some(next) = class_match(&p, pi, t[ti]) {
                        pi = next;
                        ti += 1;
                        continue;
                    }
                }
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

/// Match one char against a `[...]` class at `p[start]`; returns the index
/// past `]`, or None (no match / unterminated).
fn class_match(p: &[char], start: usize, c: char) -> Option<usize> {
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

/// Drop patterns with syntax we cannot honor ({a,b}) — in an only_trash
/// whitelist a never-matching pattern real-deletes everything (#4).
fn sanitize_patterns(list: Vec<String>, what: &str) -> Vec<String> {
    list.into_iter()
        .filter(|p| {
            if p.contains('{') || p.contains('}') {
                eprintln!("trashd-preload: WARNING: dropping unsupported {what} pattern '{p}'");
                false
            } else {
                true
            }
        })
        .collect()
}

/// Find the nearest `.trashd.toml` walking up from `path` to the filesystem
/// root, matching trashd-common's Config::load_local_config (a fixed 5-level
/// cap silently dropped deep project whitelists, #9).
fn load_local_config(path: &Path) -> Option<LocalConfig> {
    let mut dir = path.parent()?;
    loop {
        let cfg_path = dir.join(".trashd.toml");
        if cfg_path.is_file()
            && let Ok(content) = fs::read_to_string(&cfg_path)
            && let Ok(mut local) = toml::from_str::<LocalConfig>(&content)
        {
            local.never_trash = sanitize_patterns(local.never_trash, "never_trash");
            local.only_trash = sanitize_patterns(local.only_trash, "only_trash");
            return Some(local);
        }
        dir = dir.parent()?; // None at the filesystem root
    }
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

fn trash_dir_for(path: &Path) -> Result<PathBuf, ()> {
    let home_trash = home_trash_dir();
    prepare_home_trash(&home_trash)?;

    let file_dev = fs::symlink_metadata(path)
        .or_else(|_| {
            path.parent()
                .map(fs::metadata)
                .unwrap_or_else(|| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "")))
        })
        .ok()
        .map(|m| m.dev());

    let home_dev = fs::metadata(&home_trash).ok().map(|m| m.dev());

    if file_dev == home_dev {
        return Ok(home_trash);
    }

    let uid = unsafe { libc::geteuid() };
    if let Some(mountpoint) = find_mount_point(path) {
        // Check shared .Trash/ first (FreeDesktop spec §1.2.2a)
        let shared_trash = mountpoint.join(".Trash");
        if trusted_topdir(&mountpoint, uid)
            && let Ok(meta) = fs::symlink_metadata(&shared_trash)
            && !meta.file_type().is_symlink()
            && meta.is_dir()
            && (meta.uid() == 0 || meta.uid() == uid)
            && (meta.permissions().mode() & 0o1000) != 0
        {
            let uid_dir = shared_trash.join(uid.to_string());
            if ensure_private_dir(&uid_dir, uid, true).is_ok()
                && ensure_private_dir(&uid_dir.join("files"), uid, true).is_ok()
                && ensure_private_dir(&uid_dir.join("info"), uid, true).is_ok()
            {
                return Ok(uid_dir);
            }
        }

        // Fallback: .Trash-$UID (spec §1.2.2b)
        let topdir = mountpoint.join(format!(".Trash-{uid}"));
        if trusted_topdir(&mountpoint, uid)
            && ensure_private_dir(&topdir, uid, true).is_ok()
            && ensure_private_dir(&topdir.join("files"), uid, true).is_ok()
            && ensure_private_dir(&topdir.join("info"), uid, true).is_ok()
        {
            return Ok(topdir);
        }
    }

    Ok(home_trash)
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

fn prepare_home_trash(home: &Path) -> Result<(), ()> {
    let uid = unsafe { libc::geteuid() };
    let fallback = PathBuf::from(format!("/tmp/trashd-home-{uid}"));
    if home == fallback.join("Trash") {
        ensure_trusted_parent(&fallback, uid).map_err(|_| ())?;
        ensure_private_dir(&fallback, uid, true).map_err(|_| ())?;
    } else if let Some(parent) = home.parent() {
        ensure_trusted_ancestors(parent, uid).map_err(|_| ())?;
    }
    ensure_private_dir(home, uid, true).map_err(|_| ())?;
    ensure_private_dir(&home.join("files"), uid, true).map_err(|_| ())?;
    ensure_private_dir(&home.join("info"), uid, true).map_err(|_| ())?;
    Ok(())
}

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
            "unsafe trash directory ownership or type",
        ));
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
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
                "trash ancestor can be replaced by another user",
            ));
        }
    }
    Ok(())
}

/// Unescape /proc/mounts octal sequences (the kernel escapes only whitespace
/// and backslash, e.g. "\040" for space) so mount paths with spaces resolve.
fn unescape_octal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let oct: String = chars.by_ref().take(3).collect();
            if oct.len() == 3
                && let Ok(val) = u8::from_str_radix(&oct, 8)
            {
                out.push(val as char);
                continue;
            }
            out.push('\\');
            out.push_str(&oct);
        } else {
            out.push(c);
        }
    }
    out
}

fn home_trash_dir() -> PathBuf {
    // No shared /tmp fallback: without XDG or HOME the trash would land in a
    // world-readable, periodically purged directory (#35). A uid-suffixed
    // path keeps it out of other users' reach.
    dirs::data_dir()
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|h| h.join(".local/share"))
                .unwrap_or_else(|| {
                    PathBuf::from(format!("/tmp/trashd-home-{}", unsafe { libc::geteuid() }))
                })
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
fn copy_regular_verified(src: &Path, dst: &Path, expect_dev: u64, expect_ino: u64) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(src)?;
    let m = input.metadata()?;
    if !m.is_file() || m.dev() != expect_dev || m.ino() != expect_ino {
        return Err(io::Error::new(io::ErrorKind::NotFound, "source changed"));
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(dst)?;
    io::copy(&mut input, &mut output)?;
    Ok(())
}

fn exceeds_file_size_limit(cfg: &PreloadConfig, meta: &fs::Metadata) -> bool {
    meta.is_file()
        && cfg.max_file_size_mb != 0
        && meta.len() > cfg.max_file_size_mb.saturating_mul(1024 * 1024)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrashAttempt {
    Trashed,
    NotTrashed,
    /// The selected store failed its ownership/type/privacy checks. Falling
    /// through to libc here would turn an attack on the store into permanent
    /// deletion, so hooks return EACCES instead.
    UnsafeStore,
}

/// Move `path` into the appropriate trash. `expect_dev`/`expect_ino` are the
/// identity captured by the hook's eligibility stat: re-stat immediately
/// before the move and bail out if the file was REPLACED in between (#44) —
/// trashing the new inode would capture content the caller never asked to
/// delete, and then report success for it.
fn try_trash(path: &Path, expect_dev: u64, expect_ino: u64) -> TrashAttempt {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return TrashAttempt::NotTrashed;
    };
    if meta.dev() != expect_dev
        || meta.ino() != expect_ino
        || exceeds_file_size_limit(config(), &meta)
    {
        return TrashAttempt::NotTrashed;
    }
    // Directory size cap (#118): the other layers refuse oversized trees, so
    // trashing one here file-by-file would gut it where the user asked for a
    // refusal. Bounded walk, same 10k-entry cap as trashd-common.
    if meta.is_dir() && !meta.file_type().is_symlink() {
        let cfg = config();
        if cfg.max_dir_size_mb > 0 {
            let (bytes, capped) = dir_size_capped(path);
            if capped || bytes / (1024 * 1024) > cfg.max_dir_size_mb {
                return TrashAttempt::NotTrashed;
            }
        }
    }
    let trash_dir = match trash_dir_for(path) {
        Ok(path) => path,
        Err(()) => return TrashAttempt::UnsafeStore,
    };

    let files_dir = trash_dir.join("files");
    let info_dir = trash_dir.join("info");
    let uid = unsafe { libc::geteuid() };
    if ensure_private_dir(&files_dir, uid, false).is_err()
        || ensure_private_dir(&info_dir, uid, false).is_err()
    {
        return TrashAttempt::UnsafeStore;
    }

    // Atomic unique ID via O_CREAT|O_EXCL
    let base_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".into());

    let (id, info_path) = match unique_id_atomic(&info_dir, &files_dir, &base_name) {
        Some(v) => v,
        None => return TrashAttempt::NotTrashed,
    };

    let dest = files_dir.join(&id);

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => return TrashAttempt::NotTrashed,
        }
    };

    let size = meta.len();

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
        "[Trash Info]\nPath={}\nDeletionDate={}\nX-Trashd-Command=preload\nX-Trashd-PID={}\nX-Trashd-Size={size}\n",
        encode_path(&trashinfo_path),
        now.format("%Y-%m-%dT%H:%M:%S"),
        std::process::id(),
    );

    if fs::write(&info_path, &trashinfo).is_err() {
        let _ = fs::remove_file(&info_path);
        return TrashAttempt::NotTrashed;
    }

    // TOCTOU re-check just before the move (#44)
    match fs::symlink_metadata(path) {
        Ok(now) if now.dev() == expect_dev && now.ino() == expect_ino => {}
        Ok(_) => {
            let _ = fs::remove_file(&info_path);
            return TrashAttempt::NotTrashed; // replaced — let the real unlink handle the path
        }
        Err(_) => {} // vanished; rename below fails cleanly
    }

    // Move the file
    if fs::rename(path, &dest).is_ok() {
        log_preload(&format!(
            "trashed: {} -> {}",
            path.display(),
            dest.display()
        ));
        return TrashAttempt::Trashed;
    }

    // Cross-device: copy preserving symlinks, then remove original
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => {
            let _ = fs::remove_file(&info_path);
            return TrashAttempt::NotTrashed;
        }
    };

    if meta.file_type().is_symlink() {
        // Re-create symlink
        if let Ok(target) = fs::read_link(path)
            && std::os::unix::fs::symlink(&target, &dest).is_ok()
        {
            let cpath = match CString::new(path.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => {
                    let _ = fs::remove_file(&info_path);
                    let _ = fs::remove_file(&dest);
                    return TrashAttempt::NotTrashed;
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
                return TrashAttempt::NotTrashed;
            }
            log_preload(&format!("trashed (cross-dev symlink): {}", path.display()));
            return TrashAttempt::Trashed;
        }
    } else if meta.is_dir() {
        // Cross-device dirs: best-effort. For preload, fall back to real delete.
        let _ = fs::remove_file(&info_path);
        return TrashAttempt::NotTrashed;
    } else if meta.file_type().is_fifo() || meta.file_type().is_socket() {
        // fs::copy on a FIFO blocks forever waiting for a writer (#11);
        // sockets have no persistent data. Let the real unlink proceed.
        let _ = fs::remove_file(&info_path);
        return TrashAttempt::NotTrashed;
    } else if meta.file_type().is_char_device() || meta.file_type().is_block_device() {
        // Copying a device node would read unbounded data from it.
        let _ = fs::remove_file(&info_path);
        return TrashAttempt::NotTrashed;
    } else {
        // Regular file: copy + delete original. The copy opens the source
        // with O_NOFOLLOW|O_NONBLOCK and re-verifies dev/ino first: a racer
        // swapping the file for a FIFO must not block the copy forever, and
        // a symlink swap must not be read through (#111).
        if copy_regular_verified(path, &dest, meta.dev(), meta.ino()).is_err() {
            // A partial/failed copy must not strand an orphaned data file
            // in the trash (#33).
            let _ = fs::remove_file(&dest);
            let _ = fs::remove_file(&info_path);
            return TrashAttempt::NotTrashed;
        }
        {
            // Preserve permissions
            let _ = fs::set_permissions(&dest, meta.permissions());
            let cpath = match CString::new(path.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => {
                    let _ = fs::remove_file(&info_path);
                    let _ = fs::remove_file(&dest);
                    return TrashAttempt::NotTrashed;
                }
            };
            let ret = unsafe { (real_unlink())(cpath.as_ptr()) };
            if ret != 0 {
                // Unlink of original failed — clean up the copy to avoid orphan
                let _ = fs::remove_file(&info_path);
                let _ = fs::remove_file(&dest);
                return TrashAttempt::NotTrashed;
            }
            log_preload(&format!("trashed (cross-dev): {}", path.display()));
            return TrashAttempt::Trashed;
        }
    }

    let _ = fs::remove_file(&info_path);
    TrashAttempt::NotTrashed
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

    // An empty pathname is ENOENT in the kernel; joining it below would
    // resolve to the cwd (or the dirfd) itself and trash it (#84).
    if path.as_os_str().is_empty() {
        return None;
    }

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

fn finish_attempt(attempt: TrashAttempt, saved_errno: libc::c_int) -> Option<libc::c_int> {
    match attempt {
        TrashAttempt::Trashed => Some(success_with_errno(saved_errno)),
        TrashAttempt::NotTrashed => None,
        TrashAttempt::UnsafeStore => {
            unsafe { *libc::__errno_location() = libc::EACCES };
            Some(-1)
        }
    }
}

fn should_intercept() -> bool {
    !is_bypass_active() && !is_seccomp_active() && !is_process_bypassed()
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
                // Empty pathname → ENOENT; joining would trash the cwd (#84).
                if path.as_os_str().is_empty() {
                    return None;
                }
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
                if let Ok(meta) = fs::symlink_metadata(&abs)
                    && !should_skip_path(&abs)
                    && !meta.is_dir()
                    && let Some(result) =
                        finish_attempt(try_trash(&abs, meta.dev(), meta.ino()), saved_errno)
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

            if !should_intercept() {
                return None;
            }

            let is_removedir = (flags & libc::AT_REMOVEDIR) != 0;

            if let Some(abs) = resolve_at_path(dirfd, pathname) {
                // Use symlink_metadata to not follow symlinks
                if let Ok(meta) = fs::symlink_metadata(&abs)
                    && !should_skip_path(&abs)
                {
                    let is_real_dir = meta.is_dir() && !meta.file_type().is_symlink();
                    if is_removedir {
                        // NOTE: emptiness here then rename in try_trash is a small
                        // TOCTOU — a sibling could repopulate the dir in between.
                        // The result is still recoverable from the trash (residual
                        // L8), so we accept it rather than add fragile locking.
                        if is_real_dir
                            && let Ok(mut rd) = fs::read_dir(&abs)
                            && rd.next().is_none()
                            && let Some(result) =
                                finish_attempt(try_trash(&abs, meta.dev(), meta.ino()), saved_errno)
                        {
                            return Some(result);
                        }
                    } else if !is_real_dir
                        && let Some(result) =
                            finish_attempt(try_trash(&abs, meta.dev(), meta.ino()), saved_errno)
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

            if !should_intercept() {
                return None;
            }

            if let Some(path) = cstr_to_path(pathname) {
                // Empty pathname → ENOENT; joining would trash the cwd (#84).
                if path.as_os_str().is_empty() {
                    return None;
                }
                let abs = if path.is_absolute() {
                    path.clone()
                } else {
                    match std::env::current_dir() {
                        Ok(cwd) => cwd.join(&path),
                        Err(_) => return None,
                    }
                };

                // Use symlink_metadata — rmdir only applies to real directories, not symlinks
                if let Ok(meta) = fs::symlink_metadata(&abs)
                    && meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && !should_skip_path(&abs)
                    && let Ok(mut rd) = fs::read_dir(&abs)
                    && rd.next().is_none()
                    && let Some(result) =
                        finish_attempt(try_trash(&abs, meta.dev(), meta.ino()), saved_errno)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_globs_match_complete_patterns() {
        let home = dirs::home_dir().expect("test user has a home directory");
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
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(
                pattern_matches(pattern, path),
                expected,
                "{pattern}: {path}"
            );
        }
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
        cfg.bypass_processes.push(process_name(pid).unwrap());
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
    fn dir_size_cap_merges_from_config() {
        let mut cfg = PreloadConfig::default();
        assert_eq!(cfg.max_dir_size_mb, 0, "default is disabled");
        cfg.merge(toml::from_str::<PartialPreloadConfig>("max_dir_size_mb = 5").unwrap());
        assert_eq!(cfg.max_dir_size_mb, 5);
    }

    // Regression (#108): lookalike .Trash-<other-uid> directories are user
    // data, not trash — the hook must intercept them (not skip, which would
    // permanently delete).
    #[test]
    fn is_inside_trash_matches_only_own_uid_suffix() {
        let own_dir = format!("/mnt/usb/.Trash-{}", unsafe { libc::geteuid() });
        let own = Path::new(&own_dir).join("files/x");
        assert!(is_inside_trash(&own));

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
        assert!(!seccomp_deferred(false, true), "no claim, nothing to defer to");
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
        assert!(ensure_private_dir(&link, uid, true).is_err());
        assert!(ensure_trusted_ancestors(&link.join("new"), uid).is_err());
        assert!(!private.join("new").exists());
    }
}
