#[path = "legacy_config.rs"]
mod legacy_config;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_retention")]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub never_trash: Vec<String>,
    /// If non-empty, ONLY files matching these patterns are trashed.
    /// Everything else is real-deleted. `never_trash` still wins over this.
    #[serde(default)]
    pub only_trash: Vec<String>,
    #[serde(default)]
    pub bypass_processes: Vec<String>,
    /// Maximum regular-file size in MiB. `0` disables the limit.
    #[serde(default = "default_size_limit")]
    pub max_file_size_mb: u64,
    /// Maximum file size (in MB) for SHA-256 computation on trash.
    /// Files larger than this skip the hash. Set to 0 to disable hashing entirely.
    #[serde(default = "default_sha256_limit")]
    pub sha256_max_size_mb: u64,
    /// Minimum seconds between auto-purge runs. Prevents scanning the entire
    /// trash directory on every single deletion.
    #[serde(default = "default_purge_interval")]
    pub auto_purge_interval_secs: u64,
    /// Hash algorithm for file integrity: "xxhash" (fast, default) or "sha256" (cryptographic).
    #[serde(default = "default_hash_algo")]
    pub hash_algorithm: String,
    /// Maximum directory size (in MB) to trash. Directories larger than this are
    /// real-deleted. Set to 0 (default) to disable the limit.
    #[serde(default = "default_max_dir_size")]
    pub max_dir_size_mb: u64,
    /// Executable paths that bypass trash. If the deleting process's exe matches
    /// any prefix here, trash is bypassed. More precise than `bypass_processes`.
    #[serde(default)]
    pub bypass_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Auto-purge items older than this many days. `0` disables the age limit
    /// (items are kept until trimmed by size or purged manually).
    #[serde(default = "default_max_age")]
    pub max_age_days: u32,
    /// Trim the trash once it exceeds this many GB. `0` disables the size limit.
    #[serde(default = "default_max_size")]
    pub max_size_gb: f64,
    /// Purge the oldest items once disk usage reaches this percent. `0` disables.
    #[serde(default = "default_disk_pressure")]
    pub disk_pressure_percent: u8,
    /// Compress trashd's own entries older than 7 days with zstd during
    /// retention. Off by default: other file managers restore the stored
    /// bytes as they are, so a compressed entry comes back as zstd data.
    #[serde(default)]
    pub auto_compress: bool,
}

fn default_retention() -> RetentionConfig {
    RetentionConfig {
        max_age_days: default_max_age(),
        max_size_gb: default_max_size(),
        disk_pressure_percent: default_disk_pressure(),
        auto_compress: false,
    }
}

fn default_max_age() -> u32 {
    30
}
fn default_max_size() -> f64 {
    10.0
}
fn default_disk_pressure() -> u8 {
    90
}
fn default_size_limit() -> u64 {
    1024
}
fn default_sha256_limit() -> u64 {
    1 // 1 MB — only hash small files to avoid I/O overhead
}
fn default_purge_interval() -> u64 {
    60 // at most once per minute
}
fn default_hash_algo() -> String {
    "xxhash".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            retention: default_retention(),
            never_trash: default_never_trash(),
            only_trash: Vec::new(),
            bypass_processes: default_bypass_processes(),
            max_file_size_mb: 1024,
            sha256_max_size_mb: default_sha256_limit(),
            auto_purge_interval_secs: default_purge_interval(),
            hash_algorithm: default_hash_algo(),
            max_dir_size_mb: default_max_dir_size(),
            bypass_paths: Vec::new(),
        }
    }
}

/// Default never-trash patterns shared across all layers.
fn default_never_trash() -> Vec<String> {
    vec![
        "/tmp/*".into(),
        "/var/tmp/*".into(),
        "/var/cache/*".into(),
        "/proc/*".into(),
        "/sys/*".into(),
        "/dev/*".into(),
        "/dev/shm/*".into(),
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
    ]
}

fn default_bypass_processes() -> Vec<String> {
    vec![
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
        // NOTE: deliberately NO "systemd"/"systemctl": the ancestor walk
        // matches ANY ancestor by name, and graphical/systemd-launched
        // sessions have systemd in their ancestry — which silently disabled
        // interception AND passed every delete through to permanent removal
        // (#3). Services that need a bypass should use precise bypass_paths.
        "journald".into(),
        "containerd".into(),
        "dockerd".into(),
    ]
}

fn default_max_dir_size() -> u64 {
    0 // 0 = no limit (default)
}

/// Partial config for layered loading. All fields are optional so we can
/// distinguish "not set" from "set to default". Used for merging global
/// and user configs.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PartialRetention {
    max_age_days: Option<u32>,
    max_size_gb: Option<f64>,
    disk_pressure_percent: Option<u8>,
    auto_compress: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct PartialConfig {
    #[serde(default)]
    retention: Option<PartialRetention>,
    never_trash: Option<Vec<String>>,
    only_trash: Option<Vec<String>>,
    bypass_processes: Option<Vec<String>>,
    max_file_size_mb: Option<u64>,
    sha256_max_size_mb: Option<u64>,
    auto_purge_interval_secs: Option<u64>,
    hash_algorithm: Option<String>,
    max_dir_size_mb: Option<u64>,
    bypass_paths: Option<Vec<String>>,
}

impl Config {
    /// Load config with layered merge:
    ///   1. Hardcoded defaults
    ///   2. Global config (/etc/trashd/config.toml) overrides scalars, extends lists
    ///   3. User config (~/.config/trashd/config.toml) overrides scalars, extends lists
    pub fn load() -> Self {
        let mut config = Config::default();

        // Layer 1: global config
        if let Some(partial) = Self::load_partial(&Self::global_config_path()) {
            config.merge(partial);
        }

        // Layer 2: user config
        if let Some(partial) = Self::load_partial(&Self::user_config_path()) {
            config.merge(partial);
        }

        config
    }

    fn load_partial(path: &Path) -> Option<PartialConfig> {
        let contents = match crate::config_file::read(path) {
            Ok(c) => c,
            Err(_) => return None,
        };
        let dropped = |key: &str, error: &toml::de::Error| {
            crate::report_note(&format!(
                "trashd: bad config {}: ignoring '{key}': {}",
                path.display(),
                error.message()
            ));
        };
        match legacy_config::normalize(&contents)
            .and_then(|value| legacy_config::layer::<PartialConfig>(value, dropped))
        {
            Ok(partial) => Some(partial),
            Err(e) => {
                // Never eprintln!: it panics on a failing stderr, and a
                // seccomp supervisor outlives its terminal (common-policy-3).
                crate::report_note(&format!("trashd: bad config {}: {}", path.display(), e));
                None
            }
        }
    }

    fn merge(&mut self, partial: PartialConfig) {
        // Scalars: override if present
        if let Some(ret) = partial.retention {
            if let Some(v) = ret.max_age_days {
                self.retention.max_age_days = v;
            }
            if let Some(v) = ret.max_size_gb {
                self.retention.max_size_gb = v;
            }
            if let Some(v) = ret.disk_pressure_percent {
                self.retention.disk_pressure_percent = v;
            }
            if let Some(v) = ret.auto_compress {
                self.retention.auto_compress = v;
            }
        }
        if let Some(v) = partial.max_file_size_mb {
            self.max_file_size_mb = v;
        }
        if let Some(v) = partial.sha256_max_size_mb {
            self.sha256_max_size_mb = v;
        }
        if let Some(v) = partial.auto_purge_interval_secs {
            self.auto_purge_interval_secs = v;
        }
        if let Some(v) = partial.hash_algorithm {
            self.hash_algorithm = v;
        }
        if let Some(v) = partial.max_dir_size_mb {
            self.max_dir_size_mb = v;
        }

        // Lists: extend and deduplicate. only_trash entries are sanitized
        // aggressively — a pattern that can never match would make the
        // whitelist real-delete everything (#4).
        if let Some(extra) = partial.never_trash {
            for item in sanitize_patterns(&extra, "never_trash") {
                if !self.never_trash.contains(&item) {
                    self.never_trash.push(item);
                }
            }
        }
        // only_trash: user config replaces global (not additive — it's a whitelist)
        if let Some(list) = partial.only_trash {
            self.only_trash = sanitize_patterns(&list, "only_trash");
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
    }

    /// Global config path: /etc/trashd/config.toml
    /// A configuration file's table as the loader reads it: settings an
    /// older release kept under `[retention]` are moved to the top level.
    /// Editors work on this table, so `config add/remove` see the settings
    /// that actually apply, and a rewrite migrates the layout (#330).
    pub fn normalized_table(contents: &str) -> Result<toml::Table, toml::de::Error> {
        Ok(match legacy_config::normalize(contents)? {
            toml::Value::Table(table) => table,
            _ => toml::Table::new(),
        })
    }

    pub fn global_config_path() -> PathBuf {
        PathBuf::from("/etc/trashd/config.toml")
    }

    /// User config path: ~/.config/trashd/config.toml
    pub fn user_config_path() -> PathBuf {
        user_config_path_in(dirs::config_dir())
    }

    /// Legacy alias — returns user config path for backward compatibility.
    pub fn config_path() -> PathBuf {
        Self::user_config_path()
    }

    /// Check if a path should skip trash (real-delete instead).
    pub fn should_skip(&self, path: &Path) -> bool {
        self.exclusion(path).is_some()
    }

    /// Why a path skips the trash (is deleted for real), if it does.
    ///
    /// Logic:
    ///   1. Check per-directory .trashd.toml (if present, its rules apply)
    ///   2. If path matches `never_trash` → skip (real-delete)
    ///   3. If `only_trash` is non-empty and path doesn't match → skip (real-delete)
    ///   4. Otherwise → trash it
    ///
    /// The verdict is for this path alone: a directory's entries are judged
    /// by their own paths (common-policy-1, common-policy-2).
    pub fn exclusion(&self, path: &Path) -> Option<ExclusionKind> {
        // Global never_trash is an unconditional veto. A local policy cannot
        // change it, so excluded paths need no filesystem policy walk.
        if pattern_matches_any(&self.never_trash, path) {
            return Some(ExclusionKind::NeverTrash);
        }
        // Check per-directory .trashd.toml overrides
        if let Some(local) = Self::load_local_config(path) {
            // Local never_trash wins first
            if !local.never_trash.is_empty() && pattern_matches_any(&local.never_trash, path) {
                return Some(ExclusionKind::NeverTrash);
            }
            // Local only_trash: if set, it takes precedence over global only_trash
            if !local.only_trash.is_empty() {
                // The global veto already passed. Local only_trash overrides
                // global only_trash, which must not be re-applied here.
                return (!pattern_matches_any(&local.only_trash, path))
                    .then_some(ExclusionKind::NotWhitelisted);
            }
        }

        (!self.only_trash.is_empty() && !pattern_matches_any(&self.only_trash, path))
            .then_some(ExclusionKind::NotWhitelisted)
    }

    /// Evaluate only this configuration's rules, without reading local files.
    /// Useful when the caller supplies an explicit, isolated configuration.
    pub fn should_skip_configured(&self, path: &Path) -> bool {
        self.exclusion_configured(path).is_some()
    }

    /// `exclusion` without local files (see `should_skip_configured`).
    pub fn exclusion_configured(&self, path: &Path) -> Option<ExclusionKind> {
        // Global never_trash always wins
        if pattern_matches_any(&self.never_trash, path) {
            return Some(ExclusionKind::NeverTrash);
        }
        // Global only_trash: if set and path doesn't match, skip
        (!self.only_trash.is_empty() && !pattern_matches_any(&self.only_trash, path))
            .then_some(ExclusionKind::NotWhitelisted)
    }

    /// Whether a never_trash pattern excludes `dir` together with everything
    /// that can ever be below it, so a recursive removal may delete the tree
    /// for real in one pass instead of judging each entry: the pattern ends
    /// in an unescaped `*`, which matches across `/` (`/tmp/*`,
    /// `~/.cache/*`), or names a literal component (`*/node_modules`).
    /// Configured never_trash is a veto no local policy can lift, so every
    /// descendant would be excluded in turn. A suffix such as `*~` or an
    /// only_trash miss says nothing about what a directory holds (shim-1).
    pub fn never_trash_covers_tree(&self, dir: &Path) -> bool {
        let path = dir.to_string_lossy();
        self.never_trash
            .iter()
            .any(|pattern| pattern_covers_descendants(pattern) && pattern_matches(pattern, &path))
    }

    /// Look for a .trashd.toml in the file's parent directory (or ancestors).
    ///
    /// Walks all the way to the filesystem root: a fixed 5-level cap silently
    /// dropped deep project whitelists (#9), which — via only_trash — meant
    /// real deletes again. Trust note: a .trashd.toml is repo-controlled
    /// content; its `only_trash` whitelist can cause REAL DELETES of anything
    /// not listed. Only place one in trees you control.
    fn load_local_config(path: &Path) -> Option<LocalConfig> {
        use crate::local_trust::{LocalConfigFile, read_local_config};
        let mut dir = path.parent()?;
        loop {
            // A PRESENT local policy that cannot be trusted, read or parsed
            // must not fall through to an ancestor's narrower (possibly
            // whitelist-only) rules — that direction turns "trash it" into a
            // REAL delete. Treat it as "no local policy" and stop the walk,
            // with a diagnostic that never echoes file content (#198).
            let config_path = dir.join(".trashd.toml");
            match read_local_config(dir) {
                LocalConfigFile::Absent => {}
                LocalConfigFile::Ignored(reason) => {
                    warn_local_once(&config_path, || {
                        format!(
                            "trashd: warning: ignoring {}: it {reason}",
                            config_path.display()
                        )
                    });
                    return None;
                }
                LocalConfigFile::Content(content) => {
                    let mut local = match toml::from_str::<LocalConfig>(&content) {
                        Ok(local) => local,
                        Err(e) => {
                            warn_local_once(&config_path, || {
                                format!(
                                    "trashd: warning: ignoring broken {}: {}",
                                    config_path.display(),
                                    e.message()
                                )
                            });
                            return None;
                        }
                    };
                    local.never_trash = sanitize_patterns(&local.never_trash, "never_trash");
                    local.only_trash = sanitize_patterns(&local.only_trash, "only_trash");
                    return Some(local);
                }
            }
            dir = dir.parent()?; // None at the filesystem root
        }
    }
}

/// Without a configuration directory (no usable XDG_CONFIG_HOME or HOME,
/// and no passwd entry) there is no user layer. The old relative fallback
/// `~/.config` was resolved against the cwd, which anyone controlling that
/// directory could fill with policy (common-policy-7). An absolute path that
/// does not exist, as the preload uses, reads nothing and cannot be created
/// by an unprivileged `trash config`.
fn user_config_path_in(config_dir: Option<PathBuf>) -> PathBuf {
    config_dir
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("trashd")
        .join("config.toml")
}

/// Report an unusable local policy once per process: every operand of one
/// `rm`, and every trapped delete of a long-lived supervisor, repeated the
/// same warning. The set is bounded so a supervisor cannot grow it forever.
fn warn_local_once(path: &Path, message: impl FnOnce() -> String) {
    use std::collections::HashSet;
    use std::io::Write;
    use std::sync::Mutex;
    static WARNED: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);
    let mut warned = WARNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let warned = warned.get_or_insert_with(HashSet::new);
    if warned.contains(path) {
        return;
    }
    if warned.len() >= 1024 {
        warned.clear();
    }
    warned.insert(path.to_path_buf());
    // Never panic on a closed stderr (a supervisor may outlive its terminal).
    let _ = writeln!(std::io::stderr(), "{}", message());
}

/// Why a path is kept out of the trash: deleting it for real is intended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusionKind {
    /// A never_trash pattern, global or local, names it.
    NeverTrash,
    /// An only_trash whitelist is in force and does not name it.
    NotWhitelisted,
}

impl std::fmt::Display for ExclusionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ExclusionKind::NeverTrash => "in the never-trash list",
            ExclusionKind::NotWhitelisted => "not in the only-trash list",
        })
    }
}

/// Per-directory config (.trashd.toml).
///
/// TRUST: this file is untrusted repo content. A malicious checkout with
/// `only_trash = []` (or narrow) entries causes every other deletion in the
/// tree to be a REAL delete. Only place these in trees you control.
#[derive(Debug, Deserialize, Default)]
struct LocalConfig {
    #[serde(default)]
    never_trash: Vec<String>,
    #[serde(default)]
    only_trash: Vec<String>,
}

/// Check if a path matches any pattern in the list.
fn pattern_matches_any(patterns: &[String], path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    patterns
        .iter()
        .any(|pattern| pattern_matches(pattern, &path_str))
}

/// Match the complete glob, including wildcards inside directory prefixes.
/// Relative patterns may begin at any path-component boundary. A literal
/// `*/name` also matches descendants of that exact component (#17).
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let Some(rest) = pattern.strip_prefix("~/") else {
        return expanded_pattern_matches(pattern, path);
    };
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let (raw, canonical) = crate::pattern_policy::expand_home(rest, &home);
    expanded_pattern_matches(&raw, path)
        || canonical.is_some_and(|canonical| expanded_pattern_matches(&canonical, path))
}

/// Whether `pattern`, once it matches a path, matches every path below it:
/// a trailing unescaped `*` absorbs any further components, and a literal
/// `*/name` component stays in every descendant.
fn pattern_covers_descendants(pattern: &str) -> bool {
    if let Some(head) = pattern.strip_suffix('*') {
        let escapes = head.len() - head.trim_end_matches('\\').len();
        return escapes % 2 == 0;
    }
    pattern.strip_prefix("*/").is_some_and(|component| {
        !component.is_empty() && !component.contains(['/', '*', '?', '[', '\\'])
    })
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
    if crate::store::simple_glob_match(pattern, path) {
        return true;
    }
    !pattern.starts_with(['/', '*'])
        && path
            .match_indices('/')
            .any(|(index, _)| crate::store::simple_glob_match(pattern, &path[index + 1..]))
}

/// The rules every layer applies to configured patterns (#259, #402,
/// common-policy-5): `config add` refuses what the loader would drop and
/// stores what it would match.
pub use crate::pattern_policy::{normalize_pattern, pattern_is_supported};

/// Normalize configured patterns, dropping with a loud warning each one the
/// matcher cannot honour: in an only_trash whitelist a pattern that matches
/// nothing makes EVERY delete permanent (#4).
fn sanitize_patterns(list: &[String], what: &str) -> Vec<String> {
    crate::pattern_policy::sanitize_patterns(list, what, |warning| {
        crate::report_note(&format!("trashd: WARNING: {warning}"));
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tree may go in one pass only where the pattern that excludes the
    // directory excludes everything below it too (shim-1 kept the per-entry
    // sweep for every other exclusion).
    #[test]
    fn only_wildcard_tails_and_components_cover_a_tree() {
        let config = Config {
            never_trash: [
                "/tmp/*",
                "*/node_modules",
                "*~",
                "*.tmp",
                "draft\\*",
                "/srv/*/cache*",
            ]
            .map(String::from)
            .to_vec(),
            ..Config::default()
        };
        for covered in [
            "/tmp/build",
            "/tmp/a/b",
            "/p/node_modules",
            "/srv/x/cache.d",
        ] {
            assert!(
                config.never_trash_covers_tree(Path::new(covered)),
                "{covered}"
            );
            let below = Path::new(covered).join("deeper/file.rs");
            assert!(config.should_skip_configured(&below), "{}", below.display());
        }
        for not_covered in [
            "/p/thesis~",
            "/p/export.tmp",
            "/p/draft*",
            "/p/src",
            "/p/node_modules_x",
        ] {
            assert!(
                !config.never_trash_covers_tree(Path::new(not_covered)),
                "{not_covered}"
            );
        }
        assert!(pattern_covers_descendants("a\\\\*"));
        assert!(!pattern_covers_descendants("a\\*"));
        assert!(pattern_covers_descendants("*/node*"));
        assert!(!pattern_covers_descendants("*/node?"));
    }

    // #337: an escaped `*` stays literal on the fast paths too.
    #[test]
    fn escaped_wildcards_are_literal_in_every_pattern_form() {
        assert!(pattern_matches("draft\\*", "/home/u/draft*"));
        assert!(!pattern_matches("draft\\*", "/home/u/draft1"));
        assert!(pattern_matches("*.\\[x", "/home/u/file.[x"));
        assert!(pattern_matches("*/name\\?", "/home/u/name?"));
        assert!(!pattern_matches("*/name\\?", "/home/u/name1"));
    }

    #[test]
    fn unusable_local_policy_warns_once_per_file() {
        let path = Path::new("/nonexistent/warn-once-test/.trashd.toml");
        let other = Path::new("/nonexistent/warn-once-other/.trashd.toml");
        let built = std::cell::Cell::new(0);
        for _ in 0..3 {
            warn_local_once(path, || {
                built.set(built.get() + 1);
                String::new()
            });
        }
        assert_eq!(built.get(), 1);
        warn_local_once(other, || {
            built.set(built.get() + 1);
            String::new()
        });
        assert_eq!(built.get(), 2);
    }
    use std::path::Path;

    fn default_config() -> Config {
        Config::default()
    }

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
    fn shipped_template_and_readme_load_root_policy() {
        let template = include_str!("../../../config/trashd.toml");
        let readme = include_str!("../../../README.md");
        let config_section = readme.split("## Configuration").nth(1).unwrap();
        let example = config_section
            .split("```toml\n")
            .nth(1)
            .unwrap()
            .split("```")
            .next()
            .unwrap();
        for content in [template, example] {
            let edited = content
                .replace("max_file_size_mb = 1024", "max_file_size_mb = 5")
                .replace("hash_algorithm = \"xxhash\"", "hash_algorithm = \"sha256\"")
                .replace("only_trash = []", "only_trash = [\"*.py\"]")
                .replace("bypass_paths = []", "bypass_paths = [\"/opt/test/\"]");
            let mut cfg = Config::default();
            cfg.merge(toml::from_str(&edited).unwrap());
            assert_eq!(cfg.max_file_size_mb, 5);
            assert_eq!(cfg.hash_algorithm, "sha256");
            assert_eq!(cfg.only_trash, ["*.py"]);
            assert_eq!(cfg.bypass_paths, ["/opt/test/"]);
            assert!(
                !cfg.bypass_processes
                    .iter()
                    .any(|p| p == "systemd" || p == "systemctl")
            );
        }
    }

    #[test]
    fn loader_preserves_policy_from_legacy_retention_table() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "[retention]\nmax_age_days = 7\nonly_trash = [\"*.txt\"]\nmax_file_size_mb = 9\nauto_purge_interval_secs = 123\n").unwrap();
        let mut config = Config::default();
        config.merge(Config::load_partial(&path).expect("legacy config must load"));
        assert_eq!(config.only_trash, ["*.txt"]);
        assert_eq!(config.max_file_size_mb, 9);
    }

    #[test]
    fn loader_accepts_symlinked_config_and_ignores_fifo() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("dotfiles.toml");
        std::fs::write(&target, "max_file_size_mb = 17\n").unwrap();
        let path = directory.path().join("config.toml");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            Config::load_partial(&path).unwrap().max_file_size_mb,
            Some(17)
        );

        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(Config::load_partial(&path).is_none());
    }

    // store-metadata-5: automatic compression is opt-in, set like any other
    // retention key.
    #[test]
    fn auto_compress_is_off_by_default_and_layers_like_other_retention_keys() {
        assert!(!Config::default().retention.auto_compress);
        let mut config = Config::default();
        config
            .merge(toml::from_str::<PartialConfig>("[retention]\nauto_compress = true\n").unwrap());
        assert!(config.retention.auto_compress);
        config.merge(toml::from_str::<PartialConfig>("[retention]\nmax_age_days = 3\n").unwrap());
        assert!(
            config.retention.auto_compress,
            "a later layer without it reset it"
        );
    }

    #[test]
    fn misplaced_policy_in_retention_is_rejected() {
        for key in [
            "only_trash = [\"*.py\"]",
            "max_file_size_mb = 5",
            "bypass_paths = []",
        ] {
            assert!(toml::from_str::<PartialConfig>(&format!("[retention]\n{key}\n")).is_err());
        }
    }

    #[test]
    fn configured_whitelist_honors_complex_globs() {
        let cfg = Config {
            never_trash: vec!["*/generated/*".into()],
            only_trash: vec!["*.[ch]".into(), "*.py*".into(), "src/file?.rs".into()],
            ..Config::default()
        };
        assert!(!cfg.should_skip_configured(Path::new("/home/user/main.c")));
        assert!(!cfg.should_skip_configured(Path::new("/home/user/main.py.txt")));
        assert!(!cfg.should_skip_configured(Path::new("/home/user/src/file1.rs")));
        assert!(cfg.should_skip_configured(Path::new("/home/user/generated/main.c")));
        assert!(cfg.should_skip_configured(Path::new("/home/user/main.txt")));
    }

    #[test]
    fn never_trash_tmp() {
        let cfg = default_config();
        assert!(cfg.should_skip(Path::new("/tmp/foo.txt")));
        assert!(cfg.should_skip(Path::new("/var/cache/apt/something")));
        assert!(cfg.should_skip(Path::new("/proc/1/status")));
    }

    #[test]
    fn never_trash_extensions() {
        let cfg = default_config();
        assert!(cfg.should_skip(Path::new("/home/user/foo.tmp")));
        assert!(cfg.should_skip(Path::new("/home/user/foo.swp")));
        assert!(cfg.should_skip(Path::new("/home/user/foo.pyc")));
        assert!(cfg.should_skip(Path::new("/home/user/backup~")));
    }

    #[test]
    fn never_trash_git_objects() {
        let cfg = default_config();
        assert!(cfg.should_skip(Path::new("/home/user/repo/.git/objects/abc")));
        assert!(cfg.should_skip(Path::new("/home/user/repo/.git/HEAD")));
    }

    #[test]
    fn normal_files_not_skipped() {
        let cfg = default_config();
        assert!(!cfg.should_skip(Path::new("/home/user/document.txt")));
        assert!(!cfg.should_skip(Path::new("/home/user/project/main.rs")));
        assert!(!cfg.should_skip(Path::new("/home/user/photo.jpg")));
    }

    #[test]
    fn only_trash_whitelist() {
        let mut cfg = default_config();
        cfg.only_trash = vec!["*.py".into()];

        // .py files should be trashed (not skipped)
        assert!(!cfg.should_skip(Path::new("/home/user/script.py")));
        // .rs files should be skipped (not in whitelist)
        assert!(cfg.should_skip(Path::new("/home/user/main.rs")));
        // never_trash still wins over only_trash
        assert!(cfg.should_skip(Path::new("/tmp/script.py")));
    }

    // #402: an empty only_trash pattern matches no path, so a whitelist of
    // `[""]` would make every delete permanent. Sanitizing must drop it,
    // leaving the whitelist disabled (everything trashed).
    #[test]
    fn empty_only_trash_pattern_is_dropped() {
        assert!(!pattern_is_supported(""));

        let mut cfg = default_config();
        cfg.only_trash = sanitize_patterns(&["".to_string()], "only_trash");
        assert!(cfg.only_trash.is_empty());
        assert!(!cfg.should_skip(Path::new("/home/user/important.txt")));
        assert!(!cfg.should_skip(Path::new("/home/user/script.py")));
        // A real pattern beside it still works.
        cfg.only_trash = sanitize_patterns(&["".to_string(), "*.py".to_string()], "only_trash");
        assert_eq!(cfg.only_trash, ["*.py"]);
        assert!(cfg.should_skip(Path::new("/home/user/main.rs")));
        assert!(!cfg.should_skip(Path::new("/home/user/script.py")));
    }

    // common-policy-5: matched paths never end in '/' nor hold '.'
    // components, so `dir/` and `./dir/*` matched nothing; as a whitelist's
    // only entry that made every delete permanent.
    #[test]
    fn directory_and_dot_relative_patterns_match_what_they_name() {
        let home = dirs::home_dir().expect("test user has a home directory");
        let kept = sanitize_patterns(
            &["src/".into(), "./build/*".into(), "~/projects/".into()],
            "only_trash",
        );
        assert!(
            pattern_matches_any(&kept, Path::new("/h/p/src/x")),
            "{kept:?}"
        );
        assert!(
            pattern_matches_any(&kept, Path::new("/h/p/build/y")),
            "{kept:?}"
        );
        assert!(
            pattern_matches_any(&kept, &home.join("projects/a.rs")),
            "{kept:?}"
        );
        // `~/` alone is refused rather than read as the whole home.
        assert!(sanitize_patterns(&["~/".into()], "only_trash").is_empty());
        let mut cfg = default_config();
        cfg.merge(toml::from_str::<PartialConfig>("only_trash = [\"~/projects/\"]\n").unwrap());
        assert!(!cfg.should_skip_configured(&home.join("projects/a.rs")));
    }

    // common-policy-6: policy paths have canonical parents, so a HOME
    // reached through a symlink never matched its own `~/` patterns.
    #[test]
    fn home_patterns_match_through_a_symlinked_home() {
        const CHILD: &str = "TRASHD_TEST_SYMLINKED_HOME";
        const TEST: &str = "config::tests::home_patterns_match_through_a_symlinked_home";
        if crate::mounts::is_rerun_child(TEST, CHILD) {
            let base = tempfile::tempdir().unwrap();
            let real = base.path().join("real");
            std::fs::create_dir_all(real.join("docs")).unwrap();
            let link = base.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            // Safety: the re-run child runs this one test on its own.
            unsafe { std::env::set_var("HOME", &link) };
            let canonical = std::fs::canonicalize(&real).unwrap();
            let victim = canonical.join("docs/x");
            let cfg = Config {
                only_trash: vec!["~/docs/*".into()],
                never_trash: Vec::new(),
                ..Config::default()
            };
            let verdict = pattern_matches("~/docs/*", &victim.to_string_lossy())
                && pattern_matches("~/docs/*", &link.join("docs/x").to_string_lossy())
                && !cfg.should_skip_configured(&victim);
            crate::mounts::report_test_verdict(Some(verdict));
            return;
        }
        assert_eq!(crate::mounts::rerun_test(TEST, CHILD), Some(true));
    }

    // common-policy-7: without any configuration directory the user layer
    // was read from (and written to) `./~/.config` under the cwd.
    #[test]
    fn user_config_path_is_never_relative() {
        assert!(user_config_path_in(None).is_absolute());
        assert_eq!(
            user_config_path_in(Some(PathBuf::from("/c"))),
            Path::new("/c/trashd/config.toml")
        );
    }

    // cross-layer-7: a type error in one key dropped the whole layer here
    // while the preload, which does not type that key, applied the rest.
    #[test]
    fn a_mistyped_key_drops_only_itself() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "only_trash = [\"*.rs\"]\nmax_file_size_mb = 8192\nsha256_max_size_mb = 0.5\n\
             hash_algorithm = 3\n[retention]\nmax_age_days = 7\n",
        )
        .unwrap();
        let mut config = Config::default();
        config.merge(Config::load_partial(&path).expect("the valid keys still load"));
        assert_eq!(config.only_trash, ["*.rs"]);
        assert_eq!(config.max_file_size_mb, 8192);
        assert_eq!(config.retention.max_age_days, 7);
        assert_eq!(config.sha256_max_size_mb, default_sha256_limit());
        assert_eq!(config.hash_algorithm, default_hash_algo());
        // A file that does not parse at all still drops the layer.
        std::fs::write(&path, "only_trash = [\"*.rs\"\n").unwrap();
        assert!(Config::load_partial(&path).is_none());
    }

    // common-policy-3: a seccomp supervisor outlives its terminal. A load
    // warning written with eprintln! panicked on a stderr that fails
    // (EIO on a hung-up pty, EPIPE, ENOSPC), outside the supervisor's guard.
    #[test]
    fn load_warnings_never_panic_on_a_failing_stderr() {
        const CHILD: &str = "TRASHD_TEST_FAILING_STDERR";
        const TEST: &str = "config::tests::load_warnings_never_panic_on_a_failing_stderr";
        if crate::mounts::is_rerun_child(TEST, CHILD) {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.toml");
            std::fs::write(&path, "only_trash = [\"*.{o,a}\", \"\"\nnever_trash = 3\n").unwrap();
            let fixed = directory.path().join("fixed.toml");
            std::fs::write(&fixed, "only_trash = [\"*.{o,a}\", \"\"]\n").unwrap();
            // Every write to stderr now fails with ENOSPC; the verdict goes
            // to stdout.
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap();
            assert_eq!(
                unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&full), 2) },
                2
            );
            let survived = std::panic::catch_unwind(|| {
                let broken = Config::load_partial(&path).is_none();
                let mut config = Config::default();
                config.merge(Config::load_partial(&fixed).expect("the layer parses"));
                broken && config.only_trash.is_empty()
            });
            crate::mounts::report_test_verdict(Some(survived.unwrap_or(false)));
            return;
        }
        assert_eq!(crate::mounts::rerun_test(TEST, CHILD), Some(true));
    }

    #[test]
    fn pattern_matches_node_modules() {
        let cfg = default_config();
        // "node_modules/*" should match anywhere in path
        assert!(cfg.should_skip(Path::new("/home/user/project/node_modules/pkg/index.js")));
    }

    #[test]
    fn local_config_only_trash_overrides_global() {
        // This tests the fix for the bug where local only_trash
        // was overridden by global only_trash.
        let mut cfg = default_config();
        cfg.only_trash = vec!["*.txt".into()]; // global whitelist

        // A .py file would normally be skipped by global only_trash
        assert!(cfg.should_skip(Path::new("/home/user/script.py")));
        // But local .trashd.toml with only_trash=["*.py"] should override
        // (tested via integration test since it requires filesystem)
    }

    #[test]
    fn global_veto_and_fresh_local_whitelists_keep_precedence() {
        let fixture = tempfile::tempdir().unwrap();
        let policy = fixture.path().join(".trashd.toml");
        let mut config = default_config();
        config.never_trash = vec!["*.keep".into()];
        config.only_trash = vec!["*.txt".into()];
        std::fs::write(&policy, "only_trash = [\"*.py\", \"*.keep\"]\n").unwrap();
        assert!(config.should_skip(&fixture.path().join("data.keep")));
        assert!(!config.should_skip(&fixture.path().join("script.py")));
        assert!(config.should_skip(&fixture.path().join("notes.txt")));

        // A rewrite is observed immediately for operands outside the global
        // veto: neither positive nor absent local policies are cached.
        std::fs::write(&policy, "only_trash = [\"*.rs\"]\n").unwrap();
        assert!(config.should_skip(&fixture.path().join("script.py")));
        assert!(!config.should_skip(&fixture.path().join("main.rs")));
        std::fs::remove_file(&policy).unwrap();
        assert!(!config.should_skip(&fixture.path().join("notes.txt")));
        assert!(config.should_skip(&fixture.path().join("main.rs")));
    }

    #[test]
    fn broken_local_config_stops_the_ancestor_walk_instead_of_inheriting() {
        // A PRESENT but unparseable .trashd.toml must not fall through to an
        // ancestor's narrower whitelist — that would turn "trash it" into a
        // real delete of everything the ancestor's only_trash rejects (#136).
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(dir.path().join(".trashd.toml"), "only_trash = [\"*.py\"]\n").unwrap();
        std::fs::write(
            proj.join(".trashd.toml"),
            "only_trash = [\"*.py\", \"*.rs\"\n",
        )
        .unwrap();

        // Clear the built-in policy: its /tmp/* never-trash rule would mask
        // the local-config behavior under test here.
        let mut cfg = default_config();
        cfg.never_trash = Vec::new();
        let victim = proj.join("main.rs");
        // No local policy is honored, but the ANCESTOR's whitelist must not
        // apply either: without local policy the global (empty) rules decide,
        // so the file is trashed, not skipped.
        assert!(!cfg.should_skip(&victim));
    }

    /// A project whose local policy would skip (real-delete) everything.
    fn project_with_local_veto() -> (tempfile::TempDir, PathBuf, Config) {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(dir.path().join("veto.toml"), "never_trash = [\"*\"]\n").unwrap();
        let mut cfg = default_config();
        cfg.never_trash = Vec::new();
        (dir, proj, cfg)
    }

    // Regression (#198, #207): .trashd.toml decides whether deletes are
    // permanent, so only a regular file the deleting user (or root) owns and
    // nobody else can write counts. A symlink could also point root's reader
    // at /etc/shadow (echoed by parse errors) or /proc/kmsg (blocks forever).
    #[test]
    fn symlinked_local_config_is_ignored() {
        let (dir, proj, cfg) = project_with_local_veto();
        std::os::unix::fs::symlink(dir.path().join("veto.toml"), proj.join(".trashd.toml"))
            .unwrap();
        assert!(!cfg.should_skip(&proj.join("file")));
    }

    #[test]
    fn writable_local_config_is_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, proj, cfg) = project_with_local_veto();
        let local = proj.join(".trashd.toml");
        std::fs::copy(dir.path().join("veto.toml"), &local).unwrap();
        std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!cfg.should_skip(&proj.join("file")));
    }

    #[test]
    fn foreign_owned_local_config_is_ignored() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: changing a file's owner requires root");
            return;
        }
        let (dir, proj, cfg) = project_with_local_veto();
        let local = proj.join(".trashd.toml");
        std::fs::copy(dir.path().join("veto.toml"), &local).unwrap();
        std::os::unix::fs::chown(&local, Some(65534), Some(65534)).unwrap();
        assert!(!cfg.should_skip(&proj.join("file")));
    }

    #[test]
    fn healthy_local_config_still_applies_over_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(dir.path().join(".trashd.toml"), "only_trash = [\"*.py\"]\n").unwrap();
        std::fs::write(
            proj.join(".trashd.toml"),
            "only_trash = [\"*.py\", \"*.rs\"]\n",
        )
        .unwrap();

        let mut cfg = default_config();
        cfg.never_trash = Vec::new();
        assert!(!cfg.should_skip(&proj.join("main.rs")));
        assert!(cfg.should_skip(&proj.join("main.c")));
    }
}
