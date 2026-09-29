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
}

fn default_retention() -> RetentionConfig {
    RetentionConfig {
        max_age_days: default_max_age(),
        max_size_gb: default_max_size(),
        disk_pressure_percent: default_disk_pressure(),
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
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return None,
        };
        match legacy_config::normalize(&contents)
            .and_then(|value| value.try_into::<PartialConfig>())
        {
            Ok(partial) => Some(partial),
            Err(e) => {
                eprintln!("trashd: bad config {}: {}", path.display(), e);
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
    pub fn global_config_path() -> PathBuf {
        PathBuf::from("/etc/trashd/config.toml")
    }

    /// User config path: ~/.config/trashd/config.toml
    pub fn user_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("trashd")
            .join("config.toml")
    }

    /// Legacy alias — returns user config path for backward compatibility.
    pub fn config_path() -> PathBuf {
        Self::user_config_path()
    }

    /// Check if a path should skip trash (real-delete instead).
    ///
    /// Logic:
    ///   1. Check per-directory .trashd.toml (if present, its rules apply)
    ///   2. If path matches `never_trash` → skip (real-delete)
    ///   3. If `only_trash` is non-empty and path doesn't match → skip (real-delete)
    ///   4. Otherwise → trash it
    pub fn should_skip(&self, path: &Path) -> bool {
        // Check per-directory .trashd.toml overrides
        if let Some(local) = Self::load_local_config(path) {
            // Local never_trash wins first
            if !local.never_trash.is_empty() && pattern_matches_any(&local.never_trash, path) {
                return true;
            }
            // Local only_trash: if set, it takes precedence over global only_trash
            if !local.only_trash.is_empty() {
                if !pattern_matches_any(&local.only_trash, path) {
                    return true; // doesn't match local whitelist → skip
                }
                // Matched local whitelist — still check global never_trash below,
                // but skip the global only_trash check (local overrides it).
                if pattern_matches_any(&self.never_trash, path) {
                    return true;
                }
                return false;
            }
        }

        self.should_skip_configured(path)
    }

    /// Evaluate only this configuration's rules, without reading local files.
    /// Useful when the caller supplies an explicit, isolated configuration.
    pub fn should_skip_configured(&self, path: &Path) -> bool {
        // Global never_trash always wins
        if pattern_matches_any(&self.never_trash, path) {
            return true;
        }

        // Global only_trash: if set and path doesn't match, skip
        if !self.only_trash.is_empty() && !pattern_matches_any(&self.only_trash, path) {
            return true;
        }

        false
    }

    /// Look for a .trashd.toml in the file's parent directory (or ancestors).
    ///
    /// Walks all the way to the filesystem root: a fixed 5-level cap silently
    /// dropped deep project whitelists (#9), which — via only_trash — meant
    /// real deletes again. Trust note: a .trashd.toml is repo-controlled
    /// content; its `only_trash` whitelist can cause REAL DELETES of anything
    /// not listed. Only place one in trees you control.
    fn load_local_config(path: &Path) -> Option<LocalConfig> {
        let mut dir = path.parent()?;
        loop {
            let config_path = dir.join(".trashd.toml");
            if config_path.is_file() {
                // A PRESENT local policy that cannot be read or parsed must
                // not fall through to an ancestor's narrower (possibly
                // whitelist-only) rules — that direction turns "trash it"
                // into a REAL delete. Treat the broken file as "no local
                // policy" and stop the walk, with a diagnostic.
                let mut local = match std::fs::read_to_string(&config_path) {
                    Ok(content) => match toml::from_str::<LocalConfig>(&content) {
                        Ok(local) => local,
                        Err(e) => {
                            eprintln!(
                                "trashd: warning: ignoring broken {}: {e}",
                                config_path.display()
                            );
                            return None;
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "trashd: warning: ignoring unreadable {}: {e}",
                            config_path.display()
                        );
                        return None;
                    }
                };
                local.never_trash = sanitize_patterns(&local.never_trash, "never_trash");
                local.only_trash = sanitize_patterns(&local.only_trash, "only_trash");
                return Some(local);
            }
            dir = dir.parent()?; // None at the filesystem root
        }
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
    if crate::store::simple_glob_match(pattern, path) {
        return true;
    }
    !pattern.starts_with(['/', '*'])
        && path
            .match_indices('/')
            .any(|(index, _)| crate::store::simple_glob_match(pattern, &path[index + 1..]))
}

/// Drop patterns containing syntax our matcher cannot honor (`{a,b}` brace
/// expansion). Such patterns would otherwise silently behave wrong; in an
/// only_trash whitelist that means nothing matches and EVERY delete becomes
/// permanent (#4). Warn loudly so misconfiguration is visible.
fn sanitize_patterns(list: &[String], what: &str) -> Vec<String> {
    list.iter()
        .filter(|p| {
            if p.contains('{') || p.contains('}') {
                eprintln!(
                    "trashd: WARNING: dropping unsupported {what} pattern '{p}' \
                     (brace expansion is not supported)"
                );
                false
            } else {
                true
            }
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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
