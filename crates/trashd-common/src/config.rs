use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_max_age")]
    pub max_age_days: u32,
    #[serde(default = "default_max_size")]
    pub max_size_gb: f64,
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
    ]
}

/// Partial config for layered loading. All fields are optional so we can
/// distinguish "not set" from "set to default". Used for merging global
/// and user configs.
#[derive(Debug, Deserialize, Default)]
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
        match toml::from_str::<PartialConfig>(&contents) {
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

        // Lists: extend and deduplicate
        if let Some(extra) = partial.never_trash {
            for item in extra {
                if !self.never_trash.contains(&item) {
                    self.never_trash.push(item);
                }
            }
        }
        // only_trash: user config replaces global (not additive — it's a whitelist)
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
            // Local only_trash: if set and doesn't match, skip
            if !local.only_trash.is_empty() && !pattern_matches_any(&local.only_trash, path) {
                return true;
            }
            // If local only_trash matched, still check global never_trash
        }

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
    fn load_local_config(path: &Path) -> Option<LocalConfig> {
        let mut dir = path.parent()?;
        // Walk up at most 5 levels to find .trashd.toml
        for _ in 0..5 {
            let config_path = dir.join(".trashd.toml");
            if config_path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    if let Ok(local) = toml::from_str::<LocalConfig>(&content) {
                        return Some(local);
                    }
                }
            }
            dir = dir.parent()?;
        }
        None
    }
}

/// Per-directory config (.trashd.toml).
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
    patterns.iter().any(|pattern| {
        if let Some(prefix) = pattern.strip_suffix('*') {
            path_str.starts_with(prefix)
        } else if pattern.starts_with("*.") {
            path_str.ends_with(&pattern[1..])
        } else if pattern == "*~" {
            path_str.ends_with('~')
        } else if let Some(suffix) = pattern.strip_prefix("*/") {
            path_str.contains(&format!("/{suffix}"))
                || path_str.ends_with(&format!("/{}", suffix.trim_end_matches('/')))
        } else {
            path_str == *pattern
        }
    })
}
