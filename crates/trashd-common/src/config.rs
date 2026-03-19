use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_retention")]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub never_trash: Vec<String>,
    #[serde(default)]
    pub bypass_processes: Vec<String>,
    #[serde(default = "default_size_limit")]
    pub max_file_size_mb: u64,
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

impl Default for Config {
    fn default() -> Self {
        Self {
            retention: default_retention(),
            never_trash: vec![
                "/tmp/*".into(),
                "/var/tmp/*".into(),
                "/var/cache/*".into(),
                "/proc/*".into(),
                "/sys/*".into(),
                "/dev/*".into(),
                "*.o".into(),
                "*.pyc".into(),
                "*.class".into(),
                "__pycache__/*".into(),
                "node_modules/*".into(),
                "target/debug/*".into(),
                "target/release/*".into(),
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
            ],
            max_file_size_mb: 1024,
        }
    }
}

impl Config {
    /// Load config from ~/.config/trashd/config.toml, falling back to defaults.
    pub fn load() -> Self {
        let config_path = Self::config_path();
        if config_path.exists() {
            match std::fs::read_to_string(&config_path) {
                Ok(contents) => match toml::from_str(&contents) {
                    Ok(config) => return config,
                    Err(e) => eprintln!("trashd: bad config {}: {}", config_path.display(), e),
                },
                Err(e) => eprintln!("trashd: cannot read {}: {}", config_path.display(), e),
            }
        }
        Self::default()
    }

    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("trashd")
            .join("config.toml")
    }

    /// Check if a path is in the never-trash list.
    pub fn should_skip(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.never_trash.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix('*') {
                path_str.starts_with(prefix)
            } else if pattern.starts_with("*.") {
                path_str.ends_with(&pattern[1..])
            } else if let Some(suffix) = pattern.strip_prefix("*/") {
                path_str.contains(&format!("/{suffix}"))
                    || path_str.ends_with(&format!("/{}", suffix.trim_end_matches('/')))
            } else {
                path_str == *pattern
            }
        })
    }
}
