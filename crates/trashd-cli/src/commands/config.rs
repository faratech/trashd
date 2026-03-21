use crate::cli::ConfigCmd;
use crate::util::*;
use colored::Colorize;
use trashd_common::config::Config;

pub fn run(cmd: ConfigCmd) {
    match cmd {
        ConfigCmd::Show { json } => {
            let config = Config::load();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!("{}", toml::to_string_pretty(&config).unwrap_or_default());
            }
        }
        ConfigCmd::Get { key } => {
            let config = Config::load();
            match config_get(&config, &key) {
                Some(val) => println!("{val}"),
                None => {
                    eprintln!(
                        "{} unknown config key '{key}'",
                        "trash: error:".red().bold()
                    );
                    eprintln!("\nValid keys:");
                    for k in CONFIG_KEYS {
                        eprintln!("  {k}");
                    }
                    std::process::exit(1);
                }
            }
        }
        ConfigCmd::Set { key, value } => {
            let mut table = load_user_config_table();
            if config_set_scalar(&mut table, &key, &value) {
                write_user_config_table(&table);
                println!("{} {} = {}", "Set:".green().bold(), key, value);
            } else {
                eprintln!(
                    "{} unknown or list key '{key}' — use 'trash config add' for lists",
                    "trash: error:".red().bold()
                );
                std::process::exit(1);
            }
        }
        ConfigCmd::Add { key, value } => {
            let mut table = load_user_config_table();
            config_list_add(&mut table, &key, &value);
            write_user_config_table(&table);
            println!("{} added '{}' to {}", "Updated:".green().bold(), value, key);
        }
        ConfigCmd::Remove { key, value } => {
            let mut table = load_user_config_table();
            if config_list_remove(&mut table, &key, &value) {
                write_user_config_table(&table);
                println!(
                    "{} removed '{}' from {}",
                    "Updated:".green().bold(),
                    value,
                    key,
                );
            } else {
                eprintln!(
                    "{} '{}' not found in {}",
                    "trash: error:".red().bold(),
                    value,
                    key,
                );
                std::process::exit(1);
            }
        }
        ConfigCmd::Path => {
            let global = Config::global_config_path();
            let user = Config::user_config_path();
            println!("{}", "Config files (in priority order):".bold());
            println!(
                "  {} {}{}",
                "User:".green(),
                user.display(),
                if user.exists() { "" } else { " (not created)" },
            );
            println!(
                "  {} {}{}",
                "Global:".cyan(),
                global.display(),
                if global.exists() { "" } else { " (not found)" },
            );
        }
        ConfigCmd::Edit => {
            let user_path = Config::user_config_path();
            if !user_path.exists() {
                if let Some(parent) = user_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let default = Config::default();
                let content = toml::to_string_pretty(&default).unwrap_or_default();
                let _ = std::fs::write(&user_path, content);
            }
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
            let status = std::process::Command::new(&editor).arg(&user_path).status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => fatal(format!("{editor} exited with {s}")),
                Err(e) => fatal(format!("launch {editor}: {e}")),
            }
        }
        ConfigCmd::Reset { yes } => {
            let user_path = Config::user_config_path();
            if !user_path.exists() {
                println!("{}", "No user config to reset.".dimmed());
                return;
            }
            if !yes && !confirm(&format!("Remove {}? [y/N] ", user_path.display())) {
                println!("{}", "Cancelled.".dimmed());
                return;
            }
            if let Err(e) = std::fs::remove_file(&user_path) {
                fatal(e);
            }
            println!(
                "{} user config removed — using defaults",
                "Reset:".green().bold(),
            );
        }
    }
}

const CONFIG_KEYS: &[&str] = &[
    "retention.max_age_days",
    "retention.max_size_gb",
    "retention.disk_pressure_percent",
    "max_file_size_mb",
    "max_dir_size_mb",
    "sha256_max_size_mb",
    "auto_purge_interval_secs",
    "hash_algorithm",
    "never_trash",
    "only_trash",
    "bypass_processes",
    "bypass_paths",
];

fn config_get(config: &Config, key: &str) -> Option<String> {
    Some(match key {
        "retention.max_age_days" => config.retention.max_age_days.to_string(),
        "retention.max_size_gb" => config.retention.max_size_gb.to_string(),
        "retention.disk_pressure_percent" => config.retention.disk_pressure_percent.to_string(),
        "max_file_size_mb" => config.max_file_size_mb.to_string(),
        "max_dir_size_mb" => config.max_dir_size_mb.to_string(),
        "sha256_max_size_mb" => config.sha256_max_size_mb.to_string(),
        "auto_purge_interval_secs" => config.auto_purge_interval_secs.to_string(),
        "hash_algorithm" => config.hash_algorithm.clone(),
        "never_trash" => config.never_trash.join(", "),
        "only_trash" => config.only_trash.join(", "),
        "bypass_processes" => config.bypass_processes.join(", "),
        "bypass_paths" => config.bypass_paths.join(", "),
        _ => return None,
    })
}

fn load_user_config_table() -> toml::Table {
    let path = Config::user_config_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .unwrap_or_default()
}

fn write_user_config_table(table: &toml::Table) {
    let path = Config::user_config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let content = toml::to_string_pretty(table).unwrap_or_default();
    if let Err(e) = std::fs::write(&path, content) {
        fatal(format!("write config: {e}"));
    }
}

fn config_set_scalar(table: &mut toml::Table, key: &str, value: &str) -> bool {
    match key {
        "retention.max_age_days" => {
            let v: u32 = value.parse().unwrap_or_else(|_| fatal("expected integer"));
            let ret = table
                .entry("retention")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .unwrap();
            ret.insert("max_age_days".into(), toml::Value::Integer(v as i64));
        }
        "retention.max_size_gb" => {
            let v: f64 = value.parse().unwrap_or_else(|_| fatal("expected number"));
            let ret = table
                .entry("retention")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .unwrap();
            ret.insert("max_size_gb".into(), toml::Value::Float(v));
        }
        "retention.disk_pressure_percent" => {
            let v: u8 = value
                .parse()
                .unwrap_or_else(|_| fatal("expected integer 0-100"));
            let ret = table
                .entry("retention")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .unwrap();
            ret.insert(
                "disk_pressure_percent".into(),
                toml::Value::Integer(v as i64),
            );
        }
        "max_file_size_mb"
        | "max_dir_size_mb"
        | "sha256_max_size_mb"
        | "auto_purge_interval_secs" => {
            let v: u64 = value.parse().unwrap_or_else(|_| fatal("expected integer"));
            table.insert(key.into(), toml::Value::Integer(v as i64));
        }
        "hash_algorithm" => {
            if value != "xxhash" && value != "sha256" {
                fatal("hash_algorithm must be 'xxhash' or 'sha256'");
            }
            table.insert(key.into(), toml::Value::String(value.into()));
        }
        "never_trash" | "only_trash" | "bypass_processes" | "bypass_paths" => return false,
        _ => return false,
    }
    true
}

fn config_list_add(table: &mut toml::Table, key: &str, value: &str) {
    match key {
        "never_trash" | "only_trash" | "bypass_processes" | "bypass_paths" => {}
        _ => fatal(format!("'{key}' is not a list — use 'trash config set'")),
    }
    let arr = table
        .entry(key)
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .unwrap();
    let new_val = toml::Value::String(value.into());
    if !arr.contains(&new_val) {
        arr.push(new_val);
    }
}

fn config_list_remove(table: &mut toml::Table, key: &str, value: &str) -> bool {
    match key {
        "never_trash" | "only_trash" | "bypass_processes" | "bypass_paths" => {}
        _ => fatal(format!("'{key}' is not a list — use 'trash config set'")),
    }
    if let Some(arr) = table.get_mut(key).and_then(|v| v.as_array_mut()) {
        let before = arr.len();
        arr.retain(|v| v.as_str() != Some(value));
        arr.len() < before
    } else {
        false
    }
}
