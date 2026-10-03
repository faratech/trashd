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
            config_list_add(&mut table, &key, &value, &Config::load().only_trash);
            write_user_config_table(&table);
            println!("{} added '{}' to {}", "Updated:".green().bold(), value, key);
        }
        ConfigCmd::Remove { key, value } => {
            let mut table = load_user_config_table();
            if config_list_remove(&mut table, &key, &value, &Config::load().only_trash) {
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
                let _ = std::fs::write(&user_path, commented_template(&Config::default()));
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
    // A missing file is the ordinary first-write case. An existing file that
    // does not parse must STOP the edit: rewriting the table from scratch
    // here would silently discard every pre-existing setting (#143).
    match std::fs::read_to_string(&path) {
        Ok(content) => match content.parse::<toml::Table>() {
            Ok(table) => table,
            Err(e) => fatal(format!(
                "refusing to edit {}: the existing config does not parse:\n{e}\nFix or remove the file, then re-run",
                path.display()
            )),
        },
        Err(_) => toml::Table::new(),
    }
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

/// The defaults as a fully commented template. Writing them as active values
/// pinned every default in the user file, overriding the admin's
/// /etc/trashd/config.toml on the first `config edit` (#211).
fn commented_template(defaults: &Config) -> String {
    let body = toml::to_string_pretty(defaults).unwrap_or_default();
    let mut out = String::from(
        "# trashd user configuration. Every line is commented out: uncomment\n\
         # only what you want to change; the rest is inherited from\n\
         # /etc/trashd/config.toml and the built-in defaults.\n\n",
    );
    for line in body.lines() {
        if line.trim().is_empty() {
            out.push('\n');
        } else {
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn config_set_scalar(table: &mut toml::Table, key: &str, value: &str) -> bool {
    match key {
        "retention.max_age_days" => {
            let v: u32 = value.parse().unwrap_or_else(|_| fatal("expected integer"));
            // An existing scalar `retention` must error, not panic (#145) —
            // and never be silently discarded by the rewrite.
            let ret = match table
                .entry("retention")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
            {
                Some(t) => t,
                None => fatal(
                    "'retention' in the user config is not a table — fix or remove it, then re-run",
                ),
            };
            ret.insert("max_age_days".into(), toml::Value::Integer(v as i64));
        }
        "retention.max_size_gb" => {
            let v: f64 = value.parse().unwrap_or_else(|_| fatal("expected number"));
            let ret = match table
                .entry("retention")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
            {
                Some(t) => t,
                None => fatal(
                    "'retention' in the user config is not a table — fix or remove it, then re-run",
                ),
            };
            ret.insert("max_size_gb".into(), toml::Value::Float(v));
        }
        "retention.disk_pressure_percent" => {
            let v: u8 = value
                .parse()
                .unwrap_or_else(|_| fatal("expected integer 0-100"));
            let ret = match table
                .entry("retention")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
            {
                Some(t) => t,
                None => fatal(
                    "'retention' in the user config is not a table — fix or remove it, then re-run",
                ),
            };
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

/// only_trash in the user file REPLACES the inherited whitelist, so a user
/// file that does not set it yet starts from the effective list; otherwise
/// adding one pattern silently dropped the admin's patterns (#211). The
/// other lists extend the inherited ones and start empty.
fn seed_inherited_whitelist(table: &mut toml::Table, key: &str, inherited: &[String]) {
    if key == "only_trash" && !table.contains_key(key) {
        table.insert(
            key.into(),
            toml::Value::Array(inherited.iter().cloned().map(toml::Value::String).collect()),
        );
    }
}

fn config_list_add(table: &mut toml::Table, key: &str, value: &str, inherited: &[String]) {
    match key {
        "never_trash" | "only_trash" | "bypass_processes" | "bypass_paths" => {}
        _ => fatal(format!("'{key}' is not a list — use 'trash config set'")),
    }
    seed_inherited_whitelist(table, key, inherited);
    // The raw table bypasses schema validation, so an existing value can be a
    // non-array (e.g. `never_trash = "*.tmp"`): surface a readable error
    // instead of panicking (#94) — and never silently discard the mistyped
    // value.
    let arr = match table
        .entry(key)
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
    {
        Some(arr) => arr,
        None => fatal(format!(
            "'{key}' in the user config is not a list — fix or remove it, then re-run"
        )),
    };
    let new_val = toml::Value::String(value.into());
    if !arr.contains(&new_val) {
        arr.push(new_val);
    }
}

fn config_list_remove(
    table: &mut toml::Table,
    key: &str,
    value: &str,
    inherited: &[String],
) -> bool {
    match key {
        "never_trash" | "only_trash" | "bypass_processes" | "bypass_paths" => {}
        _ => fatal(format!("'{key}' is not a list — use 'trash config set'")),
    }
    seed_inherited_whitelist(table, key, inherited);
    if let Some(arr) = table.get_mut(key).and_then(|v| v.as_array_mut()) {
        let before = arr.len();
        arr.retain(|v| v.as_str() != Some(value));
        arr.len() < before
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression (#211): only_trash in the user file REPLACES the inherited
    // whitelist, so `config add only_trash` starting from an empty user list
    // silently dropped the admin's patterns (their files became real deletes).
    #[test]
    fn adding_to_only_trash_keeps_the_inherited_whitelist() {
        let mut table = toml::Table::new();
        config_list_add(&mut table, "only_trash", "*.py", &["*.txt".to_string()]);
        assert_eq!(
            table["only_trash"],
            toml::Value::Array(vec!["*.txt".into(), "*.py".into()])
        );
        // Extending lists still start empty: the layers merge.
        config_list_add(&mut table, "never_trash", "*.log", &["*.tmp".to_string()]);
        assert_eq!(
            table["never_trash"],
            toml::Value::Array(vec!["*.log".into()])
        );
    }

    // Regression (#211): `config edit` seeded the user file with every default
    // as an active value, overriding /etc/trashd/config.toml on first use.
    #[test]
    fn edit_template_sets_nothing() {
        let template = commented_template(&Config::default());
        assert!(template.contains("only_trash"));
        assert!(template.parse::<toml::Table>().unwrap().is_empty());
    }
}
