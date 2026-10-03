use crate::cli::ConfigCmd;
use crate::util::*;
use colored::Colorize;
use std::path::Path;
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
            if config_set_scalar(&mut table, &key, &value).unwrap_or_else(|e| fatal(e)) {
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
            let status = editor_command(&editor, &user_path).status();
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

/// The user config as a table. Only a missing file starts empty: any other
/// read error (invalid UTF-8, EACCES, a directory) stops the edit, since the
/// rewrite would replace a file that was never read (#230). A file that does
/// not parse stops it too: rewriting the table from scratch would discard
/// every existing setting (#143).
fn read_config_table(path: &Path) -> Result<toml::Table, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => content.parse::<toml::Table>().map_err(|e| {
            format!(
                "refusing to edit {}: the existing config does not parse:\n{e}\nFix or remove the file, then re-run",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(format!("refusing to edit {}: {e}", path.display())),
    }
}

fn load_user_config_table() -> toml::Table {
    read_config_table(&Config::user_config_path()).unwrap_or_else(|e| fatal(e))
}

fn write_user_config_table(table: &toml::Table) {
    let path = Config::user_config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let content = toml::to_string_pretty(table).unwrap_or_default();
    if let Err(e) = write_config_file(&path, &content) {
        fatal(format!("write config: {e}"));
    }
}

/// Replace the config atomically: write a synced sibling temporary and rename
/// it over the file, so a crash or a full disk never leaves a truncated
/// config (#230). A symlinked config (dotfiles) is replaced at its target,
/// and an existing file keeps its mode.
fn write_config_file(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let (Some(dir), Some(name)) = (target.parent(), target.file_name()) else {
        return Err(std::io::Error::other("config path has no file name"));
    };
    let mode = std::fs::metadata(&target)
        .map(|meta| meta.permissions().mode() & 0o7777)
        .unwrap_or(0o644);
    let temporary = dir.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::rename(&temporary, &target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// EDITOR may carry arguments ("code --wait"), so it runs through the shell
/// as git runs it, with the path passed as "$1" rather than spliced in (#230).
fn editor_command(editor: &str, path: &Path) -> std::process::Command {
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg(editor)
        .arg(path);
    command
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

/// The user file's [retention] table. An existing scalar `retention` must
/// error, not panic (#145), and never be silently discarded by the rewrite.
fn retention_table(table: &mut toml::Table) -> Result<&mut toml::Table, String> {
    table
        .entry("retention")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| {
            "'retention' in the user config is not a table — fix or remove it, then re-run".into()
        })
}

/// Set a scalar key: Ok(false) for an unknown or list key. Values are checked
/// before anything is stored, against what loading the file accepts: a u64
/// above i64::MAX wrapped negative and made the next load reject the whole
/// file, and nan/inf/negative sizes or percentages above 100 were stored as
/// given (#230).
fn config_set_scalar(table: &mut toml::Table, key: &str, value: &str) -> Result<bool, String> {
    match key {
        "retention.max_age_days" => {
            let v: u32 = value.parse().map_err(|_| "expected integer")?;
            retention_table(table)?.insert("max_age_days".into(), toml::Value::Integer(v.into()));
        }
        "retention.max_size_gb" => {
            let v: f64 = value.parse().map_err(|_| "expected number")?;
            if !v.is_finite() || v < 0.0 {
                return Err("expected a finite, non-negative number".into());
            }
            retention_table(table)?.insert("max_size_gb".into(), toml::Value::Float(v));
        }
        "retention.disk_pressure_percent" => {
            let v: u8 = value
                .parse()
                .ok()
                .filter(|v| *v <= 100)
                .ok_or("expected integer 0-100")?;
            retention_table(table)?.insert(
                "disk_pressure_percent".into(),
                toml::Value::Integer(v.into()),
            );
        }
        "max_file_size_mb"
        | "max_dir_size_mb"
        | "sha256_max_size_mb"
        | "auto_purge_interval_secs" => {
            let v: u64 = value.parse().map_err(|_| "expected integer")?;
            let v = i64::try_from(v).map_err(|_| format!("expected integer 0-{}", i64::MAX))?;
            table.insert(key.into(), toml::Value::Integer(v));
        }
        "hash_algorithm" => {
            if value != "xxhash" && value != "sha256" {
                return Err("hash_algorithm must be 'xxhash' or 'sha256'".into());
            }
            table.insert(key.into(), toml::Value::String(value.into()));
        }
        _ => return Ok(false),
    }
    Ok(true)
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

    // Regression (#230): an existing config that cannot be read (invalid
    // UTF-8, EACCES) was treated as empty and then overwritten.
    #[test]
    fn unreadable_config_is_refused_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"never_trash = [\"\xff\"]\n").unwrap();
        assert!(read_config_table(&path).is_err());
        assert!(
            read_config_table(dir.path()).is_err(),
            "a directory is not a config"
        );
        assert!(
            read_config_table(&dir.path().join("missing.toml"))
                .unwrap()
                .is_empty()
        );
    }

    // Regression (#230): the config was rewritten in place, so a crash or a
    // full disk mid-write left it truncated. The replacement is renamed into
    // place, keeps the file's mode, and writes through a symlinked config.
    #[test]
    fn config_writes_replace_the_file_atomically() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles.toml");
        std::fs::write(&real, "old = 1\n").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let before = std::fs::metadata(&real).unwrap().ino();

        write_config_file(&link, "new = 2\n").unwrap();

        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new = 2\n");
        let after = std::fs::metadata(&real).unwrap();
        assert_ne!(
            after.ino(),
            before,
            "replaced by rename, not rewritten in place"
        );
        assert_eq!(after.mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "no temporary left"
        );
    }

    // Regression (#230): u64 values above i64::MAX wrapped negative, so the
    // next load rejected the whole file; nan/inf/negative sizes and
    // percentages above 100 were stored as given.
    #[test]
    fn out_of_range_values_are_rejected() {
        let mut table = toml::Table::new();
        assert!(config_set_scalar(&mut table, "max_file_size_mb", "18446744073709551615").is_err());
        for bad in ["nan", "inf", "-1"] {
            assert!(
                config_set_scalar(&mut table, "retention.max_size_gb", bad).is_err(),
                "{bad}"
            );
        }
        assert!(config_set_scalar(&mut table, "retention.disk_pressure_percent", "101").is_err());
        assert!(
            table.is_empty(),
            "rejected values must not be stored: {table:?}"
        );
        assert_eq!(
            config_set_scalar(&mut table, "retention.disk_pressure_percent", "100"),
            Ok(true)
        );
        assert_eq!(
            config_set_scalar(&mut table, "retention.max_size_gb", "1.5"),
            Ok(true)
        );
    }

    // Regression (#230): EDITOR="code --wait" was run as one program name.
    #[test]
    fn editor_runs_through_the_shell() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("with space.toml");
        let status = editor_command("touch -m", &path).status().unwrap();
        assert!(status.success());
        assert!(path.exists());
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
