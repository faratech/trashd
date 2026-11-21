use crate::cli::ConfigCmd;
use crate::util::*;
use colored::Colorize;
use std::path::Path;
use toml_edit::{DocumentMut, Item, TableLike};
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
            // Refuse values the loader would drop or that can never do what
            // they promise, instead of reporting success for a no-op write
            // (#259, #419).
            let value = validate_list_value(&key, &value).unwrap_or_else(|e| fatal(e));
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
    "retention.auto_compress",
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
        "retention.auto_compress" => config.retention.auto_compress.to_string(),
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

/// The user config as an editable document. Only a missing file starts
/// empty: any other read error (invalid UTF-8, EACCES, a directory) stops the
/// edit, since the rewrite would replace a file that was never read (#230). A
/// file that does not parse stops it too: rewriting the table from scratch
/// would discard every existing setting (#143). Edits change the document in
/// place, so comments and the layout of everything an edit does not touch
/// survive it; rewriting a parsed table dropped them all (cli-7).
fn read_config_table(path: &Path) -> Result<DocumentMut, String> {
    let content = match trashd_common::config_file::read(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DocumentMut::new()),
        Err(e) => return Err(format!("refusing to edit {}: {e}", path.display())),
    };
    let unparsable = |e: &dyn std::fmt::Display| {
        format!(
            "refusing to edit {}: the existing config does not parse:\n{e}\nFix or remove the file, then re-run",
            path.display()
        )
    };
    let normalized = Config::normalized_table(&content).map_err(|e| unparsable(&e))?;
    let mut document: DocumentMut = content.parse().map_err(|e| unparsable(&e))?;
    promote_legacy_settings(&mut document, &normalized);
    Ok(document)
}

fn load_user_config_table() -> DocumentMut {
    read_config_table(&Config::user_config_path()).unwrap_or_else(|e| fatal(e))
}

fn write_user_config_table(document: &DocumentMut) {
    let path = Config::user_config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = write_config_file(&path, &render_config(document)) {
        fatal(format!("write config: {e}"));
    }
}

fn render_config(document: &DocumentMut) -> String {
    document.to_string()
}

/// Settings an older release kept under [retention] move to the top level,
/// where the loader applies them, so edits see the settings that actually
/// apply and the rewrite migrates the layout (#330). Each moves with its own
/// comments; one that a top-level setting shadows stays where it is.
fn promote_legacy_settings(document: &mut DocumentMut, normalized: &toml::Table) {
    let (Some(kept), Some(retention)) = (
        normalized.get("retention").and_then(toml::Value::as_table),
        document.get("retention"),
    ) else {
        return;
    };
    let inline = retention.is_inline_table();
    let Some(retention) = retention.as_table_like() else {
        return;
    };
    let legacy: Vec<String> = retention
        .iter()
        .map(|(key, _)| key.to_owned())
        .filter(|key| !kept.contains_key(key) && !document.contains_key(key))
        .collect();
    for key in legacy {
        let Some(retention) = document
            .get_mut("retention")
            .and_then(Item::as_table_like_mut)
        else {
            return;
        };
        let formatted = retention.key(&key).cloned();
        let Some(mut item) = retention.remove(&key) else {
            continue;
        };
        match formatted.filter(|_| !inline) {
            Some(formatted) => {
                document.insert_formatted(&formatted, item);
            }
            None => {
                if let Some(value) = item.as_value_mut() {
                    value.decor_mut().clear();
                }
                document.insert(&key, item);
            }
        }
    }
}

/// Add a top-level key or table the file does not have. It goes below the
/// file's trailing comments (for `config edit`'s template, the whole file)
/// when nothing has to follow it there: above them, a new [table] header
/// would capture every setting uncommented below it later.
fn insert_new(document: &mut DocumentMut, key: &str, mut item: Item) {
    let trailing = document.trailing().as_str().unwrap_or_default().to_owned();
    let below = !trailing.trim().is_empty()
        && !document.contains_key(key)
        && (item.is_table()
            || !document
                .iter()
                .any(|(_, existing)| existing.is_table() || existing.is_array_of_tables()));
    if !below {
        document.insert(key, item);
        return;
    }
    let mut prefix = trailing;
    if !prefix.ends_with('\n') {
        prefix.push('\n');
    }
    if !prefix.ends_with("\n\n") {
        prefix.push('\n');
    }
    document.set_trailing("");
    match &mut item {
        Item::Table(table) => {
            table.decor_mut().set_prefix(prefix);
            document.insert(key, item);
        }
        _ => {
            document.insert(key, item);
            if let Some(mut formatted) = document.key_mut(key) {
                formatted.leaf_decor_mut().set_prefix(prefix);
            }
        }
    }
}

/// Replace the value at `key`, keeping its comment and spacing. False when
/// `key` holds no value.
fn replace_value(table: &mut dyn TableLike, key: &str, value: &toml_edit::Value) -> bool {
    let Some(Item::Value(existing)) = table.get_mut(key) else {
        return false;
    };
    let decor = existing.decor().clone();
    *existing = value.clone();
    *existing.decor_mut() = decor;
    true
}

/// A line's own text and what follows from its newline on.
fn split_line(text: &str) -> (&str, &str) {
    text.find('\n').map_or((text, ""), |end| text.split_at(end))
}

/// Append `value`. In a multi-line array it goes on its own line, indented
/// like the value before it, which keeps its comment.
fn push_keeping_comments(array: &mut toml_edit::Array, value: &str) {
    let mut new = toml_edit::Value::from(value);
    let indent = array
        .iter()
        .last()
        .and_then(|last| last.decor().prefix()?.as_str())
        .and_then(|prefix| prefix.rfind('\n').map(|start| prefix[start..].to_owned()));
    if let Some(indent) = indent {
        // The last value's comment ends the array's trailing text.
        let trailing = array.trailing().as_str().unwrap_or_default().to_owned();
        let (comment, rest) = split_line(&trailing);
        new.decor_mut().set_prefix(format!("{comment}{indent}"));
        array.set_trailing(rest);
    }
    array.push_formatted(new);
}

/// Remove the value at `index` with its own comments. A comment on the
/// previous value's line is stored before this value: it stays.
fn remove_keeping_comments(array: &mut toml_edit::Array, index: usize) {
    let removed = array.remove(index);
    let before = removed
        .decor()
        .prefix()
        .and_then(|prefix| prefix.as_str())
        .unwrap_or_default();
    let (previous_line, _) = split_line(before);
    match array.get_mut(index) {
        Some(next) => {
            let after = next
                .decor()
                .prefix()
                .and_then(|prefix| prefix.as_str())
                .unwrap_or_default();
            let prefix = format!("{previous_line}{}", split_line(after).1);
            next.decor_mut().set_prefix(prefix);
        }
        None => {
            let trailing = array.trailing().as_str().unwrap_or_default();
            // Separator spaces before a removed last value are not kept.
            let kept = if previous_line.contains('#') {
                previous_line
            } else {
                ""
            };
            let trailing = format!("{kept}{}", split_line(trailing).1);
            array.set_trailing(trailing);
        }
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
fn retention_table(document: &mut DocumentMut) -> Result<&mut dyn TableLike, String> {
    if !document.contains_key("retention") {
        insert_new(document, "retention", toml_edit::table());
    }
    document["retention"].as_table_like_mut().ok_or_else(|| {
        "'retention' in the user config is not a table — fix or remove it, then re-run".into()
    })
}

/// Set a scalar key: Ok(false) for an unknown or list key. Values are checked
/// before anything is stored, against what loading the file accepts: a u64
/// above i64::MAX wrapped negative and made the next load reject the whole
/// file, and nan/inf/negative sizes or percentages above 100 were stored as
/// given (#230).
fn config_set_scalar(document: &mut DocumentMut, key: &str, value: &str) -> Result<bool, String> {
    let new: toml_edit::Value = match key {
        "retention.max_age_days" => {
            let v: u32 = value.parse().map_err(|_| "expected integer")?;
            i64::from(v).into()
        }
        "retention.max_size_gb" => {
            let v: f64 = value.parse().map_err(|_| "expected number")?;
            if !v.is_finite() || v < 0.0 {
                return Err("expected a finite, non-negative number".into());
            }
            v.into()
        }
        "retention.disk_pressure_percent" => {
            let v: u8 = value
                .parse()
                .ok()
                .filter(|v| *v <= 100)
                .ok_or("expected integer 0-100")?;
            i64::from(v).into()
        }
        "retention.auto_compress" => {
            let v: bool = value.parse().map_err(|_| "expected true or false")?;
            v.into()
        }
        "max_file_size_mb"
        | "max_dir_size_mb"
        | "sha256_max_size_mb"
        | "auto_purge_interval_secs" => {
            let v: u64 = value.parse().map_err(|_| "expected integer")?;
            i64::try_from(v)
                .map_err(|_| format!("expected integer 0-{}", i64::MAX))?
                .into()
        }
        "hash_algorithm" => {
            if value != "xxhash" && value != "sha256" {
                return Err("hash_algorithm must be 'xxhash' or 'sha256'".into());
            }
            value.into()
        }
        _ => return Ok(false),
    };
    match key.strip_prefix("retention.") {
        Some(name) => {
            let retention = retention_table(document)?;
            if !replace_value(retention, name, &new) {
                retention.insert(name, Item::Value(new));
            }
        }
        None => {
            if !replace_value(document.as_table_mut(), key, &new) {
                insert_new(document, key, Item::Value(new));
            }
        }
    }
    Ok(true)
}

/// only_trash in the user file REPLACES the inherited whitelist, so a user
/// file that does not set it yet starts from the effective list; otherwise
/// adding one pattern silently dropped the admin's patterns (#211). The
/// other lists extend the inherited ones and start empty.
fn seed_inherited_whitelist(document: &mut DocumentMut, key: &str, inherited: &[String]) {
    if key == "only_trash" && !document.contains_key(key) {
        let list: toml_edit::Array = inherited.iter().map(String::as_str).collect();
        insert_new(document, key, toml_edit::value(list));
    }
}

/// Write-time validation matching each list's matching semantics (#259, #419).
/// `never_trash`/`only_trash` are glob lists: the loader silently drops
/// patterns our matcher cannot honour, so `add` refuses them up front.
/// `bypass_paths` (a literal path prefix, `starts_with` against the process
/// exe) and `bypass_processes` (an exact process name) match literally, so
/// braces and other glob characters are ordinary characters there and are
/// accepted as-is. No list accepts an empty value: an empty `bypass_paths`
/// prefix matches every executable, and an empty glob pattern is a no-op the
/// user cannot have meant. A glob is stored as the loader normalizes it
/// (`src/` as `src/*`, common-policy-5); the value to store is returned.
fn validate_list_value(key: &str, value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("refusing to add an empty value to '{key}'"));
    }
    match key {
        "never_trash" | "only_trash" => trashd_common::config::normalize_pattern(value)
            .map_err(|reason| format!("unsupported pattern '{value}': {reason}")),
        _ => Ok(value.to_owned()),
    }
}

fn config_list_add(document: &mut DocumentMut, key: &str, value: &str, inherited: &[String]) {
    match key {
        "never_trash" | "only_trash" | "bypass_processes" | "bypass_paths" => {}
        _ => fatal(format!("'{key}' is not a list — use 'trash config set'")),
    }
    seed_inherited_whitelist(document, key, inherited);
    if !document.contains_key(key) {
        insert_new(document, key, toml_edit::value(toml_edit::Array::new()));
    }
    // The raw table bypasses schema validation, so an existing value can be a
    // non-array (e.g. `never_trash = "*.tmp"`): surface a readable error
    // instead of panicking (#94) — and never silently discard the mistyped
    // value.
    let arr = match document[key].as_array_mut() {
        Some(arr) => arr,
        None => fatal(format!(
            "'{key}' in the user config is not a list — fix or remove it, then re-run"
        )),
    };
    if !arr.iter().any(|v| v.as_str() == Some(value)) {
        push_keeping_comments(arr, value);
    }
}

fn config_list_remove(
    document: &mut DocumentMut,
    key: &str,
    value: &str,
    inherited: &[String],
) -> bool {
    match key {
        "never_trash" | "only_trash" | "bypass_processes" | "bypass_paths" => {}
        _ => fatal(format!("'{key}' is not a list — use 'trash config set'")),
    }
    seed_inherited_whitelist(document, key, inherited);
    let Some(arr) = document.get_mut(key).and_then(Item::as_array_mut) else {
        return false;
    };
    let before = arr.len();
    // Last first, so the indexes still to visit stay valid.
    let matches: Vec<usize> = arr
        .iter()
        .enumerate()
        .filter(|(_, v)| v.as_str() == Some(value))
        .map(|(index, _)| index)
        .collect();
    for index in matches.into_iter().rev() {
        remove_keeping_comments(arr, index);
    }
    arr.len() < before
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(list: &Item) -> Vec<&str> {
        let list = list.as_array().expect("a list");
        list.iter().map(|value| value.as_str().unwrap()).collect()
    }

    // Regression (#211): only_trash in the user file REPLACES the inherited
    // whitelist, so `config add only_trash` starting from an empty user list
    // silently dropped the admin's patterns (their files became real deletes).
    #[test]
    fn legacy_layout_lists_are_edited_where_they_apply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[retention]\nmax_age_days = 7\nnever_trash = [\"*.bak\"]\n",
        )
        .unwrap();
        let mut table = read_config_table(&path).unwrap();
        assert!(config_list_remove(&mut table, "never_trash", "*.bak", &[]));
        config_list_add(&mut table, "never_trash", "*.log", &[]);
        assert_eq!(strings(&table["never_trash"]), ["*.log"]);
        // The rest of [retention] stays where it is.
        assert_eq!(table["retention"]["max_age_days"].as_integer(), Some(7));
        assert!(table["retention"].get("never_trash").is_none());
    }

    #[test]
    fn adding_to_only_trash_keeps_the_inherited_whitelist() {
        let mut table = DocumentMut::new();
        config_list_add(&mut table, "only_trash", "*.py", &["*.txt".to_string()]);
        assert_eq!(strings(&table["only_trash"]), ["*.txt", "*.py"]);
        // Extending lists still start empty: the layers merge.
        config_list_add(&mut table, "never_trash", "*.log", &["*.tmp".to_string()]);
        assert_eq!(strings(&table["never_trash"]), ["*.log"]);
    }

    // Regression (#230): an existing config that cannot be read (invalid
    // UTF-8, EACCES) was treated as empty and then overwritten.
    #[test]
    fn unreadable_config_is_refused_not_replaced() {
        use std::os::unix::ffi::OsStrExt;
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
        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_config_table(&path).is_err());
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
        assert_eq!(
            read_config_table(&link).unwrap()["old"].as_integer(),
            Some(1)
        );

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
        let mut table = DocumentMut::new();
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

    // store-metadata-5: automatic compression is an opt-in boolean.
    #[test]
    fn auto_compress_is_a_validated_boolean_key() {
        assert!(CONFIG_KEYS.contains(&"retention.auto_compress"));
        assert_eq!(
            config_get(&Config::default(), "retention.auto_compress").as_deref(),
            Some("false")
        );
        let mut table = DocumentMut::new();
        assert!(config_set_scalar(&mut table, "retention.auto_compress", "yes").is_err());
        assert!(table.is_empty(), "{table:?}");
        assert_eq!(
            config_set_scalar(&mut table, "retention.auto_compress", "true"),
            Ok(true)
        );
        assert_eq!(table["retention"]["auto_compress"].as_bool(), Some(true));
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

    // Regression (#259): `config add` reported success for brace patterns
    // the loader drops on every read.
    #[test]
    fn brace_patterns_are_rejected_at_add_time() {
        for key in ["never_trash", "only_trash"] {
            assert!(validate_list_value(key, "{a,b}.py").is_err(), "{key}");
            assert!(validate_list_value(key, "a}.py").is_err(), "{key}");
            assert!(validate_list_value(key, "*.py").is_ok(), "{key}");
            assert!(validate_list_value(key, "*.[ch]").is_ok(), "{key}");
        }
    }

    // common-policy-5: a directory-style or `./`-relative pattern was
    // stored as written and matched nothing; `add` stores what the loader
    // matches, and refuses `~/` alone instead of reading it as the home.
    #[test]
    fn glob_patterns_are_stored_normalized() {
        for key in ["never_trash", "only_trash"] {
            assert_eq!(validate_list_value(key, "src/").as_deref(), Ok("src/*"));
            assert_eq!(
                validate_list_value(key, "./build/*").as_deref(),
                Ok("build/*")
            );
            assert_eq!(
                validate_list_value(key, "~/projects/").as_deref(),
                Ok("~/projects/*")
            );
            assert!(validate_list_value(key, "~/").is_err(), "{key}");
            assert!(validate_list_value(key, "a//b").is_err(), "{key}");
        }
        // Literal prefixes are not globs: stored exactly as given.
        assert_eq!(
            validate_list_value("bypass_paths", "/opt/tools/").as_deref(),
            Ok("/opt/tools/")
        );
    }

    // Regression (#419): the glob validator ran for every list, so literal
    // bypass values containing braces were rejected although bypass_paths is
    // a literal prefix match and bypass_processes an exact name. Only the
    // glob lists get pattern validation, and no list accepts empty values.
    #[test]
    fn bypass_lists_accept_literals_and_no_list_accepts_empty() {
        for key in ["bypass_paths", "bypass_processes"] {
            assert!(
                validate_list_value(key, "/opt/{tools}/bin").is_ok(),
                "{key}"
            );
            assert!(validate_list_value(key, "my-{proc}").is_ok(), "{key}");
            assert!(validate_list_value(key, "").is_err(), "{key}");
        }
        for key in ["never_trash", "only_trash"] {
            assert!(validate_list_value(key, "").is_err(), "{key}");
        }
        // Unknown keys are left for config_list_add to reject by name.
        assert!(validate_list_value("max_file_size_mb", "{x}").is_ok());
    }

    // Regression (cli-7): `config set/add/remove` rewrote the file from a
    // parsed table, so every comment was lost, including the commented
    // template `config edit` seeds and the user's own notes. Everything the
    // edit does not touch must survive byte for byte.
    #[test]
    fn edits_keep_comments_and_layout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let edit = |change: &dyn Fn(&mut _)| {
            let mut config = read_config_table(&path).unwrap();
            change(&mut config);
            write_config_file(&path, &render_config(&config)).unwrap();
            std::fs::read_to_string(&path).unwrap()
        };
        let original = "# keep big builds out of trash (ticket 123)\n\
                        max_dir_size_mb = 10 # per build\n\n\
                        never_trash = [\n    \"*.tmp\", # scratch files\n    \"*.o\",\n]\n\n\
                        [retention]\n# a week is plenty on this laptop\nmax_age_days = 7\n";
        std::fs::write(&path, original).unwrap();

        // A changed value is the only difference, its own comment included.
        let text = edit(&|config| {
            assert_eq!(config_set_scalar(config, "max_dir_size_mb", "50"), Ok(true));
        });
        assert_eq!(
            text,
            original.replace("max_dir_size_mb = 10", "max_dir_size_mb = 50")
        );

        // List edits keep the other values' comments.
        let text = edit(&|config| {
            config_list_add(config, "never_trash", "*.iso", &[]);
            assert!(config_list_remove(config, "never_trash", "*.o", &[]));
            assert_eq!(
                config_set_scalar(config, "retention.max_size_gb", "2.5"),
                Ok(true)
            );
        });
        for kept in [
            "# keep big builds out of trash (ticket 123)\nmax_dir_size_mb = 50 # per build\n",
            "\"*.tmp\", # scratch files\n",
            "[retention]\n# a week is plenty on this laptop\nmax_age_days = 7\n",
        ] {
            assert!(text.contains(kept), "{kept:?} lost from:\n{text}");
        }
        let table = Config::normalized_table(&text).unwrap();
        assert_eq!(
            table["never_trash"],
            toml::Value::Array(vec!["*.tmp".into(), "*.iso".into()])
        );
        assert_eq!(table["retention"]["max_size_gb"].as_float(), Some(2.5));

        // `config edit`'s template survives intact, and a new table goes below
        // it: above, it would capture every setting uncommented there later.
        let template = commented_template(&Config::default());
        std::fs::write(&path, &template).unwrap();
        let text = edit(&|config| {
            assert_eq!(
                config_set_scalar(config, "retention.max_age_days", "9"),
                Ok(true)
            );
            config_list_add(config, "bypass_processes", "make", &[]);
        });
        let (before, after) = text.split_once("\n[retention]\n").unwrap();
        assert!(before.contains(&template), "template changed:\n{text}");
        assert_eq!(after, "max_age_days = 9\n");
        let table = Config::normalized_table(&text).unwrap();
        assert_eq!(table["retention"]["max_age_days"].as_integer(), Some(9));
        assert_eq!(table["bypass_processes"][0].as_str(), Some("make"));
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
