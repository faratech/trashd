use colored::Colorize;

pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub fn parse_duration_days(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(d) = s.strip_suffix('d') {
        d.trim().parse().ok()
    } else if let Some(w) = s.strip_suffix('w') {
        w.trim().parse::<u32>().ok().map(|w| w * 7)
    } else {
        s.parse().ok()
    }
}

/// Parse a time specification into a DateTime.
/// Supports relative durations (e.g., "1h", "30m", "2d", "1w") and
/// absolute dates (e.g., "2026-03-20", "2026-03-20T14:00").
pub fn parse_time_spec(
    s: &str,
    now: &chrono::DateTime<chrono::Local>,
) -> chrono::DateTime<chrono::Local> {
    let s = s.trim();

    // Relative: "30m", "1h", "2d", "1w"
    if let Some(mins) = s.strip_suffix('m').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::minutes(mins);
    }
    if let Some(hours) = s.strip_suffix('h').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::hours(hours);
    }
    if let Some(days) = s.strip_suffix('d').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::days(days);
    }
    if let Some(weeks) = s.strip_suffix('w').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::weeks(weeks);
    }

    // Absolute: "2026-03-20T14:00:00" or "2026-03-20"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        if let Some(local) = dt.and_local_timezone(chrono::Local).single() {
            return local;
        }
    }
    if let Ok(dt) =
        chrono::NaiveDateTime::parse_from_str(&format!("{s}T00:00:00"), "%Y-%m-%dT%H:%M:%S")
    {
        if let Some(local) = dt.and_local_timezone(chrono::Local).single() {
            return local;
        }
    }

    eprintln!(
        "{} invalid time spec '{s}' — use e.g. '1h', '2d', '1w', or '2026-03-20'",
        "trash: error:".red().bold(),
    );
    std::process::exit(1);
}

pub fn print_json_entries(entries: &[trashd_common::store::TrashEntry]) {
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "original_path": e.info.original_path.to_string_lossy(),
                "deletion_date": e.info.deletion_date.format("%Y-%m-%dT%H:%M:%S").to_string(),
                "size": e.info.size,
                "command": e.info.command,
                "trash_dir": e.trash_root.to_string_lossy(),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".into())
    );
}

/// Truncate a path string for display, respecting UTF-8 char boundaries.
pub fn truncate_path(path: &str, max: usize) -> String {
    if path.len() > max {
        let start = path.floor_char_boundary(path.len() - (max - 3));
        format!("...{}", &path[start..])
    } else {
        path.to_string()
    }
}

/// Prompt the user for y/N confirmation. Returns true if yes.
pub fn confirm(msg: &str) -> bool {
    eprint!("{msg}");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim(), "y" | "Y" | "yes" | "Yes" | "YES")
}

/// Print a fatal error and exit.
pub fn fatal(msg: impl std::fmt::Display) -> ! {
    eprintln!("{} {msg}", "trash: error:".red().bold());
    std::process::exit(1);
}

/// Shared error-exit for store operations.
pub fn open_store() -> trashd_common::TrashStore {
    match trashd_common::TrashStore::open() {
        Ok(s) => s,
        Err(e) => fatal(e),
    }
}

pub use std::path::PathBuf;
