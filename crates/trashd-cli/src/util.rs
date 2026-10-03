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
        // checked_mul so an absurd week count can't silently wrap in release.
        w.trim().parse::<u32>().ok().and_then(|w| w.checked_mul(7))
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

    // Relative: "30m", "1h", "2d", "1w". try_* + checked_sub_signed so an
    // absurd magnitude (e.g. 99999999999999m) falls through to the clean
    // error below instead of panicking on a chrono overflow (#96).
    let relative = if let Some(mins) = s.strip_suffix('m').and_then(|v| v.parse::<i64>().ok()) {
        chrono::TimeDelta::try_minutes(mins).and_then(|d| now.checked_sub_signed(d))
    } else if let Some(hours) = s.strip_suffix('h').and_then(|v| v.parse::<i64>().ok()) {
        chrono::TimeDelta::try_hours(hours).and_then(|d| now.checked_sub_signed(d))
    } else if let Some(days) = s.strip_suffix('d').and_then(|v| v.parse::<i64>().ok()) {
        chrono::TimeDelta::try_days(days).and_then(|d| now.checked_sub_signed(d))
    } else if let Some(weeks) = s.strip_suffix('w').and_then(|v| v.parse::<i64>().ok()) {
        chrono::TimeDelta::try_weeks(weeks).and_then(|d| now.checked_sub_signed(d))
    } else {
        None
    };
    if let Some(dt) = relative {
        return dt;
    }

    // Absolute: "2026-03-20T14:00:00", "2026-03-20T14:00", or "2026-03-20"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        && let Some(local) = local_instant(dt)
    {
        return local;
    }
    // minutes-precision datetime: the documented "2026-03-20T14:00" form (#146)
    if s.contains('T')
        && s.matches('-').count() == 2
        && let Ok(dt) =
            chrono::NaiveDateTime::parse_from_str(&format!("{s}:00"), "%Y-%m-%dT%H:%M:%S")
        && let Some(local) = local_instant(dt)
    {
        return local;
    }
    if !s.contains('T')
        && s.matches('-').count() == 2
        && let Ok(dt) =
            chrono::NaiveDateTime::parse_from_str(&format!("{s}T00:00:00"), "%Y-%m-%dT%H:%M:%S")
        && let Some(local) = local_instant(dt)
    {
        return local;
    }

    eprintln!(
        "{} invalid time spec '{s}' — use e.g. '1h', '2d', '1w', or '2026-03-20'",
        "trash: error:".red().bold(),
    );
    std::process::exit(1);
}

/// A local wall-clock time as an instant. A time that a DST change repeats
/// takes its earlier instant, and one it skips resolves to the end of the
/// gap; `.single()` rejected both (#230). chrono's `earliest()` is not used:
/// for `Local` it returned the later instant of a repeated time.
fn local_instant(naive: chrono::NaiveDateTime) -> Option<chrono::DateTime<chrono::Local>> {
    use chrono::LocalResult;
    // Gaps last at most a few hours; the first valid minute ends this one.
    (0..=24 * 60).find_map(|minutes| {
        match naive
            .checked_add_signed(chrono::TimeDelta::minutes(minutes))?
            .and_local_timezone(chrono::Local)
        {
            LocalResult::Single(instant) => Some(instant),
            LocalResult::Ambiguous(a, b) => Some(a.min(b)),
            LocalResult::None => None,
        }
    })
}

/// `s` for human output, with control and bidi-override characters escaped:
/// names and sidecar fields come from the filesystem, and could otherwise
/// move the cursor, clear the screen, or reorder a line (#230).
pub fn printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control()
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// A path for human output; see [`printable`].
pub fn printable_path(path: &std::path::Path) -> String {
    printable(&path.to_string_lossy())
}

pub fn print_json_entries(entries: &[trashd_common::store::TrashEntry]) {
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                // Unique even when two trash roots hold the same id; accepted
                // as a selector by restore, purge and info (#210).
                "trashed_path": e.trashed_path.to_string_lossy(),
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
/// The selector for an entry named on the command line: UTF-8 targets as
/// typed, anything else by its raw bytes. A lossy conversion matched another
/// entry's ID exactly, so purge deleted the wrong file (#209).
pub fn target_selector(store: &trashd_common::TrashStore, target: &std::ffi::OsStr) -> String {
    match target.to_str() {
        Some(target) => target.to_owned(),
        None => store
            .selector_for_raw_name(target)
            .unwrap_or_else(|e| fatal(e)),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    // Regression (#230): crafted sidecars could put terminal escapes and
    // newlines into `ls`, `find` and `info` output.
    #[test]
    fn human_output_escapes_control_characters() {
        assert_eq!(
            printable("a\x1b[2Jb\nc\u{202e}d\u{7f}"),
            "a\\u{1b}[2Jb\\u{a}c\\u{202e}d\\u{7f}"
        );
        assert_eq!(printable("caf\u{e9} \\ ok"), "caf\u{e9} \\ ok");
    }

    // Regression (#230): `.single()` rejected local times that a DST change
    // repeats or skips. Ambiguous times take the earlier instant; skipped
    // times resolve to the first instant after the gap. Local time is
    // process-wide, so this runs in a child with its own TZ.
    #[test]
    fn local_times_around_dst_changes_resolve() {
        if std::env::var_os("TRASHD_DST_CHILD").is_some() {
            let now = chrono::Local::now();
            let repeated = parse_time_spec("2026-11-01T01:30", &now);
            assert_eq!(repeated.to_rfc3339(), "2026-11-01T01:30:00-04:00");
            let skipped = parse_time_spec("2026-03-08T02:30", &now);
            assert_eq!(skipped.to_rfc3339(), "2026-03-08T03:00:00-04:00");
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "util::tests::local_times_around_dst_changes_resolve",
            ])
            .env("TZ", "America/New_York")
            .env("TRASHD_DST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
