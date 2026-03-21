use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(
    store: &TrashStore,
    pattern: Option<&str>,
    after: Option<&str>,
    before: Option<&str>,
    json: bool,
) {
    let mut entries = match store.list(pattern) {
        Ok(e) => e,
        Err(e) => fatal(e),
    };

    // Apply time filters
    let now = chrono::Local::now();
    if let Some(after_str) = after {
        let cutoff = parse_time_spec(after_str, &now);
        entries.retain(|e| e.info.deletion_date >= cutoff);
    }
    if let Some(before_str) = before {
        let cutoff = parse_time_spec(before_str, &now);
        entries.retain(|e| e.info.deletion_date <= cutoff);
    }

    if entries.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("{}", "Trash is empty.".dimmed());
        }
        return;
    }

    if json {
        print_json_entries(&entries);
        return;
    }

    let home_trash = TrashStore::trash_dir();
    let multi_part = entries.iter().any(|e| e.trash_root != home_trash);

    if multi_part {
        println!(
            "{:<20} {:>10} {:<6} {:<30} {}",
            "DELETED".bold(),
            "SIZE".bold(),
            "DISK".bold(),
            "ORIGINAL PATH".bold(),
            "ID".bold(),
        );
    } else {
        println!(
            "{:<20} {:>10} {:<30} {}",
            "DELETED".bold(),
            "SIZE".bold(),
            "ORIGINAL PATH".bold(),
            "ID".bold(),
        );
    }

    for entry in &entries {
        let date = entry.info.deletion_date.format("%Y-%m-%d %H:%M");
        let size = entry
            .info
            .size
            .map(format_size)
            .unwrap_or_else(|| "?".into());
        let path = entry.info.original_path.to_string_lossy();
        let max_path = if multi_part { 40 } else { 50 };
        let path_display = truncate_path(&path, max_path);

        if multi_part {
            let disk = if entry.trash_root == home_trash {
                "home".to_string()
            } else {
                entry
                    .trash_root
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "?".into())
            };
            println!(
                "{:<20} {:>10} {:<6} {:<30} {}",
                date,
                size,
                disk,
                path_display,
                entry.id.dimmed()
            );
        } else {
            println!(
                "{:<20} {:>10} {:<30} {}",
                date,
                size,
                path_display,
                entry.id.dimmed()
            );
        }
    }

    println!("\n{} items in trash", entries.len());
}
