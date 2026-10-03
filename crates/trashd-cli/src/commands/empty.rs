use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, older: Option<&str>, dry_run: bool, yes: bool) {
    let days = match older {
        Some(s) => match parse_duration_days(s) {
            Some(d) => Some(d),
            None => fatal(format!(
                "invalid duration '{s}' (use e.g. '7d', '2w', or a number of days)"
            )),
        },
        None => None,
    };

    if dry_run {
        let entries = match store.list(None) {
            Ok(e) => e,
            Err(e) => fatal(e),
        };

        let now = chrono::Local::now();
        let mut count = 0usize;
        let mut total_size = 0u64;

        for entry in &entries {
            if let Some(d) = days {
                let age = now.signed_duration_since(entry.info.deletion_date);
                if age.num_days() < d as i64 {
                    continue;
                }
            }
            count += 1;
            total_size += entry.info.size.unwrap_or(0);
            println!(
                "  {} {} {}",
                entry.info.deletion_date.format("%Y-%m-%d %H:%M"),
                entry.info.original_path.display(),
                format_size(entry.info.size.unwrap_or(0)).dimmed(),
            );
        }

        if count == 0 {
            println!("{}", "Nothing would be deleted.".dimmed());
        } else {
            println!(
                "\n{} {} items ({}) would be permanently deleted",
                "Dry run:".yellow().bold(),
                count,
                format_size(total_size),
            );
        }
        return;
    }

    // One listing drives both the prompt and the purge: re-listing after the
    // confirmation also deleted items trashed while the prompt waited (#217).
    // Listing failures must NOT masquerade as an empty trash: that printed
    // "Nothing to empty." and exited 0 without deleting anything (#147).
    let selected = match store.entries_older_than(days) {
        Ok(entries) => entries,
        Err(e) => fatal(e),
    };
    if selected.is_empty() {
        println!("{}", "Nothing to empty.".dimmed());
        return;
    }
    if !yes {
        let size: u64 = selected
            .iter()
            .map(|entry| entry.info.size.unwrap_or(0))
            .fold(0, u64::saturating_add);
        if !confirm(&format!(
            "Permanently delete {} items ({})? [y/N] ",
            selected.len(),
            format_size(size),
        )) {
            println!("{}", "Cancelled.".dimmed());
            return;
        }
    }

    let count = store.empty_entries(&selected, days);
    if count == 0 {
        println!("{}", "Nothing to empty.".dimmed());
    } else {
        println!(
            "{} permanently deleted {} items",
            "Emptied:".green().bold(),
            count
        );
    }
}
