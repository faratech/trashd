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
            // Saturating: a crafted X-Trashd-Size can be u64::MAX (#255).
            total_size = total_size.saturating_add(entry.info.size.unwrap_or(0));
            println!(
                "  {} {} {}",
                entry.info.deletion_date.format("%Y-%m-%d %H:%M"),
                printable_path(&entry.info.original_path),
                format_size(entry.info.size.unwrap_or(0)).dimmed(),
            );
        }

        let pending = match store.pending_cleanup() {
            Ok(pending) => pending,
            Err(error) => fatal(error),
        };
        if count == 0 && pending == 0 {
            println!("{}", "Nothing would be deleted.".dimmed());
        } else if count > 0 {
            println!(
                "\n{} {} items ({}) would be permanently deleted",
                "Dry run:".yellow().bold(),
                count,
                format_size(total_size),
            );
        }
        if pending > 0 {
            println!("  {pending} unfinished deletion jobs would be retried.");
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
        if cleanup_unfinished(store) == 0 {
            println!("{}", "Nothing to empty.".dimmed());
        }
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
    cleanup_unfinished(store);
}

/// These jobs were retired by an earlier purge, so retrying them never adds
/// ordinary entries to the selection the user just confirmed.
fn cleanup_unfinished(store: &TrashStore) -> usize {
    let report = match store.cleanup_unfinished() {
        Ok(report) => report,
        Err(error) => fatal(error),
    };
    if report.removed > 0 {
        println!(
            "{} removed {} unfinished deletion jobs",
            "Cleaned:".green().bold(),
            report.removed,
        );
    }
    if report.pending > 0 {
        fatal(format!(
            "{} deletion jobs still need cleanup; retry `trash empty`",
            report.pending,
        ));
    }
    report.removed
}
