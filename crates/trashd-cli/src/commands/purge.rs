use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, target: &std::ffi::OsStr) {
    let label = printable(&target.to_string_lossy());
    let entries = match store.select_entries(target, false) {
        Ok(Some((_, entries))) => entries,
        Ok(None) => fatal(format!("trash entry not found: {label}")),
        Err(error) => fatal(error),
    };
    if entries.len() > 1 {
        eprintln!(
            "{} '{}' matches {} items — pass one item's trashed path (right column) to select it",
            "trash: ambiguous:".yellow().bold(),
            label,
            entries.len()
        );
        for entry in entries.iter().take(10) {
            eprintln!(
                "  {} {} {}",
                entry.info.deletion_date.format("%Y-%m-%d %H:%M"),
                printable_path(&entry.info.original_path),
                printable_path(&entry.trashed_path).dimmed()
            );
        }
        std::process::exit(1);
    }
    match store.purge_entry(&entries[0]) {
        Ok(()) => println!(
            "{} permanently deleted '{}'",
            "Purged:".green().bold(),
            label
        ),
        Err(error) => fatal(error),
    }
}
