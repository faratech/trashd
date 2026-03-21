use crate::util::*;
use colored::Colorize;
use trashd_common::store::TrashError;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, target: &str) {
    match store.purge(target) {
        Ok(()) => println!(
            "{} permanently deleted '{target}'",
            "Purged:".green().bold()
        ),
        Err(TrashError::AmbiguousMatch { pattern, count }) => {
            eprintln!(
                "{} '{}' matches {} items — use trash ID for exact match",
                "trash: ambiguous:".yellow().bold(),
                pattern,
                count,
            );
            if let Ok(entries) = store.list(Some(&pattern)) {
                for entry in entries.iter().take(10) {
                    eprintln!(
                        "  {} {} {}",
                        entry.info.deletion_date.format("%Y-%m-%d %H:%M"),
                        entry.info.original_path.display(),
                        entry.id.dimmed(),
                    );
                }
            }
            std::process::exit(1);
        }
        Err(e) => fatal(e),
    }
}
