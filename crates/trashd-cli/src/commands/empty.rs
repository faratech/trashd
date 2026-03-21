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

    // Confirmation prompt unless --yes
    if !yes {
        let (prompt_size, prompt_count) = if let Some(d) = days {
            let entries = store.list(None).unwrap_or_default();
            let now = chrono::Local::now();
            let mut size = 0u64;
            let mut cnt = 0u64;
            for entry in &entries {
                let age = now.signed_duration_since(entry.info.deletion_date);
                if age.num_days() >= d as i64 {
                    cnt += 1;
                    size += entry.info.size.unwrap_or(0);
                }
            }
            (size, cnt)
        } else {
            let (s, c) = store.status().unwrap_or_default();
            (s, c as u64)
        };
        if prompt_count == 0 {
            println!("{}", "Nothing to empty.".dimmed());
            return;
        }
        if !confirm(&format!(
            "Permanently delete {} items ({})? [y/N] ",
            prompt_count,
            format_size(prompt_size),
        )) {
            println!("{}", "Cancelled.".dimmed());
            return;
        }
    }

    match store.empty(days) {
        Ok(count) => {
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
        Err(e) => fatal(e),
    }
}
