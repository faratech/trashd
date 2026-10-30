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
    // Reject a malformed time filter before scanning a large trash.
    let now = chrono::Local::now();
    let after = after.map(|spec| parse_time_spec(spec, &now));
    let before = before.map(|spec| parse_time_spec(spec, &now));
    // A filter that excluded everything must not read as "Trash is empty." (#417).
    let filtered = pattern.is_some() || after.is_some() || before.is_some();

    let progress = ScanProgress::start(!json);
    let entries = store.list_for_display_filtered(pattern, |entry| {
        after.is_none_or(|cutoff| entry.info.deletion_date >= cutoff)
            && before.is_none_or(|cutoff| entry.info.deletion_date <= cutoff)
    });
    drop(progress);
    let entries = match entries {
        Ok(e) => e,
        Err(e) => fatal(e),
    };

    if entries.is_empty() {
        with_buffered_stdout(|out| {
            if json {
                writeln!(out, "[]")
            } else {
                writeln!(out, "{}", empty_listing_message(filtered).dimmed())
            }
        });
        return;
    }

    if json {
        print_json_entries(&entries);
        return;
    }

    // The store's canonical home root: entry roots are canonical, so a
    // symlinked home (ostree, stowed ~/.local) never matched trash_dir().
    let home_trash = store.home_dir();
    let multi_part = entries.iter().any(|e| e.trash_root != home_trash);

    // Stop rendering on a failed write and report final-flush failures (#380).
    // SIGPIPE stays at its default for a closed reader.
    with_buffered_stdout(|out| {
        if multi_part {
            writeln!(
                out,
                "{:<20} {:>10} {:<6} {:<30} {}",
                "DELETED".bold(),
                "SIZE".bold(),
                "DISK".bold(),
                "ORIGINAL PATH".bold(),
                "ID".bold(),
            )?;
        } else {
            writeln!(
                out,
                "{:<20} {:>10} {:<30} {}",
                "DELETED".bold(),
                "SIZE".bold(),
                "ORIGINAL PATH".bold(),
                "ID".bold(),
            )?;
        }

        for entry in &entries {
            let date = entry.info.deletion_date.format("%Y-%m-%d %H:%M");
            let size = entry
                .info
                .size
                .map(format_size)
                .unwrap_or_else(|| "?".into());
            let path = printable_path(&entry.info.original_path);
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
                        .map(|n| printable(&n.to_string_lossy()))
                        .unwrap_or_else(|| "?".into())
                };
                writeln!(
                    out,
                    "{:<20} {:>10} {:<6} {:<30} {}",
                    date,
                    size,
                    disk,
                    path_display,
                    printable(&entry.id).dimmed()
                )?;
            } else {
                writeln!(
                    out,
                    "{:<20} {:>10} {:<30} {}",
                    date,
                    size,
                    path_display,
                    printable(&entry.id).dimmed()
                )?;
            }
        }

        writeln!(out, "\n{} items in trash", entries.len())
    });
}

/// The message an empty listing gets: an unfiltered scan means the trash
/// itself is empty, while a pattern or date filter may have excluded every
/// entry of a non-empty trash (#417).
fn empty_listing_message(filtered: bool) -> &'static str {
    if filtered {
        "No entries match the given filters."
    } else {
        "Trash is empty."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression (#417): a filter that excluded everything printed the same
    // "Trash is empty." as a genuinely empty trash.
    #[test]
    fn filtered_and_unfiltered_empty_listings_differ() {
        assert_eq!(empty_listing_message(false), "Trash is empty.");
        assert_eq!(
            empty_listing_message(true),
            "No entries match the given filters."
        );
    }
}
