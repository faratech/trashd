use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, top: usize) {
    let mut entries = match store.list_for_query(|_| true) {
        Ok(e) => e,
        Err(e) => fatal_untrusted(e),
    };

    if entries.is_empty() {
        println!("{}", "Trash is empty.".dimmed());
        return;
    }

    let total_count = entries.len();
    let total = saturating_total_size(entries.iter().filter_map(|e| e.info.size));
    // Only the top-N rows are shown: partition in O(N) instead of a full
    // O(N log N) sort, then sort just the shown prefix.
    if top > 0 && entries.len() > top {
        entries.select_nth_unstable_by(top - 1, |a, b| {
            b.info.size.unwrap_or(0).cmp(&a.info.size.unwrap_or(0))
        });
        entries.truncate(top);
    }
    entries.sort_by_key(|b| std::cmp::Reverse(b.info.size.unwrap_or(0)));

    with_buffered_stdout(|out| {
        writeln!(
            out,
            "{:>10} {:<30} {}",
            "SIZE".bold(),
            "ORIGINAL PATH".bold(),
            "ID".bold(),
        )?;

        for entry in entries.iter().take(top) {
            let size = entry
                .info
                .size
                .map(format_size)
                .unwrap_or_else(|| "?".into());
            let path = printable_path(&entry.info.original_path);
            let path_display = truncate_path(&path, 50);
            writeln!(
                out,
                "{:>10} {:<30} {}",
                size,
                path_display,
                printable(&entry.id).dimmed()
            )?;
        }

        if total_count > entries.len() {
            writeln!(out, "  ... and {} more items", total_count - entries.len())?;
        }
        writeln!(out, "\n{}: {}", "Total".bold(), format_size(total))
    });
}
