use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, top: usize) {
    let mut entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => fatal(e),
    };

    if entries.is_empty() {
        println!("{}", "Trash is empty.".dimmed());
        return;
    }

    entries.sort_by_key(|b| std::cmp::Reverse(b.info.size.unwrap_or(0)));

    println!(
        "{:>10} {:<30} {}",
        "SIZE".bold(),
        "ORIGINAL PATH".bold(),
        "ID".bold(),
    );

    let total = saturating_total_size(entries.iter().filter_map(|e| e.info.size));
    for entry in entries.iter().take(top) {
        let size = entry
            .info
            .size
            .map(format_size)
            .unwrap_or_else(|| "?".into());
        let path = printable_path(&entry.info.original_path);
        let path_display = truncate_path(&path, 50);
        println!(
            "{:>10} {:<30} {}",
            size,
            path_display,
            printable(&entry.id).dimmed()
        );
    }

    if entries.len() > top {
        println!("  ... and {} more items", entries.len() - top);
    }
    println!("\n{}: {}", "Total".bold(), format_size(total));
}
