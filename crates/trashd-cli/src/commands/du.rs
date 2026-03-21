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

    entries.sort_by(|a, b| b.info.size.unwrap_or(0).cmp(&a.info.size.unwrap_or(0)));

    println!(
        "{:>10} {:<30} {}",
        "SIZE".bold(),
        "ORIGINAL PATH".bold(),
        "ID".bold(),
    );

    let total: u64 = entries.iter().filter_map(|e| e.info.size).sum();
    for entry in entries.iter().take(top) {
        let size = entry
            .info
            .size
            .map(format_size)
            .unwrap_or_else(|| "?".into());
        let path = entry.info.original_path.to_string_lossy();
        let path_display = truncate_path(&path, 50);
        println!("{:>10} {:<30} {}", size, path_display, entry.id.dimmed());
    }

    if entries.len() > top {
        println!("  ... and {} more items", entries.len() - top);
    }
    println!("\n{}: {}", "Total".bold(), format_size(total));
}
