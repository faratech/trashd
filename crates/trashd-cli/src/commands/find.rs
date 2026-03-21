use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, query: &str) {
    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => fatal(e),
    };

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| {
            let path_str = e.info.original_path.to_string_lossy();
            path_str.contains(query) || e.id.contains(query)
        })
        .collect();

    if matches.is_empty() {
        println!("{}", format!("No matches for '{query}'.").dimmed());
        return;
    }

    for entry in &matches {
        let date = entry.info.deletion_date.format("%Y-%m-%d %H:%M");
        let size = entry
            .info
            .size
            .map(format_size)
            .unwrap_or_else(|| "?".into());
        println!(
            "{:<20} {:>10} {} {}",
            date,
            size,
            entry.info.original_path.display(),
            entry.id.dimmed(),
        );
    }
    println!("\n{} matches", matches.len());
}
