use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore) {
    let progress = ScanProgress::start(true);
    let partitions = store.status_per_partition();
    drop(progress);
    match partitions {
        Ok(partitions) => {
            // Sizes come from sidecars, which anyone can write: never wrap.
            let total_size = partitions
                .iter()
                .fold(0u64, |total, p| total.saturating_add(p.total_size));
            let total_count: usize = partitions.iter().map(|p| p.count).sum();

            println!("{}", "Trash Status".bold().underline());
            println!("  Items:    {total_count}");
            println!("  Size:     {}", format_size(total_size));
            println!();

            if partitions.len() > 1 || partitions.iter().any(|p| p.label != "home") {
                println!("  {}", "Per-partition:".bold());
                for ps in &partitions {
                    println!(
                        "    {} — {} items, {}",
                        printable(&ps.label),
                        ps.count,
                        format_size(ps.total_size),
                    );
                    println!("      {}", printable_path(&ps.trash_dir).dimmed());
                }
            } else if let Some(ps) = partitions.first() {
                println!("  Location: {}", printable_path(&ps.trash_dir));
            }
        }
        Err(e) => fatal(e),
    }
}
