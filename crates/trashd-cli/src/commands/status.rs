use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore) {
    match store.status_per_partition() {
        Ok(partitions) => {
            let total_size: u64 = partitions.iter().map(|p| p.total_size).sum();
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
                        ps.label,
                        ps.count,
                        format_size(ps.total_size),
                    );
                    println!("      {}", ps.trash_dir.display().to_string().dimmed());
                }
            } else if let Some(ps) = partitions.first() {
                println!("  Location: {}", ps.trash_dir.display());
            }
        }
        Err(e) => fatal(e),
    }
}
