use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;
use trashd_common::TrashStore;

#[derive(Parser)]
#[command(
    name = "trash",
    about = "trashd — Linux recycle bin for the CLI",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List items in the trash
    Ls {
        /// Filter by glob pattern (e.g. '*.py')
        pattern: Option<String>,
    },
    /// Search trash by original path
    Find {
        /// Path substring or glob pattern to search for
        query: String,
    },
    /// Show full metadata for a trash entry
    Info {
        /// Trash ID or file name
        target: String,
    },
    /// Restore a trashed file by name or ID
    Restore {
        /// File name, trash ID, or glob pattern
        target: String,
        /// Restore to this path instead of original location
        #[arg(long = "to")]
        to: Option<PathBuf>,
    },
    /// Restore the most recently trashed item
    Undo,
    /// Permanently delete a specific trash entry
    Purge {
        /// Trash ID or file name to permanently delete
        target: String,
    },
    /// Permanently empty the trash
    Empty {
        /// Only empty items older than N days (e.g. '7d', '2w')
        #[arg(long)]
        older: Option<String>,
        /// Show what would be deleted without actually deleting
        #[arg(long)]
        dry_run: bool,
    },
    /// Show trash status (size, count, policy)
    Status,
    /// Show recent trash operations (audit log)
    Log {
        /// Number of lines to show (default: 20)
        #[arg(short = 'n', long, default_value = "20")]
        lines: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    let store = match TrashStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    };

    match cli.command {
        Commands::Ls { pattern } => cmd_ls(&store, pattern.as_deref()),
        Commands::Find { query } => cmd_find(&store, &query),
        Commands::Info { target } => cmd_info(&store, &target),
        Commands::Restore { target, to } => cmd_restore(&store, &target, to.as_deref()),
        Commands::Undo => cmd_undo(&store),
        Commands::Purge { target } => cmd_purge(&store, &target),
        Commands::Empty { older, dry_run } => cmd_empty(&store, older.as_deref(), dry_run),
        Commands::Status => cmd_status(&store),
        Commands::Log { lines } => cmd_log(lines),
    }
}

fn cmd_ls(store: &TrashStore, pattern: Option<&str>) {
    let entries = match store.list(pattern) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    };

    if entries.is_empty() {
        println!("{}", "Trash is empty.".dimmed());
        return;
    }

    let home_trash = TrashStore::trash_dir();
    let multi_part = entries.iter().any(|e| e.trash_root != home_trash);

    if multi_part {
        println!(
            "{:<20} {:>10} {:<6} {:<30} {}",
            "DELETED".bold(), "SIZE".bold(), "DISK".bold(),
            "ORIGINAL PATH".bold(), "ID".bold(),
        );
    } else {
        println!(
            "{:<20} {:>10} {:<30} {}",
            "DELETED".bold(), "SIZE".bold(),
            "ORIGINAL PATH".bold(), "ID".bold(),
        );
    }

    for entry in &entries {
        let date = entry.info.deletion_date.format("%Y-%m-%d %H:%M");
        let size = entry.info.size.map(format_size).unwrap_or_else(|| "?".into());
        let path = entry.info.original_path.to_string_lossy();

        let max_path = if multi_part { 40 } else { 50 };
        let path_display = if path.len() > max_path {
            format!("...{}", &path[path.len() - (max_path - 3)..])
        } else {
            path.to_string()
        };

        if multi_part {
            let disk = if entry.trash_root == home_trash {
                "home".to_string()
            } else {
                entry.trash_root.parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "?".into())
            };
            println!("{:<20} {:>10} {:<6} {:<30} {}", date, size, disk, path_display, entry.id.dimmed());
        } else {
            println!("{:<20} {:>10} {:<30} {}", date, size, path_display, entry.id.dimmed());
        }
    }

    println!("\n{} items in trash", entries.len());
}

fn cmd_find(store: &TrashStore, query: &str) {
    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
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
        let size = entry.info.size.map(format_size).unwrap_or_else(|| "?".into());
        println!(
            "{:<20} {:>10} {} {}",
            date, size,
            entry.info.original_path.display(),
            entry.id.dimmed(),
        );
    }
    println!("\n{} matches", matches.len());
}

fn cmd_info(store: &TrashStore, target: &str) {
    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    };

    let entry = entries.iter().find(|e| e.id == target)
        .or_else(|| entries.iter().find(|e| {
            e.info.original_path.file_name()
                .map(|n| n.to_string_lossy() == target)
                .unwrap_or(false)
        }));

    let entry = match entry {
        Some(e) => e,
        None => {
            eprintln!("{} '{target}' not found in trash", "trash: error:".red().bold());
            std::process::exit(1);
        }
    };

    println!("{}", "Trash Entry".bold().underline());
    println!("  ID:            {}", entry.id);
    println!("  Original path: {}", entry.info.original_path.display());
    println!("  Deleted:       {}", entry.info.deletion_date.format("%Y-%m-%d %H:%M:%S"));
    if let Some(ref cmd) = entry.info.command {
        println!("  Command:       {cmd}");
    }
    if let Some(pid) = entry.info.pid {
        println!("  PID:           {pid}");
    }
    if let Some(size) = entry.info.size {
        println!("  Size:          {} ({} bytes)", format_size(size), size);
    }
    if let Some(ref hash) = entry.info.sha256 {
        println!("  SHA-256:       {hash}");
    }
    println!("  Trash dir:     {}", entry.trash_root.display());
    println!("  Stored at:     {}", entry.trashed_path.display());
}

fn cmd_restore(store: &TrashStore, target: &str, to: Option<&std::path::Path>) {
    match store.restore(target, to) {
        Ok(path) => println!("{} {}", "Restored:".green().bold(), path.display()),
        Err(trashd_common::store::TrashError::AmbiguousMatch { pattern, count }) => {
            eprintln!(
                "{} '{}' matches {} items — use trash ID for exact match:",
                "trash: ambiguous:".yellow().bold(), pattern, count,
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
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_undo(store: &TrashStore) {
    match store.undo() {
        Ok(path) => println!("{} {}", "Restored:".green().bold(), path.display()),
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_purge(store: &TrashStore, target: &str) {
    match store.purge(target) {
        Ok(()) => println!("{} permanently deleted '{target}'", "Purged:".green().bold()),
        Err(trashd_common::store::TrashError::AmbiguousMatch { pattern, count }) => {
            eprintln!(
                "{} '{}' matches {} items — use trash ID for exact match",
                "trash: ambiguous:".yellow().bold(), pattern, count,
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
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_empty(store: &TrashStore, older: Option<&str>, dry_run: bool) {
    let days = match older {
        Some(s) => match parse_duration_days(s) {
            Some(d) => Some(d),
            None => {
                eprintln!(
                    "{} invalid duration '{}' (use e.g. '7d', '2w', or a number of days)",
                    "trash: error:".red().bold(), s,
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    if dry_run {
        let entries = match store.list(None) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{} {e}", "trash: error:".red().bold());
                std::process::exit(1);
            }
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
                "Dry run:".yellow().bold(), count, format_size(total_size),
            );
        }
        return;
    }

    match store.empty(days) {
        Ok(count) => {
            if count == 0 {
                println!("{}", "Nothing to empty.".dimmed());
            } else {
                println!("{} permanently deleted {} items", "Emptied:".green().bold(), count);
            }
        }
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_status(store: &TrashStore) {
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
                        ps.label, ps.count, format_size(ps.total_size),
                    );
                    println!("      {}", ps.trash_dir.display().to_string().dimmed());
                }
            } else if let Some(ps) = partitions.first() {
                println!("  Location: {}", ps.trash_dir.display());
            }
        }
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_log(lines: usize) {
    let entries = trashd_common::oplog::read_log(lines);
    if entries.is_empty() {
        println!("{}", "No operations logged yet.".dimmed());
        return;
    }
    for line in &entries {
        println!("{line}");
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn parse_duration_days(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(d) = s.strip_suffix('d') {
        d.trim().parse().ok()
    } else if let Some(w) = s.strip_suffix('w') {
        w.trim().parse::<u32>().ok().map(|w| w * 7)
    } else {
        s.parse().ok()
    }
}
