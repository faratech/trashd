use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;
use trashd_common::TrashStore;

/// Build-time version: release builds set TRASHD_VERSION env var,
/// source builds fall back to Cargo.toml version.
const VERSION: &str = match option_env!("TRASHD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(
    name = "trash",
    about = "trashd — Linux recycle bin for the CLI",
    version = VERSION,
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
        /// Only show items deleted after this time (e.g. '1h', '30m', '2d', '2026-03-20')
        #[arg(long)]
        after: Option<String>,
        /// Only show items deleted before this time (e.g. '1h', '2d', '2026-03-20')
        #[arg(long)]
        before: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
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
        /// Auto-rename if destination exists (append .1, .2, etc.)
        #[arg(long)]
        force: bool,
        /// Restore all matches (for glob patterns)
        #[arg(long)]
        all: bool,
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
        /// Skip confirmation prompt
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
    /// Show trash status (size, count, policy)
    Status,
    /// Compress old items in trash to save space (zstd)
    Compress {
        /// Only compress items older than this (e.g. '7d', '2w'). Default: 7d
        #[arg(long, default_value = "7d")]
        older: String,
        /// Show what would be compressed without doing it
        #[arg(long)]
        dry_run: bool,
    },
    /// Show largest items in trash sorted by size
    Du {
        /// Number of items to show (default: 20)
        #[arg(short = 'n', long, default_value = "20")]
        top: usize,
    },
    /// Show recent trash operations (audit log)
    Log {
        /// Number of lines to show (default: 20)
        #[arg(short = 'n', long, default_value = "20")]
        lines: usize,
    },
    /// Check and repair trash directory integrity
    Fsck {
        /// Fix problems (default: report only)
        #[arg(long)]
        fix: bool,
    },
    /// Update trashd to the latest release from GitHub
    #[command(name = "self-update")]
    SelfUpdate {
        /// Check for updates without installing
        #[arg(long)]
        check: bool,
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
        Commands::Ls {
            pattern,
            after,
            before,
            json,
        } => cmd_ls(
            &store,
            pattern.as_deref(),
            after.as_deref(),
            before.as_deref(),
            json,
        ),
        Commands::Find { query } => cmd_find(&store, &query),
        Commands::Info { target } => cmd_info(&store, &target),
        Commands::Restore {
            target,
            to,
            force,
            all,
        } => cmd_restore(&store, &target, to.as_deref(), force, all),
        Commands::Undo => cmd_undo(&store),
        Commands::Purge { target } => cmd_purge(&store, &target),
        Commands::Empty {
            older,
            dry_run,
            yes,
        } => cmd_empty(&store, older.as_deref(), dry_run, yes),
        Commands::Status => cmd_status(&store),
        Commands::Compress { older, dry_run } => cmd_compress(&store, &older, dry_run),
        Commands::Du { top } => cmd_du(&store, top),
        Commands::Log { lines } => cmd_log(lines),
        Commands::Fsck { fix } => cmd_fsck(&store, fix),
        Commands::SelfUpdate { check } => cmd_self_update(check),
    }
}

fn cmd_ls(
    store: &TrashStore,
    pattern: Option<&str>,
    after: Option<&str>,
    before: Option<&str>,
    json: bool,
) {
    let mut entries = match store.list(pattern) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    };

    // Apply time filters
    let now = chrono::Local::now();
    if let Some(after_str) = after {
        let cutoff = parse_time_spec(after_str, &now);
        entries.retain(|e| e.info.deletion_date >= cutoff);
    }
    if let Some(before_str) = before {
        let cutoff = parse_time_spec(before_str, &now);
        entries.retain(|e| e.info.deletion_date <= cutoff);
    }

    if entries.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("{}", "Trash is empty.".dimmed());
        }
        return;
    }

    if json {
        print_json_entries(&entries);
        return;
    }

    let home_trash = TrashStore::trash_dir();
    let multi_part = entries.iter().any(|e| e.trash_root != home_trash);

    if multi_part {
        println!(
            "{:<20} {:>10} {:<6} {:<30} {}",
            "DELETED".bold(),
            "SIZE".bold(),
            "DISK".bold(),
            "ORIGINAL PATH".bold(),
            "ID".bold(),
        );
    } else {
        println!(
            "{:<20} {:>10} {:<30} {}",
            "DELETED".bold(),
            "SIZE".bold(),
            "ORIGINAL PATH".bold(),
            "ID".bold(),
        );
    }

    for entry in &entries {
        let date = entry.info.deletion_date.format("%Y-%m-%d %H:%M");
        let size = entry
            .info
            .size
            .map(format_size)
            .unwrap_or_else(|| "?".into());
        let path = entry.info.original_path.to_string_lossy();

        let max_path = if multi_part { 40 } else { 50 };
        let path_display = if path.len() > max_path {
            let start = path.floor_char_boundary(path.len() - (max_path - 3));
            format!("...{}", &path[start..])
        } else {
            path.to_string()
        };

        if multi_part {
            let disk = if entry.trash_root == home_trash {
                "home".to_string()
            } else {
                entry
                    .trash_root
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "?".into())
            };
            println!(
                "{:<20} {:>10} {:<6} {:<30} {}",
                date,
                size,
                disk,
                path_display,
                entry.id.dimmed()
            );
        } else {
            println!(
                "{:<20} {:>10} {:<30} {}",
                date,
                size,
                path_display,
                entry.id.dimmed()
            );
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

fn cmd_info(store: &TrashStore, target: &str) {
    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    };

    let entry = entries.iter().find(|e| e.id == target).or_else(|| {
        entries.iter().find(|e| {
            e.info
                .original_path
                .file_name()
                .map(|n| n.to_string_lossy() == target)
                .unwrap_or(false)
        })
    });

    let entry = match entry {
        Some(e) => e,
        None => {
            eprintln!(
                "{} '{target}' not found in trash",
                "trash: error:".red().bold()
            );
            std::process::exit(1);
        }
    };

    println!("{}", "Trash Entry".bold().underline());
    println!("  ID:            {}", entry.id);
    println!("  Original path: {}", entry.info.original_path.display());
    println!(
        "  Deleted:       {}",
        entry.info.deletion_date.format("%Y-%m-%d %H:%M:%S")
    );
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
        println!("  Hash:          {hash}");
    }
    println!("  Trash dir:     {}", entry.trash_root.display());
    println!("  Stored at:     {}", entry.trashed_path.display());
}

fn cmd_restore(
    store: &TrashStore,
    target: &str,
    to: Option<&std::path::Path>,
    force: bool,
    all: bool,
) {
    // --all: restore all matches for a glob pattern
    if all {
        let entries = match store.list(Some(target)) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{} {e}", "trash: error:".red().bold());
                std::process::exit(1);
            }
        };
        if entries.is_empty() {
            eprintln!("{} no matches for '{target}'", "trash: error:".red().bold());
            std::process::exit(1);
        }
        let mut restored = 0;
        let mut failed = 0;
        for entry in &entries {
            match restore_entry(store, &entry.id, to, force) {
                Ok(path) => {
                    println!("{} {}", "Restored:".green().bold(), path.display());
                    restored += 1;
                }
                Err(e) => {
                    eprintln!("{} {}: {e}", "trash: error:".red().bold(), entry.id);
                    failed += 1;
                }
            }
        }
        if restored > 0 || failed > 0 {
            println!("\n{} restored, {} failed", restored, failed,);
        }
        if failed > 0 {
            std::process::exit(1);
        }
        return;
    }

    match restore_entry(store, target, to, force) {
        Ok(path) => println!("{} {}", "Restored:".green().bold(), path.display()),
        Err(trashd_common::store::TrashError::AmbiguousMatch { pattern, count }) => {
            eprintln!(
                "{} '{}' matches {} items. Use the exact trash ID, or --all to restore all:",
                "trash: ambiguous:".yellow().bold(),
                pattern,
                count,
            );
            if let Ok(entries) = store.list(Some(&pattern)) {
                for (i, entry) in entries.iter().take(20).enumerate() {
                    eprintln!(
                        "  {:>3}. {} {:>10} {} {}",
                        i + 1,
                        entry.info.deletion_date.format("%Y-%m-%d %H:%M"),
                        entry
                            .info
                            .size
                            .map(format_size)
                            .unwrap_or_else(|| "?".into()),
                        entry.info.original_path.display(),
                        format!("[{}]", entry.id).dimmed(),
                    );
                }
                if !entries.is_empty() {
                    eprintln!("\n  {} {}", "trash restore".bold(), entries[0].id,);
                    eprintln!("  {} {} --all", "trash restore".bold(), target,);
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

/// Restore a single entry, handling --force conflict resolution.
fn restore_entry(
    store: &TrashStore,
    target: &str,
    to: Option<&std::path::Path>,
    force: bool,
) -> Result<PathBuf, trashd_common::store::TrashError> {
    match store.restore(target, to) {
        Ok(path) => Ok(path),
        Err(trashd_common::store::TrashError::RestoreConflict(path)) if force => {
            // Auto-rename: try .1, .2, .3, ...
            let stem = path.to_string_lossy().to_string();
            for i in 1..1000 {
                let renamed = PathBuf::from(format!("{stem}.{i}"));
                if std::fs::symlink_metadata(&renamed).is_err() {
                    return store.restore(target, Some(&renamed));
                }
            }
            Err(trashd_common::store::TrashError::RestoreConflict(path))
        }
        other => other,
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
        Ok(()) => println!(
            "{} permanently deleted '{target}'",
            "Purged:".green().bold()
        ),
        Err(trashd_common::store::TrashError::AmbiguousMatch { pattern, count }) => {
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
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_empty(store: &TrashStore, older: Option<&str>, dry_run: bool, yes: bool) {
    let days = match older {
        Some(s) => match parse_duration_days(s) {
            Some(d) => Some(d),
            None => {
                eprintln!(
                    "{} invalid duration '{}' (use e.g. '7d', '2w', or a number of days)",
                    "trash: error:".red().bold(),
                    s,
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
                "Dry run:".yellow().bold(),
                count,
                format_size(total_size),
            );
        }
        return;
    }

    // Confirmation prompt unless --yes
    if !yes {
        // When --older is set, count only the items that will actually be deleted
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
        eprint!(
            "Permanently delete {} items ({})? [y/N] ",
            prompt_count,
            format_size(prompt_size),
        );
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return;
        }
        if !matches!(input.trim(), "y" | "Y" | "yes" | "Yes" | "YES") {
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
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_compress(store: &TrashStore, older: &str, dry_run: bool) {
    let days = match parse_duration_days(older) {
        Some(d) => d,
        None => {
            eprintln!(
                "{} invalid duration '{older}'",
                "trash: error:".red().bold()
            );
            std::process::exit(1);
        }
    };

    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    };

    let now = chrono::Local::now();
    let mut compressed = 0usize;
    let mut saved = 0u64;

    for entry in &entries {
        if entry.trashed_path.is_dir() || entry.orphaned {
            continue;
        }
        let age = now.signed_duration_since(entry.info.deletion_date);
        if age.num_days() < days as i64 {
            continue;
        }
        let size_before = match std::fs::metadata(&entry.trashed_path) {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if size_before < 1024 {
            continue;
        }
        // Check zstd magic — skip already compressed
        if let Ok(header) = std::fs::read(&entry.trashed_path).map(|d| {
            if d.len() >= 4 {
                u32::from_le_bytes([d[0], d[1], d[2], d[3]])
            } else {
                0
            }
        }) {
            if header == 0xFD2FB528 {
                continue;
            }
        }

        if dry_run {
            println!(
                "  {} {} ({})",
                entry.trashed_path.display(),
                entry.id.dimmed(),
                format_size(size_before),
            );
            compressed += 1;
            continue;
        }

        match compress_file_zstd(&entry.trashed_path) {
            Ok(size_after) => {
                saved += size_before.saturating_sub(size_after);
                compressed += 1;
            }
            Err(e) => {
                eprintln!(
                    "  {} {}: {e}",
                    "warn:".yellow(),
                    entry.trashed_path.display(),
                );
            }
        }
    }

    if dry_run {
        if compressed == 0 {
            println!("{}", "Nothing to compress.".dimmed());
        } else {
            println!(
                "\n{} {} items would be compressed (zstd)",
                "Dry run:".yellow().bold(),
                compressed,
            );
        }
    } else if compressed == 0 {
        println!("{}", "Nothing to compress.".dimmed());
    } else {
        println!(
            "{} compressed {} items, saved {}",
            "Done:".green().bold(),
            compressed,
            format_size(saved),
        );
    }
}

/// Compress a file in-place using zstd. Returns the new size.
fn compress_file_zstd(path: &std::path::Path) -> std::io::Result<u64> {
    let data = std::fs::read(path)?;
    let compressed = zstd::encode_all(data.as_slice(), 3)?;
    if compressed.len() < data.len() {
        // Write to temp file + rename to avoid corrupting the original on partial write
        let tmp = path.with_extension("zst.tmp");
        std::fs::write(&tmp, &compressed)?;
        std::fs::rename(&tmp, path)?;
        Ok(compressed.len() as u64)
    } else {
        Ok(data.len() as u64)
    }
}

fn cmd_du(store: &TrashStore, top: usize) {
    let mut entries = match store.list(None) {
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
        let path_display = if path.len() > 50 {
            let start = path.floor_char_boundary(path.len() - 47);
            format!("...{}", &path[start..])
        } else {
            path.to_string()
        };
        println!("{:>10} {:<30} {}", size, path_display, entry.id.dimmed());
    }

    if entries.len() > top {
        println!("  ... and {} more items", entries.len() - top);
    }
    println!("\n{}: {}", "Total".bold(), format_size(total));
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
        Err(e) => {
            eprintln!("{} {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn cmd_fsck(_store: &TrashStore, fix: bool) {
    let home_trash = TrashStore::trash_dir();
    let info_dir = home_trash.join("info");
    let files_dir = home_trash.join("files");

    let mut orphaned_info = 0usize;
    let mut orphaned_files = 0usize;
    let mut corrupt_info = 0usize;

    println!("{}", "Checking trash integrity...".bold());

    // Check for .trashinfo files without matching files
    if let Ok(entries) = std::fs::read_dir(&info_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".trashinfo") {
                continue;
            }
            let id = name.strip_suffix(".trashinfo").unwrap_or(&name);
            let file_path = files_dir.join(id);
            if !file_path.exists() {
                orphaned_info += 1;
                println!("  {} orphaned trashinfo (no file): {}", "WARN".yellow(), id);
                if fix {
                    let _ = std::fs::remove_file(entry.path());
                    println!("    {}", "removed".green());
                }
                continue; // already reported — don't also count as corrupt
            }

            // Check if trashinfo is parseable
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if trashd_common::trashinfo::TrashInfo::from_trashinfo(&content).is_none() {
                    corrupt_info += 1;
                    println!("  {} corrupt trashinfo: {}", "WARN".yellow(), id);
                    if fix {
                        let _ = std::fs::remove_file(entry.path());
                        let _ = std::fs::remove_file(&file_path);
                        println!("    {}", "removed".green());
                    }
                }
            }
        }
    }

    // Check for files without matching .trashinfo
    if let Ok(entries) = std::fs::read_dir(&files_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let info_path = info_dir.join(format!("{name}.trashinfo"));
            if !info_path.exists() {
                orphaned_files += 1;
                println!(
                    "  {} orphaned file (no trashinfo): {}",
                    "WARN".yellow(),
                    name
                );
                if fix {
                    let meta = entry.metadata();
                    if meta.map(|m| m.is_dir()).unwrap_or(false) {
                        let _ = std::fs::remove_dir_all(entry.path());
                    } else {
                        let _ = std::fs::remove_file(entry.path());
                    }
                    println!("    {}", "removed".green());
                }
            }
        }
    }

    let total = orphaned_info + orphaned_files + corrupt_info;
    if total == 0 {
        println!("{}", "No problems found.".green().bold());
    } else {
        println!(
            "\n{} problems: {} orphaned trashinfo, {} orphaned files, {} corrupt",
            total, orphaned_info, orphaned_files, corrupt_info,
        );
        if !fix {
            println!("Run {} to fix.", "trash fsck --fix".bold());
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

// ---------------------------------------------------------------------------
// Time parsing and JSON output
// ---------------------------------------------------------------------------

/// Parse a time specification into a DateTime.
/// Supports relative durations (e.g., "1h", "30m", "2d", "1w") and
/// absolute dates (e.g., "2026-03-20", "2026-03-20T14:00").
fn parse_time_spec(
    s: &str,
    now: &chrono::DateTime<chrono::Local>,
) -> chrono::DateTime<chrono::Local> {
    let s = s.trim();

    // Relative: "30m", "1h", "2d", "1w"
    if let Some(mins) = s.strip_suffix('m').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::minutes(mins);
    }
    if let Some(hours) = s.strip_suffix('h').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::hours(hours);
    }
    if let Some(days) = s.strip_suffix('d').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::days(days);
    }
    if let Some(weeks) = s.strip_suffix('w').and_then(|v| v.parse::<i64>().ok()) {
        return *now - chrono::Duration::weeks(weeks);
    }

    // Absolute: "2026-03-20T14:00:00" or "2026-03-20"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        if let Some(local) = dt.and_local_timezone(chrono::Local).single() {
            return local;
        }
    }
    if let Ok(dt) =
        chrono::NaiveDateTime::parse_from_str(&format!("{s}T00:00:00"), "%Y-%m-%dT%H:%M:%S")
    {
        if let Some(local) = dt.and_local_timezone(chrono::Local).single() {
            return local;
        }
    }

    eprintln!(
        "{} invalid time spec '{s}' — use e.g. '1h', '2d', '1w', or '2026-03-20'",
        "trash: error:".red().bold(),
    );
    std::process::exit(1);
}

fn print_json_entries(entries: &[trashd_common::store::TrashEntry]) {
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "original_path": e.info.original_path.to_string_lossy(),
                "deletion_date": e.info.deletion_date.format("%Y-%m-%dT%H:%M:%S").to_string(),
                "size": e.info.size,
                "command": e.info.command,
                "trash_dir": e.trash_root.to_string_lossy(),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".into())
    );
}

// ---------------------------------------------------------------------------
// self-update
// ---------------------------------------------------------------------------

const GITHUB_REPO: &str = "faratech/trashd";

#[derive(serde::Deserialize)]
struct GhRelease {
    tag_name: String,
    #[allow(dead_code)]
    html_url: String,
    prerelease: bool,
    assets: Vec<GhAsset>,
}

#[derive(serde::Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// Path to the update check marker file.
fn update_check_marker() -> PathBuf {
    let cache_dir = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())).join(".cache")
        });
    cache_dir.join("trashd").join("last-update-check")
}

/// Returns the cached latest version if the last check was recent enough,
/// or None if a fresh check is needed.
fn cached_update_check() -> Option<String> {
    let marker = update_check_marker();
    let meta = std::fs::metadata(&marker).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    // Debounce: skip network check if last check was < 24 hours ago
    if age.as_secs() < 86400 {
        std::fs::read_to_string(&marker).ok()
    } else {
        None
    }
}

/// Write the latest version to the marker file so subsequent checks are debounced.
fn write_update_check_cache(version: &str) {
    let marker = update_check_marker();
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, version);
}

fn cmd_self_update(check_only: bool) {
    let current = VERSION;

    // Use cached result if available (debounce 24h), unless user is
    // explicitly running `self-update` without --check (i.e., wants to install).
    let release = if check_only {
        if let Some(cached) = cached_update_check() {
            if cached == current {
                println!(
                    "{} trashd {} is already the latest version.",
                    "Up to date:".green().bold(),
                    current,
                );
                return;
            }
            println!(
                "{} {} -> {}",
                "Update available:".yellow().bold(),
                current.dimmed(),
                cached.bold(),
            );
            println!("\nRun {} to install.", "trash self-update".bold());
            return;
        }
        // Cache miss — do a fresh check
        eprint!("Checking for updates... ");
        match fetch_latest_release() {
            Ok(r) => {
                eprintln!("{}", "done".green());
                let v = r
                    .tag_name
                    .strip_prefix('v')
                    .unwrap_or(&r.tag_name)
                    .to_string();
                write_update_check_cache(&v);
                r
            }
            Err(e) => {
                eprintln!("{}", "failed".red());
                eprintln!("{} {e}", "trash: error:".red().bold());
                std::process::exit(1);
            }
        }
    } else {
        // Actual update — always fetch fresh
        eprint!("Checking for updates... ");
        match fetch_latest_release() {
            Ok(r) => {
                eprintln!("{}", "done".green());
                let v = r
                    .tag_name
                    .strip_prefix('v')
                    .unwrap_or(&r.tag_name)
                    .to_string();
                write_update_check_cache(&v);
                r
            }
            Err(e) => {
                eprintln!("{}", "failed".red());
                eprintln!("{} {e}", "trash: error:".red().bold());
                std::process::exit(1);
            }
        }
    };

    let latest = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);

    if latest == current {
        println!(
            "{} trashd {} is already the latest version.",
            "Up to date:".green().bold(),
            current,
        );
        return;
    }

    println!(
        "{} {} -> {}",
        "Update available:".yellow().bold(),
        current.dimmed(),
        latest.bold(),
    );

    if release.prerelease {
        println!("  {}", "(pre-release)".yellow());
    }

    if check_only {
        println!("\nRun {} to install.", "trash self-update".bold());
        return;
    }

    // Find the right tarball for this architecture
    let arch = std::env::consts::ARCH;
    let tarball_arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            eprintln!(
                "{} unsupported architecture: {other}",
                "trash: error:".red().bold(),
            );
            std::process::exit(1);
        }
    };

    let tarball_prefix = format!("trashd-{latest}-linux-{tarball_arch}");
    let tarball_name = format!("{tarball_prefix}.tar.gz");
    let sha_name = format!("{tarball_name}.sha256");

    let tarball_asset = release.assets.iter().find(|a| a.name == tarball_name);
    let sha_asset = release.assets.iter().find(|a| a.name == sha_name);

    let tarball_asset = match tarball_asset {
        Some(a) => a,
        None => {
            eprintln!(
                "{} no release artifact for {tarball_arch}",
                "trash: error:".red().bold(),
            );
            eprintln!("Expected: {tarball_name}");
            eprintln!(
                "Available: {}",
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(1);
        }
    };

    // Confirm
    eprint!(
        "Download and install trashd {latest} ({})? [y/N] ",
        format_size(tarball_asset.size),
    );
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return;
    }
    if !matches!(input.trim(), "y" | "Y" | "yes" | "Yes" | "YES") {
        println!("{}", "Cancelled.".dimmed());
        return;
    }

    // Download to temp dir
    let tmp_dir = std::env::temp_dir().join(format!("trashd-update-{latest}"));
    if tmp_dir.exists() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
    std::fs::create_dir_all(&tmp_dir).unwrap_or_else(|e| {
        eprintln!("{} create temp dir: {e}", "trash: error:".red().bold());
        std::process::exit(1);
    });

    let tarball_path = tmp_dir.join(&tarball_name);

    // Download tarball
    eprint!("Downloading {}... ", tarball_name);
    if let Err(e) = download_file(&tarball_asset.browser_download_url, &tarball_path) {
        eprintln!("{}", "failed".red());
        eprintln!("{} {e}", "trash: error:".red().bold());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::process::exit(1);
    }
    eprintln!("{}", "done".green());

    // Verify checksum if available
    if let Some(sha_asset) = sha_asset {
        eprint!("Verifying checksum... ");
        let sha_path = tmp_dir.join(&sha_name);
        if let Err(e) = download_file(&sha_asset.browser_download_url, &sha_path) {
            eprintln!("{}", "failed".red());
            eprintln!("{} download checksum: {e}", "trash: error:".red().bold());
            let _ = std::fs::remove_dir_all(&tmp_dir);
            std::process::exit(1);
        }
        if let Err(e) = verify_sha256(&tarball_path, &sha_path) {
            eprintln!("{}", "FAILED".red().bold());
            eprintln!("{} {e}", "trash: error:".red().bold());
            let _ = std::fs::remove_dir_all(&tmp_dir);
            std::process::exit(1);
        }
        eprintln!("{}", "ok".green());
    }

    // Extract tarball
    eprint!("Extracting... ");
    if let Err(e) = extract_tarball(&tarball_path, &tmp_dir) {
        eprintln!("{}", "failed".red());
        eprintln!("{} {e}", "trash: error:".red().bold());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::process::exit(1);
    }
    eprintln!("{}", "done".green());

    // Run install.sh from the extracted directory
    let install_dir = tmp_dir.join(&tarball_prefix);
    let install_script = install_dir.join("install.sh");
    if !install_script.exists() {
        eprintln!(
            "{} install.sh not found in release tarball",
            "trash: error:".red().bold(),
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::process::exit(1);
    }

    println!("\n{}", "Running installer...".bold());
    let status = std::process::Command::new("sudo")
        .arg("bash")
        .arg(&install_script)
        .env("TRASH_BYPASS", "1")
        .current_dir(&install_dir)
        .status();

    // Clean up temp dir
    let _ = std::fs::remove_dir_all(&tmp_dir);

    match status {
        Ok(s) if s.success() => {
            println!(
                "\n{} trashd updated to {}",
                "Success:".green().bold(),
                latest.bold(),
            );
        }
        Ok(s) => {
            eprintln!(
                "{} installer exited with {}",
                "trash: error:".red().bold(),
                s,
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{} run installer: {e}", "trash: error:".red().bold());
            std::process::exit(1);
        }
    }
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .new_agent()
}

fn fetch_latest_release() -> Result<GhRelease, String> {
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let resp = http_agent()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "trashd-self-update")
        .call()
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let release: GhRelease = resp
        .into_body()
        .read_json()
        .map_err(|e| format!("parse release JSON: {e}"))?;
    Ok(release)
}

fn download_file(url: &str, dest: &std::path::Path) -> Result<(), String> {
    let resp = http_agent()
        .get(url)
        .header("User-Agent", "trashd-self-update")
        .call()
        .map_err(|e| format!("download failed: {e}"))?;

    let mut reader = resp.into_body().into_reader();
    let mut file = std::fs::File::create(dest).map_err(|e| format!("create file: {e}"))?;
    std::io::copy(&mut reader, &mut file).map_err(|e| format!("write file: {e}"))?;
    Ok(())
}

fn verify_sha256(tarball: &std::path::Path, sha_file: &std::path::Path) -> Result<(), String> {
    // sha256sum format: "<hash>  <filename>\n"
    let content =
        std::fs::read_to_string(sha_file).map_err(|e| format!("read checksum file: {e}"))?;
    let expected = content
        .split_whitespace()
        .next()
        .ok_or("empty checksum file")?
        .to_lowercase();

    // Compute SHA-256 of the tarball
    use std::io::Read;
    let mut file = std::fs::File::open(tarball).map_err(|e| format!("open tarball: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read tarball: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hasher.hexdigest();

    if actual != expected {
        return Err(format!(
            "checksum mismatch\n  expected: {expected}\n  actual:   {actual}",
        ));
    }
    Ok(())
}

fn extract_tarball(tarball: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    let file = std::fs::File::open(tarball).map_err(|e| format!("open tarball: {e}"))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    archive.unpack(dest).map_err(|e| format!("extract: {e}"))?;
    Ok(())
}

/// Minimal SHA-256 implementation (avoids adding a crypto dependency).
struct Sha256 {
    state: [u32; 8],
    buf: Vec<u8>,
    total_len: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: Vec::new(),
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().unwrap();
            self.compress(&block);
            self.buf.drain(..64);
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn hexdigest(mut self) -> String {
        // Padding
        let bit_len = self.total_len * 8;
        self.buf.push(0x80);
        while self.buf.len() % 64 != 56 {
            self.buf.push(0);
        }
        self.buf.extend_from_slice(&bit_len.to_be_bytes());
        // Process remaining blocks
        let remaining = self.buf.clone();
        for chunk in remaining.chunks(64) {
            let block: [u8; 64] = chunk.try_into().unwrap();
            self.compress(&block);
        }
        self.state.iter().map(|s| format!("{s:08x}")).collect()
    }
}
