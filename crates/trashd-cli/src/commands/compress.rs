use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, older: &str, dry_run: bool) {
    let days = match parse_duration_days(older) {
        Some(d) => d,
        None => fatal(format!("invalid duration '{older}'")),
    };

    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => fatal(e),
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
