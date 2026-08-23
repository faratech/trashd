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
        if is_zstd(&entry.trashed_path) {
            continue;
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
                // Record that trashd compressed this entry so restore
                // decompresses by marker, never by guessing magic bytes
                // (which would corrupt a user's genuine .zst file).
                if size_after < size_before {
                    let mut info = entry.info.clone();
                    info.compressed = Some("zstd".into());
                    let _ = trashd_common::store::write_trashinfo_atomic(&entry.info_path, &info);
                }
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

/// Sniff only the first 4 bytes for the zstd magic (0x28 B5 2F FD
/// little-endian) — never slurp a whole file just to test its header.
fn is_zstd(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && u32::from_le_bytes(magic) == 0xFD2FB528
}

/// Compress a file in-place using zstd. Returns the new size.
///
/// Streams through `io::copy` into the encoder with a bounded internal buffer:
/// entry size must never drive memory use (auto-purge caps at 64 MB, but this
/// command accepts entries of any size). The write still goes through a temp
/// file + rename so a partial write can't corrupt the sole remaining copy.
fn compress_file_zstd(path: &std::path::Path) -> std::io::Result<u64> {
    let size_before = std::fs::metadata(path)?.len();
    let tmp = path.with_extension("zst.tmp");
    {
        let out = std::fs::File::create(&tmp)?;
        let mut enc = zstd::stream::Encoder::new(out, 3)?;
        let mut input = std::fs::File::open(path)?;
        std::io::copy(&mut input, &mut enc)?;
        enc.finish()?;
    }
    let compressed_len = std::fs::metadata(&tmp)?.len();
    if compressed_len < size_before {
        std::fs::rename(&tmp, path)?;
        Ok(compressed_len)
    } else {
        // Incompressible content — discard the attempt, keep the original.
        let _ = std::fs::remove_file(&tmp);
        Ok(size_before)
    }
}
