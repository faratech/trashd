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
        if entry.orphaned {
            continue;
        }
        // symlink_metadata: a trashed SYMLINK must never be compressed —
        // reading through it would slurp its target and renaming the
        // compressed data over it would replace the link with a regular
        // file (#45).
        let stored_meta = match std::fs::symlink_metadata(&entry.trashed_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !stored_meta.is_file() {
            continue;
        }
        let age = now.signed_duration_since(entry.info.deletion_date);
        if age.num_days() < days as i64 {
            continue;
        }
        let size_before = stored_meta.len();
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

        match compress_file_zstd(
            &entry.trashed_path,
            &entry.info_path,
            &entry.info,
            size_before,
        ) {
            Ok(Some(size_after)) => {
                saved += size_before.saturating_sub(size_after);
                compressed += 1;
            }
            Ok(None) => {} // not worth compressing; original untouched
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

/// Compress a trashed entry's data in-place with zstd (streaming, bounded
/// memory). Returns `Some(new_size)` when swapped, `None` when compression
/// wasn't worthwhile.
///
/// Crash-safe ordering (#23): the `X-Trashd-Compressed` marker is recorded
/// BEFORE the compressed data is renamed over the original. A crash in the
// window then leaves plain data with a stale marker — which restore detects
/// (decode failure) and recovers from — instead of zstd bytes with NO marker,
/// which restore would silently serve as "original content". If the final
/// swap fails, the marker is reverted so the entry stays consistent.
fn compress_file_zstd(
    path: &std::path::Path,
    info_path: &std::path::Path,
    info: &trashd_common::trashinfo::TrashInfo,
    size_before: u64,
) -> std::io::Result<Option<u64>> {
    use trashd_common::store::write_trashinfo_atomic;

    let tmp = path.with_extension("zst.tmp");
    {
        let out = std::fs::File::create(&tmp)?;
        let mut enc = zstd::stream::Encoder::new(out, 3)?;
        let mut input = std::fs::File::open(path)?;
        std::io::copy(&mut input, &mut enc)?;
        enc.finish()?;
    }
    let compressed_len = std::fs::metadata(&tmp)?.len();
    if compressed_len >= size_before {
        // Incompressible content — discard the attempt, keep the original.
        let _ = std::fs::remove_file(&tmp);
        return Ok(None);
    }

    // 1) Marker first.
    let mut marked = info.clone();
    marked.compressed = Some("zstd".into());
    write_trashinfo_atomic(info_path, &marked)?;

    // 2) Then the atomic data swap.
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        // Revert the marker: data is still plaintext.
        let _ = write_trashinfo_atomic(info_path, info);
        return Err(e);
    }
    Ok(Some(compressed_len))
}
