use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(_store: &TrashStore, fix: bool) {
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
                    // NEVER delete the data file just because its metadata is
                    // unparseable — the file in files/<id> is intact and is
                    // exactly what the trash bin exists to protect. Quarantine:
                    // leave both the data and the (still-present) sidecar in
                    // place so the data is never auto-orphaned, and tell the
                    // user where to recover it by hand.
                    if fix {
                        println!(
                            "    {} data preserved at {} (metadata unreadable; recover manually)",
                            "kept".green(),
                            file_path.display(),
                        );
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

    // Rebuild SQLite index from .trashinfo files
    if fix {
        print!("\nRebuilding index... ");
        match rebuild_index(&home_trash) {
            Ok(count) => println!("{} ({count} entries)", "done".green()),
            Err(e) => println!("{} {e}", "failed".red()),
        }
    }
}

/// Scan all .trashinfo files and rebuild the SQLite index from scratch.
fn rebuild_index(trash_dir: &std::path::Path) -> Result<usize, Box<dyn std::error::Error>> {
    let info_dir = trash_dir.join("info");
    // Must match the path the store actually reads/writes (store.rs uses the
    // same shared constant), otherwise --fix rebuilds a throwaway file.
    let index_path = trash_dir.join(trashd_common::index::REL_PATH);

    // Ensure parent dir exists
    if let Some(parent) = index_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let index = trashd_common::index::TrashIndex::open(&index_path)?;

    let mut entries = Vec::new();
    if let Ok(dir_entries) = std::fs::read_dir(&info_dir) {
        for entry in dir_entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".trashinfo") {
                continue;
            }
            let id = name.strip_suffix(".trashinfo").unwrap_or(&name).to_string();
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Some(info) = trashd_common::trashinfo::TrashInfo::from_trashinfo(&content) {
                    entries.push((id, info, trash_dir.to_path_buf()));
                }
            }
        }
    }

    let count = index.rebuild(&entries)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // C1: `fsck --fix` must NEVER delete the data file just because its
    // .trashinfo is unparseable — the file in files/<id> is intact and is
    // exactly what the trash bin exists to protect.
    #[test]
    fn fix_preserves_data_on_corrupt_trashinfo() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/fsck-test")
            .join(format!("d-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_DATA_HOME", &dir);

        let store = TrashStore::open().unwrap();
        let trash = TrashStore::trash_dir();
        fs::create_dir_all(trash.join("info")).unwrap();
        fs::create_dir_all(trash.join("files")).unwrap();
        // Corrupt sidecar (not a valid [Trash Info] header) + intact data file.
        fs::write(trash.join("info/keep.trashinfo"), "GARBAGE not a header\n").unwrap();
        fs::write(trash.join("files/keep"), b"precious").unwrap();

        run(&store, true); // fsck --fix

        assert!(
            trash.join("files/keep").exists(),
            "data file must be preserved when its metadata is corrupt"
        );
        assert_eq!(fs::read(trash.join("files/keep")).unwrap(), b"precious");

        let _ = fs::remove_dir_all(&dir);
    }
}
