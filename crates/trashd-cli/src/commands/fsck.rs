use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, fix: bool) {
    println!("{}", "Checking trash integrity...".bold());

    let roots = store.all_trash_dirs();
    // Label each root only when there is more than one: the common single-root
    // case keeps its historical output.
    let multi = roots.len() > 1;

    let mut orphaned_info = 0usize;
    let mut orphaned_files = 0usize;
    let mut corrupt_info = 0usize;

    for (trash_dir, label) in &roots {
        if multi {
            println!("\n{} ({})", trash_dir.display(), label);
        }
        let (oi, of, ci) = check_trash_dir(trash_dir, fix);
        orphaned_info += oi;
        orphaned_files += of;
        corrupt_info += ci;
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

    // Rebuild only the HOME index when fixing: the store serves exactly one
    // SQLite index (at the home root); per-mount roots have none, so writing
    // there would just drop unused files (and fail on read-only media).
    // The per-root CHECKS above are what makes fsck multi-partition (#157).
    if fix {
        let home = store.home_dir();
        if roots.iter().any(|(p, _)| p == home) {
            print!("\nRebuilding index in {}... ", home.display());
            match rebuild_index(home) {
                Ok(count) => println!("{} ({count} entries)", "done".green()),
                Err(e) => println!("{} {e}", "failed".red()),
            }
        }
    }
}

/// Check one trash root; returns (orphaned_info, orphaned_files, corrupt_info).
fn check_trash_dir(trash_dir: &std::path::Path, fix: bool) -> (usize, usize, usize) {
    let info_dir = trash_dir.join("info");
    let files_dir = trash_dir.join("files");

    let mut orphaned_info = 0usize;
    let mut orphaned_files = 0usize;
    let mut corrupt_info = 0usize;

    // Check for .trashinfo files without matching files
    if let Ok(entries) = std::fs::read_dir(&info_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".trashinfo") {
                continue;
            }
            let id = name.strip_suffix(".trashinfo").unwrap_or(&name);
            let file_path = files_dir.join(id);
            // symlink_metadata (not exists()): a DANGLING symlink in files/
            // is still an entry we must not silently discard by declaring its
            // trashinfo orphaned.
            if std::fs::symlink_metadata(&file_path).is_err() {
                orphaned_info += 1;
                println!("  {} orphaned trashinfo (no file): {}", "WARN".yellow(), id);
                if fix {
                    // Report reality: a sidecar that is actually a directory
                    // or a read-only volume must not print "removed" and
                    // exit 0 with the file still present (#156).
                    match std::fs::remove_file(entry.path()) {
                        Ok(()) => println!("    {}", "removed".green()),
                        Err(e) => println!("    {} {e}", "failed:".red()),
                    }
                }
                continue; // already reported — don't also count as corrupt
            }

            // Check if trashinfo is parseable
            if let Ok(content) = std::fs::read_to_string(entry.path())
                && trashd_common::trashinfo::TrashInfo::from_trashinfo(&content).is_none()
            {
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

    // Check for files without matching .trashinfo
    if let Ok(entries) = std::fs::read_dir(&files_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let info_path = info_dir.join(format!("{name}.trashinfo"));
            if !sidecar_is_usable(&info_path) {
                orphaned_files += 1;
                println!(
                    "  {} orphaned file (no trashinfo): {}",
                    "WARN".yellow(),
                    name
                );
                if fix {
                    // Orphaned data may be recoverable user data (a crash or a
                    // failed restore can produce exactly this state). Deleting
                    // it permanently in an automatic "fix" is against the
                    // preserve-data philosophy — require explicit per-item
                    // confirmation. symlink_metadata so dangling symlinks are
                    // classified correctly, not followed.
                    let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    if crate::util::confirm(&format!(
                        "    permanently delete orphaned '{}'? This cannot be undone [y/N] ",
                        entry.path().display()
                    )) {
                        let res = if is_dir {
                            std::fs::remove_dir_all(entry.path())
                        } else {
                            std::fs::remove_file(entry.path())
                        };
                        match res {
                            Ok(()) => println!("    {}", "removed".green()),
                            Err(e) => println!("    {} {e}", "failed:".red()),
                        }
                    } else {
                        println!(
                            "    {} data preserved at {} (recover manually)",
                            "kept".green(),
                            entry.path().display()
                        );
                    }
                }
            }
        }
    }

    (orphaned_info, orphaned_files, corrupt_info)
}

/// Whether `files/<id>` has a usable sidecar, matching the store's own
/// classification (`sidecar_version` requires a REGULAR file via
/// symlink_metadata). `exists()` would follow a dangling symlink and
/// misclassify intact data as orphaned/deletable (#99).
fn sidecar_is_usable(info_path: &std::path::Path) -> bool {
    info_path
        .symlink_metadata()
        .map(|m| m.is_file())
        .unwrap_or(false)
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
            if let Ok(content) = std::fs::read_to_string(entry.path())
                && let Some(info) = trashd_common::trashinfo::TrashInfo::from_trashinfo(&content)
            {
                entries.push((id, info, trash_dir.to_path_buf()));
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
        let dir = tempfile::tempdir().unwrap();
        let trash = dir.path().join("Trash");
        let store = TrashStore::open_isolated(&trash, trashd_common::Config::default()).unwrap();
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
    }

    // Regression (#99): a DANGLING sidecar symlink must not make fsck classify
    // intact data as an orphaned file it offers to permanently delete. The
    // classification matches the store's: only a regular-file sidecar is
    // usable, and a symlink — dangling or not — never counts.
    #[test]
    fn sidecar_classification_matches_store_semantics() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular.trashinfo");
        fs::write(&regular, "[Trash Info]\n").unwrap();
        let dangling = dir.path().join("dangling.trashinfo");
        symlink(dir.path().join("nowhere"), &dangling).unwrap();
        let live_link = dir.path().join("link.trashinfo");
        symlink(&regular, &live_link).unwrap();

        assert!(sidecar_is_usable(&regular));
        assert!(
            !sidecar_is_usable(&dangling),
            "dangling symlink is not usable"
        );
        assert!(
            !sidecar_is_usable(&live_link),
            "symlinked sidecar is not usable"
        );
        assert!(!sidecar_is_usable(&dir.path().join("missing.trashinfo")));
    }
}
