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
