use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, target: &std::ffi::OsStr) {
    let label = printable(&target.to_string_lossy());
    let mut entries = match store.select_entries(target, false) {
        Ok(Some((_, entries))) => entries,
        Ok(None) => fatal(format!("'{label}' not found in trash")),
        Err(error) => fatal(error),
    };
    if entries.len() > 1 {
        eprintln!(
            "{} '{}' matches {} entries — pass one entry's trashed path (right column) to select it",
            "trash: ambiguous:".yellow().bold(),
            label,
            entries.len(),
        );
        for entry in entries.iter().take(10) {
            eprintln!(
                "  {} {} {}",
                entry.info.deletion_date.format("%Y-%m-%d %H:%M"),
                printable_path(&entry.info.original_path),
                printable_path(&entry.trashed_path).dimmed()
            );
        }
        std::process::exit(1);
    }
    let entry = entries.remove(0);

    println!("{}", "Trash Entry".bold().underline());
    println!("  ID:            {}", printable(&entry.id));
    println!(
        "  Original path: {}",
        printable_path(&entry.info.original_path)
    );
    println!(
        "  Deleted:       {}",
        entry.info.deletion_date.format("%Y-%m-%d %H:%M:%S")
    );

    // File type from the trashed copy
    let file_type = match std::fs::symlink_metadata(&entry.trashed_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                "symlink"
            } else if meta.is_dir() {
                "directory"
            } else {
                "file"
            }
        }
        Err(_) => "missing",
    };
    println!("  Type:          {file_type}");

    if let Some(ref cmd) = entry.info.command {
        println!("  Command:       {}", printable(cmd));
    }
    if let Some(pid) = entry.info.pid {
        println!("  PID:           {pid}");
    }
    if let Some(size) = entry.info.size {
        println!("  Size:          {} ({} bytes)", format_size(size), size);
    }
    if let Some(ref hash) = entry.info.sha256 {
        println!("  Hash:          {}", printable(hash));
    }
    println!("  Trash dir:     {}", printable_path(&entry.trash_root));
    println!("  Stored at:     {}", printable_path(&entry.trashed_path));
}
