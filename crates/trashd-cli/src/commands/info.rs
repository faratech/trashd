use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, target: &str) {
    let entries = match store.list(None) {
        Ok(e) => e,
        Err(e) => fatal(e),
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
        None => fatal(format!("'{target}' not found in trash")),
    };

    println!("{}", "Trash Entry".bold().underline());
    println!("  ID:            {}", entry.id);
    println!("  Original path: {}", entry.info.original_path.display());
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
