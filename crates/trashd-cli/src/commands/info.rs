use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;
use trashd_common::store::TrashError;

pub fn run(store: &TrashStore, target: &str) {
    // Same resolution as restore/purge (find_entry): unique-ID preference,
    // filename fallback, and refusal on cross-root ambiguous IDs — first-match
    // here could describe the wrong copy (#148).
    let entry = match store.find_entry(target) {
        Ok(e) => e,
        Err(TrashError::AmbiguousMatch { pattern, count }) => fatal(format!(
            "'{pattern}' matches {count} entries in different trash roots — \
             pass one entry's trashed path (from 'trash ls --json <pattern>') to select it"
        )),
        // A listing failure must surface as itself, not masquerade as "not
        // found" (restore/purge share find_entry and do the same).
        Err(e @ (TrashError::Io(_) | TrashError::Index(_))) => fatal(e),
        Err(_) => fatal(format!("'{target}' not found in trash")),
    };

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
