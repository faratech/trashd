use crate::util::*;
use colored::Colorize;
use std::path::Path;
use trashd_common::store::TrashError;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, target: &str, to: Option<&Path>, force: bool, all: bool) {
    if all {
        run_all(store, target, to, force);
        return;
    }

    match restore_entry(store, target, to, force) {
        Ok(path) => println!("{} {}", "Restored:".green().bold(), path.display()),
        Err(TrashError::AmbiguousMatch { pattern, count }) => {
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
        Err(e) => fatal(e),
    }
}

fn run_all(store: &TrashStore, target: &str, to: Option<&Path>, force: bool) {
    let entries = match store.list(Some(target)) {
        Ok(e) => e,
        Err(e) => fatal(e),
    };
    if entries.is_empty() {
        fatal(format!("no matches for '{target}'"));
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
        println!("\n{} restored, {} failed", restored, failed);
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

/// Restore a single entry, handling --force conflict resolution.
fn restore_entry(
    store: &TrashStore,
    target: &str,
    to: Option<&Path>,
    force: bool,
) -> Result<PathBuf, TrashError> {
    match store.restore(target, to) {
        Ok(path) => Ok(path),
        Err(TrashError::RestoreConflict(path)) if force => {
            // Auto-rename: try .1, .2, .3, ...
            let stem = path.to_string_lossy().to_string();
            for i in 1..1000 {
                let renamed = PathBuf::from(format!("{stem}.{i}"));
                if std::fs::symlink_metadata(&renamed).is_err() {
                    return store.restore(target, Some(&renamed));
                }
            }
            Err(TrashError::RestoreConflict(path))
        }
        other => other,
    }
}
