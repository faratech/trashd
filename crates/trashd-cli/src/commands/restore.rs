use crate::util::*;
use colored::Colorize;
use std::path::Path;
use trashd_common::TrashStore;
use trashd_common::store::{TrashEntry, TrashError};

pub fn run(
    store: &TrashStore,
    target: &std::ffi::OsStr,
    to: Option<&Path>,
    force: bool,
    all: bool,
) {
    let label = printable(&target.to_string_lossy());
    let mut entries = match store.select_entries(target, all) {
        Ok(Some((_, entries))) => entries,
        Ok(None) if all => fatal(format!("no matches for '{label}'")),
        Ok(None) => fatal(format!("trash entry not found: {label}")),
        Err(error) => fatal(error),
    };
    if all {
        run_all(store, &entries, to, force);
        return;
    }
    if entries.len() > 1 {
        eprintln!(
            "{} '{}' matches {} items. Use the exact trash ID, or --all to restore all:",
            "trash: ambiguous:".yellow().bold(),
            label,
            entries.len()
        );
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
                printable_path(&entry.info.original_path),
                printable_path(&entry.trashed_path).dimmed()
            );
        }
        eprintln!(
            "\n  {} {}",
            "trash restore".bold(),
            printable_path(&entries[0].trashed_path)
        );
        eprintln!("  {} {} --all", "trash restore".bold(), label);
        std::process::exit(1);
    }
    match restore_selected_entry(store, &mut entries[0], to, force) {
        Ok(path) => println!("{} {}", "Restored:".green().bold(), printable_path(&path)),
        Err(error) => fatal(error),
    }
}

fn run_all(store: &TrashStore, entries: &[TrashEntry], to: Option<&Path>, force: bool) {
    let mut restored = 0;
    let mut failed = 0;
    for (entry, result) in entries.iter().zip(store.restore_batch(entries, to, force)) {
        match result {
            Ok(path) => {
                println!("{} {}", "Restored:".green().bold(), printable_path(&path));
                restored += 1;
            }
            Err(e) => {
                eprintln!(
                    "{} {}: {}",
                    "trash: error:".red().bold(),
                    printable(&entry.id),
                    printable(&e.to_string())
                );
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
fn restore_selected_entry(
    store: &TrashStore,
    entry: &mut TrashEntry,
    to: Option<&Path>,
    force: bool,
) -> Result<PathBuf, TrashError> {
    // Keep the same resolved snapshot through conflict handling instead of
    // enumerating every sidecar a second time for one --force restore.
    let mut restore = |destination: Option<&Path>| store.restore_entry(entry, destination);
    match restore(to) {
        Ok(path) => Ok(path),
        Err(TrashError::RestoreConflict(path)) if force => {
            // Auto-rename: try .1, .2, .3, ... off a NORMALIZED base so a
            // trailing-slash `--to backup/` yields the sibling "backup.1",
            // not a hidden "backup/.1" inside the directory (#158).
            let base = trashd_common::store::normalize_conflict_base(&path);
            for i in 1..1000 {
                let mut name = base.as_os_str().to_os_string();
                name.push(format!(".{i}"));
                let renamed = PathBuf::from(name);
                if std::fs::symlink_metadata(&renamed).is_err() {
                    return restore(Some(&renamed));
                }
            }
            Err(TrashError::RestoreConflict(path))
        }
        other => other,
    }
}

#[cfg(test)]
fn restore_entry(
    store: &TrashStore,
    target: &str,
    to: Option<&Path>,
    force: bool,
) -> Result<PathBuf, TrashError> {
    let mut entry = store.find_entry(target)?;
    restore_selected_entry(store, &mut entry, to, force)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn force_restore_keeps_existing_paths_and_uses_the_next_free_suffix() {
        let fixture = tempfile::tempdir().unwrap();
        let mut config = trashd_common::Config::default();
        config.never_trash.clear();
        let store = TrashStore::open_isolated(&fixture.path().join("Trash"), config).unwrap();
        let original = fixture.path().join("document");
        fs::write(&original, b"recover me").unwrap();
        let id = store.trash(&original, None).unwrap();
        fs::write(&original, b"keep original").unwrap();
        fs::write(fixture.path().join("document.1"), b"keep suffix").unwrap();
        assert!(matches!(
            restore_entry(&store, &id, None, false),
            Err(TrashError::RestoreConflict(_))
        ));
        let restored = restore_entry(&store, &id, None, true).unwrap();
        assert_eq!(restored, fixture.path().join("document.2"));
        assert_eq!(fs::read(restored).unwrap(), b"recover me");
        assert_eq!(fs::read(original).unwrap(), b"keep original");
        assert_eq!(
            fs::read(fixture.path().join("document.1")).unwrap(),
            b"keep suffix"
        );
        assert!(store.list(None).unwrap().is_empty());
    }

    #[test]
    fn force_restore_normalizes_a_trailing_slash_destination() {
        let fixture = tempfile::tempdir().unwrap();
        let mut config = trashd_common::Config::default();
        config.never_trash.clear();
        let store = TrashStore::open_isolated(&fixture.path().join("Trash"), config).unwrap();
        let original = fixture.path().join("document");
        fs::write(&original, b"recover me").unwrap();
        let id = store.trash(&original, None).unwrap();
        let destination = fixture.path().join("backup/");
        fs::create_dir(&destination).unwrap();
        let restored = restore_entry(&store, &id, Some(&destination), true).unwrap();
        assert_eq!(restored, fixture.path().join("backup.1"));
        assert_eq!(fs::read(restored).unwrap(), b"recover me");
        assert!(destination.is_dir());
        assert!(fs::read_dir(destination).unwrap().next().is_none());
    }
}
