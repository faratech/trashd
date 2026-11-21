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
        Err(error) => fatal_untrusted(error),
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
        Err(error) => fatal_untrusted(error),
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
    // The store resolves the conflict itself, on the snapshot it was given:
    // a `.N` name built here from the entry's recorded path came back to it
    // as a destination the user chose, free of the checks that keep a
    // recorded path below its topdir and off symlinks (cli-6).
    if force {
        store.restore_entry_renamed(entry, to)
    } else {
        store.restore_entry(entry, to)
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

    // Regression (cli-2): an error naming a recorded path or ID went to the
    // terminal raw. A crafted sidecar's `Path=...%1B]52;c;...%07` loaded
    // attacker text into the clipboard (OSC 52) through `restore` and `undo`.
    #[test]
    fn restore_and_undo_errors_escape_recorded_paths() {
        const CHILD: &str = "TRASHD_RESTORE_ERROR_CHILD";
        const TEST: &str =
            "commands::restore::tests::restore_and_undo_errors_escape_recorded_paths";
        if let Some(value) = std::env::var_os(CHILD) {
            let (command, root) = value.to_str().unwrap().split_once(':').unwrap();
            let mut config = trashd_common::Config::default();
            config.never_trash.clear();
            let store = TrashStore::open_isolated(Path::new(root), config).unwrap();
            let id = store.list(None).unwrap().remove(0).id;
            match command {
                "restore" => run(&store, id.as_ref(), None, false, false),
                _ => crate::commands::undo::run(&store),
            }
            unreachable!("the conflict must end the command");
        }
        let fixture = tempfile::tempdir().unwrap();
        let mut config = trashd_common::Config::default();
        config.never_trash.clear();
        let root = fixture.path().join("Trash");
        let store = TrashStore::open_isolated(&root, config).unwrap();
        let original = fixture.path().join("name\x1b]52;c;QQ==\x07");
        fs::write(&original, b"recover me").unwrap();
        store.trash(&original, None).unwrap();
        fs::write(&original, b"recreated").unwrap();
        for command in ["restore", "undo"] {
            let value = format!("{command}:{}", root.display());
            let output = crate::util::rerun_test(TEST, CHILD, value.as_ref());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{command}: {stderr}");
            assert!(
                stderr.contains("original path already exists"),
                "{command}: {stderr}"
            );
            assert!(
                !output.stderr.contains(&0x1b) && !output.stderr.contains(&0x07),
                "{command}: raw control bytes reached the terminal: {stderr:?}"
            );
            assert!(stderr.contains("name\\u{1b}]52;c;QQ==\\u{7}"), "{stderr}");
        }
        assert_eq!(fs::read(&original).unwrap(), b"recreated");
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
