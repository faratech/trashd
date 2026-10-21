use crate::util::*;
use colored::Colorize;
use std::path::Path;
use trashd_common::TrashStore;
use trashd_common::store::TrashError;

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
                        entry.trashed_path.display().to_string().dimmed(),
                    );
                }
                if !entries.is_empty() {
                    // The trashed path is unique even across trash roots (#210).
                    eprintln!(
                        "\n  {} {}",
                        "trash restore".bold(),
                        entries[0].trashed_path.display()
                    );
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
    for (entry, result) in entries.iter().zip(store.restore_batch(&entries, to, force)) {
        match result {
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
    // Keep the same resolved snapshot through conflict handling instead of
    // enumerating every sidecar a second time for one --force restore.
    let mut entry = store.find_entry(target)?;
    let mut restore = |destination: Option<&Path>| store.restore_entry(&mut entry, destination);
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
