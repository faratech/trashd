use crate::util::{printable, printable_path};
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore, fix: bool) {
    // Problems found by a check, or left behind by --fix, fail the command
    // so scripts can act on it (#156).
    if !check(store, fix) {
        std::process::exit(1);
    }
}

/// Check (and with `fix`, repair) every trash root. False when problems were
/// found, or --fix left any behind (a failed removal, a kept corrupt sidecar
/// or orphan, an unchecked root).
fn check(store: &TrashStore, fix: bool) -> bool {
    println!("{}", "Checking trash integrity...".bold());

    let roots = store.all_trash_dirs();
    // Label each root only when there is more than one: the common single-root
    // case keeps its historical output.
    let multi = roots.len() > 1;

    let mut found = Findings::default();

    for (trash_dir, label) in &roots {
        if multi {
            println!("\n{} ({})", printable_path(trash_dir), printable(label));
        }
        found.add(check_trash_dir(store, trash_dir, fix));
    }

    let total = found.orphaned_info + found.orphaned_files + found.corrupt_info;
    if total == 0 && found.unchecked == 0 {
        println!("{}", "No problems found.".green().bold());
    } else {
        if total > 0 {
            println!(
                "\n{} problems: {} orphaned trashinfo, {} orphaned files, {} corrupt",
                total, found.orphaned_info, found.orphaned_files, found.corrupt_info,
            );
        }
        // An unlockable root (read-only media) was not checked at all; it
        // used to be reported as one corrupt sidecar.
        if found.unchecked > 0 {
            println!("{} trash root(s) could not be checked", found.unchecked);
        }
        if !fix && total > 0 {
            println!("Run {} to fix.", "trash fsck --fix".bold());
        }
    }

    if fix {
        found.unresolved == 0 && found.unchecked == 0
    } else {
        total == 0 && found.unchecked == 0
    }
}

/// What checking the trash roots found.
#[derive(Debug, Default, PartialEq, Eq)]
struct Findings {
    orphaned_info: usize,
    orphaned_files: usize,
    corrupt_info: usize,
    /// Problems --fix did not resolve.
    unresolved: usize,
    /// Roots that could not be locked for checking.
    unchecked: usize,
}

impl Findings {
    #[cfg(test)]
    fn counts(&self) -> (usize, usize, usize) {
        (self.orphaned_info, self.orphaned_files, self.corrupt_info)
    }

    fn add(&mut self, other: Findings) {
        self.orphaned_info += other.orphaned_info;
        self.orphaned_files += other.orphaned_files;
        self.corrupt_info += other.corrupt_info;
        self.unresolved += other.unresolved;
        self.unchecked += other.unchecked;
    }
}

/// Check one trash root.
fn check_trash_dir(store: &TrashStore, trash_dir: &std::path::Path, fix: bool) -> Findings {
    check_trash_dir_with_listing(store, trash_dir, fix, listing)
}

fn check_trash_dir_with_listing<I: Iterator<Item = std::io::Result<std::fs::DirEntry>>>(
    store: &TrashStore,
    trash_dir: &std::path::Path,
    fix: bool,
    mut listing: impl FnMut(&std::path::Path, &mut usize) -> Option<I>,
) -> Findings {
    let guard = if fix {
        match store.lock_trash_root(trash_dir) {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("Could not lock {}: {e}", printable_path(trash_dir));
                return Findings {
                    unchecked: 1,
                    ..Findings::default()
                };
            }
        }
    } else {
        None
    };
    let info_dir = trash_dir.join("info");
    let files_dir = trash_dir.join("files");

    let mut orphaned_info = 0usize;
    let mut orphaned_files = 0usize;
    let mut corrupt_info = 0usize;
    let mut unresolved = 0usize;
    let mut unchecked = 0usize;
    let mut parser = trashd_common::trashinfo::TrashInfoParser::default();

    // Check for .trashinfo files without matching files
    if let Some(entries) = listing(&info_dir, &mut unchecked) {
        for entry in checked_entries(entries, &info_dir, &mut unchecked) {
            // Raw bytes: a lossy name pointed at a different (missing) data
            // file, so --fix deleted valid sidecars of non-UTF-8 entries (#212).
            use std::os::unix::ffi::OsStrExt;
            let name = entry.file_name();
            let Some(stem) = name.as_bytes().strip_suffix(b".trashinfo") else {
                continue;
            };
            let id = std::ffi::OsStr::from_bytes(stem);
            let file_path = files_dir.join(id);
            // Names are attacker-chosen: never echo control characters.
            let id = printable(&id.to_string_lossy());
            // symlink_metadata (not exists()): a DANGLING symlink in files/
            // is still an entry we must not silently discard by declaring its
            // trashinfo orphaned.
            if std::fs::symlink_metadata(&file_path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                // A fresh sidecar may belong to a trash still in flight: its
                // data lands after it (#169, #212).
                if !trashd_common::store::data_absence_is_retired(&entry.path()) {
                    continue;
                }
                orphaned_info += 1;
                println!("  {} orphaned trashinfo (no file): {}", "WARN".yellow(), id);
                if fix {
                    // Report reality: a sidecar that is actually a directory
                    // or a read-only volume must not print "removed" and
                    // exit 0 with the file still present (#156).
                    match std::fs::remove_file(entry.path()) {
                        Ok(()) => println!("    {}", "removed".green()),
                        Err(e) => {
                            println!("    {} {e}", "failed:".red());
                            unresolved += 1;
                        }
                    }
                }
                continue; // already reported — don't also count as corrupt
            }

            // Check if trashinfo is parseable
            let usable = trashd_common::trashinfo::read_sidecar(&entry.path())
                .ok()
                .and_then(|content| parser.parse(&content))
                .is_some();
            if !usable {
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
                        printable_path(&file_path),
                    );
                    unresolved += 1;
                }
            }
        }
    }

    // Capture candidates while publication is excluded. Use the raw name
    // for sidecar lookup: different Unix names can have the same lossy ID.
    let mut candidates = Vec::new();
    if let Some(entries) = listing(&files_dir, &mut unchecked) {
        for entry in checked_entries(entries, &files_dir, &mut unchecked) {
            let mut info_name = entry.file_name();
            info_name.push(".trashinfo");
            let info_path = info_dir.join(info_name);
            if !sidecar_is_usable(&info_path) {
                candidates.push(entry);
            }
        }
    }

    // Snapshots are needed only for a repair that can actually purge an
    // orphan. Avoid rereading all roots for report-only or clean checks.
    // Index by the actual path both to keep colliding lossy IDs distinct
    // and to avoid a linear search through the trash for every orphan.
    // Only this root is listed: listing every root once per root made a
    // repair quadratic in the number of roots.
    let snapshots: std::collections::HashMap<_, _> = if fix && !candidates.is_empty() {
        store
            .list_root(trash_dir)
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| entry.orphaned)
            .map(|entry| (entry.trashed_path.clone(), entry))
            .collect()
    } else {
        std::collections::HashMap::new()
    };
    drop(guard);
    // Release the guard before asking the user. purge_resolved revalidates
    // the captured entry after consent.
    orphaned_files += candidates.len();
    for entry in candidates {
        let name = entry.file_name();
        println!(
            "  {} orphaned file (no trashinfo): {}",
            "WARN".yellow(),
            printable(&name.to_string_lossy())
        );
        if fix {
            // Orphaned data can be recoverable user data. Require explicit
            // per-item confirmation before permanently deleting it.
            let Some(snapshot) = snapshots.get(&entry.path()) else {
                unresolved += 1;
                continue;
            };
            if crate::util::confirm(&format!(
                "    permanently delete orphaned '{}'? This cannot be undone [y/N] ",
                printable_path(&entry.path())
            )) {
                let res = store.purge_resolved(snapshot);
                match res {
                    Ok(()) => println!("    {}", "removed".green()),
                    Err(e) => {
                        println!("    {} {e}", "failed:".red());
                        unresolved += 1;
                    }
                }
            } else {
                println!(
                    "    {} data preserved at {} (recover manually)",
                    "kept".green(),
                    printable_path(&entry.path())
                );
                unresolved += 1;
            }
        }
    }

    Findings {
        orphaned_info,
        orphaned_files,
        corrupt_info,
        unresolved,
        unchecked: unchecked.min(1),
    }
}

/// A root's `info/` or `files/` listing. One that exists but cannot be read
/// leaves the root unchecked: skipping it printed "No problems found" and
/// exited 0 (#347).
fn listing(dir: &std::path::Path, unchecked: &mut usize) -> Option<std::fs::ReadDir> {
    match std::fs::read_dir(dir) {
        Ok(listing) => Some(listing),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("Could not read {}: {e}", printable_path(dir));
            *unchecked += 1;
            None
        }
    }
}

/// Opening a directory can succeed even when reading its entries fails.
/// Keep useful entries, but never report an incomplete root as clean (#398).
fn checked_entries(
    entries: impl Iterator<Item = std::io::Result<std::fs::DirEntry>>,
    dir: &std::path::Path,
    unchecked: &mut usize,
) -> impl Iterator<Item = std::fs::DirEntry> {
    entries.filter_map(move |entry| match entry {
        Ok(entry) => Some(entry),
        Err(error) => {
            eprintln!("Could not read {}: {error}", printable_path(dir));
            *unchecked += 1;
            None
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn each_directory_read_failure_preserves_other_findings() {
        for failed_dir in ["info", "files"] {
            let fixture = tempfile::tempdir().unwrap();
            let root = fixture.path().join("Trash");
            let store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
            aged_sidecar(
                &root,
                std::ffi::OsStr::new("missing"),
                &fixture.path().join("missing"),
            );
            fs::write(root.join("info/corrupt.trashinfo"), b"invalid metadata").unwrap();
            fs::write(root.join("files/corrupt"), b"recoverable").unwrap();
            fs::write(root.join("files/orphan"), b"recoverable orphan").unwrap();

            let found = check_trash_dir_with_listing(&store, &root, false, |dir, unchecked| {
                listing(dir, unchecked).map(|entries| {
                    let mut entries = entries.collect::<Vec<_>>();
                    if dir.file_name() == Some(std::ffi::OsStr::new(failed_dir)) {
                        // Insert a fault among real directory entries. A
                        // failure of either pass must not hide useful work
                        // before/after it or in the other pass.
                        entries.insert(1, Err(std::io::Error::from_raw_os_error(libc::EIO)));
                    }
                    entries.into_iter()
                })
            });
            assert_eq!(found.counts(), (1, 1, 1), "failed {failed_dir} scan");
            assert_eq!(found.unchecked, 1, "failed {failed_dir} scan");
            assert_eq!(
                fs::read(root.join("files/corrupt")).unwrap(),
                b"recoverable"
            );
            assert_eq!(
                fs::read(root.join("files/orphan")).unwrap(),
                b"recoverable orphan"
            );
        }
    }

    #[test]
    fn directory_iteration_errors_fail_both_fsck_modes() {
        const TEST: &str = "commands::fsck::tests::directory_iteration_errors_fail_both_fsck_modes";
        const CHILD: &str = "TRASHD_FSCK_READDIR_EIO_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // The unfiltered parent owns cleanup: the child deliberately
            // cannot enumerate directories after installing its filter.
            let fixture = tempfile::tempdir().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env(CHILD, fixture.path())
                .env("TRASH_BYPASS", "1")
                .status()
                .unwrap();
            assert!(status.success(), "fsck iteration-error child failed");
            return;
        }

        let root = std::path::PathBuf::from(std::env::var_os(CHILD).unwrap()).join("Trash");
        let store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
        assert!(check(&store, false));
        assert!(check(&store, true));
        let orphan = root.join("files/recoverable");
        fs::write(&orphan, b"preserve this data").unwrap();
        assert!(!check(&store, false));

        // A real kernel fault after opendir succeeds, rather than a failed
        // open or a mocked result. Re-exec confines the irreversible filter.
        let mut filters = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: libc::SYS_getdents64 as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x0005_0000 | libc::EIO as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            },
        ];
        let program = libc::sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_mut_ptr(),
        };
        let installed = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0) == 0
        };
        if !installed {
            eprintln!(
                "SKIP: seccomp fault injection unavailable: {}",
                std::io::Error::last_os_error()
            );
            return;
        }

        let mut listing = fs::read_dir(root.join("info")).unwrap();
        assert_eq!(
            listing.next().unwrap().unwrap_err().raw_os_error(),
            Some(libc::EIO),
            "the opened directory must fail during iteration",
        );
        drop(listing);
        assert!(!check(&store, false), "an incomplete check must fail");
        assert!(!check(&store, true), "an incomplete repair must fail");
        assert_eq!(fs::read(&orphan).unwrap(), b"preserve this data");
    }

    #[test]
    fn special_sidecars_are_reported_without_reading_or_deleting_them() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{FileTypeExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Trash");
        let store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
        let fifo = root.join("info/fifo.trashinfo");
        let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        symlink(&fifo, root.join("info/link.trashinfo")).unwrap();
        fs::create_dir(root.join("info/directory.trashinfo")).unwrap();
        for name in ["fifo", "link", "directory"] {
            fs::write(root.join("files").join(name), b"recoverable").unwrap();
        }

        assert_eq!(check_trash_dir(&store, &root, false).counts(), (0, 3, 3));
        assert!(!check(&store, false), "special sidecars must fail fsck");
        assert!(fifo.symlink_metadata().unwrap().file_type().is_fifo());
        for name in ["fifo", "link", "directory"] {
            assert_eq!(
                fs::read(root.join("files").join(name)).unwrap(),
                b"recoverable"
            );
        }
    }

    #[test]
    fn fix_waits_for_writer_publication() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Trash");
        let store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
        let guard = store.lock_trash_root(&root).unwrap();
        let sidecar = root.join("info/active.trashinfo");
        let info = trashd_common::trashinfo::TrashInfo::new(dir.path().join("source"));
        fs::write(&sidecar, info.to_trashinfo_string()).unwrap();
        let worker_root = root.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let store =
                TrashStore::open_isolated(&worker_root, trashd_common::Config::default()).unwrap();
            started_tx.send(()).unwrap();
            let result = check_trash_dir(&store, &worker_root, true).counts();
            done_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        assert!(sidecar.is_file());
        fs::write(root.join("files/active"), b"complete").unwrap();
        drop(guard);
        assert_eq!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            (0, 0, 0)
        );
        worker.join().unwrap();
        assert_eq!(fs::read(root.join("files/active")).unwrap(), b"complete");
        assert!(sidecar.is_file());
    }

    /// An entry whose sidecar is old enough to be past the in-flight grace.
    fn aged_sidecar(
        root: &std::path::Path,
        id: &std::ffi::OsStr,
        original: &std::path::Path,
    ) -> std::path::PathBuf {
        let mut name = id.to_os_string();
        name.push(".trashinfo");
        let sidecar = root.join("info").join(name);
        let info = trashd_common::trashinfo::TrashInfo::new(original.to_path_buf());
        fs::write(&sidecar, info.to_trashinfo_string()).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&sidecar)
            .unwrap()
            .set_modified(old)
            .unwrap();
        sidecar
    }

    // Regression (#212): a non-UTF-8 entry's data was looked up through a
    // lossy name, looked missing, and --fix deleted its valid sidecar.
    #[test]
    fn fix_keeps_sidecars_of_non_utf8_entries() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Trash");
        let store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
        let id = std::ffi::OsStr::from_bytes(b"report-\xff");
        fs::write(root.join("files").join(id), b"data").unwrap();
        let sidecar = aged_sidecar(&root, id, &dir.path().join(id));
        assert_eq!(check_trash_dir(&store, &root, true).counts(), (0, 0, 0));
        assert!(
            sidecar.exists(),
            "valid sidecar of a non-UTF-8 entry was deleted"
        );
    }

    #[test]
    fn fix_only_purges_the_raw_orphan_that_was_confirmed() {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        use std::process::{Command, Stdio};

        if let Some(root) = std::env::var_os("TRASHD_FSCK_CHILD_ROOT") {
            let root = std::path::PathBuf::from(root);
            let store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
            assert_eq!(check_trash_dir(&store, &root, true).counts(), (0, 2, 0));
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Trash");
        let _store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
        for name in [b"entry-\xff", b"entry-\xfe"] {
            fs::write(
                root.join("files").join(std::ffi::OsStr::from_bytes(name)),
                name,
            )
            .unwrap();
        }
        let entries: Vec<_> = fs::read_dir(root.join("files"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::fsck::tests::fix_only_purges_the_raw_orphan_that_was_confirmed",
                "--nocapture",
            ])
            .env("TRASHD_FSCK_CHILD_ROOT", &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"y\nn\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(!entries[0].exists(), "the confirmed orphan must be deleted");
        assert!(entries[1].exists(), "the declined orphan must be preserved");
    }

    // Regression (#212): a sidecar written moments ago can belong to a trash
    // still in flight (its data lands afterwards), so it is not an orphan yet.
    #[test]
    fn fix_leaves_in_flight_sidecars_alone() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Trash");
        let store = TrashStore::open_isolated(&root, trashd_common::Config::default()).unwrap();
        let sidecar = root.join("info/landing.trashinfo");
        let info = trashd_common::trashinfo::TrashInfo::new(dir.path().join("landing"));
        fs::write(&sidecar, info.to_trashinfo_string()).unwrap();
        check_trash_dir(&store, &root, true);
        assert!(sidecar.exists(), "an in-flight sidecar was removed");
        // Once past the grace period, a sidecar without data is an orphan.
        let aged = aged_sidecar(
            &root,
            std::ffi::OsStr::new("gone"),
            &dir.path().join("gone"),
        );
        check_trash_dir(&store, &root, true);
        assert!(!aged.exists());
    }

    #[test]
    fn clean_and_problem_checks_report_their_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let trash = dir.path().join("Trash");
        let store = TrashStore::open_isolated(&trash, trashd_common::Config::default()).unwrap();
        assert!(check(&store, false), "a clean trash passes");
        fs::write(trash.join("files/orphan"), b"x").unwrap();
        assert!(!check(&store, false), "a found problem fails the check");
    }

    // #347: a root whose listing cannot be read was not checked, so it must
    // not pass as clean.
    #[test]
    fn unreadable_roots_fail_the_check() {
        let dir = tempfile::tempdir().unwrap();
        let trash = dir.path().join("Trash");
        let store = TrashStore::open_isolated(&trash, trashd_common::Config::default()).unwrap();
        fs::remove_dir(trash.join("info")).unwrap();
        assert!(
            check(&store, false),
            "a missing info/ holds nothing to check"
        );
        fs::write(trash.join("info"), b"not a directory").unwrap();
        let found = check_trash_dir(&store, &trash, false);
        assert_eq!(found.unchecked, 1);
        assert!(!check(&store, false));
    }

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

        // The kept corrupt sidecar is a problem --fix left behind (#156).
        assert!(!check(&store, true), "fsck --fix must report failure");

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
