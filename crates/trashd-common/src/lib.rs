pub mod config;
pub mod config_file;
pub mod directorysizes;
pub mod display;
pub mod fdops;
pub(crate) mod local_trust;
pub mod mounts;
pub mod oplog;
pub(crate) mod pattern_policy;
pub mod proc_stat;
pub mod store;
pub mod store_lock;
pub(crate) mod trash_id;
pub mod trashinfo;

pub use config::Config;
pub use mounts::trash_dir_for_path;
pub use store::TrashStore;

/// Diagnostics of modules the standalone preload shares via `#[path]`
/// (legacy_config): the preload routes them through a writer that cannot
/// harm its host process; here they go to stderr.
pub(crate) fn report_note(msg: &str) {
    use std::io::Write;
    #[cfg(test)]
    if test_notes::keep(msg) {
        return;
    }
    let _ = writeln!(std::io::stderr(), "{msg}");
}

/// Test seam: the notes a test's own thread reports, collected instead of
/// printed.
#[cfg(test)]
pub(crate) mod test_notes {
    thread_local! {
        static NOTES: std::cell::RefCell<Option<Vec<String>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(crate) fn keep(msg: &str) -> bool {
        NOTES
            .with_borrow_mut(|notes| notes.as_mut().map(|notes| notes.push(msg.to_owned())))
            .is_some()
    }

    /// What `action` returns, and the notes it reported.
    pub(crate) fn of<T>(action: impl FnOnce() -> T) -> (T, Vec<String>) {
        NOTES.with_borrow_mut(|notes| *notes = Some(Vec::new()));
        let result = action();
        (
            result,
            NOTES.with_borrow_mut(Option::take).unwrap_or_default(),
        )
    }
}
