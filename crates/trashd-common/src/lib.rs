pub mod config;
pub mod directorysizes;
pub mod index;
pub(crate) mod local_trust;
pub mod mounts;
pub mod oplog;
pub mod store;
pub mod store_lock;
pub mod trashinfo;

pub use config::Config;
pub use index::TrashIndex;
pub use mounts::trash_dir_for_path;
pub use store::TrashStore;

/// Diagnostics of modules the standalone preload shares via `#[path]`
/// (legacy_config): the preload routes them through a writer that cannot
/// harm its host process; here they go to stderr.
pub(crate) fn report_note(msg: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{msg}");
}
