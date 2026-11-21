use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore) {
    match store.undo() {
        Ok(path) => println!("{}", restored_confirmation(&path)),
        Err(e) => fatal_untrusted(e),
    }
}

/// The undo confirmation names a path the trash sidecar chose, so it is
/// escaped exactly like `restore`'s output: a trashed name can carry
/// terminal control bytes (#416, #230).
fn restored_confirmation(path: &std::path::Path) -> String {
    format!("{} {}", "Restored:".green().bold(), printable_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression (#416): undo printed `path.display()` raw, so a crafted
    // filename moved the cursor or recolored the terminal after the restore.
    #[test]
    fn undo_confirmation_escapes_control_characters() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let path = std::path::Path::new(OsStr::from_bytes(b"/tmp/work/esc\x1b[31mred\n.txt"));
        let message = restored_confirmation(path);
        assert!(
            message.ends_with("/tmp/work/esc\\u{1b}[31mred\\u{a}.txt"),
            "unescaped confirmation: {message:?}"
        );
    }
}
