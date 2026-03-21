use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

pub fn run(store: &TrashStore) {
    match store.undo() {
        Ok(path) => println!("{} {}", "Restored:".green().bold(), path.display()),
        Err(e) => fatal(e),
    }
}
