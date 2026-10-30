use crate::util::with_buffered_stdout;
use colored::Colorize;
#[allow(unused_imports)]
use std::io::Write as _;

pub fn run(lines: usize) {
    let entries = trashd_common::oplog::read_log(lines);
    if entries.is_empty() {
        println!("{}", "No operations logged yet.".dimmed());
        return;
    }
    // One buffered stream instead of a line-buffered write per entry.
    with_buffered_stdout(|out| {
        for line in &entries {
            writeln!(out, "{line}")?;
        }
        Ok(())
    });
}
