use colored::Colorize;

pub fn run(lines: usize) {
    let entries = trashd_common::oplog::read_log(lines);
    if entries.is_empty() {
        println!("{}", "No operations logged yet.".dimmed());
        return;
    }
    for line in &entries {
        println!("{line}");
    }
}
