use clap::{Arg, Command};
use clap_complete::{generate_to, Shell};
use std::env;
use std::fs;
use std::path::PathBuf;

fn build_cli() -> Command {
    Command::new("trash")
        .version(env!("CARGO_PKG_VERSION"))
        .about("trashd — Linux recycle bin for the CLI")
        .subcommand(
            Command::new("ls")
                .about("List items in the trash")
                .arg(Arg::new("pattern").help("Filter by glob pattern (e.g. '*.py')")),
        )
        .subcommand(
            Command::new("find")
                .about("Search trash by original path")
                .arg(Arg::new("query").required(true).help("Path substring or glob pattern")),
        )
        .subcommand(
            Command::new("info")
                .about("Show full metadata for a trash entry")
                .arg(Arg::new("target").required(true).help("Trash ID or file name")),
        )
        .subcommand(
            Command::new("restore")
                .about("Restore a trashed file by name or ID")
                .arg(Arg::new("target").required(true).help("File name, trash ID, or glob"))
                .arg(Arg::new("to").long("to").help("Restore to this path instead of original location")),
        )
        .subcommand(Command::new("undo").about("Restore the most recently trashed item"))
        .subcommand(
            Command::new("purge")
                .about("Permanently delete a specific trash entry")
                .arg(Arg::new("target").required(true).help("Trash ID or file name to permanently delete")),
        )
        .subcommand(
            Command::new("empty")
                .about("Permanently empty the trash (requires confirmation)")
                .arg(Arg::new("older").long("older").help("Only items older than this (e.g. '7d', '2w')"))
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(clap::ArgAction::SetTrue)
                        .help("Preview what would be deleted without deleting"),
                )
                .arg(
                    Arg::new("yes")
                        .short('y')
                        .long("yes")
                        .action(clap::ArgAction::SetTrue)
                        .help("Skip confirmation prompt"),
                ),
        )
        .subcommand(Command::new("status").about("Show trash status (size, count, per-partition breakdown)"))
        .subcommand(
            Command::new("compress")
                .about("Compress old items in trash to save space (zstd)")
                .arg(
                    Arg::new("older")
                        .long("older")
                        .default_value("7d")
                        .help("Only compress items older than this (e.g. '7d', '2w')"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(clap::ArgAction::SetTrue)
                        .help("Show what would be compressed without doing it"),
                ),
        )
        .subcommand(
            Command::new("du")
                .about("Show largest items in trash sorted by size")
                .arg(
                    Arg::new("top")
                        .short('n')
                        .long("top")
                        .default_value("20")
                        .help("Number of items to show"),
                ),
        )
        .subcommand(
            Command::new("log")
                .about("Show recent trash operations (audit trail)")
                .arg(
                    Arg::new("lines")
                        .short('n')
                        .long("lines")
                        .default_value("20")
                        .help("Number of lines to show"),
                ),
        )
        .subcommand(
            Command::new("fsck")
                .about("Check and repair trash directory integrity")
                .arg(
                    Arg::new("fix")
                        .long("fix")
                        .action(clap::ArgAction::SetTrue)
                        .help("Fix problems (default: report only)"),
                ),
        )
}

fn main() {
    let out_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()),
    )
    .parent()
    .unwrap()
    .parent()
    .unwrap()
    .join("target")
    .join("completions");

    fs::create_dir_all(&out_dir).unwrap();

    let mut cmd = build_cli();
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        generate_to(shell, &mut cmd, "trash", &out_dir).unwrap();
    }

    // Generate man pages
    let man_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()),
    )
    .parent()
    .unwrap()
    .parent()
    .unwrap()
    .join("target")
    .join("man");

    fs::create_dir_all(&man_dir).unwrap();

    let man = clap_mangen::Man::new(build_cli());
    let mut buf = Vec::new();
    man.render(&mut buf).unwrap();
    fs::write(man_dir.join("trash.1"), buf).unwrap();

    for subcmd in build_cli().get_subcommands() {
        let name = format!("trash-{}", subcmd.get_name());
        let static_name: &'static str = Box::leak(name.clone().into_boxed_str());
        let man = clap_mangen::Man::new(subcmd.clone().name(static_name));
        let mut buf = Vec::new();
        man.render(&mut buf).unwrap();
        fs::write(man_dir.join(format!("{name}.1")), buf).unwrap();
    }
}
