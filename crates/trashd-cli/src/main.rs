mod cli;
mod commands;
mod util;

use clap::Parser;
use cli::{Cli, Commands};

/// Build-time version: release builds set TRASHD_VERSION env var,
/// source builds fall back to Cargo.toml version.
pub const VERSION: &str = match option_env!("TRASHD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

// Die quietly on a closed reader (SIGPIPE, exit 141) like GNU tools, instead
// of Rust's default SIGPIPE-ignore turning the next println! into a panic
// with exit 101 (#129). An inherited SIGCHLD=SIG_IGN (WSL's login) makes the
// kernel reap the installer/editor we spawn, so waiting for it fails ECHILD.
fn main() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
    let cli = Cli::parse();

    // config/log/self-update never touch the store; opening it unconditionally
    // made them fail (and create the trash tree + index) as a side effect —
    // including `trash self-update`, the recovery path for a broken install.
    match cli.command {
        Commands::Log { lines } => commands::log::run(lines),
        Commands::Config(subcmd) => commands::config::run(subcmd),
        Commands::SelfUpdate { check } => commands::self_update::run(check),
        cmd => {
            let store = util::open_store();
            match cmd {
                Commands::Ls {
                    pattern,
                    after,
                    before,
                    json,
                } => commands::ls::run(
                    &store,
                    pattern
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .as_deref(),
                    after.as_deref(),
                    before.as_deref(),
                    json,
                ),
                Commands::Find { query } => commands::find::run(&store, &query.to_string_lossy()),
                Commands::Info { target } => commands::info::run(&store, &target.to_string_lossy()),
                Commands::Restore {
                    target,
                    to,
                    force,
                    all,
                } => commands::restore::run(
                    &store,
                    &target.to_string_lossy(),
                    to.as_deref(),
                    force,
                    all,
                ),
                Commands::Undo => commands::undo::run(&store),
                Commands::Purge { target } => {
                    commands::purge::run(&store, &target.to_string_lossy())
                }
                Commands::Empty {
                    older,
                    dry_run,
                    yes,
                } => commands::empty::run(&store, older.as_deref(), dry_run, yes),
                Commands::Status => commands::status::run(&store),
                Commands::Compress { older, dry_run } => {
                    commands::compress::run(&store, &older, dry_run)
                }
                Commands::Du { top } => commands::du::run(&store, top),
                Commands::Fsck { fix } => commands::fsck::run(&store, fix),
                _ => unreachable!("store-independent commands handled above"),
            }
        }
    }
}
