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

fn main() {
    let cli = Cli::parse();
    let store = util::open_store();

    match cli.command {
        Commands::Ls {
            pattern,
            after,
            before,
            json,
        } => commands::ls::run(
            &store,
            pattern.as_ref().map(|p| p.to_string_lossy().into_owned()).as_deref(),
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
        } => commands::restore::run(&store, &target.to_string_lossy(), to.as_deref(), force, all),
        Commands::Undo => commands::undo::run(&store),
        Commands::Purge { target } => commands::purge::run(&store, &target.to_string_lossy()),
        Commands::Empty {
            older,
            dry_run,
            yes,
        } => commands::empty::run(&store, older.as_deref(), dry_run, yes),
        Commands::Status => commands::status::run(&store),
        Commands::Compress { older, dry_run } => commands::compress::run(&store, &older, dry_run),
        Commands::Du { top } => commands::du::run(&store, top),
        Commands::Log { lines } => commands::log::run(lines),
        Commands::Fsck { fix } => commands::fsck::run(&store, fix),
        Commands::Config(subcmd) => commands::config::run(subcmd),
        Commands::SelfUpdate { check } => commands::self_update::run(check),
    }
}
