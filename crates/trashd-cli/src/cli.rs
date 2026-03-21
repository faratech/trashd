use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "trash",
    about = "trashd — Linux recycle bin for the CLI",
    version = crate::VERSION,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List items in the trash
    Ls {
        /// Filter by glob pattern (e.g. '*.py')
        pattern: Option<String>,
        /// Only show items deleted after this time (e.g. '1h', '30m', '2d', '2026-03-20')
        #[arg(long)]
        after: Option<String>,
        /// Only show items deleted before this time (e.g. '1h', '2d', '2026-03-20')
        #[arg(long)]
        before: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Search trash by original path
    Find {
        /// Path substring or glob pattern to search for
        query: String,
    },
    /// Show full metadata for a trash entry
    Info {
        /// Trash ID or file name
        target: String,
    },
    /// Restore a trashed file by name or ID
    Restore {
        /// File name, trash ID, or glob pattern
        target: String,
        /// Restore to this path instead of original location
        #[arg(long = "to")]
        to: Option<PathBuf>,
        /// Auto-rename if destination exists (append .1, .2, etc.)
        #[arg(long)]
        force: bool,
        /// Restore all matches (for glob patterns)
        #[arg(long)]
        all: bool,
    },
    /// Restore the most recently trashed item
    Undo,
    /// Permanently delete a specific trash entry
    Purge {
        /// Trash ID or file name to permanently delete
        target: String,
    },
    /// Permanently empty the trash
    Empty {
        /// Only empty items older than N days (e.g. '7d', '2w')
        #[arg(long)]
        older: Option<String>,
        /// Show what would be deleted without actually deleting
        #[arg(long)]
        dry_run: bool,
        /// Skip confirmation prompt
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
    /// Show trash status (size, count, policy)
    Status,
    /// Compress old items in trash to save space (zstd)
    Compress {
        /// Only compress items older than this (e.g. '7d', '2w'). Default: 7d
        #[arg(long, default_value = "7d")]
        older: String,
        /// Show what would be compressed without doing it
        #[arg(long)]
        dry_run: bool,
    },
    /// Show largest items in trash sorted by size
    Du {
        /// Number of items to show (default: 20)
        #[arg(short = 'n', long, default_value = "20")]
        top: usize,
    },
    /// Show recent trash operations (audit log)
    Log {
        /// Number of lines to show (default: 20)
        #[arg(short = 'n', long, default_value = "20")]
        lines: usize,
    },
    /// Check and repair trash directory integrity
    Fsck {
        /// Fix problems (default: report only)
        #[arg(long)]
        fix: bool,
    },
    /// View or modify trashd configuration
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Update trashd to the latest release from GitHub
    #[command(name = "self-update")]
    SelfUpdate {
        /// Check for updates without installing
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Show active configuration (merged defaults + global + user)
    Show {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Get a config value
    Get {
        /// Config key (e.g. 'retention.max_age_days', 'max_file_size_mb')
        key: String,
    },
    /// Set a config value in user config (~/.config/trashd/config.toml)
    Set {
        /// Config key (e.g. 'retention.max_age_days', 'max_file_size_mb')
        key: String,
        /// Value to set
        value: String,
    },
    /// Add a value to a list config (never_trash, bypass_processes, etc.)
    Add {
        /// List config key
        key: String,
        /// Value to add
        value: String,
    },
    /// Remove a value from a list config
    Remove {
        /// List config key
        key: String,
        /// Value to remove
        value: String,
    },
    /// Show config file paths
    Path,
    /// Open user config in $EDITOR
    Edit,
    /// Reset user config to defaults (removes ~/.config/trashd/config.toml)
    Reset {
        /// Skip confirmation prompt
        #[arg(short = 'y', long = "yes")]
        yes: bool,
    },
}
