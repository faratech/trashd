use clap::Parser;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use trashd_common::store::is_parent_bypassed;
use trashd_common::TrashStore;

/// trashd rm shim — drop-in replacement that moves files to trash instead of deleting.
///
/// Supports all standard rm flags. Files are moved to ~/.local/share/Trash/
/// and can be restored with `trash restore` or `trash undo`.
#[derive(Parser)]
#[command(name = "rm", disable_help_flag = true)]
struct Rm {
    /// Remove directories and their contents recursively
    #[arg(short = 'r', short_alias = 'R', long = "recursive")]
    recursive: bool,

    /// Ignore nonexistent files and arguments, never prompt
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Prompt before every removal
    #[arg(short = 'i')]
    interactive_always: bool,

    /// Prompt once before removing more than three files
    #[arg(short = 'I')]
    interactive_once: bool,

    /// Remove empty directories
    #[arg(short = 'd', long = "dir")]
    dir: bool,

    /// Explain what is being done
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// TRASHD: bypass trash and permanently delete
    #[arg(long = "permanent", alias = "no-trash")]
    permanent: bool,

    /// Show help
    #[arg(long = "help")]
    help: bool,

    /// Files and directories to remove
    #[arg(trailing_var_arg = true)]
    files: Vec<PathBuf>,
}

fn main() -> ExitCode {
    // Check bypass env var
    if std::env::var("TRASH_BYPASS").unwrap_or_default() == "1" {
        return passthrough();
    }

    let args = match Rm::try_parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return passthrough();
        }
    };

    if args.help {
        println!("trashd rm — files are moved to trash instead of deleted");
        println!("Use --permanent or TRASH_BYPASS=1 for real deletion");
        println!("Use `trash undo` to restore the last deletion");
        println!("Use `trash ls` to see trashed files\n");
        return passthrough_with_args(&["--help"]);
    }

    // If --permanent, pass through to real rm (stripping our custom flags)
    if args.permanent {
        let filtered: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| a != "--permanent" && a != "--no-trash")
            .collect();
        return passthrough_with_args(&filtered.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    }

    if args.files.is_empty() {
        if args.force {
            return ExitCode::SUCCESS;
        }
        eprintln!("rm: missing operand");
        return ExitCode::FAILURE;
    }

    let store = match TrashStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("trashd: failed to open trash store: {e}");
            eprintln!("trashd: falling back to real rm");
            return passthrough();
        }
    };

    // Check if a parent process is in the bypass list
    if is_parent_bypassed(&store.config().bypass_processes) {
        return passthrough();
    }

    // Handle -I: prompt once if more than 3 files
    if args.interactive_once && !args.force && args.files.len() > 3 {
        let msg = format!("rm: remove {} arguments? [y/N] ", args.files.len());
        if !prompt_user(&msg) {
            return ExitCode::SUCCESS;
        }
    }

    let cmd_str = format!(
        "rm {}",
        std::env::args()
            .skip(1)
            .map(|a| {
                if a.contains(' ') || a.contains('\'') || a.contains('"') || a.contains('\\') {
                    format!("'{}'", a.replace('\'', "'\\''"))
                } else {
                    a
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut exit_code = ExitCode::SUCCESS;

    for file in &args.files {
        let meta = match file.symlink_metadata() {
            Ok(m) => m,
            Err(_) if args.force => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!(
                    "rm: cannot remove '{}': No such file or directory",
                    file.display()
                );
                exit_code = ExitCode::FAILURE;
                continue;
            }
            Err(e) => {
                eprintln!("rm: cannot remove '{}': {e}", file.display());
                exit_code = ExitCode::FAILURE;
                continue;
            }
        };

        let is_dir = meta.is_dir() && !meta.file_type().is_symlink();

        // Check if it's a directory without -r
        if is_dir && !args.recursive && !args.dir {
            eprintln!("rm: cannot remove '{}': Is a directory", file.display());
            exit_code = ExitCode::FAILURE;
            continue;
        }

        // Non-empty dir without -r
        if is_dir && args.dir && !args.recursive
            && std::fs::read_dir(file)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false)
            {
                eprintln!(
                    "rm: cannot remove '{}': Directory not empty",
                    file.display()
                );
                exit_code = ExitCode::FAILURE;
                continue;
            }

        // Handle -i: prompt before each removal
        if args.interactive_always && !args.force {
            let kind = if meta.file_type().is_symlink() {
                "symbolic link"
            } else if is_dir {
                "directory"
            } else {
                "regular file"
            };
            let msg = format!("rm: remove {kind} '{}'? [y/N] ", file.display());
            if !prompt_user(&msg) {
                continue;
            }
        }

        match store.trash(file, Some(&cmd_str)) {
            Ok(id) => {
                if args.verbose {
                    eprintln!("trashed '{}' [{}]", file.display(), id);
                }
                trashd_common::oplog::notify_desktop(
                    "Moved to Trash",
                    &format!("{}", file.display()),
                );
            }
            Err(trashd_common::store::TrashError::Excluded(_)) => {
                if args.verbose {
                    eprintln!("rm (real): '{}'", file.display());
                }
                if let Err(e) = real_rm(file, args.recursive) {
                    eprintln!("rm: cannot remove '{}': {e}", file.display());
                    exit_code = ExitCode::FAILURE;
                }
            }
            Err(e) => {
                eprintln!("trashd: failed to trash '{}': {e}", file.display());
                eprintln!("trashd: falling back to real rm for this file");
                if let Err(e) = real_rm(file, args.recursive) {
                    eprintln!("rm: cannot remove '{}': {e}", file.display());
                    exit_code = ExitCode::FAILURE;
                }
            }
        }
    }

    exit_code
}

/// Prompt user on stderr, return true if they answer 'y' or 'Y'.
fn prompt_user(msg: &str) -> bool {
    eprint!("{msg}");
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim(), "y" | "Y" | "yes" | "Yes" | "YES")
}

/// Find the real rm binary.
fn real_rm_path() -> PathBuf {
    let stashed = PathBuf::from("/usr/local/lib/trashd/real/rm");
    if stashed.exists() {
        return stashed;
    }

    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if dir.contains("trashd") {
                continue;
            }
            let candidate = PathBuf::from(dir).join("rm");
            if candidate.exists() {
                return candidate;
            }
        }
    }

    for path in &["/usr/bin/rm", "/bin/rm"] {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }

    PathBuf::from("/usr/bin/rm")
}

fn passthrough() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    passthrough_with_args(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
}

fn passthrough_with_args(args: &[&str]) -> ExitCode {
    let rm = real_rm_path();
    // Set TRASH_BYPASS=1 so the LD_PRELOAD layer doesn't re-intercept
    // the real rm's unlink() calls when we're passing through.
    match Command::new(&rm).args(args).env("TRASH_BYPASS", "1").status() {
        Ok(status) => {
            if status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(status.code().unwrap_or(1) as u8)
            }
        }
        Err(e) => {
            eprintln!("trashd: failed to exec {}: {e}", rm.display());
            ExitCode::FAILURE
        }
    }
}

/// Remove a file/dir/symlink correctly using symlink_metadata.
/// `recursive` must be true for directories to be removed (matches rm -r semantics).
fn real_rm(path: &PathBuf, recursive: bool) -> std::io::Result<()> {
    // Set TRASH_BYPASS so the LD_PRELOAD layer doesn't re-intercept
    // our unlink/rmdir calls when we genuinely want a real delete.
    std::env::set_var("TRASH_BYPASS", "1");
    let result = real_rm_inner(path, recursive);
    std::env::remove_var("TRASH_BYPASS");
    result
}

fn real_rm_inner(path: &PathBuf, recursive: bool) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;

    if meta.file_type().is_symlink() {
        std::fs::remove_file(path)
    } else if meta.is_dir() {
        if !recursive {
            return Err(std::io::Error::other(
                "Is a directory",
            ));
        }
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}
