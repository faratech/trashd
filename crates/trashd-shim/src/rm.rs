use clap::Parser;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use trashd_common::TrashStore;
use trashd_common::store::is_parent_bypassed;

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

    /// Long form of -i / -I. WHEN is never, once, or always (default: always).
    /// Without this, `rm --interactive` failed to parse and fell through to a
    /// PERMANENT delete instead of trashing. require_equals matches GNU's
    /// optional-argument convention and stops a following filename being eaten
    /// as the WHEN value.
    #[arg(long = "interactive", num_args = 0..=1, default_missing_value = "always", require_equals = true, value_name = "WHEN")]
    interactive: Option<String>,

    /// Remove empty directories
    #[arg(short = 'd', long = "dir")]
    dir: bool,

    /// Explain what is being done
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Accepted for GNU rm compatibility (don't cross filesystem boundaries on
    /// recursive delete). Accepting it means we still TRASH rather than fall
    /// through to a permanent delete.
    #[arg(long = "one-file-system")]
    one_file_system: bool,

    /// Accepted for GNU rm compatibility. Optional value `all` is allowed.
    #[arg(long = "preserve-root", num_args = 0..=1, require_equals = true, value_name = "all")]
    preserve_root: Option<String>,

    /// Accepted for GNU rm compatibility.
    #[arg(long = "no-preserve-root")]
    no_preserve_root: bool,

    /// TRASHD: bypass trash and permanently delete
    #[arg(long = "permanent", alias = "no-trash")]
    permanent: bool,

    /// Print version and exit
    #[arg(long = "version")]
    version: bool,

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
        return passthrough_with_args(&[std::ffi::OsString::from("--help")]);
    }

    if args.version {
        println!("trashd rm shim {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    // GNU rm's preserve-root guard, actually enforced: the flags were parsed
    // "for compatibility" and discarded, so `rm -rf /` proceeded to destroy
    // the whole tree (#2). Refuse operands that ARE the root unless
    // --no-preserve-root was given (matches GNU semantics — top-level
    // entries like /* expand to operands that are not "/" itself).
    if args.recursive
        && !args.no_preserve_root
        && args.files.iter().any(is_root_operand)
    {
        eprintln!("rm: it is dangerous to operate recursively on '/'");
        eprintln!("rm: use --no-preserve-root to override the failsafe");
        return ExitCode::FAILURE;
    }

    // Accepted for GNU rm compatibility — parsed so these invocations trash
    // rather than fall through to a permanent delete.
    let _ = (&args.one_file_system, &args.preserve_root);

    // Fold --interactive[=WHEN] into the -i / -I behavior. A bare --interactive
    // maps to "always" via default_missing_value.
    let mut interactive_always = args.interactive_always;
    let mut interactive_once = args.interactive_once;
    match args.interactive.as_deref() {
        Some("always") => interactive_always = true,
        Some("once") => interactive_once = true,
        Some("never") | None => {}
        Some(other) => {
            eprintln!("rm: invalid argument '{other}' for '--interactive'");
            eprintln!("Valid arguments are: 'never', 'once', 'always'");
            return ExitCode::FAILURE;
        }
    }

    // If --permanent, pass through to real rm (stripping our custom flags).
    // args_os (NOT args): argv may contain non-UTF-8 filenames, and
    // std::env::args() PANICS on them — the file would be neither trashed
    // nor deleted (#14).
    if args.permanent {
        let filtered: Vec<std::ffi::OsString> = std::env::args_os()
            .skip(1)
            .filter(|a| a != "--permanent" && a != "--no-trash")
            .collect();
        return passthrough_with_args(&filtered);
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
    if interactive_once && !args.force && args.files.len() > 3 {
        let msg = format!("rm: remove {} arguments? [y/N] ", args.files.len());
        if !prompt_user(&msg) {
            return ExitCode::SUCCESS;
        }
    }

    let cmd_str = format!(
        "rm {}",
        std::env::args_os()
            .skip(1)
            .map(|a| {
                // Lossy only for the log line — the actual file operation
                // uses the original PathBuf.
                let a = a.to_string_lossy();
                if a.contains(' ') || a.contains('\'') || a.contains('"') || a.contains('\\') {
                    format!("'{}'", a.replace('\'', "'\\''"))
                } else {
                    a.into_owned()
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
        if is_dir
            && args.dir
            && !args.recursive
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
        if interactive_always && !args.force {
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
            // Configured guards are REFUSALS, not fallbacks: a size cap or a
            // trash-self-target means "leave the data alone". Escalating to
            // permanent delete would invert the user's intent (#10).
            Err(e @ (trashd_common::store::TrashError::TooLarge { .. }
                     | trashd_common::store::TrashError::Refused(_))) => {
                eprintln!("rm: refusing to remove '{}': {e}", file.display());
                exit_code = ExitCode::FAILURE;
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

/// True when an operand IS the filesystem root ("/", "//", "///", ...).
/// Matches GNU rm's preserve-root guard, which refuses exactly these.
fn is_root_operand(p: &PathBuf) -> bool {
    let mut comps = p.components();
    matches!(comps.next(), Some(std::path::Component::RootDir)) && comps.next().is_none()
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
        if !stash_is_shim(&stashed) {
            return stashed;
        }
        // Poisoned stash: executing a copy of THIS SHIM as the "real" rm
        // recurses without bound (the copy passes through to itself even
        // with TRASH_BYPASS=1). Fall back to PATH discovery instead.
        eprintln!(
            "trashd: warning: {} is a copy of the trashd shim — ignoring it (reinstall to repair)",
            stashed.display()
        );
    }

    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if dir.contains("trashd") {
                continue;
            }
            let candidate = PathBuf::from(dir).join("rm");
            if candidate.exists() && !stash_is_shim(&candidate) {
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

/// Detect a shim masquerading as the real rm (poisoned stash from an older
/// installer that resolved `which rm` while the shim was already on PATH).
/// Probe `--version` ONCE and cache: a genuine rm never mentions "trashd",
/// while the shim identifies itself. Must NOT be called with TRASH_BYPASS in
/// the environment — the probe relies on the shim's `--version` short-circuit
/// (which exits before any passthrough) to avoid recursion.
fn stash_is_shim(path: &PathBuf) -> bool {
    use std::sync::OnceLock;
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::process::Command::new(path)
            .arg("--version")
            .output()
            .map(|o| {
                let out = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                out.contains("trashd")
            })
            .unwrap_or(true) // unreadable/unrunnable — don't trust it
    })
}

fn passthrough() -> ExitCode {
    // args_os: never panic on non-UTF-8 argv (#14)
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    passthrough_with_args(&args)
}

fn passthrough_with_args(args: &[std::ffi::OsString]) -> ExitCode {
    let rm = real_rm_path();
    // Set TRASH_BYPASS=1 so the LD_PRELOAD layer doesn't re-intercept
    // the real rm's unlink() calls when we're passing through.
    match Command::new(&rm)
        .args(args)
        .env("TRASH_BYPASS", "1")
        .status()
    {
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
    // Safety: the shim is single-threaded (no other threads to race with).
    unsafe {
        std::env::set_var("TRASH_BYPASS", "1");
    }
    let result = real_rm_inner(path, recursive);
    unsafe {
        std::env::remove_var("TRASH_BYPASS");
    }
    result
}

fn real_rm_inner(path: &PathBuf, recursive: bool) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;

    if meta.file_type().is_symlink() {
        std::fs::remove_file(path)
    } else if meta.is_dir() {
        if !recursive {
            return Err(std::io::Error::other("Is a directory"));
        }
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard GNU rm options that previously failed to parse — which made the
    // shim fall through to a PERMANENT delete instead of trashing.
    #[test]
    fn parses_gnu_compat_options() {
        for argv in [
            &["rm", "--interactive", "f"][..],
            &["rm", "--interactive=once", "f"][..],
            &["rm", "--interactive=never", "f"][..],
            &["rm", "--one-file-system", "f"][..],
            &["rm", "--preserve-root", "f"][..],
            &["rm", "--preserve-root=all", "f"][..],
            &["rm", "--no-preserve-root", "f"][..],
            &["rm", "--version"][..],
        ] {
            assert!(
                Rm::try_parse_from(argv).is_ok(),
                "should parse (not bypass to permanent delete): {argv:?}"
            );
        }
    }

    // A bare --interactive must default to "always" and NOT swallow the file.
    #[test]
    fn bare_interactive_defaults_to_always_and_keeps_file() {
        let a = Rm::try_parse_from(["rm", "--interactive", "f"]).unwrap();
        assert_eq!(a.interactive.as_deref(), Some("always"));
        assert_eq!(a.files, vec![PathBuf::from("f")]);
    }

    // Regression (audit #2): the preserve-root guard refuses exactly the
    // root operand — "/", "//" etc. — never ordinary absolute paths.
    #[test]
    fn root_operand_detection() {
        assert!(is_root_operand(&PathBuf::from("/")));
        assert!(is_root_operand(&PathBuf::from("//")));
        assert!(!is_root_operand(&PathBuf::from("/tmp")));
        assert!(!is_root_operand(&PathBuf::from("/tmp/")));
        assert!(!is_root_operand(&PathBuf::from("relative")));
        assert!(!is_root_operand(&PathBuf::from(".")));
    }
}
