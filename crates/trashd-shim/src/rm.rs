use clap::{CommandFactory, FromArgMatches, Parser};
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
#[command(name = "rm", disable_help_flag = true, args_override_self = true)]
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

    /// Prompt once before recursive removal or removing more than three files
    #[arg(short = 'I')]
    interactive_once: bool,

    /// Long form of -i / -I. WHEN is never, once, or always (default: always).
    /// Without this, `rm --interactive` failed to parse and fell through to a
    /// PERMANENT delete instead of trashing. require_equals matches GNU's
    /// optional-argument convention and stops a following filename being eaten
    /// as the WHEN value.
    #[arg(long = "interactive", num_args = 0..=1, default_missing_value = "always", require_equals = true, value_name = "WHEN", value_parser = ["never", "once", "always"], action = clap::ArgAction::Append)]
    interactive: Vec<String>,

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

    /// Files and directories to remove.
    /// No trailing_var_arg: GNU rm permutes operands so `rm f -r` must work,
    /// and swallowing everything after the first operand silently turned
    /// later flags into filenames (#51). Invalid options fail without deleting.
    #[arg(allow_hyphen_values = false)]
    files: Vec<PathBuf>,
}

fn main() -> ExitCode {
    // Die quietly on a closed reader instead of panicking on a broken pipe
    // (Rust ignores SIGPIPE by default) (#129).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // Check bypass env var
    if std::env::var("TRASH_BYPASS").unwrap_or_default() == "1" {
        return passthrough();
    }

    let matches = match Rm::command().try_get_matches() {
        Ok(matches) => matches,
        Err(e) => {
            eprintln!("{e}");
            // Parsing a flag must never escalate a protected removal into a
            // permanent deletion. Valid repeated flags are accepted above.
            return ExitCode::FAILURE;
        }
    };
    let args = Rm::from_arg_matches(&matches).expect("validated rm arguments");
    let behavior = RemovalBehavior::from_matches(&matches);

    if args.help {
        println!("trashd rm — files are moved to trash instead of deleted");
        println!("Use --permanent or TRASH_BYPASS=1 for real deletion");
        println!("Use `trash undo` to restore the last deletion");
        println!("Use `trash ls` to see trashed files\n");
        return passthrough_with_args(&[std::ffi::OsString::from("--help")]);
    }

    if args.version {
        println!("trashd rm shim {}", env!("TRASHD_VERSION"));
        return ExitCode::SUCCESS;
    }

    // GNU rm's preserve-root guard, actually enforced: the flags were parsed
    // "for compatibility" and discarded, so `rm -rf /` proceeded to destroy
    // the whole tree (#2). Refuse operands that ARE the root unless
    // --no-preserve-root was given (matches GNU semantics — top-level
    // entries like /* expand to operands that are not "/" itself).
    if args.recursive && !args.no_preserve_root && args.files.iter().any(|f| is_root_operand(f)) {
        eprintln!("rm: it is dangerous to operate recursively on '/'");
        eprintln!("rm: use --no-preserve-root to override the failsafe");
        return ExitCode::FAILURE;
    }

    // Accepted for GNU rm compatibility — parsed so these invocations trash
    // rather than fall through to a permanent delete.
    let _ = args.one_file_system;
    // GNU --preserve-root=all additionally refuses mount-point operands.
    let preserve_all = args.preserve_root.as_deref() == Some("all");

    // If --permanent, pass through to real rm (stripping our custom flags).
    // args_os (NOT args): argv may contain non-UTF-8 filenames, and
    // std::env::args() PANICS on them — the file would be neither trashed
    // nor deleted (#14).
    //
    // Only occurrences BEFORE the `--` separator can be flags: clap parses
    // everything after `--` as positional operands, so a file literally named
    // `--permanent` (given via `rm --permanent -- --permanent`) must survive
    // the filter intact and reach the real rm.
    if args.permanent {
        let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        let bypass_flag = |a: &std::ffi::OsString| {
            a.as_os_str() != "--permanent" && a.as_os_str() != "--no-trash"
        };
        let filtered: Vec<std::ffi::OsString> = match raw.iter().position(|a| a == "--") {
            // Strip the bypass flags only BEFORE `--`; the tail (including the
            // separator) is operand territory and must pass through verbatim.
            Some(i) => raw[..i]
                .iter()
                .filter(|a| bypass_flag(a))
                .cloned()
                .chain(raw[i..].iter().cloned())
                .collect(),
            None => raw.iter().filter(|a| bypass_flag(a)).cloned().collect(),
        };
        return passthrough_with_args(&filtered);
    }

    if args.files.is_empty() {
        if behavior.ignore_missing {
            return ExitCode::SUCCESS;
        }
        eprintln!("rm: missing operand");
        return ExitCode::FAILURE;
    }

    let store = match TrashStore::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("trashd: failed to open trash store: {e}");
            eprintln!("trashd: refusing removal because protected storage is unavailable");
            return ExitCode::FAILURE;
        }
    };

    // Check if a parent process is in the bypass list
    if is_parent_bypassed(&store.config().bypass_processes) {
        return passthrough();
    }

    // GNU -I prompts for recursive removal even with one operand.
    if behavior.prompt_once(args.recursive, args.files.len()) {
        let recursive = if args.recursive { "recursively " } else { "" };
        let msg = format!(
            "rm: {recursive}remove {} arguments? [y/N] ",
            args.files.len()
        );
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
        // GNU rm refuses operands naming '.' or '..' (including `subdir/..`):
        // resolving them here would operate on the WRONG directory — a
        // trailing `..` collapsed to its parent's parent by normalize_path
        // used to trash the caller's CWD and report success (#83).
        if is_dot_operand(file) {
            eprintln!(
                "rm: refusing to remove '.' or '..': skipping directory '{}'",
                file.display()
            );
            exit_code = ExitCode::FAILURE;
            continue;
        }

        let meta = match file.symlink_metadata() {
            Ok(m) => m,
            Err(e) if behavior.ignore_missing && e.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
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

        // rm -d has rmdir semantics: a non-directory operand is an error, like
        // GNU rm's "Not a directory" — not a silent trash of the file (#149).
        if args.dir && !args.recursive && !is_dir {
            eprintln!("rm: cannot remove '{}': Not a directory", file.display());
            exit_code = ExitCode::FAILURE;
            continue;
        }

        // --preserve-root=all: refuse directory operands that are mount
        // points, like GNU rm's "Device or resource busy" (#119).
        if is_dir && preserve_all && is_mount_point(file) {
            eprintln!(
                "rm: cannot remove '{}': Device or resource busy",
                file.display()
            );
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
        if behavior.interaction == Interaction::Always {
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
                // -d excluded empty directories fall back to rmdir semantics
                // (not real rm's blanket "Is a directory" error) (#149).
                if let Err(e) = real_rm(file, args.recursive, args.dir) {
                    eprintln!("rm: cannot remove '{}': {e}", file.display());
                    exit_code = ExitCode::FAILURE;
                }
            }
            // Configured guards are REFUSALS, not fallbacks: a size cap or a
            // trash-self-target means "leave the data alone". Escalating to
            // permanent delete would invert the user's intent (#10).
            Err(
                e @ (trashd_common::store::TrashError::TooLarge { .. }
                | trashd_common::store::TrashError::Refused(_)),
            ) => {
                eprintln!("rm: refusing to remove '{}': {e}", file.display());
                exit_code = ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("trashd: failed to trash '{}': {e}", file.display());
                eprintln!("trashd: refusing permanent removal; use --permanent to bypass trash");
                exit_code = ExitCode::FAILURE;
            }
        }
    }

    exit_code
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Interaction {
    #[default]
    Never,
    Once,
    Always,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct RemovalBehavior {
    interaction: Interaction,
    ignore_missing: bool,
}

impl RemovalBehavior {
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        // GNU semantics (#117): interaction follows flag order, but
        // ignore_missing is monotonic — set by -f, never cleared by -i/-I.
        // Clap indices preserve ordering within short groups (-fi vs -if)
        // and across long options. Keep every --interactive occurrence:
        // `-f --interactive=always --interactive=never` must still report a
        // missing operand, because `always` cancelled force along the way.
        let mut options = Vec::new();
        for (name, value) in [
            ("force", "force"),
            ("interactive_always", "always"),
            ("interactive_once", "once"),
        ] {
            if matches.get_flag(name) {
                options.push((matches.index_of(name).unwrap(), value));
            }
        }
        if let Some(indices) = matches.indices_of("interactive") {
            options.extend(
                indices.zip(
                    matches
                        .get_many::<String>("interactive")
                        .unwrap()
                        .map(String::as_str),
                ),
            );
        }
        options.sort_unstable_by_key(|(index, _)| *index);

        let mut behavior = Self::default();
        for (_, option) in options {
            match option {
                "force" => {
                    behavior.ignore_missing = true;
                    behavior.interaction = Interaction::Never;
                }
                "always" | "once" => {
                    // GNU never clears ignore_missing_files outside -f: an
                    // interaction flag only changes PROMPTING, so
                    // `rm -f -i missing` still exits 0 silently (#117).
                    behavior.interaction = if option == "always" {
                        Interaction::Always
                    } else {
                        Interaction::Once
                    };
                }
                // GNU --interactive=never cancels prompting but preserves
                // the current missing-file policy, unlike --force.
                "never" => behavior.interaction = Interaction::Never,
                _ => unreachable!("clap validated the interactive option"),
            }
        }
        behavior
    }

    fn prompt_once(&self, recursive: bool, operands: usize) -> bool {
        self.interaction == Interaction::Once && (recursive || operands > 3)
    }
}

/// True when an operand IS the filesystem root ("/", "//", "///", ...).
/// Matches GNU rm's preserve-root guard, which refuses exactly these.
fn is_root_operand(p: &std::path::Path) -> bool {
    let mut comps = p.components();
    matches!(comps.next(), Some(std::path::Component::RootDir)) && comps.next().is_none()
}

/// True when `p` is a mount point: its device differs from its parent's.
fn is_mount_point(p: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // Resolve relative operands first: a bare name's lexical parent is ""
    // and would stat-fail, silently disabling the check (round-3 review).
    let absolute = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            Err(_) => return false,
        }
    };
    let parent_dev = absolute
        .parent()
        .and_then(|parent| std::fs::metadata(parent).ok());
    match (std::fs::symlink_metadata(&absolute), parent_dev) {
        (Ok(child), Some(parent)) => child.dev() != parent.dev(),
        _ => false,
    }
}

/// True when the operand's final component is `.` or `..` — the shapes GNU rm
/// refuses outright. Anything else (including `a/../b`, whose last component
/// is `b`) is handled by the kernel's own resolution.
fn is_dot_operand(p: &std::path::Path) -> bool {
    matches!(
        p.components().next_back(),
        Some(std::path::Component::CurDir) | Some(std::path::Component::ParentDir)
    )
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
    // Prefer the stash NEXT TO THIS SHIM: the installer puts the shim at
    // ${PREFIX}/lib/trashd/bin/rm and the stash at ${PREFIX}/lib/trashd/real/rm,
    // so a custom PREFIX install would otherwise never find its stash (#101).
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::fs::read_link("/proc/self/exe")
        && let Some(bin) = exe.parent()
        && let Some(trashd_dir) = bin.parent()
    {
        candidates.push(trashd_dir.join("real/rm"));
    }
    // Legacy default-layout stash.
    candidates.push(PathBuf::from("/usr/local/lib/trashd/real/rm"));

    for stashed in candidates {
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
            break;
        }
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
            // Same poisoning guard as the stash and PATH candidates: a shim
            // copy installed over the real rm must not be exec'd (#116).
            if !stash_is_shim(&p) {
                return p;
            }
            eprintln!(
                "trashd: warning: {} is a copy of the trashd shim — ignoring it (reinstall to repair)",
                p.display()
            );
        }
    }

    PathBuf::from("/usr/bin/rm")
}

/// Detect a shim masquerading as the real rm (poisoned stash from an older
/// installer that resolved `which rm` while the shim was already on PATH).
/// Probe `--version` ONCE and cache: a genuine rm never mentions "trashd",
/// while the shim identifies itself. The probe MUST strip TRASH_BYPASS from
/// the child's environment: a shim-copy probe inherits the bypass early-return
/// and would otherwise spawn its own probe recursively — unbounded forking
/// (#85) — instead of exiting through the `--version` short-circuit.
fn stash_is_shim(path: &PathBuf) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    // Cache PER PATH: a single process-global boolean made the first result
    // poison every other candidate — with a shim-copy stash, genuine
    // /usr/bin/rm was "rejected" without ever being probed and --permanent
    // became unusable (round-3 regression review of #116).
    static CACHED: OnceLock<Mutex<HashMap<PathBuf, bool>>> = OnceLock::new();
    let cache = CACHED.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(map) = cache.lock()
        && let Some(verdict) = map.get(path)
    {
        return *verdict;
    }
    let verdict = std::process::Command::new(path)
        .arg("--version")
        .env_remove("TRASH_BYPASS")
        .output()
        .map(|o| {
            let out = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            out.contains("trashd")
        })
        .unwrap_or(true); // unreadable/unrunnable — don't trust it
    if let Ok(mut map) = cache.lock() {
        map.insert(path.clone(), verdict);
    }
    verdict
}

fn passthrough() -> ExitCode {
    // args_os: never panic on non-UTF-8 argv (#14)
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    passthrough_with_args(&args)
}

fn passthrough_with_args(args: &[std::ffi::OsString]) -> ExitCode {
    let rm = real_rm_path();
    // Terminal guard (#116): if EVERY candidate turned out to be a shim copy,
    // exec'ing it would recurse without bound (each copy bypasses to its own
    // passthrough). Fail loudly instead of forking forever.
    if stash_is_shim(&rm) {
        eprintln!(
            "trashd: error: no genuine rm binary found ({} is a shim copy); refusing to recurse",
            rm.display()
        );
        return ExitCode::FAILURE;
    }
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
/// `recursive` must be true for directories to be removed (matches rm -r semantics);
/// `dir_only` (rm -d) allows removing an EMPTY directory via rmdir semantics.
fn real_rm(path: &PathBuf, recursive: bool, dir_only: bool) -> std::io::Result<()> {
    // Set TRASH_BYPASS so the LD_PRELOAD layer doesn't re-intercept
    // our unlink/rmdir calls when we genuinely want a real delete.
    // Safety: the shim is single-threaded (no other threads to race with).
    unsafe {
        std::env::set_var("TRASH_BYPASS", "1");
    }
    let result = real_rm_inner(path, recursive, dir_only);
    unsafe {
        std::env::remove_var("TRASH_BYPASS");
    }
    result
}

fn real_rm_inner(path: &PathBuf, recursive: bool, dir_only: bool) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;

    if meta.file_type().is_symlink() {
        if dir_only && !recursive {
            return Err(std::io::Error::other("Not a directory"));
        }
        std::fs::remove_file(path)
    } else if meta.is_dir() {
        if recursive {
            std::fs::remove_dir_all(path)
        } else if dir_only {
            std::fs::remove_dir(path)
        } else {
            Err(std::io::Error::other("Is a directory"))
        }
    } else if dir_only && !recursive {
        Err(std::io::Error::other("Not a directory"))
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
        assert_eq!(a.interactive, vec!["always"]);
        assert_eq!(a.files, vec![PathBuf::from("f")]);
    }

    fn behavior(argv: &[&str]) -> RemovalBehavior {
        let matches = Rm::command().try_get_matches_from(argv).unwrap();
        RemovalBehavior::from_matches(&matches)
    }

    #[test]
    fn repeated_standard_flags_remain_protected() {
        for argv in [
            &["rm", "-ff", "file"][..],
            &["rm", "-r", "--recursive", "dir"][..],
            &["rm", "-rRr", "dir"][..],
            &["rm", "-vv", "--verbose", "file"][..],
            &["rm", "-dd", "--dir", "dir"][..],
            &["rm", "-iiII", "file"][..],
            &["rm", "--force", "--force", "file"][..],
            &["rm", "--one-file-system", "--one-file-system", "file"][..],
            &["rm", "--preserve-root=all", "--preserve-root=all", "file"][..],
            &["rm", "--no-preserve-root", "--no-preserve-root", "file"][..],
            &["rm", "--interactive=once", "--interactive=once", "file"][..],
        ] {
            let args = Rm::try_parse_from(argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            assert_eq!(args.files.len(), 1);
        }
    }

    #[test]
    fn force_and_interactive_follow_argument_order() {
        for (flags, interaction, ignore_missing) in [
            (vec!["-fi"], Interaction::Always, true),
            (vec!["-if"], Interaction::Never, true),
            (vec!["-f", "-i"], Interaction::Always, true),
            (vec!["-i", "-f"], Interaction::Never, true),
            (vec!["-fI"], Interaction::Once, true),
            (vec!["-If"], Interaction::Never, true),
            (vec!["-iI"], Interaction::Once, false),
            (vec!["-Ii"], Interaction::Always, false),
            (vec!["--force", "--interactive"], Interaction::Always, true),
            (vec!["--interactive", "--force"], Interaction::Never, true),
            (
                vec!["--force", "--interactive=once"],
                Interaction::Once,
                true,
            ),
            (
                vec!["--interactive=once", "--force"],
                Interaction::Never,
                true,
            ),
            (vec!["-i", "--interactive=never"], Interaction::Never, false),
            (vec!["-f", "--interactive=never"], Interaction::Never, true),
            (
                vec!["-f", "--interactive=always", "--interactive=never"],
                Interaction::Never,
                true,
            ),
            (
                vec!["--interactive=always", "-f", "--interactive=never"],
                Interaction::Never,
                true,
            ),
            (vec!["-fif"], Interaction::Never, true),
            (vec!["-ifi"], Interaction::Always, true),
        ] {
            let argv: Vec<_> = ["rm"].into_iter().chain(flags).chain(["file"]).collect();
            assert_eq!(
                behavior(&argv),
                RemovalBehavior {
                    interaction,
                    ignore_missing
                },
                "{argv:?}"
            );
        }
    }

    #[test]
    fn once_prompts_for_recursive_or_more_than_three_operands() {
        for flags in [vec!["-I"], vec!["--interactive=once"], vec!["-f", "-I"]] {
            let argv: Vec<_> = ["rm"].into_iter().chain(flags).collect();
            let behavior = behavior(&argv);
            for operands in 1..=3 {
                assert!(behavior.prompt_once(true, operands));
                assert!(!behavior.prompt_once(false, operands));
            }
            assert!(behavior.prompt_once(false, 4));
        }
        assert!(!behavior(&["rm", "-If"]).prompt_once(true, 4));
    }

    #[test]
    fn arguments_after_separator_are_not_prompt_options() {
        let argv = ["rm", "-f", "--", "-i", "--interactive=always"];
        assert_eq!(behavior(&argv).interaction, Interaction::Never);
        let args = Rm::try_parse_from(argv).unwrap();
        assert_eq!(
            args.files,
            vec![PathBuf::from("-i"), PathBuf::from("--interactive=always")]
        );
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

    // Regression (#83): operands whose final component is `.` or `..` are
    // refused outright, like GNU rm. `a/../b` (final component `b`) is NOT
    // one of them — the kernel resolves it correctly.
    #[test]
    fn dot_operand_detection() {
        for operand in [".", "..", "./", "a/..", "a/b/../..", "/tmp/.."] {
            assert!(is_dot_operand(Path::new(operand)), "{operand}");
        }
        for operand in ["", "file", "a/b", "/tmp/x/", "a/../b", "./file"] {
            assert!(!is_dot_operand(Path::new(operand)), "{operand}");
        }
    }

    // Regression (#103): the --permanent passthrough filter must strip the
    // bypass flags only BEFORE the `--` separator; operands after `--` are
    // filenames and must reach the real rm verbatim.
    #[test]
    fn permanent_filter_keeps_post_separator_operands() {
        // Reimplemented here against the same rule main() applies, so a
        // regression in either copy is caught.
        let filter = |raw: &[&str]| -> Vec<String> {
            match raw.iter().position(|a| *a == "--") {
                Some(i) => raw[..i]
                    .iter()
                    .filter(|a| !matches!(**a, "--permanent" | "--no-trash"))
                    .map(|a| a.to_string())
                    .chain(raw[i..].iter().map(|a| a.to_string()))
                    .collect(),
                None => raw
                    .iter()
                    .filter(|a| !matches!(**a, "--permanent" | "--no-trash"))
                    .map(|a| a.to_string())
                    .collect(),
            }
        };

        assert_eq!(
            filter(&["--permanent", "--", "--permanent"]),
            vec!["--", "--permanent"]
        );
        assert_eq!(filter(&["--permanent", "f"]), vec!["f"]);
        assert_eq!(filter(&["--no-trash", "-rf", "d"]), vec!["-rf", "d"]);
        assert_eq!(filter(&["f"]), vec!["f"]);
    }
}
