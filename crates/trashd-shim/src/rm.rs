use clap::{CommandFactory, FromArgMatches, Parser};
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use trashd_common::TrashStore;
use trashd_common::store::is_parent_bypassed;

/// `eprintln!` that never panics: stderr can be full (ENOSPC) or closed, and
/// a diagnostic that aborts the process AFTER a removal succeeded would turn
/// a trashed file into a reported failure with exit 101 (#436). GNU rm's
/// fprintf ignores the error the same way.
macro_rules! rm_err {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// `println!` that never panics, for the same reason as `rm_err!` (#436):
/// GNU aborts on a failed stdout through close_stdout, but a trash tool must
/// never turn completed work into a reported failure.
macro_rules! rm_out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

/// trashd rm shim — drop-in replacement that moves files to trash instead of deleting.
///
/// Supports all standard rm flags. Files are moved to ~/.local/share/Trash/
/// and can be restored with `trash restore` or `trash undo`.
#[derive(Parser)]
#[command(
    name = "rm",
    disable_help_flag = true,
    args_override_self = true,
    infer_long_args = true
)]
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
    /// as the WHEN value. The spellings are GNU's synonym table, checked
    /// after parsing (#434).
    #[arg(long = "interactive", num_args = 0..=1, default_missing_value = "always", require_equals = true, value_name = "WHEN", action = clap::ArgAction::Append)]
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
    /// The switch itself is resolved from the raw command line in
    /// `scan_preserve_root`, because its state is ORDER-dependent (#430).
    #[arg(long = "preserve-root", num_args = 0..=1, require_equals = true, value_name = "all", value_parser = clap::builder::PossibleValuesParser::new(["all"]))]
    preserve_root: Option<String>,

    /// Accepted for GNU rm compatibility. Like `preserve_root`, this only
    /// feeds the initial value of the scan; the last occurrence on the
    /// command line decides (#430).
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
    /// The parser accepts empty operands, which GNU diagnoses like any other
    /// missing file while removing the rest (#433).
    #[arg(allow_hyphen_values = false, value_parser = OperandParser)]
    files: Vec<PathBuf>,
}

/// Accepts any operand, including the empty one: GNU rm diagnoses `rm ""`
/// like any other missing file (`rm: cannot remove '': No such file or
/// directory`) and still removes the rest (#433). Clap's own PathBuf parser
/// refuses empty values outright.
#[derive(Clone)]
struct OperandParser;

impl clap::builder::TypedValueParser for OperandParser {
    type Value = PathBuf;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        Ok(PathBuf::from(value.to_os_string()))
    }
}

/// GNU rm's `--interactive` spellings and what each means (rm.c's
/// interactive_args/interactive_vals) (#434). The value is checked after
/// clap parses, not in a value parser: clap would dress the diagnostic in
/// its own `error:` format, and GNU's wording is the spec here.
const INTERACTIVE_WHEN: &[(&str, &str)] = &[
    ("never", "never"),
    ("no", "never"),
    ("none", "never"),
    ("once", "once"),
    ("always", "always"),
    ("yes", "always"),
];

/// The meaning of a --interactive=WHEN value, the way GNU rm's XARGMATCH
/// resolves it (#434): an exact spelling wins; otherwise the value
/// abbreviates every spelling it prefixes and is accepted when they all
/// agree (`n` means never through three spellings), ambiguous when they
/// disagree, and invalid when it abbreviates none. `Err` carries GNU's
/// diagnostic either way.
fn interactive_when(value: &str) -> Result<&'static str, String> {
    let mut meaning: Option<&str> = None;
    let mut ambiguous = false;
    for (spelling, canonical) in INTERACTIVE_WHEN {
        if *spelling == value {
            // An exact spelling is never ambiguous.
            return Ok(canonical);
        }
        if spelling.starts_with(value) {
            match meaning {
                Some(previous) if previous != *canonical => ambiguous = true,
                _ => meaning = Some(canonical),
            }
        }
    }
    if ambiguous {
        // The value abbreviates spellings with different meanings.
        return Err(interactive_diagnostic(value, meaning));
    }
    match meaning {
        Some(canonical) => Ok(canonical),
        // The value abbreviates nothing.
        None => Err(interactive_diagnostic(value, None)),
    }
}

/// GNU's diagnostic under a rejected --interactive value, with its hint
/// grouped the way the argmatch listing groups synonyms (#434).
fn interactive_diagnostic(value: &str, meaning: Option<&str>) -> String {
    let complaint = if meaning.is_some() {
        "ambiguous"
    } else {
        "invalid"
    };
    format!(
        "{}\n{}",
        format_args!("rm: {complaint} argument '{value}' for '--interactive'"),
        concat!(
            "Valid arguments are:\n",
            "  - 'never', 'no', 'none'\n",
            "  - 'once'\n",
            "  - 'always', 'yes'"
        )
    )
}

fn main() -> ExitCode {
    // Die quietly on a closed reader instead of panicking on a broken pipe
    // (Rust ignores SIGPIPE by default) (#129). An inherited SIGCHLD=SIG_IGN
    // (WSL's login) lets the kernel reap the real rm before we can wait for
    // it: the genuine binary then looked like a shim copy and was refused.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
    // Check bypass env var
    if std::env::var("TRASH_BYPASS").unwrap_or_default() == "1" {
        return passthrough();
    }

    let matches = match Rm::command().try_get_matches() {
        Ok(matches) => matches,
        Err(e) => {
            rm_err!("{e}");
            // Parsing a flag must never escalate a protected removal into a
            // permanent deletion. Valid repeated flags are accepted above.
            return ExitCode::FAILURE;
        }
    };
    let args = Rm::from_arg_matches(&matches).expect("validated rm arguments");
    // GNU answers a bad --interactive=WHEN during option parsing, in argv
    // order, and removes nothing (#434).
    if let Some(values) = matches.get_many::<String>("interactive") {
        for value in values {
            if let Err(message) = interactive_when(value) {
                rm_err!("{message}");
                return ExitCode::FAILURE;
            }
        }
    }
    let behavior = RemovalBehavior::from_matches(&matches);

    // GNU rm keeps ONE preserve-root switch over the whole command line, so
    // its state is resolved from the raw argv here: clap only sees two
    // unrelated flags with no order between them (#430, #431).
    let preserve_root =
        match scan_preserve_root(!args.no_preserve_root, std::env::args_os().skip(1)) {
            Some(preserve_root) => preserve_root,
            None => {
                rm_err!("rm: you may not abbreviate the --no-preserve-root option");
                return ExitCode::FAILURE;
            }
        };

    if args.help {
        rm_out!("trashd rm — files are moved to trash instead of deleted");
        rm_out!("Use --permanent or TRASH_BYPASS=1 for real deletion");
        rm_out!("Use `trash undo` to restore the last deletion");
        rm_out!("Use `trash ls` to see trashed files\n");
        return passthrough_with_args(&[std::ffi::OsString::from("--help")]);
    }

    if args.version {
        rm_out!("trashd rm shim {}", env!("TRASHD_VERSION"));
        return ExitCode::SUCCESS;
    }

    // GNU rm's preserve-root guard, actually enforced: the flags were parsed
    // "for compatibility" and discarded, so `rm -rf /` proceeded to destroy
    // the whole tree (#2). Refuse operands that ARE the root unless
    // --no-preserve-root was the LAST spelling of the switch (matches GNU
    // semantics — top-level entries like /* expand to operands that are not
    // "/" itself).
    if args.recursive
        && preserve_root
        && args
            .files
            .iter()
            .any(|f| is_root_operand(&effective_operand(f)))
    {
        rm_err!("rm: it is dangerous to operate recursively on '/'");
        rm_err!("rm: use --no-preserve-root to override the failsafe");
        return ExitCode::FAILURE;
    }

    // Accepted for GNU rm compatibility — parsed so these invocations trash
    // rather than fall through to a permanent delete.
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
        return passthrough_with_args(&strip_bypass_flags(raw));
    }

    if args.files.is_empty() {
        if behavior.ignore_missing {
            return ExitCode::SUCCESS;
        }
        rm_err!("rm: missing operand");
        return ExitCode::FAILURE;
    }

    // A bypassed caller (make, git, package managers) passes through before
    // any store work: it must not depend on, or pay for, a usable trash.
    let config = trashd_common::Config::load();
    if is_parent_bypassed(&config.bypass_processes) {
        return passthrough();
    }

    let store = match TrashStore::open_with_config(config) {
        Ok(s) => s,
        Err(e) => {
            rm_err!("trashd: failed to open trash store: {e}");
            rm_err!("trashd: refusing removal because protected storage is unavailable");
            return ExitCode::FAILURE;
        }
    };

    // GNU -I prompts for recursive removal even with one operand.
    if behavior.prompt_once(args.recursive, args.files.len()) {
        // GNU's wording (#355).
        let count = args.files.len();
        let noun = if count == 1 { "argument" } else { "arguments" };
        let recursive = if args.recursive { " recursively" } else { "" };
        let msg = format!("rm: remove {count} {noun}{recursive}? [y/N] ");
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
    let mut notification = TrashedNotification::default();

    for operand in &args.files {
        // GNU rm refuses operands naming '.' or '..' (including `subdir/..`):
        // resolving them here would operate on the WRONG directory — a
        // trailing `..` collapsed to its parent's parent by normalize_path
        // used to trash the caller's CWD and report success (#83).
        if is_dot_operand(operand) {
            rm_err!(
                "rm: refusing to remove '.' or '..': skipping directory '{}'",
                operand.display()
            );
            exit_code = ExitCode::FAILURE;
            continue;
        }
        let file = &effective_operand(operand);

        let meta = match file.symlink_metadata() {
            Ok(m) => m,
            Err(e) if behavior.ignore_missing && is_missing(&e) => {
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                rm_err!(
                    "rm: cannot remove '{}': No such file or directory",
                    file.display()
                );
                exit_code = ExitCode::FAILURE;
                continue;
            }
            Err(e) => {
                rm_err!("rm: cannot remove '{}': {}", file.display(), as_rm_says(e));
                exit_code = ExitCode::FAILURE;
                continue;
            }
        };

        let is_dir = meta.is_dir() && !meta.file_type().is_symlink();

        // Check if it's a directory without -r
        if is_dir && !args.recursive && !args.dir {
            rm_err!("rm: cannot remove '{}': Is a directory", file.display());
            exit_code = ExitCode::FAILURE;
            continue;
        }

        // --preserve-root=all: refuse directory operands that are mount
        // points, like GNU rm's "Device or resource busy" (#119).
        if is_dir && preserve_all && is_mount_point(file) {
            rm_err!(
                "rm: cannot remove '{}': Device or resource busy",
                file.display()
            );
            exit_code = ExitCode::FAILURE;
            continue;
        }

        // rmdir(2) refuses a mount point as busy before anything else; as
        // a trash operand it only prepared a trash inside itself. Under -i
        // rm asks about an empty one first; one with entries is refused like
        // any directory with entries (#368).
        if is_dir
            && args.dir
            && !args.recursive
            && EntryStat::of(file).is_ok_and(|entry| entry.mount(file))
        {
            let interactive = behavior.interaction == Interaction::Always;
            if !interactive
                || std::fs::read_dir(file).is_ok_and(|mut listing| listing.next().is_none())
            {
                if interactive
                    && !prompt_user(&format!(
                        "rm: remove directory '{}'? [y/N] ",
                        file.display()
                    ))
                {
                    continue;
                }
                rm_err!(
                    "rm: cannot remove '{}': Device or resource busy",
                    file.display()
                );
                exit_code = ExitCode::FAILURE;
                continue;
            }
        }

        // Non-empty dir without -r
        if is_dir && args.dir && !args.recursive {
            match std::fs::read_dir(file).map(|mut d| d.next().is_some()) {
                Ok(false) => {}
                Ok(true) => {
                    rm_err!(
                        "rm: cannot remove '{}': Directory not empty",
                        file.display()
                    );
                    exit_code = ExitCode::FAILURE;
                    continue;
                }
                // Unlistable: only rmdir(2) can tell whether it is empty, and
                // an empty directory holds no data to keep. Trashing it as if
                // empty moved its whole unseen contents away.
                Err(_) => {
                    // -i still confirms it first (#342).
                    if behavior.interaction == Interaction::Always
                        && !prompt_user(&format!(
                            "rm: remove directory '{}'? [y/N] ",
                            file.display()
                        ))
                    {
                        continue;
                    }
                    if let Err(e) = real_rm(file, false, true) {
                        rm_err!("rm: cannot remove '{}': {}", file.display(), as_rm_says(e));
                        exit_code = ExitCode::FAILURE;
                    }
                    continue;
                }
            }
        }

        // --one-file-system pins the walk to one device; -i walks so that
        // every entry is confirmed, as GNU rm prompts for each. A mounted
        // operand never moves: the walk empties it and leaves it (#366).
        let mounted = || EntryStat::of(file).is_ok_and(|entry| entry.mount(file));
        if args.recursive
            && is_dir
            && (args.one_file_system || behavior.interaction == Interaction::Always || mounted())
        {
            use std::os::unix::fs::MetadataExt;
            let walk = Walk {
                store: &store,
                device: args.one_file_system.then(|| meta.dev()),
                behavior: &behavior,
                args: &args,
                command: &cmd_str,
                notification: &mut notification,
                failures: 0,
                budget: PlanBudget::new(),
            };
            if !walk.remove(file) {
                exit_code = ExitCode::FAILURE;
            }
            continue;
        }

        // Handle -i: prompt before each removal
        if behavior.interaction == Interaction::Always {
            let kind = kind_of(&meta);
            let msg = format!("rm: remove {kind} '{}'? [y/N] ", file.display());
            if !prompt_user(&msg) {
                continue;
            }
        } else if matches!(
            behavior.interaction,
            Interaction::Sometimes | Interaction::Once
        ) && write_protected(&meta)
        {
            // GNU rm's default asks before removing anything the effective
            // user may not write to, and -I leaves that check active after
            // its one question (#432). -f and --interactive=never suppress
            // it. Unlike GNU, which checks for a tty first, the question is
            // asked unconditionally: stdin that is not a tty answers EOF and
            // the file is kept, which errs toward keeping data. GNU words
            // other types (fifos, sockets, devices) by kind too; the plain
            // question here follows the filed wording for them.
            let kind = kind_of(&meta);
            let msg = match kind {
                "regular file" | "regular empty file" | "directory" => {
                    format!("rm: remove write-protected {kind} '{}'? ", file.display())
                }
                _ => format!("rm: remove '{}'? ", file.display()),
            };
            if !prompt_user(&msg) {
                continue;
            }
        }

        // GNU -v names every entry it removes, children before the directory
        // holding them, the operand last (#435). The tree moves with a single
        // rename, so it is listed BEFORE it moves and reported only once the
        // move succeeded.
        let listed = if args.verbose {
            list_removal_order(file, is_dir)
        } else {
            Vec::new()
        };

        match store.trash(file, Some(&cmd_str)) {
            Ok(_) => {
                for (path, was_dir) in &listed {
                    report_removed(path, *was_dir);
                }
                flush_removed();
                notification.add(file);
            }
            Err(trashd_common::store::TrashError::Excluded(_)) => {
                // -d excluded empty directories fall back to rmdir semantics
                // (not real rm's blanket "Is a directory" error) (#149).
                if let Err(e) = real_rm(file, args.recursive, args.dir) {
                    if !is_reported(&e) {
                        rm_err!("rm: cannot remove '{}': {}", file.display(), as_rm_says(e));
                    }
                    exit_code = ExitCode::FAILURE;
                } else {
                    for (path, was_dir) in &listed {
                        report_removed(path, *was_dir);
                    }
                    flush_removed();
                }
            }
            // Configured guards are REFUSALS, not fallbacks: a size cap or a
            // trash-self-target means "leave the data alone". Escalating to
            // permanent delete would invert the user's intent (#10). A tree
            // holding a mount moves whole or not at all: carried into the
            // trash the mount moved with it, and split around it, rm reached
            // into what it mounts and kept nothing configured out (#368).
            Err(
                e @ (trashd_common::store::TrashError::TooLarge { .. }
                | trashd_common::store::TrashError::Refused(_)
                | trashd_common::store::TrashError::HoldsMount(_)),
            ) => {
                rm_err!("rm: refusing to remove '{}': {e}", file.display());
                exit_code = ExitCode::FAILURE;
            }
            // What rm could not remove either (a mount point, a read-only
            // filesystem): --permanent would not help (#368, #370).
            Err(trashd_common::store::TrashError::Unremovable(e)) => {
                rm_err!("rm: cannot remove '{}': {}", file.display(), as_rm_says(e));
                exit_code = ExitCode::FAILURE;
            }
            Err(trashd_common::store::TrashError::Io(e))
                if e.raw_os_error() == Some(libc::EBUSY) =>
            {
                rm_err!(
                    "rm: cannot remove '{}': Device or resource busy",
                    file.display()
                );
                exit_code = ExitCode::FAILURE;
            }
            Err(e) => {
                rm_err!("trashd: failed to trash '{}': {e}", file.display());
                rm_err!("trashd: refusing permanent removal; use --permanent to bypass trash");
                exit_code = ExitCode::FAILURE;
            }
        }
    }

    notification.send();
    exit_code
}

/// GNU rm -f ignores operands that do not exist, including paths through a
/// non-directory (`file/x`, ENOTDIR).
fn is_missing(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// One desktop notification per invocation: `rm *` spawned a notify-send
/// process (and a reaper thread) for every operand.
#[derive(Default)]
struct TrashedNotification {
    count: usize,
    first: Option<PathBuf>,
}

impl TrashedNotification {
    fn add(&mut self, path: &std::path::Path) {
        self.count += 1;
        self.first.get_or_insert_with(|| path.to_path_buf());
    }

    fn send(self) {
        let body = match (self.count, self.first) {
            (0, _) | (_, None) => return,
            (1, Some(path)) => path.display().to_string(),
            (count, Some(path)) => format!("{} and {} more items", path.display(), count - 1),
        };
        trashd_common::oplog::notify_desktop("Moved to Trash", &body);
    }
}

/// How much rm asks. The default is GNU rm's RMI_SOMETIMES: without any
/// flag, a question is asked only for entries the effective user may not
/// write to (#432).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Interaction {
    /// -f and --interactive=never: no question is ever asked.
    Never,
    /// The default: ask only for write-protected entries.
    #[default]
    Sometimes,
    /// -I and --interactive=once: one question up front, then like Sometimes.
    Once,
    /// -i and --interactive=always: a question for every entry.
    Always,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct RemovalBehavior {
    interaction: Interaction,
    ignore_missing: bool,
}

impl RemovalBehavior {
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        // Interaction follows flag order, but ignore_missing is monotonic:
        // set by -f, never cleared by -i/-I. That is GNU rm before 9.x and
        // uutils rm (#117); GNU 9.x lets -i/-I clear it again.
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
                        .map(|value| {
                            interactive_when(value).expect("validated --interactive value")
                        }),
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
                    // Only -f touches ignore_missing here: an interaction
                    // flag changes PROMPTING, so `rm -f -i missing` exits 0
                    // silently, as uutils and older GNU rm do (#117).
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

/// True when an operand IS the filesystem root. Like GNU rm's preserve-root
/// guard this compares device and inode, so `/`, `//`, a bind mount of the
/// root and a trailing-slash symlink to it (`link/` follows the link) are all
/// refused, not just the literal spellings (#190).
fn is_root_operand(p: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut comps = p.components();
    if matches!(comps.next(), Some(std::path::Component::RootDir)) && comps.next().is_none() {
        return true;
    }
    match (std::fs::symlink_metadata(p), std::fs::metadata("/")) {
        (Ok(operand), Ok(root)) => operand.dev() == root.dev() && operand.ino() == root.ino(),
        _ => false,
    }
}

/// The final state of GNU rm's one preserve-root switch across the raw
/// command line: `--no-preserve-root` clears it, a later `--preserve-root`
/// sets it again, and the last occurrence decides (rm.c answers the two
/// spellings sequentially in argv order) (#430). Clap has no ordering
/// between two different flags, so the raw argv is walked again here; GNU
/// permutes operands, so options count anywhere before `--`. `initial` only
/// reads the `--no-preserve-root` clap field; with no occurrence of either
/// spelling the switch is on either way.
///
/// `None` rejects an unambiguous abbreviation of `--no-preserve-root`, which
/// GNU answers with a diagnostic and removes nothing, checking the exact
/// spelling of this one option while all others may abbreviate (#431).
/// A --help/--version option stops the scan like GNU's option loop, leaving
/// those short-circuits (which run before any removal) in charge.
fn scan_preserve_root(
    initial: bool,
    tokens: impl IntoIterator<Item = std::ffi::OsString>,
) -> Option<bool> {
    use std::os::unix::ffi::OsStrExt;
    let mut guard = initial;
    for token in tokens {
        let bytes = token.as_bytes();
        if bytes == b"--" {
            break; // Only operands follow, and none of them is an option.
        }
        let Some(body) = bytes.strip_prefix(b"--") else {
            continue; // Short flags and operands never touch the switch.
        };
        let body = &body[..body.iter().position(|&b| b == b'=').unwrap_or(body.len())];
        if b"help".starts_with(body) || b"version".starts_with(body) {
            break;
        }
        match body {
            b"no-preserve-root" => guard = false,
            // Reaching the parser at all means clap resolved the spelling,
            // so only --no-preserve-root can share this prefix (#431).
            other if b"no-preserve-root".starts_with(other) => return None,
            // Abbreviated or not, any spelling of --preserve-root sets the
            // switch again (#430).
            other if b"preserve-root".starts_with(other) => guard = true,
            _ => {}
        }
    }
    Some(guard)
}

/// The object rm actually removes. A trailing slash makes the kernel follow a
/// final symlink (`rm -r link/` empties the link's target), so such an
/// operand is resolved: policy, trashing and real deletion must all see the
/// target, not the link's own location (#190). Other operands are unchanged.
fn effective_operand(operand: &std::path::Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let bytes = operand.as_os_str().as_bytes();
    let end = bytes.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    if end == 0 || end == bytes.len() {
        return operand.to_path_buf();
    }
    let link = std::path::Path::new(std::ffi::OsStr::from_bytes(&bytes[..end]));
    match link.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::canonicalize(operand).unwrap_or_else(|_| operand.to_path_buf())
        }
        _ => operand.to_path_buf(),
    }
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
    use std::os::unix::ffi::OsStrExt;
    let bytes = p.as_os_str().as_bytes();
    let end = bytes.iter().rposition(|b| *b != b'/').map_or(0, |i| i + 1);
    matches!(
        bytes[..end].rsplit(|b| *b == b'/').next(),
        Some(b"." | b"..")
    )
}

/// Traverse through retained directory descriptors, never following a leaf
/// symlink. Each operand supplies its own device, matching GNU rm.
fn open_walk_dir(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn homogeneous_tree(path: &std::path::Path, device: u64) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let entry = EntryStat::of(path)?;
    // Any mount point, on this filesystem or another, cannot move with the
    // tree. Otherwise only directories compare devices, like rm (overlayfs
    // reports a file's from its layer) (#358).
    let foreign = entry.dev != device;
    if entry.mount(path) {
        return Ok(false);
    }
    if !entry.is_dir() {
        return Ok(true);
    }
    if foreign {
        return Ok(false);
    }
    let dir = open_walk_dir(path)?;
    if dir.metadata()?.dev() != device {
        return Ok(false);
    }
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    for entry in std::fs::read_dir(pinned)? {
        if !homogeneous_tree(&entry?.path(), device)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// What a walk decided for one entry (`rm -ri`, `--one-file-system`).
enum Walked {
    /// Remove the entry as one: a non-directory, or a directory the walk did
    /// not descend (no prompts, one filesystem throughout).
    Whole,
    /// A descended directory, pinned by its descriptor, with the decisions
    /// for the entries it held.
    Dir {
        dir: PlannedDir,
        entries: Vec<Planned>,
        state: DirState,
    },
    /// Its removal was declined: rm still asks about its directory.
    Kept,
    /// Descent declined, refused, failed or on another filesystem: like
    /// rm, its directories stay without being asked about.
    Held,
    /// A mount point that neither moves nor is removed: a bind-mounted file,
    /// or an empty mounted directory accepted under -i. Reported busy when
    /// carried out and, like a held entry, keeps its directories (#358).
    Busy,
    /// Vanished under -f: nothing to do, and nothing that keeps its parent.
    Gone,
}

/// What became of a descended directory itself.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DirState {
    /// It and everything under it were confirmed.
    Confirmed,
    /// Its removal was confirmed although an entry under it was declined:
    /// rm reports it not empty.
    Refused,
    /// Its removal was declined.
    Declined,
    /// Something under it is held, so it was never asked about.
    Held,
    /// A mount point: its entries go, it stays, reported busy (#358).
    Busy,
}

/// A planned entry: its name, the identity it was confirmed with, and the
/// decision.
struct Planned {
    name: std::ffi::OsString,
    identity: (u64, u64),
    decision: Walked,
}

/// A directory inode pinned until its confirmations are applied or dropped.
/// Sharing the live count with the budget refunds pins for declined subtrees.
struct PlannedDir {
    file: std::fs::File,
    pins: std::rc::Rc<std::cell::Cell<usize>>,
}

impl std::ops::Deref for PlannedDir {
    type Target = std::fs::File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl Drop for PlannedDir {
    fn drop(&mut self) {
        self.pins.set(self.pins.get() - 1);
    }
}

/// Bound a single operand's pending confirmations. Refuse the whole operand
/// before mutation if a limit is reached, preserving both its answers and
/// the pinned directory identities even under a low descriptor limit.
struct PlanBudget {
    bytes_left: usize,
    max_pins: usize,
    pins: std::rc::Rc<std::cell::Cell<usize>>,
    exhausted: bool,
}

impl PlanBudget {
    const MAX_BYTES: usize = 32 * 1024 * 1024;
    const MAX_DEPTH: usize = 128;
    const MAX_PINS: usize = 256;

    fn new() -> Self {
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // The filesystem-boundary survey holds a directory and listing per
        // traversal level in addition to retained plan pins. Reserve both,
        // plus room for the store, diagnostics, and operand parent handle.
        let max_pins = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            let open = std::fs::read_dir("/proc/self/fd")
                .map(|listing| listing.count())
                .unwrap_or(16);
            ((limit.rlim_cur as usize).saturating_sub(open + 16) / 3).min(Self::MAX_PINS)
        } else {
            16
        };
        Self {
            bytes_left: Self::MAX_BYTES,
            max_pins,
            pins: std::rc::Rc::new(std::cell::Cell::new(0)),
            exhausted: false,
        }
    }

    fn reserve(&mut self, name: &std::ffi::OsStr) -> bool {
        use std::os::unix::ffi::OsStrExt;
        // Include spare Vec capacity and the temporary listing of names,
        // which overlaps the growing plan while children are traversed.
        let bytes = 2
            * (std::mem::size_of::<Planned>()
                + std::mem::size_of::<std::ffi::OsString>()
                + name.as_bytes().len());
        match self.bytes_left.checked_sub(bytes) {
            Some(left) => {
                self.bytes_left = left;
                true
            }
            None => {
                self.exhausted = true;
                false
            }
        }
    }

    fn pin(&mut self, file: std::fs::File) -> Option<PlannedDir> {
        if self.pins.get() >= self.max_pins {
            self.exhausted = true;
            return None;
        }
        self.pins.set(self.pins.get() + 1);
        Some(PlannedDir {
            file,
            pins: self.pins.clone(),
        })
    }
}

/// Remove a directory operand entry by entry: confined to `device` when
/// given (--one-file-system), and confirming each entry under -i. Every
/// answer is collected before anything moves, so each fully confirmed
/// subtree, the operand included, becomes one trash entry that undo
/// restores whole. Prompts and messages name the operand's own paths, not
/// the descriptor paths the walk resolves through (#342).
///
/// The answers can be old by the time they are carried out: an entry is
/// acted on only while it is still the one confirmed, a directory moves as
/// one only while it holds exactly what was confirmed, and a planned
/// directory is never deleted recursively. Anything new is left in place
/// and its directory reported not empty, as rm does (#351).
struct Walk<'a> {
    store: &'a TrashStore,
    device: Option<u64>,
    behavior: &'a RemovalBehavior,
    args: &'a Rm,
    command: &'a str,
    notification: &'a mut TrashedNotification,
    /// Errors reported so far. Like rm, a directory with one below it
    /// stays without another message (#363, #368).
    failures: usize,
    budget: PlanBudget,
}

/// What trashing an entry came to.
enum Outcome {
    Done,
    /// Configured not to be trashed: the caller removes it for real.
    Excluded,
    /// A filesystem was mounted inside it since it was confirmed: it no
    /// longer moves as one.
    Confined,
    /// It holds a mount point, which stays: it does not move (#368).
    HoldsMount(trashd_common::store::TrashError),
}

impl Walk<'_> {
    /// Returns whether every entry was handled without error.
    fn remove(mut self, path: &std::path::Path) -> bool {
        use std::os::fd::AsRawFd;
        let (decision, identity) = self.plan(path, path, true, 0);
        if self.budget.exhausted {
            return false;
        }
        if matches!(decision, Walked::Kept | Walked::Held | Walked::Gone) {
            return self.failures == 0;
        }
        if let Walked::Busy = decision {
            self.report(path, std::io::Error::from_raw_os_error(libc::EBUSY));
            return self.failures == 0;
        }
        // O_PATH: removing needs no read access to the parent (#370).
        use std::os::unix::fs::OpenOptionsExt;
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| std::path::Path::new(".")),
            );
        match (parent, path.file_name()) {
            (Ok(parent), Some(name)) => {
                self.act(parent.as_raw_fd(), name, path, path, identity, decision);
            }
            (Err(e), _) => self.report(path, e),
            (_, None) => self.report(path, std::io::Error::from_raw_os_error(libc::EINVAL)),
        }
        self.failures == 0
    }

    fn interactive(&self) -> bool {
        self.behavior.interaction == Interaction::Always
    }

    fn report(&mut self, display: &std::path::Path, error: impl std::fmt::Display) {
        rm_err!(
            "rm: cannot remove '{}': {}",
            display.display(),
            as_rm_says(error)
        );
        self.failures += 1;
    }

    /// Report an I/O error, except a vanished entry under -f.
    fn report_io(&mut self, display: &std::path::Path, error: std::io::Error) {
        if !(self.behavior.ignore_missing && is_missing(&error)) {
            self.report(display, error);
        }
    }

    fn skip_device(&mut self, display: &std::path::Path) -> Walked {
        rm_err!(
            "rm: skipping '{}', since it's on a different device",
            display.display()
        );
        self.failures += 1;
        Walked::Held
    }

    fn open_plan_dir(
        &mut self,
        access: &std::path::Path,
        display: &std::path::Path,
    ) -> Option<PlannedDir> {
        match open_walk_dir(access) {
            Ok(file) => match self.budget.pin(file) {
                Some(dir) => Some(dir),
                None => {
                    self.report(display, "confirmation plan exceeds file descriptor budget");
                    None
                }
            },
            Err(e) => {
                self.report(display, e);
                None
            }
        }
    }

    /// Plan the removal of `access`, which is the walk's `operand` itself
    /// or an entry below it.
    fn plan(
        &mut self,
        access: &std::path::Path,
        display: &std::path::Path,
        operand: bool,
        depth: usize,
    ) -> (Walked, (u64, u64)) {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        use trashd_common::store::TrashError;
        let entry = match EntryStat::of(access) {
            Ok(entry) => entry,
            Err(e) if self.behavior.ignore_missing && is_missing(&e) => {
                return (Walked::Gone, (0, 0));
            }
            Err(e) => {
                self.report(display, e);
                return (Walked::Held, (0, 0));
            }
        };
        let identity = (entry.dev, entry.ino);
        let real_dir = entry.is_dir();
        let foreign = self.device.is_some_and(|device| entry.dev != device);
        let mount = entry.mount(access);
        // Like rm, a directory on another filesystem is skipped. Under -i rm
        // asks first: to remove an empty one, to descend into one with
        // entries (which is then skipped) (#357). An empty one that is a
        // mount is busy; one that is not (a btrfs subvolume) is removed.
        // Only directories compare devices: overlayfs reports a file's from
        // its layer (#358).
        if real_dir && foreign {
            if !self.interactive() {
                return (self.skip_device(display), identity);
            }
            let empty = std::fs::read_dir(access).is_ok_and(|mut listing| listing.next().is_none());
            let question = if empty {
                format!("rm: remove directory '{}'? [y/N] ", display.display())
            } else {
                format!("rm: descend into directory '{}'? [y/N] ", display.display())
            };
            return match (prompt_user(&question), empty) {
                (false, _) => (Walked::Held, identity),
                (true, true) if mount => (Walked::Busy, identity),
                // Not a mount (a btrfs subvolume): removed if it is still
                // empty when carried out (#361).
                (true, true) => match self.open_plan_dir(access, display) {
                    Some(dir) => (
                        Walked::Dir {
                            dir,
                            entries: Vec::new(),
                            state: DirState::Confirmed,
                        },
                        identity,
                    ),
                    None => (Walked::Held, identity),
                },
                (true, false) => (self.skip_device(display), identity),
            };
        }
        // A bind-mounted file, from any filesystem, is offered like any file
        // and is busy (#358).
        if !real_dir && mount {
            let declined = self.interactive()
                && !prompt_user(&format!(
                    "rm: remove {} '{}'? [y/N] ",
                    kind_name(entry.mode, entry.size),
                    display.display()
                ));
            return (if declined { Walked::Kept } else { Walked::Busy }, identity);
        }
        // Only a mount named as the operand, or one confirmed under -i, is
        // emptied; any other stays as it is, busy: emptying it reached
        // into a bind mount's source (#368).
        if real_dir && mount && !operand && !self.interactive() {
            return (Walked::Busy, identity);
        }
        // Preserve size and trash-self refusals before any descendant
        // changes. A mounted directory never moves, so only its own topdir
        // trash inside it does not refuse it (#360, #361).
        let eligible = if real_dir && mount {
            self.store.check_mount_eligibility(access)
        } else {
            self.store.check_trash_eligibility(access)
        };
        match eligible {
            Ok(()) | Err(TrashError::Excluded(_)) => {}
            Err(e) => {
                self.report(display, e);
                return (Walked::Held, identity);
            }
        }
        let interactive = self.interactive();
        let is_dir = real_dir;
        // A mounted directory never moves: its entries are removed and it
        // stays, busy, as rm leaves it (#358).
        let descend = is_dir
            && (interactive
                || mount
                || match self.device {
                    Some(device) => match homogeneous_tree(access, device) {
                        Ok(same) => !same,
                        Err(e) => {
                            self.report(display, e);
                            return (Walked::Held, identity);
                        }
                    },
                    None => false,
                });
        if !descend {
            let kind = kind_name(entry.mode, entry.size);
            let confirmed = !interactive
                || prompt_user(&format!(
                    "rm: remove {kind} '{}'? [y/N] ",
                    display.display()
                ));
            let decision = if confirmed {
                Walked::Whole
            } else {
                Walked::Kept
            };
            return (decision, identity);
        }

        if depth >= PlanBudget::MAX_DEPTH {
            self.budget.exhausted = true;
            self.report(
                display,
                "confirmation plan exceeds directory depth or file descriptor budget",
            );
            return (Walked::Held, identity);
        }
        let Some(dir) = self.open_plan_dir(access, display) else {
            return (Walked::Held, identity);
        };
        match dir.metadata() {
            Ok(meta) if (meta.dev(), meta.ino()) != identity => {
                self.report(display, "replaced while being examined");
                return (Walked::Held, identity);
            }
            Ok(_) => {}
            Err(e) => {
                self.report(display, e);
                return (Walked::Held, identity);
            }
        }
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        let listing = match std::fs::read_dir(&pinned) {
            Ok(listing) => listing,
            Err(e) => {
                self.report(display, e);
                return (Walked::Held, identity);
            }
        };
        let mut names = Vec::new();
        for entry in listing {
            let name = match entry {
                Ok(entry) => entry.file_name(),
                Err(e) => {
                    self.report(display, e);
                    return (Walked::Held, identity);
                }
            };
            if !self.budget.reserve(&name) {
                self.report(display, "confirmation plan exceeds 32 MiB memory budget");
                return (Walked::Held, identity);
            }
            names.push(name);
        }
        // rm asks to descend only into a directory that has entries.
        if interactive
            && !names.is_empty()
            && !prompt_user(&format!(
                "rm: descend into directory '{}'? [y/N] ",
                display.display()
            ))
        {
            return (Walked::Held, identity);
        }
        let (mut whole, mut held) = (true, false);
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let (decision, identity) =
                self.plan(&pinned.join(&name), &display.join(&name), false, depth + 1);
            match &decision {
                Walked::Whole | Walked::Gone => {}
                Walked::Dir {
                    state: DirState::Confirmed,
                    ..
                } => {}
                Walked::Kept
                | Walked::Dir {
                    state: DirState::Declined,
                    ..
                } => whole = false,
                Walked::Held | Walked::Busy | Walked::Dir { .. } => held = true,
            }
            entries.push(Planned {
                name,
                identity,
                decision,
            });
            if self.budget.exhausted {
                return (Walked::Held, identity);
            }
        }
        // Like rm: a held entry keeps its directories without a question;
        // after a declined one rm still asks, and removing then fails as
        // not empty.
        let empty = entries.is_empty();
        let state = if held {
            DirState::Held
        } else if mount {
            // Removed of its entries; asked about like rm, then busy.
            if interactive
                && !prompt_user(&format!(
                    "rm: remove directory '{}'? [y/N] ",
                    display.display()
                ))
            {
                // Declining an empty one keeps its ancestors quietly (#355).
                if empty {
                    return (Walked::Held, identity);
                }
                DirState::Declined
            } else {
                DirState::Busy
            }
        } else if interactive
            && !prompt_user(&format!(
                "rm: remove directory '{}'? [y/N] ",
                display.display()
            ))
        {
            // rm asks about an empty directory before descending: declining
            // it keeps its ancestors without a question, like a declined
            // descent (#355).
            if empty {
                return (Walked::Held, identity);
            }
            DirState::Declined
        } else if whole {
            DirState::Confirmed
        } else {
            DirState::Refused
        };
        // Binary lookup during verification avoids a linear search for
        // every current name in a wide directory.
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        (
            Walked::Dir {
                dir,
                entries,
                state,
            },
            identity,
        )
    }

    /// Carry out `decision` for `name` in the pinned `parent`.
    fn act(
        &mut self,
        parent: std::os::fd::RawFd,
        name: &std::ffi::OsStr,
        access: &std::path::Path,
        display: &std::path::Path,
        identity: (u64, u64),
        decision: Walked,
    ) {
        use std::os::fd::AsRawFd;
        let busy = || std::io::Error::from_raw_os_error(libc::EBUSY);
        match decision {
            Walked::Kept | Walked::Held | Walked::Gone => {}
            Walked::Busy => self.report(display, busy()),
            Walked::Whole => {
                if self.interactive() && !self.still(parent, name, display, identity) {
                    return;
                }
                match self.trash(parent, name, access, display) {
                    Some(Outcome::Confined) => self.report(display, busy()),
                    // It stays for the mount it holds.
                    Some(Outcome::HoldsMount(error)) => self.report(display, error),
                    Some(Outcome::Excluded) => {
                        // A confirmed entry is never a directory (those are
                        // descended), so whatever replaced it cannot be
                        // removed recursively (#355). Without prompts, not
                        // descended means nothing under it needed confirming.
                        let is_dir = !self.interactive()
                            && access
                                .symlink_metadata()
                                .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink());
                        self.real_remove(access, display, is_dir);
                    }
                    Some(Outcome::Done) | None => {}
                }
            }
            Walked::Dir {
                dir,
                entries,
                state,
            } => {
                let mut state = state;
                if state == DirState::Confirmed
                    && entry_at(parent, name).is_ok_and(|(_, _, mount)| mount)
                {
                    // Mounted over since it was confirmed (a bind keeps its
                    // identity): its confirmed entries go, it stays, busy,
                    // as rm leaves a mount point (#362).
                    state = DirState::Busy;
                }
                let confirmed = state == DirState::Confirmed;
                if confirmed {
                    // A directory replaced since is not the one confirmed.
                    if !self.still(parent, name, display, identity) {
                        return;
                    }
                    if unchanged(&dir, &entries) {
                        match self.trash(parent, name, access, display) {
                            Some(Outcome::Done) | None => return,
                            // Never recursively: what it holds may be new;
                            // or something mounted inside it stays.
                            Some(
                                Outcome::Excluded | Outcome::Confined | Outcome::HoldsMount(_),
                            ) => {}
                        }
                    }
                }
                // Entry by entry, each still as it was confirmed.
                let pinned = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
                let failures = self.failures;
                for planned in entries {
                    self.act(
                        dir.as_raw_fd(),
                        &planned.name,
                        &pinned.join(&planned.name),
                        &display.join(&planned.name),
                        planned.identity,
                        planned.decision,
                    );
                }
                // Like rm, the directories of what could not be removed stay
                // without another message, a mount among them (#363, #368).
                if self.failures > failures {
                    return;
                }
                if state == DirState::Busy {
                    self.report(display, busy());
                    return;
                }
                if state == DirState::Refused {
                    self.report(display, std::io::Error::from_raw_os_error(libc::ENOTEMPTY));
                } else if confirmed {
                    // Now empty unless something new arrived, which stays.
                    match std::fs::read_dir(&pinned).map(|mut listing| listing.next().is_none()) {
                        Ok(true) => match self.trash(parent, name, access, display) {
                            Some(Outcome::Excluded) => {
                                if let Err(e) = real_rm(access, false, true) {
                                    self.report_io(display, e);
                                }
                            }
                            Some(Outcome::Confined | Outcome::HoldsMount(_)) => {
                                self.report(display, busy())
                            }
                            Some(Outcome::Done) | None => {}
                        },
                        Ok(false) => {
                            self.report(display, std::io::Error::from_raw_os_error(libc::ENOTEMPTY))
                        }
                        Err(e) => self.report_io(display, e),
                    }
                }
            }
        }
    }

    /// Whether `name` is still the entry confirmed as `identity`.
    fn still(
        &mut self,
        parent: std::os::fd::RawFd,
        name: &std::ffi::OsStr,
        display: &std::path::Path,
        identity: (u64, u64),
    ) -> bool {
        match identity_at(parent, name) {
            Ok(current) if current == identity => true,
            Ok(_) => {
                self.report(display, "replaced since it was confirmed");
                false
            }
            Err(e) => {
                self.report_io(display, e);
                false
            }
        }
    }

    /// Trash one entry; `None` when that failed (already reported).
    fn trash(
        &mut self,
        parent: std::os::fd::RawFd,
        name: &std::ffi::OsStr,
        access: &std::path::Path,
        display: &std::path::Path,
    ) -> Option<Outcome> {
        use trashd_common::store::TrashError;
        // A confirmation can be old by now: a filesystem mounted inside the
        // tree meanwhile must still stay out of a --one-file-system removal.
        // Without prompts the plan's own check is current.
        // An entry accepted while already on another filesystem (an empty
        // btrfs subvolume) was asked about as such; only the walk's own
        // filesystem is rechecked. A directory that no longer moves whole is
        // carried out entry by entry instead (#360).
        if let Some(device) = self.device
            && self.interactive()
            && access
                .symlink_metadata()
                .is_ok_and(|meta| std::os::unix::fs::MetadataExt::dev(&meta) == device)
        {
            match homogeneous_tree(access, device) {
                Ok(true) => {}
                Ok(false) => return Some(Outcome::Confined),
                Err(e) => {
                    self.report_io(display, e);
                    return None;
                }
            }
        }
        // Read before the move: afterwards the entry is gone (#435). A
        // directory that moves whole still holds its entries and is named
        // entry by entry; one emptied beforehand is past its entries, so its
        // listing is the directory alone.
        let listed = if self.args.verbose {
            list_removal_order(display, was_directory(access))
        } else {
            Vec::new()
        };
        let moved = match self
            .store
            .trash_at(parent, name, access, Some(self.command))
        {
            Err(TrashError::Io(e)) if e.raw_os_error() == Some(libc::EXDEV) => {
                self.store.trash(access, Some(self.command))
            }
            other => other,
        };
        match moved {
            Ok(_) => {
                for (path, was_dir) in &listed {
                    report_removed(path, *was_dir);
                }
                flush_removed();
                self.notification.add(display);
                Some(Outcome::Done)
            }
            Err(TrashError::Excluded(_)) => Some(Outcome::Excluded),
            Err(e @ TrashError::HoldsMount(_)) => Some(Outcome::HoldsMount(e)),
            Err(TrashError::Io(e)) => {
                self.report_io(display, e);
                None
            }
            Err(TrashError::NotFound(_)) if self.behavior.ignore_missing => None,
            Err(e) => {
                self.report(display, e);
                None
            }
        }
    }

    /// Remove an excluded entry the walk did not descend for real.
    fn real_remove(&mut self, access: &std::path::Path, display: &std::path::Path, is_dir: bool) {
        // Listed before the real removal reaches it (#435).
        let listed = if self.args.verbose {
            list_removal_order(display, is_dir)
        } else {
            Vec::new()
        };
        match real_rm_shown(access, display, is_dir, false) {
            Ok(()) => {
                for (path, was_dir) in &listed {
                    report_removed(path, *was_dir);
                }
                flush_removed();
            }
            Err(e) if is_reported(&e) => self.failures += 1,
            Err(e) => self.report_io(display, e),
        }
    }
}

/// Whether `path` is a directory a removal would have descended into — a
/// symlink is a leaf, whatever it points at (#435).
fn was_directory(path: &std::path::Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
}

/// What a walk needs to know about an entry, from one statx: its type,
/// identity, size and whether it is the root of a mount, which no other
/// stat call reports (#358).
struct EntryStat {
    mode: u32,
    dev: u64,
    ino: u64,
    size: u64,
    /// None on kernels before 5.8, which do not report it.
    mount_root: Option<bool>,
}

impl EntryStat {
    fn of(path: &std::path::Path) -> std::io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        if unsafe {
            // statx(2) would trigger an automount there (#371).
            libc::statx(
                libc::AT_FDCWD,
                name.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
                libc::STATX_TYPE | libc::STATX_MODE | libc::STATX_INO | libc::STATX_SIZE,
                &mut stx,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            // A seccomp profile refusing statx (older container runtimes
            // answer EPERM, which glibc does not fall back from): lstat.
            if !matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOSYS)) {
                return Err(error);
            }
            use std::os::unix::fs::MetadataExt;
            let meta = path.symlink_metadata()?;
            return Ok(Self {
                mode: meta.mode(),
                dev: meta.dev(),
                ino: meta.ino(),
                size: meta.len(),
                mount_root: None,
            });
        }
        let root = libc::STATX_ATTR_MOUNT_ROOT as u64;
        Ok(Self {
            mode: u32::from(stx.stx_mode),
            dev: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
            ino: stx.stx_ino,
            size: stx.stx_size,
            mount_root: (stx.stx_attributes_mask & root != 0)
                .then_some(stx.stx_attributes & root != 0),
        })
    }

    fn is_dir(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }

    /// Whether the entry at `path` is a mount point. Without the kernel's
    /// answer (before 5.8), its mount differs from its directory's; a device
    /// alone cannot tell, since overlayfs reports a file's from its layer,
    /// nor can an identity, which a bind source shares (#361).
    fn mount(&self, path: &std::path::Path) -> bool {
        self.mount_root.unwrap_or_else(|| {
            use std::os::unix::ffi::OsStrExt;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            match (
                std::ffi::CString::new(path.as_os_str().as_bytes()),
                std::ffi::CString::new(parent.as_os_str().as_bytes()),
            ) {
                (Ok(entry), Ok(parent)) => mounts_differ(
                    mount_id(libc::AT_FDCWD, &entry, 0),
                    mount_id(libc::AT_FDCWD, &parent, libc::AT_SYMLINK_FOLLOW),
                ),
                _ => false,
            }
        })
    }
}

/// The ID of the mount `name` (relative to `dir`) is on.
fn mount_id(dir: std::os::fd::RawFd, name: &std::ffi::CStr, flags: libc::c_int) -> Option<i32> {
    trashd_common::mounts::mount_id_at(dir, name, flags)
}

/// Two known, different mounts.
fn mounts_differ(entry: Option<i32>, parent: Option<i32>) -> bool {
    matches!((entry, parent), (Some(entry), Some(parent)) if entry != parent)
}

/// How rm names a file type, from its mode and size.
fn kind_name(mode: u32, size: u64) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFLNK => "symbolic link",
        libc::S_IFDIR => "directory",
        libc::S_IFIFO => "fifo",
        libc::S_IFSOCK => "socket",
        libc::S_IFCHR => "character special file",
        libc::S_IFBLK => "block special file",
        _ if size == 0 => "regular empty file",
        _ => "regular file",
    }
}

/// (device, inode) of `name` in `parent`, without following a symlink.
fn identity_at(parent: std::os::fd::RawFd, name: &std::ffi::OsStr) -> std::io::Result<(u64, u64)> {
    entry_at(parent, name).map(|(dev, ino, _)| (dev, ino))
}

/// (device, inode) of `name` in `parent` and whether it is a mount point.
fn entry_at(
    parent: std::os::fd::RawFd,
    name: &std::ffi::OsStr,
) -> std::io::Result<(u64, u64, bool)> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes())?;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            parent,
            name.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            libc::STATX_TYPE | libc::STATX_INO,
            &mut stx,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOSYS)) {
            return Err(error);
        }
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) }
            != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mount = mounts_differ(
            mount_id(parent, &name, 0),
            mount_id(parent, c"", libc::AT_EMPTY_PATH),
        );
        return Ok((stat.st_dev, stat.st_ino, mount));
    }
    let root = libc::STATX_ATTR_MOUNT_ROOT as u64;
    let mount = if stx.stx_attributes_mask & root != 0 {
        stx.stx_attributes & root != 0
    } else {
        mounts_differ(
            mount_id(parent, &name, 0),
            mount_id(parent, c"", libc::AT_EMPTY_PATH),
        )
    };
    Ok((
        libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
        stx.stx_ino,
        mount,
    ))
}

/// Whether the pinned `dir` holds exactly the planned entries, all still
/// the ones confirmed, and so on all the way down.
fn unchanged(dir: &std::fs::File, entries: &[Planned]) -> bool {
    use std::os::fd::AsRawFd;
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    let Ok(listing) = std::fs::read_dir(&pinned) else {
        return false;
    };
    let mut current = 0usize;
    for entry in listing {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Ok(index) = entries.binary_search_by(|planned| planned.name.cmp(&name)) else {
            return false;
        };
        let planned = &entries[index];
        if matches!(planned.decision, Walked::Gone) {
            return false;
        }
        // Still the entry confirmed, and not since become a mount point (a
        // bind over it keeps its identity): a mount never moves with its
        // directory (#361).
        match entry_at(dir.as_raw_fd(), &name) {
            Ok((dev, ino, false)) if (dev, ino) == planned.identity => {}
            _ => return false,
        }
        if let Walked::Dir { dir, entries, .. } = &planned.decision
            && !unchanged(dir, entries)
        {
            return false;
        }
        current += 1;
    }
    current
        == entries
            .iter()
            .filter(|p| !matches!(p.decision, Walked::Gone))
            .count()
}

/// Prompt user on stderr, return true if they answer 'y' or 'Y'.
fn prompt_user(msg: &str) -> bool {
    prompt_user_with(
        msg,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )
}

/// The core of `prompt_user` on injected streams: the question goes to
/// `prompt`, one line is read from `input` (#432). A question that cannot be
/// written (a full or closed stderr) is answered no WITHOUT reading: an
/// unaskable question must never panic (#436) nor remove.
fn prompt_user_with(
    msg: &str,
    input: &mut dyn std::io::BufRead,
    prompt: &mut dyn std::io::Write,
) -> bool {
    if prompt
        .write_all(msg.as_bytes())
        .and_then(|()| prompt.flush())
        .is_err()
    {
        return false;
    }
    let mut answer = String::new();
    if input.read_line(&mut answer).is_err() {
        return false;
    }
    // GNU's C-locale rule: an answer starting with y or Y ("yeah" yes,
    // " y" no) (#355).
    matches!(answer.as_bytes().first(), Some(b'y' | b'Y'))
}

/// Whether rm's default interactive mode asks before removing this entry:
/// GNU rm asks when the effective user may not write to it, and exempts
/// symlinks (whose permission bits are meaningless) (#432).
fn write_protected(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // GNU grants privileged users every write (can_write_any_file), so it
    // never asks root; neither do we, keeping root's scripted removals
    // silent like GNU's.
    let privileged = unsafe { libc::geteuid() == 0 };
    !privileged
        && !meta.file_type().is_symlink()
        && write_protected_by_bits(meta.mode(), meta.uid(), meta.gid())
}

/// The mode-bit half of that question, on injected ids: the owner class when
/// euid owns the entry, the group class when egid matches, "other"
/// otherwise. GNU answers through faccessat(W_OK, AT_EACCESS), which also
/// credits ACLs and supplementary groups; the bit comparison answers the
/// same for ordinary permission bits and errs toward asking where an ACL
/// would grant write — that is, toward keeping data (#432).
fn write_protected_by_bits(mode: u32, uid: u32, gid: u32) -> bool {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    if uid == euid {
        mode & libc::S_IWUSR == 0
    } else if gid == egid {
        mode & libc::S_IWGRP == 0
    } else {
        mode & libc::S_IWOTH == 0
    }
}

thread_local! {
    /// Buffered `-v` output: line-buffered stdout cost one write syscall
    /// per removed entry, which dominates a large tree's reporting.
    /// Flushed per operand by `flush_removed`.
    static REMOVED_OUT: std::cell::RefCell<std::io::BufWriter<std::io::Stdout>> =
        std::cell::RefCell::new(std::io::BufWriter::new(std::io::stdout()));
}

/// GNU -v's stdout line for one removed entry (#435). Write errors are
/// ignored (#436): GNU aborts through close_stdout when stdout fails, but a
/// trash tool must never turn a completed removal into a reported failure.
fn report_removed(path: &std::path::Path, is_dir: bool) {
    use std::io::Write as _;
    let what = if is_dir {
        "removed directory"
    } else {
        "removed"
    };
    REMOVED_OUT.with(|out| {
        let _ = writeln!(out.borrow_mut(), "{what} '{}'", path.display());
    });
}

fn flush_removed() {
    use std::io::Write as _;
    REMOVED_OUT.with(|out| {
        let _ = out.borrow_mut().flush();
    });
}

/// Every entry `rm -v` names for one trashed operand (#435): depth-first
/// post-order in each directory's read order — children before the
/// directory holding them, the operand last — which is the order GNU rm's
/// removal follows. A non-directory is the operand alone.
fn list_removal_order(path: &std::path::Path, is_dir: bool) -> Vec<(PathBuf, bool)> {
    let mut listed = Vec::new();
    if is_dir {
        collect_removal_order(path, &mut listed, 0);
    }
    listed.push((path.to_path_buf(), is_dir));
    listed
}

/// The `-v` listing of everything under `dir`, each directory after its own
/// entries. The cap keeps an enormous tree from trading unbounded memory for
/// messages: past it, deeper entries stay unreported while the move itself
/// is unaffected.
fn collect_removal_order(dir: &std::path::Path, listed: &mut Vec<(PathBuf, bool)>, depth: usize) {
    const MAX_ENTRIES: usize = 100_000;
    const MAX_DEPTH: usize = 100;
    if depth >= MAX_DEPTH || listed.len() >= MAX_ENTRIES {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // Unreadable now: the move itself will report it if it fails.
    };
    for entry in entries.flatten() {
        if listed.len() >= MAX_ENTRIES {
            return;
        }
        let path = entry.path();
        // file_type does not follow symlinks: a link to a directory is
        // removed as a link, like GNU's leaf handling (#435).
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            collect_removal_order(&path, listed, depth + 1);
            listed.push((path, true));
        } else {
            listed.push((path, false));
        }
    }
}

/// How rm names a file's type in its prompts.
fn kind_of(meta: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::MetadataExt;
    kind_name(meta.mode(), meta.len())
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
        match genuine_rm(&stashed) {
            None => continue,
            Some(true) => return stashed,
            Some(false) => {
                // Poisoned stash: executing a copy of THIS SHIM as the "real"
                // rm recurses without bound (the copy passes through to itself
                // even with TRASH_BYPASS=1). Fall back to PATH discovery.
                rm_err!(
                    "trashd: warning: {} is a copy of the trashd shim — ignoring it (reinstall to repair)",
                    stashed.display()
                );
                break;
            }
        }
    }

    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if dir.contains("trashd") {
                continue;
            }
            let candidate = PathBuf::from(dir).join("rm");
            if genuine_rm(&candidate) == Some(true) {
                return candidate;
            }
        }
    }

    for path in &["/usr/bin/rm", "/bin/rm"] {
        let p = PathBuf::from(path);
        // Same poisoning guard as the stash and PATH candidates: a shim copy
        // installed over the real rm must not be exec'd (#116).
        match genuine_rm(&p) {
            None => {}
            Some(true) => return p,
            Some(false) => rm_err!(
                "trashd: warning: {} is a copy of the trashd shim — ignoring it (reinstall to repair)",
                p.display()
            ),
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
/// Whether `path` exists (None if not) and is a genuine rm, not a shim
/// copy. One stat serves both the existence check and the probe identity.
fn genuine_rm(path: &PathBuf) -> Option<bool> {
    let meta = std::fs::metadata(path).ok()?;
    Some(!probed_shim(path, Some(&meta)))
}

fn stash_is_shim(path: &PathBuf) -> bool {
    probed_shim(path, None)
}

fn probed_shim(path: &PathBuf, meta: Option<&std::fs::Metadata>) -> bool {
    use std::sync::Mutex;
    // Cache PER PATH: a single process-global boolean made the first result
    // poison every other candidate — with a shim-copy stash, genuine
    // /usr/bin/rm was "rejected" without ever being probed and --permanent
    // became unusable (round-3 regression review of #116). A few paths: a
    // list, not a HashMap whose RandomState asks the kernel for keys.
    static CACHED: Mutex<Vec<(PathBuf, bool)>> = Mutex::new(Vec::new());
    if let Ok(list) = CACHED.lock()
        && let Some((_, verdict)) = list.iter().find(|(known, _)| known == path)
    {
        return *verdict;
    }
    // Every passthrough (each rm in a make recipe) forked and exec'd this
    // probe again. A verdict stays valid while the candidate keeps its
    // identity, which includes the ctime no unprivileged writer can set.
    let identity = match meta {
        Some(meta) => Some(probe_identity_of(meta)),
        None => probe_identity(path),
    };
    let remembered = identity
        .as_deref()
        .and_then(|identity| ProbeVerdicts::load().get(path, identity));
    let verdict = remembered.unwrap_or_else(|| {
        let probe = std::process::Command::new(path)
            .arg("--version")
            .env_remove("TRASH_BYPASS")
            .output();
        let verdict = probe
            .as_ref()
            .map(|o| {
                let out = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                out.contains("trashd")
            })
            .unwrap_or(true); // unreadable/unrunnable — don't trust it
        // Only a completed probe describes the binary: a spawn failure
        // (process limit, ENOMEM) or a killed probe says nothing about it,
        // and remembering one refused every later passthrough (#339). A
        // genuine rm may reject --version (busybox exits 1); a shim verdict
        // needs a successful one (#352).
        if let Some(identity) = &identity
            && probe.is_ok_and(|o| o.status.code().is_some() && (!verdict || o.status.success()))
        {
            ProbeVerdicts::load().remember(path, identity, verdict);
        }
        verdict
    });
    if let Ok(mut list) = CACHED.lock() {
        list.push((path.clone(), verdict));
    }
    verdict
}

/// What a probe verdict is valid for: the candidate's device, inode, size,
/// modification and status-change times (ctime cannot be set by users).
fn probe_identity(path: &std::path::Path) -> Option<String> {
    Some(probe_identity_of(&std::fs::metadata(path).ok()?))
}

fn probe_identity_of(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "{}:{}:{}:{}.{}:{}.{}",
        meta.dev(),
        meta.ino(),
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec()
    )
}

/// Probe verdicts remembered across invocations in the user's cache
/// directory. The file only counts when it is a regular file owned by this
/// user that nobody else can write; any problem just means probing again.
struct ProbeVerdicts {
    file: Option<PathBuf>,
    /// (verdict, identity, hex-encoded candidate path) per line.
    lines: Vec<(bool, String, String)>,
}

impl ProbeVerdicts {
    fn location() -> Option<PathBuf> {
        let base = match std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from) {
            Some(cache) if cache.is_absolute() => cache,
            _ => PathBuf::from(std::env::var_os("HOME").filter(|h| !h.is_empty())?).join(".cache"),
        };
        Some(base.join("trashd/real-rm-probes"))
    }

    fn load() -> Self {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = Self::location();
        let mut lines = Vec::new();
        if let Some(path) = &file
            && let Ok(mut handle) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
            && let Ok(meta) = handle.metadata()
            && meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o022 == 0
            && meta.len() <= 64 * 1024
        {
            // The observed length, read exactly: read_to_string re-queried
            // the size and position and probed for EOF.
            let mut bytes = Vec::with_capacity(meta.len() as usize);
            let content = (&mut handle)
                .take(meta.len())
                .read_to_end(&mut bytes)
                .ok()
                .and_then(|_| String::from_utf8(bytes).ok());
            if let Some(content) = content {
                lines = content
                    .lines()
                    .filter_map(|line| {
                        let mut fields = line.split(' ');
                        let verdict = match fields.next()? {
                            "shim" => true,
                            "real" => false,
                            _ => return None,
                        };
                        let identity = fields.next()?.to_string();
                        let path = fields.next()?.to_string();
                        fields.next().is_none().then_some((verdict, identity, path))
                    })
                    .collect();
            }
        }
        Self { file, lines }
    }

    fn key(path: &std::path::Path) -> String {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn get(&self, path: &std::path::Path, identity: &str) -> Option<bool> {
        let key = Self::key(path);
        self.lines
            .iter()
            .find(|(_, id, candidate)| *candidate == key && id == identity)
            .map(|(verdict, _, _)| *verdict)
    }

    fn remember(mut self, path: &std::path::Path, identity: &str, verdict: bool) {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let Some(file) = self.file.take() else {
            return;
        };
        let key = Self::key(path);
        self.lines.retain(|(_, _, candidate)| *candidate != key);
        self.lines.push((verdict, identity.to_string(), key));
        let keep = self.lines.len().saturating_sub(32);
        let content: String = self.lines[keep..]
            .iter()
            .map(|(verdict, identity, candidate)| {
                let verdict = if *verdict { "shim" } else { "real" };
                format!("{verdict} {identity} {candidate}\n")
            })
            .collect();
        let Some(directory) = file.parent() else {
            return;
        };
        // Only inside a cache base this user owns: under `sudo -E`, creating
        // the user's missing ~/.cache, or a trashd directory in it, left
        // root-owned directories the user could not write (#339). A base
        // that is a symlink to such a directory counts (#352).
        let owned = |path: &std::path::Path| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path)
                .is_ok_and(|meta| meta.is_dir() && meta.uid() == unsafe { libc::geteuid() })
        };
        let Some(base) = directory.parent() else {
            return;
        };
        if !owned(base) {
            // A missing base is created only where this user owns its parent.
            if base.symlink_metadata().is_ok()
                || !base.parent().is_some_and(owned)
                || std::fs::DirBuilder::new().mode(0o700).create(base).is_err()
            {
                return;
            }
        }
        let _ = std::fs::DirBuilder::new().mode(0o700).create(directory);
        if !owned(directory) {
            return;
        }
        let staging = directory.join(format!(".real-rm-probes.{}", std::process::id()));
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staging)
            .and_then(|mut handle| std::io::Write::write_all(&mut handle, content.as_bytes()));
        if written.is_err() || std::fs::rename(&staging, &file).is_err() {
            // A raw syscall: the preload would move this scratch file into
            // the trash.
            if let Ok(staging) = std::ffi::CString::new(staging.as_os_str().as_encoded_bytes()) {
                unsafe { libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, staging.as_ptr(), 0) };
            }
        }
    }
}

fn passthrough() -> ExitCode {
    // args_os: never panic on non-UTF-8 argv (#14)
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    passthrough_with_args(&strip_bypass_flags(args))
}

/// Remove shim-only options even when TRASH_BYPASS skips argument parsing.
/// Validate prefixes against option metadata without parsing the full argv:
/// bypass callers can use options supported only by their real rm (#276).
fn strip_bypass_flags(args: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let command = std::sync::OnceLock::new();
    let mut operands = false;
    args.into_iter()
        .filter(|arg| {
            if operands {
                return true;
            }
            if arg == "--" {
                operands = true;
                return true;
            }
            let Some(prefix) = arg.to_str().and_then(|s| s.strip_prefix("--")) else {
                return true;
            };
            if prefix == "permanent" || prefix == "no-trash" {
                return false;
            }
            if prefix.is_empty()
                || !("permanent".starts_with(prefix) || "no-trash".starts_with(prefix))
            {
                return true;
            }
            // Construct the parser only for abbreviated custom options.
            // Ambiguous prefixes such as --p or --no remain real-rm input.
            let command = command.get_or_init(Rm::command);
            command.get_arguments().any(|option| {
                option.get_id() != "permanent"
                    && option
                        .get_long()
                        .into_iter()
                        .chain(option.get_all_aliases().into_iter().flatten())
                        .any(|name| name.starts_with(prefix))
            })
        })
        .collect()
}

fn passthrough_with_args(args: &[std::ffi::OsString]) -> ExitCode {
    let rm = real_rm_path();
    // Terminal guard (#116): if EVERY candidate turned out to be a shim copy,
    // exec'ing it would recurse without bound (each copy bypasses to its own
    // passthrough). Fail loudly instead of forking forever.
    if stash_is_shim(&rm) {
        rm_err!(
            "trashd: error: no genuine rm binary found ({} is a shim copy); refusing to recurse",
            rm.display()
        );
        return ExitCode::FAILURE;
    }
    // Set TRASH_BYPASS=1 so the LD_PRELOAD layer doesn't re-intercept
    // the real rm's unlink() calls when we're passing through. Exec in
    // place: a child and a wait cost a process per passthrough, and turned
    // the real rm's death by a signal into exit 1 (#353).
    use std::os::unix::process::CommandExt;
    let error = Command::new(&rm).args(args).env("TRASH_BYPASS", "1").exec();
    rm_err!("trashd: failed to exec {}: {error}", rm.display());
    ExitCode::FAILURE
}

/// Remove a file/dir/symlink correctly using symlink_metadata.
/// `recursive` must be true for directories to be removed (matches rm -r semantics);
/// `allow_empty_dir` (rm -d) additionally permits removing an EMPTY directory.
fn real_rm(path: &std::path::Path, recursive: bool, allow_empty_dir: bool) -> std::io::Result<()> {
    real_rm_shown(path, path, recursive, allow_empty_dir)
}

/// `real_rm` of `path`, shown to the user as `display`.
fn real_rm_shown(
    path: &std::path::Path,
    display: &std::path::Path,
    recursive: bool,
    allow_empty_dir: bool,
) -> std::io::Result<()> {
    // Set TRASH_BYPASS so the LD_PRELOAD layer doesn't re-intercept
    // our unlink/rmdir calls when we genuinely want a real delete.
    // Safety: the shim is single-threaded (no other threads to race with).
    unsafe {
        std::env::set_var("TRASH_BYPASS", "1");
    }
    let result = real_rm_inner(path, display, recursive, allow_empty_dir);
    unsafe {
        std::env::remove_var("TRASH_BYPASS");
    }
    result
}

fn real_rm_inner(
    path: &std::path::Path,
    display: &std::path::Path,
    recursive: bool,
    allow_empty_dir: bool,
) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;

    if meta.file_type().is_symlink() {
        std::fs::remove_file(path)
    } else if meta.is_dir() {
        if recursive {
            remove_tree_shown(path, display)
        } else if allow_empty_dir {
            std::fs::remove_dir(path)
        } else {
            Err(std::io::Error::other("Is a directory"))
        }
    } else {
        std::fs::remove_file(path)
    }
}

/// An error as rm words it: the system's message, without the " (os error
/// N)" Rust appends.
fn as_rm_says(error: impl std::fmt::Display) -> String {
    let text = error.to_string();
    match text.rfind(" (os error ") {
        Some(at) if text.ends_with(')') => text[..at].to_owned(),
        _ => text,
    }
}

/// An error `real_rm` already reported entry by entry.
#[derive(Debug)]
struct Reported;

impl std::fmt::Display for Reported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("already reported")
    }
}

impl std::error::Error for Reported {}

fn is_reported(error: &std::io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Reported>())
}

/// rm -r of the directory `path` for real, by descriptor (see
/// `remove_tree_for_real`): like rm, whatever can go goes and each entry
/// that stays is reported once, as `display` shows it; a mount inside stays
/// as it is (#368, #369).
fn remove_tree_shown(path: &std::path::Path, display: &std::path::Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let name = std::ffi::CString::new(name.as_bytes())?;
    // O_PATH: removing needs write and search access to the parent, never
    // read access, as rm needs none.
    use std::os::unix::fs::OpenOptionsExt;
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new(".")),
        )?;
    let removed = trashd_common::store::remove_tree_for_real(
        parent.as_raw_fd(),
        &name,
        &mut |below, error| {
            let shown = if below.as_os_str().is_empty() {
                display.to_path_buf()
            } else {
                display.join(below)
            };
            rm_err!(
                "rm: cannot remove '{}': {}",
                shown.display(),
                as_rm_says(error)
            );
        },
    );
    if removed {
        Ok(())
    } else {
        Err(std::io::Error::other(Reported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A fresh directory for symlink fixtures; nothing in it is ever removed.
    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("trashd-shim-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // `rm -rf link/` operates on the link's TARGET (a trailing slash forces
    // the kernel to follow it): a link to `/` must trip preserve-root like
    // GNU's dev/ino check, not slip past a lexical comparison (#190).
    #[test]
    fn preserve_root_sees_through_a_trailing_slash_symlink() {
        let dir = scratch("root");
        let link = dir.join("rootlink");
        std::os::unix::fs::symlink("/", &link).unwrap();
        let mut spelled = link.clone().into_os_string();
        spelled.push("/");
        assert!(is_root_operand(Path::new(&spelled)));
        // Without the slash the operand is the symlink itself.
        assert!(!is_root_operand(&link));
    }

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

    // Regression (#250): GNU rm accepts unambiguous long-option prefixes,
    // and rejects --preserve-root values other than "all".
    #[test]
    fn gnu_prefix_abbreviations_and_preserve_root_values() {
        let a = Rm::try_parse_from(["rm", "--rec", "-f", "dir"]).unwrap();
        assert!(a.recursive && a.force);
        let b = Rm::try_parse_from(["rm", "--verb", "f"]).unwrap();
        assert!(b.verbose);
        assert!(
            Rm::try_parse_from(["rm", "--preserve-root=foo", "-f", "f"]).is_err(),
            "arbitrary --preserve-root values must be rejected like GNU rm"
        );
        assert!(Rm::try_parse_from(["rm", "--preserve-root=all", "-f", "f"]).is_ok());
    }

    // #430: the preserve-root switch is ONE value over the command line —
    // the last spelling of either option decides, wherever it appears.
    #[test]
    fn preserve_root_switch_follows_the_last_spelling() {
        let from_clap = |tokens: &[&str]| {
            // This mirrors main(): the initial value is the clap field, and
            // clap only sees option spellings before the `--` separator.
            let options = tokens.splitn(2, |token| *token == "--").next().unwrap();
            let no_preserve_root = options.contains(&"--no-preserve-root");
            scan_preserve_root(
                !no_preserve_root,
                tokens.iter().map(std::ffi::OsString::from),
            )
        };
        assert_eq!(from_clap(&[]), Some(true));
        assert_eq!(from_clap(&["--no-preserve-root"]), Some(false));
        assert_eq!(
            from_clap(&["--no-preserve-root", "--preserve-root"]),
            Some(true)
        );
        assert_eq!(
            from_clap(&["--preserve-root=all", "--no-preserve-root"]),
            Some(false)
        );
        // GNU permutes operands: options count anywhere before `--`.
        assert_eq!(
            from_clap(&["-rf", "dir", "--no-preserve-root"]),
            Some(false)
        );
        assert_eq!(from_clap(&["--", "--no-preserve-root"]), Some(true));
        // --help/--version stop the scan like GNU's option loop; whatever
        // state it reached is moot, because those short-circuits run before
        // any removal.
        assert!(from_clap(&["--no-preserve-root", "--help"]).is_some());
        assert!(from_clap(&["--help", "--no-preserve-root"]).is_some());
    }

    // #431: GNU checks the exact spelling of --no-preserve-root and rejects
    // any abbreviation with a diagnostic, removing nothing. Every other
    // option may still abbreviate.
    #[test]
    fn abbreviating_no_preserve_root_is_refused() {
        let scan =
            |tokens: &[&str]| scan_preserve_root(true, tokens.iter().map(std::ffi::OsString::from));
        assert_eq!(scan(&["--no-preserve"]), None);
        assert_eq!(scan(&["--no-p"]), None);
        assert_eq!(scan(&["--no-preserve-root"]), Some(false));
        assert_eq!(scan(&["--no-preserve-root", "--no-preserve"]), None);
        assert_eq!(scan(&["--no-preserve", "--help"]), None);
        // --no-trash is --permanent's alias, not a spelling of the switch.
        assert_eq!(scan(&["--no-trash"]), Some(true));
        // Abbreviations of --preserve-root keep setting it, as GNU's do.
        assert_eq!(scan(&["--no-preserve-root", "--preserv"]), Some(true));
        assert_eq!(scan(&["--no-preserve-root", "--preserve-root"]), Some(true));
    }

    // A bare --interactive must default to "always" and NOT swallow the file.
    #[test]
    fn bare_interactive_defaults_to_always_and_keeps_file() {
        let a = Rm::try_parse_from(["rm", "--interactive", "f"]).unwrap();
        assert_eq!(a.interactive, vec!["always"]);
        assert_eq!(a.files, vec![PathBuf::from("f")]);
    }

    // #434: GNU's XARGMATCH table for --interactive, including exact
    // synonyms and prefixes that agree on one meaning.
    #[test]
    fn interactive_when_matches_gnu_xargmatch() {
        for (value, expected) in [
            ("never", "never"),
            ("no", "never"),
            ("none", "never"),
            ("n", "never"),
            ("ne", "never"),
            ("non", "never"),
            ("once", "once"),
            ("o", "once"),
            ("on", "once"),
            ("always", "always"),
            ("yes", "always"),
            ("a", "always"),
            ("al", "always"),
            ("y", "always"),
        ] {
            assert_eq!(interactive_when(value), Ok(expected), "{value}");
            // The invocation still parses, so a valid WHEN never falls
            // through to a permanent delete.
            let args = Rm::try_parse_from(["rm", &format!("--interactive={value}"), "f"]).unwrap();
            assert_eq!(args.files, vec![PathBuf::from("f")], "{value}");
        }
    }

    // #434: a value no spelling matches is invalid; one abbreviating
    // spellings with different meanings is ambiguous ('' prefixes all six).
    // Both carry GNU's wording and valid-arguments listing.
    #[test]
    fn invalid_interactive_when_carries_gnus_diagnostic() {
        for (value, complaint) in [("xx", "invalid"), ("nope", "invalid"), ("", "ambiguous")] {
            let err = interactive_when(value).unwrap_err();
            let expected = format!("rm: {complaint} argument '{value}' for '--interactive'\n");
            assert!(
                err.starts_with(&expected),
                "{value}: expected {expected:?}, got {err:?}"
            );
            assert!(
                err.contains("Valid arguments are:\n  - 'never', 'no', 'none'\n  - 'once'\n  - 'always', 'yes'"),
                "{value}: {err:?}"
            );
        }
    }

    // #433: an empty operand parses, so the loop can diagnose it like GNU
    // (`rm: cannot remove '': No such file or directory`) and remove the
    // rest.
    #[test]
    fn empty_operands_are_accepted() {
        let args = Rm::try_parse_from(["rm", "", "f"]).unwrap();
        assert_eq!(args.files, vec![PathBuf::from(""), PathBuf::from("f")]);
        let args = Rm::try_parse_from(["rm", "f", ""]).unwrap();
        assert_eq!(args.files, vec![PathBuf::from("f"), PathBuf::from("")]);
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

    // #358, #359: the root is a mount root by the kernel's attribute and in
    // the mountinfo fallback; an ordinary directory is neither.
    #[test]
    fn mount_roots_are_recognized() {
        // A tmpfs mount (which encodes file handles) where the host has one:
        // the kernel's attribute and the mount-ID fallback agree on it.
        for candidate in ["/dev/shm", "/run", "/tmp"] {
            let path = Path::new(candidate);
            let Ok(mut entry) = EntryStat::of(path) else {
                continue;
            };
            let name = std::ffi::CString::new(candidate).unwrap();
            if entry.mount_root != Some(true) || mount_id(libc::AT_FDCWD, &name, 0).is_none() {
                continue;
            }
            entry.mount_root = None;
            assert!(
                entry.mount(path),
                "the mount-ID fallback agrees on {candidate}"
            );
            break;
        }
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut plain = EntryStat::of(manifest).unwrap();
        assert!(plain.is_dir() && !plain.mount(manifest));
        plain.mount_root = None;
        assert!(!plain.mount(manifest));
        assert_eq!(kind_name(libc::S_IFREG, 0), "regular empty file");
        assert_eq!(kind_name(libc::S_IFIFO, 0), "fifo");
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

    // #432: with no flag at all the shim behaves like GNU's RMI_SOMETIMES,
    // and only -f / --interactive=never silence it entirely.
    #[test]
    fn default_interaction_is_sometimes() {
        assert_eq!(
            RemovalBehavior::default().interaction,
            Interaction::Sometimes
        );
        assert_eq!(behavior(&["rm", "f"]).interaction, Interaction::Sometimes);
        assert_eq!(behavior(&["rm", "-I", "f"]).interaction, Interaction::Once);
        for argv in [
            &["rm", "-f", "f"][..],
            &["rm", "--interactive=never", "f"],
            &["rm", "-f", "--interactive=never", "f"],
        ] {
            assert_eq!(behavior(argv).interaction, Interaction::Never, "{argv:?}");
        }
    }

    // #432: the write-protected question follows the effective identity —
    // owner class, then group class, then "other" — and a symlink is never
    // asked about, whatever it points at.
    #[test]
    fn write_protection_follows_the_effective_identity() {
        use std::os::unix::fs::MetadataExt;
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        // The owner class decides when euid owns the entry.
        assert!(write_protected_by_bits(0o444, euid, egid.wrapping_add(1)));
        assert!(!write_protected_by_bits(0o644, euid, egid.wrapping_add(1)));
        // The group class when the owner is someone else but egid matches.
        assert!(write_protected_by_bits(0o444, euid.wrapping_add(1), egid));
        assert!(!write_protected_by_bits(0o464, euid.wrapping_add(1), egid));
        // Otherwise "other".
        assert!(write_protected_by_bits(
            0o444,
            euid.wrapping_add(1),
            egid.wrapping_add(1)
        ));
        assert!(!write_protected_by_bits(
            0o446,
            euid.wrapping_add(1),
            egid.wrapping_add(1)
        ));

        let dir = scratch("wprot");
        let file = dir.join("f");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o444))
            .unwrap();
        let meta = std::fs::symlink_metadata(&file).unwrap();
        // Whatever this process's privilege, the answer matches the bits.
        assert_eq!(
            write_protected(&meta),
            unsafe { libc::geteuid() } != 0
                && write_protected_by_bits(meta.mode(), meta.uid(), meta.gid())
        );
        // A symlink's bits are meaningless: never asked about.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(!write_protected(&std::fs::symlink_metadata(&link).unwrap()));
    }

    // #432/#436: prompting reads one line and applies GNU's yes rule; a
    // question that cannot be written is answered no WITHOUT reading stdin.
    #[test]
    fn prompting_declines_when_the_question_cannot_be_asked() {
        let answer = |input: &str| {
            let mut reader = std::io::BufReader::new(input.as_bytes());
            let mut sink = std::io::sink();
            prompt_user_with("rm: remove 'f'? ", &mut reader, &mut sink)
        };
        assert!(answer("y\n"));
        assert!(answer("yes\n"));
        assert!(answer("Y\n"));
        assert!(answer("yeah\n"));
        assert!(!answer("n\n"));
        assert!(!answer(" y\n"));
        assert!(!answer(""), "EOF declines");

        struct Full;
        impl std::io::Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        struct Untouched;
        impl std::io::Read for Untouched {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("stdin must not be read when the question cannot be asked")
            }
        }
        let mut reader = std::io::BufReader::new(Untouched);
        let mut full = Full;
        assert!(!prompt_user_with(
            "rm: remove 'f'? ",
            &mut reader,
            &mut full
        ));
    }

    // #435: -v names entries in GNU's removal order — each directory after
    // its entries, the operand last — without following a symlinked
    // directory.
    #[test]
    fn verbose_listing_is_postorder_children_before_directories() {
        let dir = scratch("verbose");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a"), b"x").unwrap();
        std::fs::write(dir.join("sub/b"), b"x").unwrap();
        let listed = list_removal_order(&dir, true);
        let position = |name: &str| {
            listed
                .iter()
                .position(|(path, _)| *path == dir.join(name))
                .unwrap_or_else(|| panic!("{name} absent from {listed:?}"))
        };
        let (b, sub, operand) = (position("sub/b"), position("sub"), position(""));
        assert!(b < sub && sub < operand, "{listed:?}");
        assert_eq!(operand, listed.len() - 1, "{listed:?}");
        let is_dir = |name: &str| {
            listed
                .iter()
                .find(|(path, _)| *path == dir.join(name))
                .unwrap()
                .1
        };
        assert!(is_dir("sub") && is_dir(""));
        assert!(!is_dir("a") && !is_dir("sub/b"));
        // A file operand is the operand alone.
        let file = dir.join("a");
        assert_eq!(
            list_removal_order(&file, false),
            vec![(file.clone(), false)]
        );
        // A symlink to the directory itself is a leaf: listed, not followed.
        std::os::unix::fs::symlink(&dir, dir.join("loop")).unwrap();
        let listed = list_removal_order(&dir, true);
        assert_eq!(listed.len(), 5, "{listed:?}"); // sub/b, a, loop, sub, dir
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
        let filter = |raw: &[&str]| -> Vec<String> {
            strip_bypass_flags(raw.iter().map(std::ffi::OsString::from).collect())
                .into_iter()
                .map(|arg| arg.into_string().unwrap())
                .collect()
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
