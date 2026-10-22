# trashd

[![CI](https://github.com/faratech/trashd/actions/workflows/ci.yml/badge.svg)](https://github.com/faratech/trashd/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.99.1%2B-orange.svg)](https://www.rust-lang.org/)

**A recycle bin for Linux that works everywhere — interactive shells, scripts, cron jobs, services, and the desktop.**

Deleted the wrong file with `rm`? With trashd there is nothing new to learn: keep typing `rm` as usual and the file lands in the trash instead of disappearing. Bring it back with one command:

```console
$ rm notes.txt
$ trash undo
```

That is the whole idea. The rest of this page explains how to install trashd, every command it provides, how to tune it, and — for the curious — exactly how it intercepts deletions without slowing your system down.

> [!NOTE]
> trashd is Linux-only. It needs no desktop environment: the desktop trash and the command-line trash are the same trash, so files you delete in a terminal show up in GNOME Files, Dolphin, Thunar, and other file managers (and vice versa).

---

## Contents

- [What is trashd?](#what-is-trashd)
- [See it in action](#see-it-in-action)
- [Quick start](#quick-start)
- [Everyday use](#everyday-use)
- [Complete `trash` command reference](#complete-trash-command-reference)
- [Delete permanently on purpose](#delete-permanently-on-purpose)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Where trashed files live](#where-trashed-files-live)
- [Keeping trash under control](#keeping-trash-under-control)
- [Safety, limits, and honest fallbacks](#safety-limits-and-honest-fallbacks)
- [Troubleshooting and FAQ](#troubleshooting-and-faq)
- [Advanced: wrapping commands by hand](#advanced-wrapping-commands-by-hand)
- [Install options in detail](#install-options-in-detail)
- [For developers](#for-developers)
- [Compatibility](#compatibility)
- [Contributing](#contributing)

---

## What is trashd?

On Windows and macOS, deleting a file usually moves it to a Recycle Bin or Trash folder first. You get a grace period to change your mind. On a Linux command line, `rm file.txt` is forever — one typo, one wrong glob (`rm *.txt` in the wrong directory), one script bug, and the file is gone.

trashd closes that gap. Once installed, deletions are **redirected to a standard trash folder** instead of being carried out immediately:

| You do this | Without trashd | With trashd |
| --- | --- | --- |
| `rm report.pdf` | Gone forever | Moved to trash — `trash restore report.pdf` brings it back |
| A script runs `rm -rf build/` | Gone forever | Moved to trash as one entry — `trash undo` brings it back |
| Python runs `os.remove(path)` | Gone forever | Moved to trash (the program does not need to know trashd exists) |
| A compiled or static binary unlinks a file | Gone forever | Moved to trash when the command runs under `trashd-exec` |

### How is this different from similar tools?

- **`trash-cli`** gives you a separate `trash-put` command. It only protects you when you remember to use it — existing scripts that call `rm` are unprotected. trashd protects `rm` itself, plus programs that never call `rm` at all.
- **`safe-rm`** blocks deletions of listed paths. It does not give you a restorable trash.
- **Shell aliases** (`alias rm='rm -i'`) only exist in your interactive shell. They do nothing for cron, scripts, `find -delete`, or other programs. trashd works below the shell.

trashd protects you at four independent layers (a PATH shim, an `LD_PRELOAD` hook, a kernel-level seccomp supervisor, and an audit daemon). You do not need to understand them to use trashd — [How it works](#how-it-works) explains them in plain language later. The short version: whichever way a program tries to delete a file, at least one layer is likely to catch it and move the file to trash instead.

### What trashd is not

- It is **not a backup system**. Trashed files still live on the same disk. If the disk dies, they die with it. Keep real backups of anything irreplaceable.
- It is **not undeletion**. Files that bypass trashd (see [Safety, limits, and honest fallbacks](#safety-limits-and-honest-fallbacks)) and files purged from trash are gone.
- It does **not change file-manager behaviour**. Your desktop already trashed files correctly; trashd makes the command line share that same trash.

---

## See it in action

```console
$ echo "important draft" > report.txt
$ rm report.txt                 # looks normal — but the file was trashed, not deleted
$ trash ls
2026-10-22 14:30      16 B  /home/you/report.txt    report.txt.20261022143000

$ trash undo                    # oops-proof: restore the last thing you deleted
Restored: /home/you/report.txt

$ rm -rf old-project/           # directories work too, as a single trash entry
$ trash ls
2026-10-22 14:31     2.1 MB  /home/you/old-project  old-project.20261022143100

$ trash restore old-project     # bring it back by name
$ trash status                  # how much is in the trash right now?
$ trash empty                   # permanently delete everything in trash (asks first)
```

Programs are covered too — no code changes, no wrapper needed for ordinary scripts:

```console
$ python3 -c "import os; os.remove('cache.db')"   # caught by the LD_PRELOAD layer
$ trash ls
2026-10-22 14:32     48 KB  /home/you/cache.db      cache.db.20261022143200
```

---

## Quick start

### You need

- A **Linux** system (any distribution; see [Compatibility](#compatibility) for kernel notes — the core `rm` protection works on every kernel).
- **Rust 1.99.1 or newer** (`cargo`) to build from source. Check with `cargo --version`. Install Rust from [rustup.rs](https://rustup.rs/) if you do not have it.
- `sudo` access for the system-wide install.

> [!TIP]
> Short on time? Run the four commands below, open a new terminal, and skip to [Everyday use](#everyday-use). You can come back for configuration and internals later.

### Install

```bash
git clone https://github.com/faratech/trashd.git
cd trashd
sudo ./install.sh
```

Run the installer with `sudo` from your normal (non-root) account that owns the checkout. It compiles as your user in a private staging area — never as root — using the committed `Cargo.lock`, then installs:

1. The `trash` command and helpers into `/usr/local/bin/` and `/usr/local/lib/trashd/`.
2. An `rm` shim that shadows the real `rm` on your `PATH` (the real `rm` is kept safely at `/usr/local/lib/trashd/real/rm`).
3. The `LD_PRELOAD` library, registered system-wide in `/etc/ld.so.preload` so scripts, cron jobs, and services are covered too.
4. A login-shell hook (`/etc/profile.d/trashd.sh`) that activates the shim (and, for root shells, kernel-level protection).
5. The `trashd` audit daemon as a systemd service, plus an optional weekly cleanup timer (shipped disabled — see [Keeping trash under control](#keeping-trash-under-control)).
6. Man pages (`man trash`, `man trash-ls`, …) and shell completions for bash, zsh, and fish.
7. A commented starter config at `/etc/trashd/config.toml` (nothing is overridden until you edit it).

### Start using it

Open a **new terminal** (or run `source /etc/profile.d/trashd.sh` in the current one), then verify:

```console
$ rm --version        # prints "trashd rm shim …" (the real rm answers `rm --help`)
$ echo hello > ~/demo.txt && rm ~/demo.txt
$ trash ls            # demo.txt should be listed (use your home dir: /tmp is never-trashed by default)
$ trash undo          # and now it is back
```

If `trash ls` shows the file, you are protected. Every `rm` from now on — in this shell, in scripts, in cron — moves files to trash instead of deleting them.

### Uninstall

```bash
sudo ./install.sh --uninstall           # remove trashd, KEEP everything already in trash
sudo ./install.sh --uninstall --purge   # remove trashd AND permanently delete all trash
```

Uninstalling removes the binaries, the `LD_PRELOAD` registration (first, so no process is left pointing at a missing library), the shell hook, the systemd service, man pages, completions, and config. **By default your trashed files are left exactly where they are** — uninstalling a safety net should not destroy the things it caught. Add `--purge` only if you also want every trash directory (for every user, on every mounted filesystem) emptied for good.

Other install methods (`make install`, distro package templates, manual copies) are covered in [Install options in detail](#install-options-in-detail).

---

## Everyday use

### Just keep using `rm`

You do not need to change any habits or scripts. The shim accepts the GNU `rm` flags you already use:

```bash
rm file.txt              # moved to trash, not deleted
rm -rf project/          # whole directory moved to trash as one entry
rm -i important.txt      # asks before each file (same wording style as GNU rm)
rm -I *.tmp              # asks once when removing 3+ files or recursing
rm -v file.txt           # verbose: trashed 'file.txt' [file.txt]
rm -d empty_dir/         # remove an empty directory (refuses a non-empty one, like rm)
rm -- *.txt              # names starting with a dash still work after --
```

Good to know:

- **Interactivity matches GNU `rm`.** `-i`, `-I`, `--interactive=never|once|always`, `-f/--force`, `-r/-R/--recursive`, `-d/--dir`, `-v/--verbose`, `--one-file-system`, and `--preserve-root` (including the refusal to recursively remove `/`) behave as `rm` users expect — except the outcome is "moved to trash" instead of "deleted".
- **A declined prompt deletes nothing.** If you answer "no" at a confirmation prompt, that file stays where it is. Files created inside a directory *while* you are being asked about it are never swept up: each confirmed subtree is trashed as exactly what you confirmed.
- **Very large recursive deletes are planned safely.** Before mutating anything, the shim pins the directories it walked (32 MiB planning budget per operand, depth limit 128). If an operand is too large to plan safely, that operand is refused *before* anything is removed — never half-trashed.
- **In a desktop session** (`$DISPLAY` or `$WAYLAND_DISPLAY` set), trashing shows a desktop notification via `notify-send` when available.
- **Bad flags fail safe.** An unrecognised `rm` flag is an error and deletes nothing. It never falls through to a permanent delete.

### The `trash` command

Use `trash` to inspect and manage what has accumulated. The five commands most people need:

```bash
trash ls                 # list everything in trash (all disks, newest first)
trash undo               # restore the most recently trashed item — the "oops" button
trash restore notes.txt  # restore one item by name
trash status             # how many items, how much space, per-disk breakdown
trash empty              # permanently delete everything in trash (asks for confirmation)
```

A typical recovery session:

```console
$ trash ls
2026-10-22 09:14     1.2 MB  /home/you/Downloads/big-report.pdf  big-report.pdf.20261022091400
2026-10-22 11:02      16 B   /home/you/notes.txt                 notes.txt.20261022110200
2026-10-21 18:40   340.0 KB  /mnt/data/photos/cat.jpg            cat.jpg.20261021184000

$ trash info notes.txt          # full details: when, by what command, integrity hash…
$ trash restore notes.txt       # back to /home/you/notes.txt
$ trash restore '*.jpg' --all   # restore several matches at once
$ trash purge big-report.pdf    # permanently delete just this one entry
```

Handy variations:

```bash
trash ls '*.py'                      # filter by glob (matches file name or full original path)
trash ls --after 2d                  # only items deleted in the last 2 days
trash ls --before 2026-10-01         # only items deleted before a date
trash ls --json                      # machine-readable output for scripts
trash find ~/projects                # search by original-path substring (glob works too)
trash restore report.txt --to .      # restore somewhere else instead of the original place
trash restore report.txt --force     # if the destination exists, restore as report.txt.1, .2, …
trash du                             # biggest items in trash, largest first
trash du -n 10                       # top 10 only
trash log                            # recent trash/restore/purge history
trash log -n 50                      # last 50 operations
```

Choosing the right item:

- `restore`, `purge`, and `info` accept a **file name, a trash ID, or a glob** (for `restore`). If a name is ambiguous — for example the same file name trashed from two different disks — trashd lists the candidates and asks you to pass one entry's **trashed path** instead (the `trashed_path` value from `trash ls --json`, e.g. `~/.local/share/Trash/files/notes.txt`). That path is always unique. File names with non-UTF-8 bytes are matched byte-for-byte.
- If several entries match and you did not pass `--all`, `trash restore` lists the candidates and exits without restoring anything — re-run with an exact trash ID, one entry's trashed path, or `--all`.
- If the original location is occupied again, `restore` refuses rather than overwriting — use `--to <dir>` to put the file elsewhere, or `--force` to auto-rename.

Emptying and housekeeping:

```bash
trash empty --dry-run        # preview what would be permanently deleted (with sizes)
trash empty --older 7d       # permanently delete only items older than 7 days
trash empty --older 2w       # …or 2 weeks (bare numbers also work: --older 30 means 30 days)
trash empty -y               # skip the "are you sure?" prompt (for scripts)
trash compress               # shrink items older than 7 days in place (zstd; restore still works)
trash compress --older 3d    # compress items older than 3 days
trash compress --dry-run     # preview compression without changing anything
trash fsck                   # check trash health (orphaned or corrupt entries)
trash fsck --fix             # repair what can be repaired safely (asks per orphaned file)
```

`trash empty` also finishes housekeeping you cannot see: it retries deletions that were interrupted earlier and cleans up abandoned copy/compression leftovers — without ever deleting ordinary entries beyond the ones you confirmed. `trash status` reports any such pending jobs separately so the numbers stay honest, and a failed cleanup exits with an error so scripts and timers notice.

Every subcommand has a man page (`man trash-restore`) and `--help` (`trash restore --help`). The next section is the complete reference.

---

## Complete `trash` command reference

Run `trash --help` for the list, `trash <command> --help` for one command, and `trash --version` for the version. Durations used by `--older` accept `7d` (days), `2w` (weeks), or a bare number of days (`30`). Time filters on `trash ls` additionally accept `30m`, `1h`, and dates such as `2026-03-20` or `2026-03-20T14:00`.

### Inspecting the trash

| Command | What it does |
| --- | --- |
| `trash ls [pattern]` | List trashed items across all disks, newest first. Optional glob filters by file name or full original path. |
| `trash ls --after <when>` | Only items deleted at or after `<when>` (e.g. `1h`, `2d`, `2026-03-20`). |
| `trash ls --before <when>` | Only items deleted at or before `<when>`. |
| `trash ls --json` | Emit a JSON array instead of the table. Each object includes `id`, `original_path`, `trashed_path`, `deletion_date`, and `size` — use `trashed_path` when a name is ambiguous. |
| `trash find <query>` | Search by original-path substring, or by glob if the query contains `*`, `?`, or `[`. Prints matches and a count. |
| `trash info <target>` | Show full metadata for one entry: ID, original path, deletion time, size, stored integrity hash, trash directory, and on-disk storage path. |
| `trash status` | Totals (items, size), any pending interrupted-cleanup jobs, and a per-partition breakdown. |
| `trash du [-n N]` | Largest items first. `-n`/`--top N` limits the list (default 20). Header shows `SIZE`, `ORIGINAL PATH`, `ID`. |
| `trash log [-n N]` | Show the recent operation log (`-n`/`--lines N`, default 20; `trash log -n 50` for more). |

Example `trash status` output:

```console
$ trash status
Trash Status
  Items:    15
  Size:     2.3 MB

  Per-partition:
    /mnt/data (ext4) — 3 items, 1.8 MB
      /mnt/data/.Trash-1000
    home — 12 items, 512 KB
      /home/user/.local/share/Trash
```

### Restoring and deleting

| Command | What it does |
| --- | --- |
| `trash restore <target>` | Restore one entry (name, ID, or glob) to its original location. Refuses to overwrite an existing destination. |
| `trash restore <target> --to <path>` | Restore to a different directory or file path instead. |
| `trash restore <target> --force` | If the destination exists, keep both by restoring as `name.1`, `name.2`, … |
| `trash restore <target> --all` | Restore every entry matching a glob (without `--all`, only one match is restored). |
| `trash undo` | Restore the single most recently trashed item. The fastest fix for "I just deleted the wrong thing". |
| `trash purge <target>` | Permanently delete one entry (name, ID, or its unique trashed path). No confirmation — this is final. |
| `trash empty` | Permanently delete trash entries. Asks `Permanently delete N items (size)? [y/N]` first. |
| `trash empty --older <dur>` | With `empty`: only entries older than the duration. Still retries interrupted-cleanup jobs. |
| `trash empty --dry-run` | Preview the selection (and any pending cleanup retries) without deleting anything. |
| `trash empty -y` / `--yes` | Skip the confirmation prompt. Intended for scripts and the cleanup timer. |
| `trash compress [--older <dur>]` | Compress entries older than the duration in place with zstd (default `7d`). Restoring a compressed entry decompresses it transparently. |
| `trash compress --dry-run` | Preview what would be compressed. |
| `trash fsck` | Check every trash directory for orphaned metadata, orphaned files, and corrupt `.trashinfo` files. Exits non-zero if any problem (or an unreadable trash root) is found, so scripts can gate on it. |
| `trash fsck --fix` | Repair: removes orphaned `.trashinfo` files; asks before removing each orphaned data file. Corrupt metadata is never auto-deleted — the data file is preserved for manual recovery. Exits non-zero if anything remains broken afterwards. |

Notes that save surprises:

- **`trash purge` and `trash empty` are permanent.** There is no undo for an undo. `empty` asks first (unless `-y`); `purge` does not, because you named a single item.
- **Orphaned files** (data in trash with no metadata, shown by `trash ls` as `? (orphaned: name)`) can happen if a trash operation was interrupted or another tool wrote to the trash. `trash fsck` explains them; `trash fsck --fix` offers to clean them up.
- **Compressed files restore normally.** trashd detects compression by the zstd magic bytes, decompresses on restore, and verifies the integrity hash against the *decompressed* bytes. You never handle `.zst` files yourself.
- **`trash ls` performance:** listings stream output and only retain matches when filtering or sorting, so a very large trash stays responsive. `find` and `du` avoid filesystem stats they do not need.

### Configuring and updating from the CLI

| Command | What it does |
| --- | --- |
| `trash config show` | Print the effective (merged) configuration as TOML. Add `--json` for JSON. |
| `trash config get <key>` | Print one value, e.g. `trash config get retention.max_age_days`. Unknown keys list the valid ones. |
| `trash config set <key> <value>` | Set a scalar in your user config (`~/.config/trashd/config.toml`), e.g. `trash config set retention.max_age_days 14`. |
| `trash config add <key> <value>` | Append to a list key (`never_trash`, `only_trash`, `bypass_processes`, `bypass_paths`). Patterns are validated before writing. |
| `trash config remove <key> <value>` | Remove a value previously added to a list key in your user config. |
| `trash config path` | Show the user and global config file paths (and whether each exists). |
| `trash config edit` | Open your user config in `$EDITOR` (default `vi`; values like `code --wait` work). Creates a fully-commented template first if none exists — nothing changes until you uncomment a line. |
| `trash config reset [-y]` | Delete your user config so defaults + global config apply again. Asks first unless `-y`. |
| `trash self-update [--check]` | Check GitHub for a newer release; without `--check`, download and install it. Verifies the release build attestation with `gh attestation verify` when `gh` is available. |
| `trash self-update --allow-unverified` | Install even when attestation cannot be verified (for example, `gh` is not installed). Prefer installing `gh` instead. |

`trash self-update` only manages installs in a root-owned prefix (the normal `install.sh` layout). If trashd came from your distribution's package manager (paths under `/usr`), it leaves the install alone and tells you to use the package manager. `trash config …`, `trash log`, and `trash self-update` never create or require a usable trash directory, so they keep working even if your trash is broken — `self-update` is deliberately usable as a recovery path.

Valid keys for `get`/`set`/`add`/`remove`: `retention.max_age_days`, `retention.max_size_gb`, `retention.disk_pressure_percent`, `max_file_size_mb`, `max_dir_size_mb`, `sha256_max_size_mb`, `auto_purge_interval_secs`, `hash_algorithm`, plus the list keys `never_trash`, `only_trash`, `bypass_processes`, `bypass_paths`. Scalars use `set`; lists use `add`/`remove` (each command tells you if you pick the wrong one). Values are validated before they are written — an out-of-range number is rejected rather than saved into a config that would then fail to load. Config writes are atomic (temporary file + rename), preserve symlinked dotfile targets, and keep the existing file mode.

---

## Delete permanently on purpose

Sometimes you really do want a file gone — secrets, huge build artifacts, anything you would never restore. trashd never traps you:

```bash
rm --permanent file.txt        # permanent delete through the shim (alias: --no-trash)
TRASH_BYPASS=1 rm file.txt     # permanent delete via environment variable
TRASH_BYPASS=1 ./deploy.sh     # run a whole script with trashd disabled
```

| Method | Scope | Notes |
| --- | --- | --- |
| `rm --permanent <files>` (alias `--no-trash`) | One `rm` invocation | The shim strips its own flags and runs the real `rm` with `TRASH_BYPASS=1` set for the child, so the `LD_PRELOAD` layer does not re-intercept it. Everything after `--` is treated as a file name, so a file literally named `--permanent` is safe: `rm --permanent -- --permanent`. |
| `TRASH_BYPASS=1` in the environment | One command or a whole script/session | Checked by the shim, the `LD_PRELOAD` hooks, and the seccomp supervisor. Export it to disable protection for a stretch of work; unset it to re-enable. |
| `trashd-exec` without wrapping | One command | Only commands you explicitly wrap get kernel-level trapping. Ordinary programs still have shim/preload coverage unless bypassed as above. |
| Config rules (`never_trash`, size limits, process bypasses) | Permanent, policy-driven | See [Configuration](#configuration). Files matching `never_trash`, files/directories over the size limits, and deletions by bypassed processes are deleted for real, automatically. |

> [!WARNING]
> Permanent means permanent. None of the methods in this section leave a copy in trash, and `trash undo` cannot help afterwards. When in doubt, trash it first and `trash purge` it later — you get the same disk space back, with a grace period in between.

---

## Configuration

Out of the box, trashd needs no configuration. When you do want to tune it — keep build artifacts out of trash, keep trash smaller, exempt a tool — you have three ways in, from quickest to most powerful:

```bash
trash config set retention.max_age_days 14        # quick: change one setting
trash config add never_trash '*.iso'              # quick: exempt a pattern (note quoting below)
trash config edit                                  # full control: edit the config file
trash config show                                  # see the effective result of all layers
```

> [!TIP]
> Prefer `trash config …` for one-off changes: it validates values, writes atomically, and never clobbers comments or unrelated settings the way a careless hand-edit can. Use `trash config edit` when you want the annotated template in front of you.

### Where settings live

Settings are layered. Later layers refine earlier ones:

| Priority | Location | Who it is for |
| --- | --- | --- |
| 1 (lowest) | Built-in defaults | Sensible behaviour with no files at all |
| 2 | `/etc/trashd/config.toml` | Admin policy for the whole machine |
| 3 | `~/.config/trashd/config.toml` | Your personal overrides (`trash config path` shows the exact paths; honours `$XDG_CONFIG_HOME`) |
| 4 (highest, narrowest) | `.trashd.toml` in a project directory | Per-project rules (see below) |

How layers combine depends on the kind of setting:

- **Single values** (retention days, size limits, hash algorithm): the highest layer that sets the value wins. Your user config beats the admin's global config beats the default.
- **Lists that accumulate** (`never_trash`, `bypass_processes`, `bypass_paths`): layers **add together**. An admin can guarantee `*.key` is never trashed, and you cannot quietly remove that guarantee from your user config — you can only add more patterns.
- **`only_trash` (the whitelist):** the user layer **replaces** the global one. Extending a whitelist would silently widen it, so replacement is the safer rule.
- **Per-directory `.trashd.toml`:** its `never_trash` is checked early, but a global `never_trash` still wins over a local `only_trash`. A project cannot re-trash what the admin excluded.

`trash config show` prints the merged result exactly as trashd sees it, so you never have to guess which layer won.

### The settings that matter most

```bash
# Keep trash for 14 days instead of 30, and cap it at 5 GB
trash config set retention.max_age_days 14
trash config set retention.max_size_gb 5

# Never trash disk images or anything under ~/scratch (real delete instead)
trash config add never_trash '*.iso'
trash config add never_trash '~/scratch/*'

# Only trash source files; delete everything else for real (whitelist mode)
trash config add only_trash '*.rs'
trash config add only_trash '*.py'

# Let a build tool delete without trashing (it churns thousands of temp files)
trash config add bypass_processes 'my-build-tool'
```

A note on quoting: `trash config add` stores the value you pass as one pattern. Quote it so your shell does not expand `*` into filenames first (`'*.iso'`, not `*.iso`). Patterns are validated on add — a pattern the loader would ignore (for example one using unsupported `{a,b}` brace expansion) is rejected with an explanation instead of being saved as a silent no-op.

### Full configuration reference

The same settings as a file (this is what `trash config edit` gives you, commented). Defaults shown:

```toml
# Files matching these patterns are deleted for real, never trashed.
# User config EXTENDS this list — admin patterns cannot be removed.
never_trash = [
    "/tmp/*", "/var/tmp/*", "/var/cache/*",
    "/proc/*", "/sys/*", "/dev/*", "/dev/shm/*", "/run/*",
    "*.o", "*.pyc", "*.class",
    "*.lock", "*.pid", "*.sock", "*.socket",
    "*.tmp", "*.swp", "*~",
    "__pycache__/*", "node_modules/*",
    "target/debug/*", "target/release/*",
    "*/.git/*",
]

# Whitelist mode: if non-empty, ONLY matching files are trashed;
# everything else is deleted for real. never_trash still wins.
# Empty (default) = everything is eligible for trash.
# User config REPLACES the global value.
only_trash = []

# Processes (and their children) whose deletions bypass trash.
# Matched by walking the deleting process's ancestry in /proc.
# Defaults cover package managers and build tools that churn temp files.
# systemd/systemctl are deliberately NOT in this list.
bypass_processes = [
    "apt", "apt-get", "dpkg",
    "yum", "dnf", "pacman", "rpm",
    "pip", "cargo", "rustup", "rustup-init", "npm", "make",
    "git",
    "journald",
    "containerd", "dockerd",
]

# Executables whose deletions bypass trash, matched by path prefix
# against /proc/self/exe. More precise than bypass_processes.
bypass_paths = []

max_file_size_mb = 1024        # single files larger than this skip trash (0 = no limit)
max_dir_size_mb = 0            # directories larger than this skip trash (0 = no limit, default)
hash_algorithm = "xxhash"      # "xxhash" (XXH3-128, fast) or "sha256" (cryptographic)
sha256_max_size_mb = 1         # only files up to this size get an integrity hash (0 = no hashing)
auto_purge_interval_secs = 60  # minimum seconds between automatic retention scans

[retention]
max_age_days = 30              # auto-purge items older than this
max_size_gb = 10.0             # auto-purge oldest items beyond this total size
disk_pressure_percent = 90     # when the trash disk is fuller than this, purge oldest items
```

The shipped template at [`config/trashd.toml`](config/trashd.toml) carries the same defaults with explanatory comments, and `install.sh` installs it to `/etc/trashd/config.toml` without overwriting an existing admin config on reinstall.

### Pattern syntax

`never_trash`, `only_trash`, `trash ls <pattern>`, and `trash find <query>` (in glob mode) share one wildcard syntax, matched against the file's absolute path:

| Pattern | Example | Matches |
| --- | --- | --- |
| Trailing `/*` | `/tmp/*` | Everything under `/tmp/` |
| Extension | `*.pyc` | Any path ending in `.pyc` |
| Infix | `*/.git/*` | Any path containing `/.git/` |
| Component | `*/core` | A path component named exactly `core`, and everything under it |
| Single char / class | `file?.[ch]` | `file1.c`, `file2.h`, … (`?` = one character, `[...]` = class or range) |
| Recursive | `src/**/*.rs` | Like `*`, but `**` spans directory separators freely |
| Home-relative | `~/docs/*` | Expanded against the current user's home directory |
| Exact | `/var/run/lock` | That exact path only |

Fine print worth knowing:

- Relative patterns such as `src/*` can begin matching at any path-component boundary, so they work wherever the project sits on disk.
- A single `*` already spans `/` in this syntax; `**` is accepted for familiarity and behaves the same way.
- Brace expansion (`*.{jpg,png}`) is **not** supported. `trash config add` rejects such patterns, and hand-edited configs log a warning and ignore them — they never silently match nothing while looking correct.
- Matching is on the absolute path with symlinks in parent components resolved for policy checks, so a symlinked directory cannot smuggle an excluded path past `never_trash`.

### Per-project rules: `.trashd.toml`

Drop a `.trashd.toml` in a project root to tune trash behaviour for that tree:

```toml
# build output is reproducible — delete it for real, never trash it
never_trash = ["build/*", "dist/*", "*.log"]
# …or the opposite: in this repo, only source and config are worth keeping
only_trash = ["src/*", "*.config", "*.env"]
```

When a file is deleted, trashd walks up from the file's directory to `/` and uses the **nearest** `.trashd.toml`. Two safety rules keep shared directories safe:

- The file only counts if it is a **regular file owned by you (or root) that nobody else can write to**. A symlink, another user's file (shared directory, USB stick), or a group/world-writable file is ignored with a warning — and the search stops there, so a stranger's narrower rules never replace a trusted ancestor's.
- An unparseable `.trashd.toml` also stops the search (with a warning, reported once per file by the `rm` shim) rather than being skipped silently.
- The audit daemon never reads per-directory files; they affect interception only.

### Environment variables

| Variable | Effect |
| --- | --- |
| `TRASH_BYPASS=1` | Disable interception entirely (shim, preload, and seccomp all honour it). The main "off switch" — see [Delete permanently on purpose](#delete-permanently-on-purpose). |
| `TRASHD_SECCOMP_AUTO=0` | Stop login shells from auto-wrapping root shells with `trashd-exec`. Set in your shell profile if you only want explicit wrapping. |
| `TRASHD_SECCOMP_ACTIVE` | Read-only status set by `trashd-exec` once kernel protection is live (`1` = active). Check it with `echo $TRASHD_SECCOMP_ACTIVE`; do not set it yourself — the preload verifies a matching cookie before trusting it. |
| `TRASHD_PRELOAD_LOG=1` | Make the `LD_PRELOAD` layer log every interception to stderr (e.g. `[trashd-preload] trashed: /path -> …`). The first tool to reach for when a deletion was (or was not) caught unexpectedly. |
| `EDITOR` | Editor used by `trash config edit` (default `vi`). May include arguments, e.g. `EDITOR="code --wait"`. |
| `DISPLAY` / `WAYLAND_DISPLAY` | When either is set, the shim sends a desktop notification (via `notify-send`) after trashing. Unset in SSH/cron sessions, where notifications are skipped. |

`TRASHD_SECCOMP_ATTEMPTED` also exists, but it is an internal recursion guard set by the profile script — you should never need to set or clear it by hand.

---

## How it works

You do not need this section to use trashd. Read it when you want to know *why* a deletion was or was not caught, or when you are deciding whether trashd fits a server, a container, or a locked-down environment.

The one-sentence version: **four independent safety nets watch for deletions at four different levels of the system, and the first one that catches a deletion moves the file to the trash instead.** If one net has a hole (a program that avoids it), another usually catches the same deletion lower down.

```text
  You, a script, cron, a service
                │
                ▼
  ┌─────────────────────────────┐
  │ 1 · PATH shim               │  `rm` itself is trash-aware
  │    trashd-rm as `rm`        │  Catches: anything that runs `rm`
  └──────────────┬──────────────┘
                 ▼  (anything that deletes without `rm` falls through)
  ┌─────────────────────────────┐
  │ 2 · LD_PRELOAD hook         │  library calls are redirected
  │    libtrashd_preload.so     │  Catches: Python, Perl, C, Go, …
  └──────────────┬──────────────┘
                 ▼  (static binaries / raw syscalls fall through)
  ┌─────────────────────────────┐
  │ 4 · seccomp supervisor      │  syscalls are trapped in the kernel
  │    trashd-exec              │  Catches: static binaries, raw syscalls
  └──────────────┬──────────────┘
                 ▼
  ┌─────────────────────────────┐
  │ Trash store                 │  FreeDesktop trash folders
  │ ~/.local/share/Trash/ + …   │  Shared with your desktop
  └─────────────────────────────┘

  ┌─────────────────────────────┐
  │ 3 · fanotify daemon         │  watches ALL deletions system-wide
  │    trashd (audit only)      │  Cannot stop a deletion — it logs it
  └─────────────────────────────┘
```

Layer numbering follows the order the layers were built, not the order above: Layer 3 (the daemon) observes from the side and never sits in the deletion path, which is why it is drawn separately.

### The four layers at a glance

| Layer | What it is, in plain words | What it catches | What it misses |
| --- | --- | --- | --- |
| **1 — PATH shim** (`trashd-rm`) | The `rm` program on your `PATH` is replaced by a trash-aware twin. Your shell, scripts, and `find -exec rm` all run it without knowing. | Every `rm` invocation, with full GNU `rm` flag behaviour plus prompts and `--permanent`. | Programs that delete without ever running `rm`. |
| **2 — `LD_PRELOAD` hook** (`libtrashd_preload.so`) | A small library loaded into every dynamically-linked program that quietly redirects the standard "delete this file" library calls (`unlink`, `unlinkat`, `rmdir`, `remove`) to the trash. | Deletions from almost any normal program: Python `os.remove()`, Perl `unlink`, `os.Remove` in Go, C programs, file managers' helpers… no code changes needed. | Statically-linked binaries (no library calls to hook), and setuid programs (the system strips `LD_PRELOAD` for safety). Needs the library registered in `/etc/ld.so.preload` for system-wide coverage. |
| **3 — fanotify daemon** (`trashd`) | A background service that asks the kernel to *report* every file deletion on the system. It cannot intervene. | Nothing is intercepted — instead you get an audit trail of deletions that bypassed every other layer, with PID, process name, and path. | By design it prevents nothing. Think smoke detector, not sprinkler. |
| **4 — seccomp supervisor** (`trashd-exec`) | A wrapper that runs a command under a kernel filter: every raw "delete" system call pauses and asks a supervisor "trash this, or let it through?" before the kernel acts. | The hardest cases: statically-linked binaries, programs that clear `LD_PRELOAD`, code issuing raw syscalls. The last line of defence. | Only protects commands actually run under it: explicit `trashd-exec <cmd>`, plus root login shells that auto-wrap (see below). A wrapped command cannot elevate privileges (`NoNewPrivs`) — see caveats. |

After a default `install.sh` install: Layers 1 and 2 are active for everyone (shells, cron, services), Layer 3 runs as a systemd service, and Layer 4 auto-activates only for **interactive root login shells** (non-root shells keep full `sudo` behaviour via Layers 1–2). Anyone can opt into Layer 4 for a specific command with `trashd-exec`. Distribution packages built from [`packaging/`](packaging/) install the Layer 2 library *without* registering it — add its path to `/etc/ld.so.preload` yourself to enable that layer there.

### Which layer catches what?

| Situation | Caught by | Why |
| --- | --- | --- |
| `rm file.txt` in your shell | Layer 1 (shim) | `rm` *is* the shim |
| `find . -name '*.tmp' -exec rm {} +` | Layer 1 | Each `rm` run is the shim |
| Cron job that runs `rm` | Layer 2 | Cron does not source the profile hook, so it runs the real `rm` — whose `unlink()` calls the preload hooks (a login-shell cron job may hit Layer 1 first) |
| `python3 -c "import os; os.remove('x')"` | Layer 2 (preload) | Library call hooked inside the Python process |
| A systemd service calling `unlink()` | Layer 2 | Services inherit `/etc/ld.so.preload` (unless the unit explicitly bypasses trashd) |
| Statically-linked binary deleting files | Layer 4 only, and only under `trashd-exec` | No `rm`, no library calls — only the kernel sees it |
| setuid program deleting files | Layer 4 only, and only under `trashd-exec` | The loader strips `LD_PRELOAD` from setuid binaries |
| `rm --permanent …`, `TRASH_BYPASS=1 …` | Nothing — on purpose | You asked for a real delete |
| `git clean`, `make clean`, package managers | Nothing — on purpose | Listed in `bypass_processes` by default; their deletions are real deletes |

### How the layers avoid double-trashing

Only the first layer to catch a deletion acts; the others stand down:

- When the shim passes a command through to the real `rm` (for `--permanent` and bypassed callers), it sets `TRASH_BYPASS=1` for the child so Layer 2 does not re-intercept the deletion on its way down.
- When Layer 4 is active for a process, Layer 2 checks for `TRASHD_SECCOMP_ACTIVE=1` **plus a per-session cookie proving the supervisor's filter is really the one in charge** before deferring. A stale marker, an unrelated seccomp filter, or a wrapper from an incompatible release does *not* cause deferral — the preload keeps protecting the process itself.
- On x86-64, a deferred handoff replays the deletion as the *same kind* of syscall the program originally made (`unlink`, `rmdir`, or `unlinkat`; `remove()` tries `unlink` then `rmdir`). This matters because a program's own seccomp sandbox may allow one syscall and forbid another — trashd never substitutes a forbidden one.
- Layer 3 never intercepts anything, so it can never double-act; it only records.

<details>
<summary><strong>Deep dive — Layer 1: the PATH shim</strong> (implementation detail; skip unless debugging)</summary>

Installed as `/usr/local/lib/trashd/bin/rm` (plus an `unlink` symlink), prepended to `PATH` by `/etc/profile.d/trashd.sh`. It locates the real `rm` from a stashed copy at `/usr/local/lib/trashd/real/rm`, falling back to a `PATH` search that skips trashd directories, then `/usr/bin/rm`.

Recursive deletes are *planned before anything moves*: directory identities are pinned with open descriptors so a path swapped mid-prompt cannot redirect the deletion; each operand gets a 32 MiB planning budget, a depth limit of 128, and at most 256 retained descriptors (fewer under a low file-descriptor limit). Exceeding a budget refuses that operand before mutation. Answers at `-i`/`-I` prompts apply only to the entries that were confirmed — entries appearing afterwards are left alone. Wide-directory verification sorts planned names and binary-searches instead of rescanning.

</details>

<details>
<summary><strong>Deep dive — Layer 2: the LD_PRELOAD library</strong> (implementation detail; skip unless debugging)</summary>

Hooks `unlink()`, `unlinkat()`, `rmdir()`, and `remove()` via `dlsym(RTLD_NEXT, …)`. glibc's `remove()` reaches hidden internal aliases, so it is interposed directly rather than relying on the `unlink`/`rmdir` hooks. The library is deliberately standalone (no `trashd-common` dependency) to keep the `.so` small (~870 KB) — it is loaded into *every* process on the system, so weight matters; config parsing and trash-directory selection are duplicated for this reason.

Safety mechanisms inside the `.so`:

- **Re-entrancy guard:** a thread-local flag prevents trashd's own internal `rename()`/`mkdir()` calls from re-entering the hooked functions.
- **Trash-directory skip:** paths inside any trash folder (`~/.local/share/Trash/`, `.Trash-$UID/`, `.Trash/`) are never intercepted, so trash maintenance (`trash empty`, restores) cannot recurse into itself.
- **Config change detection:** the config file's mtime is re-checked at most every 60 seconds and changes are logged. A full reload still requires process restart — mutating global state inside a preload library is unsafe, so long-running processes keep the policy they started with.
- **Unsafe-trash refusal:** a trash directory another user could control is rejected with `EACCES` rather than used. A home that simply cannot host a trash (e.g. a service account with `HOME=/nonexistent`) falls through to the real syscall, and root running with another user's `HOME` uses root's own trash instead.

</details>

<details>
<summary><strong>Deep dive — Layer 3: the fanotify audit daemon</strong> (implementation detail; skip unless debugging)</summary>

Watches all real filesystems for `FAN_DELETE` / `FAN_DELETE_SELF` (files and directories, `FAN_ONDIR`) using `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (Linux 5.9+). Deleted paths are reconstructed from the parent directory's file handle plus the event's filename, resolved with `open_by_handle_at()` on the matching mount; no directory descriptors are held open, so mounts can still be unmounted cleanly. Virtual filesystems (tmpfs, ramfs, devtmpfs, overlay, squashfs) are skipped, I/O is non-blocking with a 1-second poll, and with nothing markable the daemon idles and re-scans mounts every second. It runs under systemd with `AmbientCapabilities=CAP_SYS_ADMIN` (unit: [`install/systemd/trashd.service`](install/systemd/trashd.service)) and logs PID, process name, and path for every deletion it sees — including deletions that deliberately bypassed trashd.

One shared ordering guarantee spans layers: trash publication, compression, and retirement all take a persistent private lock (`.trashd/store.lock`) per trash root, and cleanup re-validates an entry's data identity and metadata version before mutating it, so a recycled ID can never inherit a previous entry's purge/compress decision. Install all rebuilt components from the same release together — older writers do not participate in this lock (existing IDs and `.trashinfo` files remain compatible, no migration needed).

</details>

<details>
<summary><strong>Deep dive — Layer 4: the seccomp supervisor</strong> (process architecture, Landlock, namespaces; skip unless debugging)</summary>

`trashd-exec` runs four cooperating processes:

1. **Child** — installs a BPF seccomp filter (`SECCOMP_RET_USER_NOTIF`), hands the notification descriptor to its parent over a Unix socketpair (`SCM_RIGHTS`), waits for a startup acknowledgement, publishes `TRASHD_SECCOMP_ACTIVE=1` plus a random session cookie, and only then `exec`s your command. Explicit wrapping sets `PR_SET_NO_NEW_PRIVS`; `--preserve-privileges` (used for auto-wrapped root shells) installs via `CAP_SYS_ADMIN` instead and falls back cleanly when unavailable.
2. **Supervisor** — receives syscall notifications, asks the orchestrator (below) to read the target's path arguments and duplicate its directory descriptors, resolves every path through those *pinned* descriptors, applies config policy, then either trashes the file (success reply) or lets the real syscall run (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`). Absolute paths are confined to the target's pinned root. Relative paths escaping a pinned cwd/dirfd via `..` or symlinks resolve normally only when the target shares the supervisor's root mount and namespace; for chrooted or namespaced targets they are handed back to the target's kernel — the supervisor never retries them through a host-namespace path. When trashing requires a copy (different filesystem, or no `RENAME_NOREPLACE` as on NFS), the copy is made from the pinned parent, exactly as the store's `trash()` does. trashd's own `trash` CLI and shim are never intercepted (their deletes are store-internal). Notification IDs are validated against TOCTOU races.
3. **Watchdog** — holds a duplicate of the notification descriptor and supervises the supervisor. If the supervisor dies, the watchdog immediately drains pending notifications through a shared "decline" handler (marked preload handoffs get `ENOSYS` so the preload trashes in-process; unmarked deletes continue in the target's kernel; Landlock setup attempts are recorded before continuing), then forks a replacement supervisor. If forking fails, the handler serves notifications itself until no filtered task remains. When every filtered task has exited, the listener reports hangup and both processes exit instead of retrying forever.
4. **Orchestrator** — stays an ancestor and subreaper of your command and all its descendants. It brokers `process_vm_readv()` and `pidfd_getfd()` over a private socket so the supervisor keeps working under Yama `ptrace_scope=1`, across forks and supervisor restarts. It forwards `SIGHUP`/`SIGINT`/`SIGTERM` via pidfds, reaps exited children, and finally returns your command's original exit status. Background descendants keep the wrapper alive until they finish. It deliberately waits with the default `SIGCHLD` disposition even when it inherited `SIG_IGN` (WSL's `login` passes one to every shell — inheriting it once spun this loop at 100% CPU), and restores the inherited disposition for your command.

The BPF filter is architecture-specific: x86-64 traps `SYS_unlink` (87), `SYS_unlinkat` (263), and `SYS_rmdir` (84); aarch64 traps only `SYS_unlinkat` (35), the only one of the three that exists there. Both also trap `SYS_landlock_restrict_self` (446) to record restriction attempts before the kernel executes them.

Upgrade note: install `trashd-exec` and `libtrashd_preload.so` from the same release, then restart wrapped sessions and long-running preloaded processes. Inherited filters and already-loaded libraries do not update in place; the cookie check stops new preload code deferring to an incompatible old wrapper, but only a restart completes the upgrade.

Failure behaviour: if filter installation succeeds but memory access, root/cwd/descriptor pinning, `openat2`, or supervisor readiness fails, the filtered child is reaped and your command runs **unwrapped in place of the wrapper** (both markers cleared, signal state restored, no resident wrapper left behind). If the supervisor itself cannot start, the wrapper aborts rather than stranding your command behind a dead listener. `Device or resource busy (os error 16)` means an inherited filter already owns a listener — it cannot be removed from inside a namespace; the wrapper reports the downgrade and Layers 1–2 keep protecting you.

Landlock: any `landlock_restrict_self` attempt after startup (even one the kernel then rejects) sets a session-wide flag shared by the watchdog and every supervisor, surviving supervisor replacement and the restricting task's exit, with no per-task limit. From then on, deletions stay in the target's own security context: a deferring preload trashes in-process under that context, while static binaries and raw syscalls proceed to the kernel — which may permanently delete what the policy permits, and refuses what it forbids. Domains inherited at startup are shared with the supervisor, whose renames the kernel already checks. If restriction tracking is unavailable, the supervisor declines mutations and refuses untracked restriction setup. (This behaviour resolves the Landlock privilege issue tracked as #390.)

Credential rule: the supervisor declines a trapped delete when the target's filesystem UID/GID, groups, or effective capabilities differ from its own (for example `su`/`sudo` to another user inside a wrapped root shell, or a process that dropped capabilities). The target's own layers and kernel permissions decide instead — a privileged supervisor never spends credentials the caller does not have.

</details>

---

## Where trashed files live

trashd follows the [FreeDesktop.org Trash specification](https://specifications.freedesktop.org/trash/latest/) — the same standard your desktop file manager uses — which is why terminal and desktop trash are literally the same folders.

The guiding rule: **a file is trashed on the same filesystem it was deleted from**, so trashing is an instant rename rather than a slow copy:

| Where the file was | Where it goes |
| --- | --- |
| Same filesystem as your home | `~/.local/share/Trash/` (more precisely `$XDG_DATA_HOME/Trash/`, falling back to `~/.local/share/Trash/`) |
| Another filesystem with a valid shared trash (`$topdir/.Trash/` exists, is a real directory, has the sticky bit) | `$topdir/.Trash/$UID/` (created for you with mode `0700` when needed) |
| Another filesystem without a valid shared trash | `$topdir/.Trash-$UID/` (private per-user directory) |
| No usable topdir trash at all | Falls back to the home trash, copying across filesystems (see below) |

Filesystem boundaries are found by comparing device IDs (`st_dev`) and parsing `/proc/mounts` for the longest matching mount prefix. You never pick a location yourself: `trash ls`, `restore`, `purge`, `empty`, `status`, and `du` all scan *every* trash root automatically, and `trash info` tells you which one holds a given entry.

Inside each trash root:

```text
~/.local/share/Trash/
├── files/           # the trashed data itself, under unique trash IDs
├── info/            # one <id>.trashinfo metadata file per entry (see Compatibility)
├── directorysizes   # size cache required by the spec (written atomically)
└── .trashd/
    ├── operations.log   # audit log shown by `trash log`
    ├── store.lock       # cross-process lock for publish/compress/retire
    └── last_purge       # throttle marker for automatic retention scans
```

### When a copy is unavoidable

A rename only works within one filesystem and only when the filesystem supports no-replace rename. When it cannot (`EXDEV` across filesystems, or `EINVAL`/`ENOSYS` where `RENAME_NOREPLACE` is unsupported, e.g. NFS or 9p), trashd copies instead — carefully, and never by re-resolving a path an attacker could swap:

1. **Snapshot:** every node in the tree (device, inode, mode, size, mtime, ctime) is recorded first.
2. **Copy:** regular files, symlinks (recreated, never followed), directories, and FIFOs are copied with exclusive creation through pinned descriptors; each file is verified unchanged afterwards and synced. Owner/group/mode are preserved where permitted; set-id bits are dropped when the owner cannot be preserved. Device nodes and sockets cannot be reproduced and abort the copy. Depth is capped at 100 levels.
3. **Retire:** only source nodes still matching the snapshot are removed. Anything created or changed during the copy stays put, and the operation reports itself incomplete while keeping the complete, valid trash entry.

If a copy fails part-way, the orphaned `.trashinfo` and partial copy are cleaned up before the error returns. Any *other* rename error (`EACCES`, `EPERM`, `EROFS`) is reported as-is — the source could not be removed either, so pretending otherwise would lose track of the file. Restores that need a staged copy publish with atomic no-replace semantics and refuse (keeping the trashed source) on filesystems that cannot provide them, rather than risk overwriting a competing directory; regular files may publish via exclusive hard-link where supported.

---

## Keeping trash under control

A trash that grows forever is just a second disk-full problem. trashd keeps it bounded three ways: automatically after every deletion, on a schedule if you enable it, and whenever you ask.

### Automatic retention (after every trash operation)

After each trash operation, trashd runs a retention pass — throttled to at most once per `auto_purge_interval_secs` (default 60s, tracked via the `last_purge` marker) so a script deleting 10,000 files does not scan the trash 10,000 times. Each pass runs four phases, gentlest first:

1. **Age:** permanently delete entries older than `retention.max_age_days` (default 30).
2. **Compress:** shrink surviving entries older than 7 days with zstd (level 3) *before* deleting anything for space — reclaiming room without losing data often makes phase 3 unnecessary. Only trashd's own entries are compressed (entries other tools created stay readable by them). Already-compressed data (zstd magic), files under 1 KB, files with extended attributes, and directories are skipped; a file is only replaced when compression actually shrank it, keeping its original timestamps.
3. **Size:** if the trash still exceeds `retention.max_size_gb` (default 10 GB), purge the oldest survivors until it fits. Sizes claimed by metadata on removable media are never trusted beyond what is actually on disk.
4. **Disk pressure:** if the home-trash filesystem is fuller than `retention.disk_pressure_percent` (default 90%), purge the oldest 10% of survivors that are at least an hour old. The one-hour grace means a file you *just* deleted is never pressure-purged — `trash undo` right after a delete always works.

### Scheduled cleanup (optional)

The installer ships a per-user systemd timer, **disabled by default**, that runs `trash empty --older 30d -y` weekly (with up to an hour of random delay, and `Persistent=true` so a missed week runs at next login):

```bash
systemctl --user enable --now trashd-cleanup.timer   # turn scheduled cleanup on
systemctl --user list-timers trashd-cleanup.timer    # check when it will run
systemctl --user disable --now trashd-cleanup.timer   # turn it off again
```

Because cleanup failures exit non-zero, a failing run shows up as a failed unit instead of silently leaving a full trash. To change the schedule or age, edit the user units (`trashd-cleanup.timer` / `trashd-cleanup.service` under your user unit directory) or simply disable the timer and use your own cron entry running `trash empty --older <dur> -y`.

### By hand

```bash
trash status                  # size and count, per partition (+ pending cleanup jobs)
trash du -n 10                # the 10 biggest space hogs
trash compress --dry-run      # what would compression save?
trash compress                # compress entries older than 7 days
trash empty --dry-run         # what would emptying delete?
trash empty --older 7d        # delete only the old stuff (asks first)
trash empty -y                # delete everything, no prompt (scripts)
```

### Integrity hashes: knowing a restored file is intact

When a file up to `sha256_max_size_mb` (default 1 MB) is trashed, trashd stores a content hash in its metadata (`X-Trashd-Hash`; very old entries may carry `X-Trashd-SHA256` — both are read). On restore, the hash is recomputed and compared:

- **`hash_algorithm = "xxhash"` (default):** XXH3-128 at roughly 10 GB/s — a 1 MB file hashes in about 100 µs. Detects bit rot, bad disks, and partial copies. Not cryptographic.
- **`hash_algorithm = "sha256"`:** slower, but cryptographic — choose it when you need authenticity, not just integrity.

A mismatch never blocks the restore; you get your file plus a clear warning:

```text
trashd: warning: hash mismatch for restored file /home/user/data.csv
  expected: af8f72d9a92c0c4fceb70b3c89911f2b
  actual:   3cdfb8a99b35162b65d20bd3eda6cafa
  file may be corrupted — verify contents before use
```

Restore tries *both* algorithms regardless of the current setting (the algorithm may have changed since the file was trashed), and compression is transparent to all of this — the hash is checked against decompressed bytes. Changing `hash_algorithm` never requires rehashing existing entries. With `sha256_max_size_mb = 0`, hashing is off entirely.

---

## Safety, limits, and honest fallbacks

trashd is engineered so that *trashd's own bugs should not become your data loss* — but it cannot promise every deletion is recoverable. This section is the honest boundary. Read it before relying on trashd for anything critical.

### Design guarantees

- **Interception preserves your permissions.** Trashing happens with the deleting process's own kernel credentials. A file you could not delete, trashd cannot delete for you — and (for the seccomp supervisor) a privileged supervisor never spends credentials the caller lacks: when the target's filesystem UID/GID, groups, or capabilities differ from the supervisor's, the supervisor declines and the target's own layers and kernel decide.
- **Symlinks are never followed for metadata.** Trashing a symlink trashes the link, not its target. Dangling symlinks trash normally. In cross-filesystem copies, symlinks are recreated as symlinks.
- **No silent overwrites.** Trash IDs are claimed atomically (`O_CREAT|O_EXCL` on the `.trashinfo` file — simultaneous deletes of the same name each get a unique ID, with file names truncated to 223 bytes to stay within filesystem limits). Restores refuse to overwrite an existing destination unless you pass `--force`. The `directorysizes` cache is replaced by atomic rename; config writes are atomic too.
- **Prompts mean what they say.** Confirmation answers apply only to the exact entries confirmed (see Layer 1 deep dive); nothing created afterwards is swept up.
- **Corruption is surfaced, not hidden.** Hash mismatches warn on restore; `trash fsck` exits non-zero on any problem (orphaned `.trashinfo`, orphaned data file, corrupt metadata, unreadable trash root) so scripts notice; corrupt metadata is never auto-deleted because the data file may still be recoverable by hand.

### When a file is really deleted (no trash copy)

| Situation | What happens | How to change it |
| --- | --- | --- |
| `rm --permanent`, `--no-trash`, or `TRASH_BYPASS=1` | Real delete | That is the request — no change needed |
| Path matches `never_trash` (yours, admin's, or a project's) | Real delete | `trash config show` to see the merged list; user entries via `trash config remove` |
| `only_trash` is set and the path does not match | Real delete | Add the pattern, or clear the whitelist |
| File larger than `max_file_size_mb` / directory larger than `max_dir_size_mb` | Real delete (directories whose size cannot be fully checked — the walk caps at 10,000 entries — are refused rather than guessed at when `max_dir_size_mb` is set) | Raise or zero (`0` = unlimited) the limit |
| Deleting process (or an ancestor) is in `bypass_processes`, or its executable matches `bypass_paths` | Real delete | Remove the entry, or exempt one invocation with an explicit `trash`-side workflow |
| Deletion by a statically-linked binary *not* run under `trashd-exec` | Real delete (Layers 1–2 cannot see it) | Run it as `trashd-exec <cmd>` |
| Deletion inside a wrapped session after a Landlock restriction attempt | Preload trashes in-process where loaded; static/raw-syscall deletions proceed to the kernel and may permanently delete what policy permits | Expected: the kernel enforces the target's own Landlock policy; trashd never overrides it |
| Trash storage is unsafe (e.g. another user could control the trash directory) | Preload refuses with `EACCES`; the shim reports an error and deletes nothing | Fix ownership/permissions on the trash directory |
| Trash cannot be created at all (e.g. service account with `HOME=/nonexistent`) | Preload lets the real `unlink`/`rmdir` run; root with a foreign `HOME` uses root's own trash | Give the account a real home, or accept real deletes for it |
| Other operational failure inside preload (after safety checks) | The result of the real syscall is returned so the calling program still works | Check `TRASHD_PRELOAD_LOG=1` output and `trash log` |

The pattern: trashd prefers **keeping the caller's program working** over hard-failing every deletion, except where using the trash would itself be unsafe (controllable-by-others trash directory, unplannable recursive delete, unpublishable cross-device restore), where it refuses instead. The seccomp wrapper follows the same philosophy — setup failures run your command unwrapped with a clear report rather than not at all; only a supervisor that cannot start aborts the launch, because running behind a dead listener would strand syscalls.

### Performance expectations

- **Same-filesystem trashing is a rename** plus metadata/policy checks — effectively instant, even for large trees.
- **`LD_PRELOAD` overhead** is a few string comparisons per `unlink()` for non-trashed paths; negligible in practice.
- **The audit daemon** receives events asynchronously and adds no blocking overhead to deleting processes.
- **Cross-filesystem trashing copies bytes** (like `mv` across devices), including content checks for hardlinked files before retiring source links. Large trees on other mounts cost what a copy costs.
- **Retention scans** read all `.trashinfo` files but run at most once per `auto_purge_interval_secs`. Directory-size eligibility walks cap at 10,000 entries. Hashing applies only up to `sha256_max_size_mb`.
- **Large-trash queries** are built for scale: `ls` streams and retains only matches, `find`/`du` skip stats they do not need, JSON output streams without building one giant string, and directory-size cache repair validates candidate rows incrementally.

---

## Troubleshooting and FAQ

Start every investigation the same way: reproduce with `TRASHD_PRELOAD_LOG=1 <command>` and read stderr, then check `trash ls` and `trash log`. Most surprises are policy (a config pattern or bypass), not bugs.

### "I ran `rm` and the file is just gone"

Work through these in order:

1. **Was it actually the shim?** `which rm` should point into `…/lib/trashd/bin/rm` in login shells. Non-login shells, minimal cron environments, and containers may not have sourced `/etc/profile.d/trashd.sh` — Layer 2 usually still covers the deletion; check `trash ls`.
2. **Was bypass active?** `TRASH_BYPASS=1` in the environment, `--permanent` in the command, or a caller in `bypass_processes` (defaults include `git`, `make`, `cargo`, package managers — `git clean` and `make clean` deleting for real is intentional). `trash config show` prints the merged policy.
3. **Did policy exclude the path?** `/tmp/*`, `*.tmp`, `node_modules/*`, and friends are in the default `never_trash`. Files over `max_file_size_mb` (default 1 GB) also skip trash.
4. **Did retention already purge it?** Items older than `retention.max_age_days` (default 30) are purged automatically. `trash log` shows `PURGE` lines.
5. **Static binary?** Only Layer 4 sees it, and only under `trashd-exec`.

### "My program's deletions are not trashed, but `rm` works"

Almost always one of: the program is statically linked (use `trashd-exec ./your-program`), it runs setuid (same answer), it is — or descends from — a `bypass_processes` entry, or on a packaging-based install the preload library was never registered in `/etc/ld.so.preload`. `TRASHD_PRELOAD_LOG=1 ./your-program` confirms whether the hooks fire at all.

### "How do I see why the seccomp layer is or is not active?"

```bash
echo $TRASHD_SECCOMP_ACTIVE   # "1" = kernel trapping live in this shell
trashd-exec ./your-command    # wrap one command explicitly
trashd-exec bash              # wrap a whole shell session
```

Automatic wrapping applies to interactive **root** login shells only; non-root shells rely on Layers 1–2 so `sudo` keeps working normally. Set `TRASHD_SECCOMP_AUTO=0` to opt a root shell out. Remember the trade-off of explicit wrapping: the wrapped command runs with `NoNewPrivs`, so setuid/file-capability elevation inside it (including some `sudo` uses) will not work — that is the kernel's price for syscall trapping, not a trashd choice. If you see `Device or resource busy (os error 16)`, an outer wrapper already owns a seccomp listener for your session; the inner wrapper steps aside and Layers 1–2 keep protecting you.

### "Can I use trashd in cron / systemd / SSH / containers?"

- **Cron:** yes, with nothing to configure. Cron does not source `/etc/profile.d/trashd.sh`, so a job's `rm` is usually the real binary — but every dynamically-linked process inherits `/etc/ld.so.preload`, so Layer 2 hooks the deletions inside it (and inside any script interpreter the job runs). Jobs started from a login shell may hit the Layer 1 shim first. Layer 4 does not wrap cron jobs.
- **systemd services:** covered by Layer 2 via `/etc/ld.so.preload`, unless the unit deliberately scrubs it. Note the default `bypass_processes` list is matched by process ancestry — a service *launched by* a bypassed tool inherits the bypass.
- **SSH sessions:** login shells get the profile hook like local ones. Non-login SSH commands still have Layer 2.
- **Containers:** trashd protects the host it is installed on. Inside a container you get whatever layers exist *inside* that container's image and mounts; a host-side install does not reach in. The fanotify daemon skips overlay filesystems, so container deletions on overlays are not audited from the host.

### "Does trashd work with my desktop's trash?"

Yes — same folders, same spec. Files trashed from the terminal appear in GNOME Files / Dolphin / Thunar / Nemo and can be restored there; files trashed from the desktop appear in `trash ls` and can be restored with `trash restore`. trashd-only metadata (`X-Trashd-*` fields) is ignored by other implementations, as the spec requires, and auto-compression only touches trashd's own entries so other tools' files stay byte-identical.

### "Will `trash empty` in a script hang waiting for input?"

Without `-y` it always asks when it has entries to delete — and with no terminal to answer from (cron, a timer, `stdin` closed), the prompt reads EOF and cancels, deleting nothing. That fail-safe is why scripts must pass `-y` explicitly (the shipped cleanup timer does). `trash empty --dry-run` never prompts and never deletes — safe to run anywhere for a preview.

### "How do I update or roll back?"

`trash self-update --check` reports whether a newer GitHub release exists; `trash self-update` installs it (verifying the build attestation via `gh` when available — otherwise pass `--allow-unverified` consciously). Install `trashd-exec` and the preload library from the same release together, and restart already-wrapped sessions and long-running processes afterwards: live processes keep the filter/library they started with. Package-managed (`/usr`) installs are updated by your package manager, not by `self-update`. To roll back, reinstall the older release the same way you installed originally; trash contents and `.trashinfo` files are compatible across versions and never need migration.

### "Something's wrong with the trash itself"

Run `trash fsck` (read-only) and then `trash fsck --fix` if it reports orphans. Exit codes are script-friendly: non-zero means "problems found" (or, with `--fix`, "problems remain"). If `trash` commands themselves fail because the trash is broken, `trash config …`, `trash log`, and `trash self-update` still work — they never touch the store.

### Still stuck?

Open an issue at [github.com/faratech/trashd/issues](https://github.com/faratech/trashd/issues) with: `trash --version`, `uname -r`, the exact command that misbehaved, what you expected, and what happened — plus `TRASHD_PRELOAD_LOG=1` output when interception is involved. The checklist in [CONTRIBUTING.md](CONTRIBUTING.md) is the same list.

---

## Advanced: wrapping commands by hand

Most users never type these commands — Layers 1–2 are automatic — but they are the tools for the gaps those layers cannot cover.

### `trashd-exec`: kernel-level protection for one command

```bash
trashd-exec ./deploy.sh        # protect one command (and everything it spawns)
trashd-exec bash               # protect a whole shell session
echo $TRASHD_SECCOMP_ACTIVE    # "1" while wrapping is live
```

Use it for statically-linked binaries, programs that scrub `LD_PRELOAD`, and anything making raw syscalls. Know the costs before wrapping long-lived or privileged work:

- The wrapped command runs with **`NoNewPrivs` set, irreversibly**: setuid binaries and file capabilities inside it cannot elevate. (`--preserve-privileges` avoids this using `CAP_SYS_ADMIN`, which is why auto-wrapped root shells use it; it falls back cleanly when the capability is unavailable.)
- The wrapper stays alive until **all descendants** exit — background daemons spawned by the command keep `trashd-exec` running and return the *command's* exit status only at the end.
- Protection is published (`TRASHD_SECCOMP_ACTIVE=1` plus cookie) only *after* memory access, root/cwd pinning, and supervisor readiness all succeed; on setup failure your command runs unwrapped instead of failing (supervisor startup failure is the one abort case).
- Upgrade hygiene: wrapper and preload must come from the same release; restart wrapped sessions after upgrading.

### `LD_PRELOAD` by hand

System-wide registration is the default, but per-command use is handy for testing or minimal installs:

```bash
# Protect exactly one invocation
LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so python3 cleanup.py

# Watch every interception on stderr while you test
TRASHD_PRELOAD_LOG=1 LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so python3 cleanup.py
# stderr: [trashd-preload] trashed: /home/user/cache.db -> …
```

Long-running processes only pick up config changes at restart (mtime changes are detected and logged every 60s, never hot-applied — mutating global state inside a preload library is unsafe by design).

---

## Install options in detail

The [Quick start](#quick-start) path (`sudo ./install.sh`) is recommended. The alternatives exist for packagers, custom prefixes, and minimal installs.

### Build and install with `make`

`make` builds as your own user; `sudo make install` only copies artifacts and never compiles as root:

```bash
make
sudo make install            # default prefix /usr/local; override with PREFIX=/usr etc.
sudo make uninstall          # removes the install; your trash contents are preserved
```

`make install` stages the same layout as `install.sh` (binaries, shim, daemon + `trashd` symlink, man pages from `target/man/`, completions), templates the chosen `PREFIX` into `/etc/profile.d/trashd.sh` and the systemd units (so custom prefixes actually activate), installs the shipped config only when none exists, and — for native (non-`DESTDIR`) installs — registers the preload library in `/etc/ld.so.preload`. `make uninstall` deregisters `LD_PRELOAD` *before* deleting the `.so` and stops the daemon first. Staging with `DESTDIR=…` never touches the host's `ld.so.preload` or systemd.

### Distribution packages

Templates live in [`packaging/`](packaging/): an RPM spec (`trashd.spec`) and an Arch `PKGBUILD`. They build with `cargo build --release --locked` and install via `make install PREFIX=/usr`. Two behavioural notes: packages install the preload library **without** registering it in `/etc/ld.so.preload` (enable Layer 2 by adding the library path there), and the admin config is preserved across upgrades (`%config(noreplace)` / `backup=`). `trash self-update` deliberately refuses to manage package-owned `/usr` installs.

### Manual install (what the scripts do, by hand)

```bash
cargo build --release --locked
cp target/release/trash /usr/local/bin/
cp target/release/trashd-rm /usr/local/lib/trashd/bin/rm   # plus an `unlink` symlink beside it
cp target/release/libtrashd_preload.so /usr/local/lib/trashd/
cp target/release/trashd-exec /usr/local/bin/
cp target/release/trashd /usr/local/bin/
```

A manual copy alone does not activate anything: you still need the `PATH` hook (`install/profile.d/trashd.sh`), the `/etc/ld.so.preload` entry for Layer 2, and the systemd unit (`install/systemd/trashd.service`) for Layer 3. Prefer `install.sh` or `make install` unless you are packaging.

### Updating

Re-run `sudo ./install.sh` (or `trash self-update`) with the new release. Existing trash, config, and `.trashinfo` files carry over without migration. Restart auto-wrapped shells and long-running processes so they pick up the new wrapper/library pair, and always update `trashd-exec` and `libtrashd_preload.so` together — the cookie handshake keeps mismatched pairs safe (preload simply stops deferring), but only matched pairs get full Layer 4 behaviour.

---

## For developers

### Build

```bash
cargo build --release              # full workspace build
cargo build -p trashd-cli          # a single crate
./install.sh                       # see Quick start for the sudo workflow
```

The workspace pins Rust via `rust-toolchain.toml` (channel + `clippy`/`rustfmt` components) — `rustup` honours it automatically, and CI deliberately installs no separate toolchain so the pin cannot drift.

### Test

```bash
TRASH_BYPASS=1 cargo test --workspace     # unit tests (TRASH_BYPASS stops a system-wide preload interfering)
sudo ./tests/integration.sh target/release          # CLI + shim, end-to-end in a disposable filesystem
sudo ./tests/install_regression.sh target/release   # install.sh itself, inside the sandbox
sudo python3 tests/shim_regression.py target/release/trashd-rm
tests/glibc_floor.sh 2.28 <artifacts>               # release artifacts must honour the glibc 2.28 floor
```

Subprocess suites enter [`tests/sandbox.py`](tests/sandbox.py): a disposable chroot in private mount/PID namespaces with isolated `HOME`/XDG, read-only system runtimes, only the requested built binaries copied in, and sentinel checks proving mounted trash outside the sandbox is untouched. They require Linux mount privileges (hence `sudo`) and **fail closed** if isolation cannot be established — never run legacy tests against installed binaries, never source the installed profile, and never empty host trash to set up a test. Set `REQUIRE_SECCOMP=1` (via `sudo env …`) to make an unavailable seccomp listener a failure instead of a skip, and `TRASHD_TEST_NETWORK=1` for the opt-in self-update network check. Releases are built with `cargo zigbuild --target <triple>.2.28` to hold the glibc floor verified by `tests/glibc_floor.sh`.

Two testing rules that bite newcomers (also in [CONTRIBUTING.md](CONTRIBUTING.md)): destructive store tests must use `TrashStore::open_isolated` with an explicit temporary root — `TrashStore::open()` plus `XDG_DATA_HOME` still sees mounted trash — and store tests run with `--test-threads=1` in CI for the suites that share filesystem fixtures.

### Project layout

```text
trashd/
├── crates/
│   ├── trashd-common/     # shared core library (all policy lives here)
│   │   ├── config.rs          layered TOML config + pattern matching
│   │   ├── store.rs           TrashStore: trash/restore/purge/empty/auto-purge
│   │   ├── store/             listing + unfinished-cleanup helpers
│   │   ├── trashinfo.rs       .trashinfo parser/serializer (FreeDesktop spec)
│   │   ├── mounts.rs          multi-partition trash discovery
│   │   ├── directorysizes.rs  spec `directorysizes` cache (atomic writes)
│   │   └── oplog.rs           operation log + desktop notifications
│   ├── trashd-cli/        # `trash` CLI (clap; commands in src/commands/)
│   ├── trashd-shim/       # `trashd-rm`: drop-in `rm` replacement
│   ├── trashd-preload/    # `libtrashd_preload.so` — standalone, no trashd-common dep
│   ├── trashd-seccomp/    # `trashd-exec`: supervisor + watchdog + broker + BPF filter
│   └── trashd-daemon/     # `trashd`: fanotify audit daemon (built as `trashd`)
├── config/trashd.toml     # shipped default config template
├── install/               # profile.d hook + systemd units (service, cleanup timer)
├── packaging/             # RPM spec + Arch PKGBUILD templates
└── tests/                 # sandboxed end-to-end suites (sandbox.py, integration.sh, …)
```

| Binary produced | Crate | Role |
| --- | --- | --- |
| `trash` | `trashd-cli` | User CLI: `ls`, `find`, `info`, `restore`, `undo`, `purge`, `empty`, `compress`, `du`, `status`, `log`, `fsck`, `config`, `self-update` |
| `trashd-rm` | `trashd-shim` | Drop-in `rm` (installed as `rm` on the shim `PATH`), Layer 1 |
| `libtrashd_preload.so` | `trashd-preload` | `LD_PRELOAD` hooks for `unlink`/`unlinkat`/`rmdir`/`remove`, Layer 2 (~870 KB, standalone) |
| `trashd-exec` | `trashd-seccomp` | Seccomp supervisor, watchdog, and ancestor broker, Layer 4 |
| `trashd` | `trashd` (in `crates/trashd-daemon/`) | fanotify audit daemon (systemd service), Layer 3 |

Dependency direction is one-way (`trashd-cli`/`-shim`/`-seccomp`/daemon → `trashd-common`; preload → nothing), which keeps the preload `.so` small enough to load into every process. If you change config parsing or trash-directory selection, remember the preload duplicates that logic — update both, or the layers will disagree.

### Operation log

Every trash, restore, purge, and empty operation appends one line to `~/.local/share/Trash/.trashd/operations.log` (per trash root):

```text
2026-03-19T22:51:22 pid=20574 PURGE id=old_backup.tar.gz
2026-03-19T22:51:22 pid=20577 TRASH id=report.pdf path=/home/user/report.pdf cmd=rm report.pdf
2026-03-19T22:51:22 pid=20582 EMPTY count=3 filter=all
2026-03-19T22:51:22 pid=20598 RESTORE id=report.pdf to=/home/user/report.pdf
```

Read it with `trash log` (last 20 lines) or `trash log -n 100`. It is the fastest way to answer "what deleted this, and when?" after the fact.

---

## Compatibility

### System requirements

| Requirement | Needed for | Notes |
| --- | --- | --- |
| Linux, any kernel | Layers 1–2 (shim + preload) | The protection most users rely on |
| Linux 5.6+ | Layer 4 (seccomp user-notification, `openat2` pinning) | Older kernels simply lack kernel trapping |
| Linux 5.9+ | Layer 3 (fanotify FID reporting) | The daemon idles harmlessly without markable mounts |
| `CAP_SYS_ADMIN` (via systemd ambient capabilities) | Layer 3 daemon | Granted by the shipped unit; you do not set it by hand |
| Rust 1.99.1+ | Building from source only | Runtime has no Rust dependency |
| systemd | Daemon + cleanup timer (optional conveniences) | Layers 1, 2, and 4 work without systemd |

Architectures: x86-64 is the primary target (including an optional i686 preload for 32-bit processes on multilib systems); aarch64 is supported for Layers 1–3 and for Layer 4's `unlinkat`-only filter. Release artifacts are built against a glibc 2.28 floor, so they run on older enterprise distributions.

### FreeDesktop.org Trash specification v1.0

trashd implements the full [Trash specification v1.0](https://specifications.freedesktop.org/trash/latest/), which is what makes desktop interoperability work:

- **Directories:** `$XDG_DATA_HOME/Trash/` for home trash (private, current-user-owned `files/` + `info/`); `$topdir/.Trash/$UID/` when the shared `$topdir/.Trash/` passes spec validation (real directory, root/current-user owned, sticky bit; per-user dir owner-validated, mode `0700`); `$topdir/.Trash-$UID/` as the private fallback — unsafe candidates fall back to home trash rather than being trusted.
- **Metadata (`.trashinfo`):** first line exactly `[Trash Info]`; `Path=` percent-encoded per RFC 2396 (absolute for home trash, topdir-relative for topdir trash — relative paths containing `..` are rejected; the value is *not* trimmed, since encoded spaces are meaningful); `DeletionDate=` in ISO 8601 local time (DST-ambiguous times take the latest reading, DST gaps shift forward an hour); duplicate keys resolve first-occurrence-wins; unknown keys are ignored for forward compatibility.
- **Extensions:** trashd adds spec-compliant `X-` fields other tools ignore — `X-Trashd-Command`, `X-Trashd-PID`, `X-Trashd-Size`, `X-Trashd-Hash` (older entries: `X-Trashd-SHA256`), `X-Trashd-Compressed`. Example:

  ```ini
  [Trash Info]
  Path=/home/user/project/main.py
  DeletionDate=2026-03-19T14:30:00
  X-Trashd-Command=rm -rf project/
  X-Trashd-PID=48231
  X-Trashd-Size=4096
  X-Trashd-Hash=a1b2c3…
  ```

- **Orphans are emergencies, per spec:** a file in `files/` without its `.trashinfo` "MUST be presented as such" — `trash ls` lists it as orphaned and `trash fsck` reports it, instead of hiding it.
- **No private database:** entries are read from `.trashinfo` files directly; there is no SQLite cache to drift out of sync (cache files left by older versions are simply left untouched).

---

## Contributing

Contributions are welcome — bug reports, documentation fixes, and code. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for the build/test workflow, code style (`cargo fmt`, `cargo clippy -- -D warnings`, no `.unwrap()` in library code), and the sandbox testing rules. Changes are recorded in [CHANGELOG.md](CHANGELOG.md); the current release is 0.1.14.

Found a deletion that trashd missed or mishandled? That is exactly the bug class this project cares most about — please file it at [github.com/faratech/trashd/issues](https://github.com/faratech/trashd/issues) with version, kernel, reproduction steps, expected vs. actual behaviour, and `TRASHD_PRELOAD_LOG=1` output where relevant.

## License

[MIT](LICENSE) © Faratech

*Delete boldly. Restore calmly.*




