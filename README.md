# trashd

A Linux recycle bin that actually works — in scripts, cron jobs, and at the desktop.

Unlike `safe-rm` (which only blocks deletes) or `trash-cli` (which requires calling `trash-put` instead of `rm`), trashd intercepts destructive commands transparently across four independent layers. Scripts that call `rm` get trash protection without any code changes. Programs that call `unlink()` directly get caught too. Even statically-linked binaries making raw syscalls are intercepted at the kernel boundary.

Every layer is fail-safe: if trashing fails for any reason, the real delete executes normally. trashd never blocks or hangs a deletion.

## How it works

```
  User / Script / Cron
        │
        ▼
┌──────────────────────────┐
│  Layer 1: PATH shims     │  rm → move to trash
│  /usr/local/lib/trashd/  │  --permanent bypasses
└──────────┬───────────────┘
           │ (if shim missed it)
           ▼
┌──────────────────────────┐
│  Layer 2: LD_PRELOAD     │  intercepts unlink(), rmdir()
│  libtrashd_preload.so    │  catches Python, Perl, Go, C...
└──────────┬───────────────┘
           │ (if preload missed it)
           ▼
┌──────────────────────────┐
│  Layer 4: seccomp        │  traps syscalls at kernel boundary
│  trashd-exec             │  catches static binaries, raw syscalls
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  Trash Store             │  FreeDesktop.org Trash spec v1.0
│  ~/.local/share/Trash/   │  + per-mountpoint .Trash-$UID/
└──────────┬───────────────┘
           │ (Layer 3 watches everything)
           ▼
┌──────────────────────────┐
│  fanotify daemon         │  detects ALL deletions system-wide
│  trashd-daemon           │  audit log (cannot intercept)
└──────────────────────────┘
```

All four layers are enabled by default after install. They complement each other:

### Layer 1 — PATH shim (`trashd-rm`)

A drop-in `rm` replacement installed at `/usr/local/lib/trashd/bin/rm`, prepended to `$PATH` via `/etc/profile.d/trashd.sh`. Intercepts any `rm` invocation from shell scripts, cron jobs, `find -exec`, `xargs`, and interactive use.

Supports all standard GNU `rm` flags: `-r`/`-R`/`--recursive`, `-f`/`--force`, `-i` (prompt per file), `-I` (prompt once for 3+ files), `-d`/`--dir` (empty directories), `-v`/`--verbose`. Adds `--permanent` and `--no-trash` to bypass trash when needed.

Discovers the real `rm` binary via a stashed copy at `/usr/local/lib/trashd/real/rm`, falling back to PATH search (skipping trashd directories), then `/usr/bin/rm`. When passing through to real `rm`, sets `TRASH_BYPASS=1` in the child environment so the LD_PRELOAD layer doesn't re-intercept the delete.

In GUI sessions (when `$DISPLAY` or `$WAYLAND_DISPLAY` is set), sends a desktop notification via `notify-send` when files are trashed.

### Layer 2 — LD_PRELOAD (`libtrashd_preload.so`)

A shared library that hooks `unlink()`, `unlinkat()`, and `rmdir()` at the libc level using `dlsym(RTLD_NEXT, ...)`. Catches deletions from any dynamically-linked program — Python's `os.remove()`, Perl's `unlink`, Go's `os.Remove()`, compiled C programs, anything that calls libc.

Enabled system-wide via `/etc/ld.so.preload` (installed automatically). The library is intentionally standalone — no dependency on `trashd-common` or SQLite — to keep the `.so` small (~870 KB) and avoid pulling heavy dependencies into every process on the system.

Key safety mechanisms:
- **Re-entrancy guard** — A thread-local `Cell<bool>` prevents internal `rename()`/`mkdir()` calls during trash operations from re-entering the hooked `unlink()`.
- **Trash directory skip** — Paths inside `~/.local/share/Trash/`, `.Trash-$UID/`, and `.Trash/` are never intercepted. This prevents the preload from trashing SQLite journal files and `.trashinfo` cleanup operations.
- **Seccomp deference** — When `TRASHD_SECCOMP_ACTIVE=1` is set (by Layer 4), the preload skips interception entirely to avoid double-trashing.
- **Config change detection** — Checks config file mtime every 60 seconds and logs when changes are detected. Full reload requires process restart (intentional — mutating global state in a preload `.so` is unsafe).

### Layer 3 — fanotify daemon (`trashd-daemon`)

A system service that monitors all real filesystems for `FAN_DELETE`, `FAN_DELETE_SELF`, and `FAN_MOVED_FROM` events using fanotify with `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (requires Linux 5.9+). Detection and audit only — it cannot intercept or prevent deletions.

Resolves deleted file paths by parsing extended `fanotify_event_info_fid` structs to extract the parent directory's file handle and the deleted filename. The parent is resolved via `open_by_handle_at()` against cached per-mount `O_PATH` file descriptors. Logs every deletion with PID, process name, and path.

Runs as a systemd service with `AmbientCapabilities=CAP_SYS_ADMIN`. Skips virtual filesystems (tmpfs, ramfs, devtmpfs, overlay, squashfs). Uses non-blocking I/O with a 1-second poll timeout.

### Layer 4 — seccomp supervisor (`trashd-exec`)

The most robust layer. Traps `unlink(2)`, `unlinkat(2)`, and `rmdir(2)` at the kernel syscall boundary using a BPF seccomp filter with `SECCOMP_RET_USER_NOTIF`. Catches everything — statically-linked binaries, setuid programs, programs that clear `LD_PRELOAD`, and raw syscalls.

**Three-process architecture:**

1. **Child** — Installs the BPF seccomp filter via `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...)`, passes the notification file descriptor to the parent via `SCM_RIGHTS` over a Unix socketpair, then `execvp()`'s the target command. Requires `prctl(PR_SET_NO_NEW_PRIVS, 1)` before installing the filter.

2. **Supervisor** — Receives notifications via `ioctl(SECCOMP_IOCTL_NOTIF_RECV)`, reads the target process's path argument from memory via `process_vm_readv()`, resolves relative paths using `/proc/{pid}/cwd` or `/proc/{pid}/fd/{dirfd}`, applies config filters, and either trashes the file (responding with success) or lets the real syscall execute (responding with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`). Validates notification IDs to mitigate TOCTOU races.

3. **Watchdog** — Holds a `dup()`'d copy of the notification fd. Monitors the supervisor via `waitpid()`. On supervisor death: immediately drains all pending notifications with `CONTINUE` (fail-safe — blocked processes resume with real deletes), then forks a new supervisor. If fork fails, enters emergency passthrough mode (responds `CONTINUE` to everything forever).

The orchestrator forwards `SIGINT` and `SIGTERM` to the child process, then waits for it and cleans up the supervisor and watchdog.

The BPF filter is architecture-specific: x86_64 traps `SYS_unlink` (87), `SYS_unlinkat` (263), and `SYS_rmdir` (84). aarch64 traps only `SYS_unlinkat` (35) since the other two syscalls don't exist on that architecture.

Interactive shells are automatically wrapped via `/etc/profile.d/trashd.sh`, which detects interactive mode (`case "$-" in *i*`), sets `TRASHD_SECCOMP_ACTIVE=1`, and `exec`'s the shell under `trashd-exec`. A guard variable prevents infinite re-exec.

### How the layers interact

Layer 4 (seccomp) is the primary layer for interactive shells — it's the most robust. Layer 2 (LD_PRELOAD) provides system-wide fallback coverage for daemons, cron jobs, and non-interactive processes that don't go through `profile.d`. The preload checks `TRASHD_SECCOMP_ACTIVE` and defers when seccomp is active, preventing double interception.

Layer 1 (shim) catches `rm` specifically and provides the user-facing flags (`--permanent`, `-i`, `-v`). When it passes through to real `rm`, it sets `TRASH_BYPASS=1` so Layer 2 doesn't re-intercept.

Layer 3 (daemon) runs independently as an audit trail — it sees everything, including deletions that bypass all other layers.

| Scenario | Layer 1 | Layer 2 | Layer 4 |
|----------|---------|---------|---------|
| `rm file.txt` in shell | Catches | — | — |
| `python3 -c "os.remove(...)"` | — | Catches | — |
| Statically-linked binary | — | Misses | Catches |
| `setuid` program (LD_PRELOAD stripped) | — | Misses | Catches |
| Cron job | Catches (rm) | Catches (unlink) | Misses |
| Systemd service | — | Bypassed | — |

## Install

```bash
git clone https://github.com/faratech/trashd.git
cd trashd
sudo ./install.sh
```

Requires Rust (cargo). The install script:

1. Updates the Rust toolchain and workspace dependencies
2. Builds all crates in release mode
3. Installs binaries to `/usr/local/bin/` and `/usr/local/lib/trashd/`
4. Stashes the real `rm` binary at `/usr/local/lib/trashd/real/rm`
5. Creates the PATH shim at `/usr/local/lib/trashd/bin/rm` (+ `unlink` symlink)
6. Adds `libtrashd_preload.so` to `/etc/ld.so.preload` (system-wide)
7. Installs `/etc/profile.d/trashd.sh` (PATH shim + seccomp wrapper)
8. Installs and starts the `trashd-daemon` systemd service
9. Installs man pages to `/usr/local/share/man/man1/`
10. Installs shell completions for bash, zsh, and fish
11. Creates global config at `/etc/trashd/config.toml`

Start a new shell or run:
```bash
source /etc/profile.d/trashd.sh
```

### Uninstall

```bash
sudo ./install.sh --uninstall
```

Removes all binaries, libraries, config, man pages, shell completions, the systemd service, the `/etc/ld.so.preload` entry (removed *before* deleting the `.so` to prevent error messages), and **all FreeDesktop.org trash directories** across all users and all mount points — including `~/.local/share/Trash/` for every user in `/home/` and `/root`, plus `$mountpoint/.Trash-$UID/` and `$mountpoint/.Trash/` on every mounted filesystem.

### Manual install

```bash
cargo build --release
cp target/release/trash /usr/local/bin/
cp target/release/trashd-rm /usr/local/lib/trashd/bin/rm
cp target/release/libtrashd_preload.so /usr/local/lib/trashd/
cp target/release/trashd-exec /usr/local/bin/
cp target/release/trashd-daemon /usr/local/bin/
```

## Usage

### Transparent interception (just use rm normally)

```bash
rm file.txt              # moved to trash, not deleted
rm -rf project/          # directory moved to trash
rm -i important.txt      # prompts before trashing (like real rm)
rm -I *.tmp              # prompt once if 3+ files
rm -v file.txt           # verbose: "trashed 'file.txt' [file.txt]"
rm -d empty_dir/         # remove empty directory (checks emptiness first)
```

### Manage trash

```bash
trash ls                 # list trashed files (all partitions, newest first)
trash ls '*.py'          # filter by glob pattern (matches name or full path)
trash find ~/projects    # search by original path substring
trash info <id>          # show full metadata: command, PID, size, hash, trash dir, storage path
trash restore foo.txt    # restore to original location
trash restore foo --to . # restore to current directory
trash undo               # restore the most recently trashed item
trash purge foo.txt      # permanently delete a specific entry
trash empty              # permanently empty all trash (prompts for confirmation)
trash empty -y           # skip confirmation prompt
trash empty --older 7d   # purge items older than 7 days
trash empty --older 2w   # purge items older than 2 weeks
trash empty --dry-run    # preview what would be deleted (with sizes)
trash du                 # show largest items in trash, sorted by size
trash du -n 10           # show top 10 largest
trash compress           # compress items older than 7 days (native zstd)
trash compress --older 3d # compress items older than 3 days
trash compress --dry-run # preview what would be compressed
trash status             # show total size, count, per-partition breakdown
trash log                # show recent operations (audit trail)
trash log -n 50          # show last 50 operations
trash fsck               # check trash directory integrity
trash fsck --fix         # fix orphaned and corrupt entries
trash --version          # show version
```

### Bypass trash when needed

```bash
rm --permanent file.txt         # real delete through the shim
rm --no-trash file.txt          # same thing
TRASH_BYPASS=1 rm file.txt      # real delete via env var
TRASH_BYPASS=1 ./deploy.sh      # disable for an entire script
```

### Seccomp supervisor

```bash
# Wrap a single command — catches static binaries, raw syscalls
trashd-exec ./deploy.sh

# Wrap a shell session
trashd-exec bash

# Already active in interactive shells (via profile.d)
echo $TRASHD_SECCOMP_ACTIVE  # "1" if active
```

### LD_PRELOAD

```bash
# Per-command
LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so python3 cleanup.py

# System-wide (enabled by default after install via /etc/ld.so.preload)

# Debug logging (shows every interception on stderr)
TRASHD_PRELOAD_LOG=1 rm file.txt
# stderr: [trashd-preload] trashed: /home/user/file.txt -> ...
```

## Multi-partition support

Files are always trashed on the same filesystem to avoid slow cross-device copies. Per the FreeDesktop.org spec:

- Same filesystem as `$HOME` → `~/.local/share/Trash/`
- Different filesystem, shared `.Trash/` with sticky bit → `$mountpoint/.Trash/$UID/`
- Different filesystem, no shared trash → `$mountpoint/.Trash-$UID/`
- Both fail → falls back to home trash (cross-device copy)

Filesystem boundaries are detected by comparing `st_dev` (device IDs) from `stat()`. Mount points are discovered by parsing `/proc/mounts` and selecting the longest matching prefix.

```
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

Listing, restore, purge, and empty all work across all partitions automatically.

### Cross-device move mechanics

When `fs::rename()` fails (different filesystems), trashd falls back to copy + delete:

1. **Symlinks** — Recreated at the destination via `std::os::unix::fs::symlink()`. The link target is preserved exactly — the symlink itself is moved, not the target.
2. **Directories** — Recursively copied via `copy_tree()`, which preserves permissions, recreates symlinks (doesn't follow them), and skips special files (FIFOs, devices, sockets). Depth-limited to 100 levels to prevent crashes from symlink loops or bind mount cycles.
3. **Regular files** — Copied via `fs::copy()`, permissions set after writing (per spec — file might be made unwriteable by its own permissions).

If the copy fails, the orphaned `.trashinfo` and any partial copy are cleaned up before returning the error.

## Configuration

### Layered config

Four layers, each optional, merged in order:

1. **Hardcoded defaults** — Built into the binary
2. **Global** `/etc/trashd/config.toml` — Admin-managed, applies to all users
3. **User** `~/.config/trashd/config.toml` — Personal overrides
4. **Per-directory** `.trashd.toml` — Project-level rules (searched up to 5 parent levels)

**Merge rules:**
- **Scalars** (retention days, size limits, hash algorithm): user overrides global overrides defaults
- **Lists** (`never_trash`, `bypass_processes`, `bypass_paths`): user *extends* global — admin-set patterns cannot be removed by individual users
- **`only_trash`**: user *replaces* global (it's a whitelist — extending doesn't make sense)

### Full config reference

```toml
[retention]
max_age_days = 30           # auto-purge items older than this (default: 30)
max_size_gb = 10.0          # cap total trash size (default: 10.0)
disk_pressure_percent = 90  # purge oldest when disk usage exceeds this (default: 90)

# Paths that should never be trashed (real-deleted instead).
# User configs extend this list — admin patterns can't be removed.
never_trash = [
    "/tmp/*",
    "/var/tmp/*",
    "/var/cache/*",
    "/proc/*",
    "/sys/*",
    "/dev/*",
    "/dev/shm/*",
    "/run/*",
    "*.o",
    "*.pyc",
    "*.class",
    "*.lock",
    "*.pid",
    "*.sock",
    "*.socket",
    "*.tmp",
    "*.swp",
    "*~",
    "__pycache__/*",
    "node_modules/*",
    "target/debug/*",
    "target/release/*",
    "*/.git/*",
]

# If set, ONLY files matching these patterns are trashed.
# Everything else is real-deleted. never_trash still takes priority.
# Empty (default) means all files are eligible for trash.
only_trash = []

# Parent processes that bypass trash automatically.
# Detected by walking /proc/{pid}/stat up the process tree.
bypass_processes = [
    "apt", "apt-get", "dpkg",
    "yum", "dnf", "pacman", "rpm",
    "pip", "cargo", "npm", "make",
    "git",
    "systemd", "systemctl", "journald",
    "containerd", "dockerd",
]

# Executable paths that bypass trash (prefix match on /proc/self/exe).
# More precise than bypass_processes — matches the full exe path.
bypass_paths = []

max_file_size_mb = 1024        # files over this skip trash (default: 1024)
max_dir_size_mb = 0            # directories over this skip trash (0 = no limit)
hash_algorithm = "xxhash"      # "xxhash" (XXH3-128, ~10x faster) or "sha256" (cryptographic)
sha256_max_size_mb = 1         # only hash files smaller than this (default: 1 MB)
auto_purge_interval_secs = 60  # min seconds between auto-purge scans (default: 60)
```

### Pattern matching syntax

| Pattern | Example | Matches |
|---------|---------|---------|
| `prefix/*` | `/tmp/*` | Anything starting with `/tmp/` |
| `*.ext` | `*.pyc` | Anything ending with `.pyc` |
| `*/.infix/*` | `*/.git/*` | Anything containing `/.git/` in the path |
| `*/name` | `*/core` | Anything with `/core` in the path or ending with `/core` |
| `*~` | `*~` | Anything ending with `~` (editor backups) |
| exact | `/var/run/lock` | Exact string match |

Patterns are matched against the file's absolute path. The same syntax works in `never_trash`, `only_trash`, per-directory `.trashd.toml`, and `trash ls` pattern arguments.

### Per-directory overrides

Place a `.trashd.toml` in any project directory to customize trash behavior for that tree:

```toml
# These patterns are checked first (before global config)
never_trash = ["build/*", "dist/*", "*.log"]
only_trash = ["src/*", "*.config", "*.env"]
```

Searched up to 5 parent levels from the file being deleted. Global `never_trash` still wins over local `only_trash` — an admin-excluded pattern can't be overridden by a project config.

## Auto-purge and compression

After every trash operation, trashd runs an automatic retention policy (throttled to at most once per `auto_purge_interval_secs`, default 60 seconds):

**Phase 1 — Age purge:** Delete items older than `retention.max_age_days`.

**Phase 2 — Auto-compress:** Before purging by size, compress items older than 7 days using native zstd (level 3). This reclaims space without losing data — often enough to avoid purging at all. Skips already-compressed files (detected by zstd magic `0xFD2FB528`), files under 1 KB, and directories. Only replaces the file if compression actually reduced the size.

**Phase 3 — Size trim:** If total trash exceeds `retention.max_size_gb`, purge the oldest surviving items until under the limit.

**Phase 4 — Disk pressure:** If the home trash filesystem exceeds `retention.disk_pressure_percent` usage, purge the oldest 10% of surviving items.

### Manual compression

```bash
trash compress                # compress items older than 7 days
trash compress --older 3d     # compress items older than 3 days
trash compress --dry-run      # preview without compressing
```

Uses native zstd (the `zstd` Rust crate — no system dependency). Typical results: text files see 95%+ compression; binaries ~50%. Already-compressed files and files under 1 KB are automatically skipped.

### Transparent decompression on restore

When restoring a compressed file, trashd detects the zstd magic header (`0x28B52FFD`) and decompresses the content in-place before returning it to the user. Hash verification runs against the decompressed content, so the original hash matches correctly. This is fully transparent — the user always gets their original file back.

## Integrity and hash verification

### On trash

A file hash is computed for files smaller than `sha256_max_size_mb` (default 1 MB). The algorithm is configurable:

- **xxhash** (default) — XXH3-128, ~10x faster than SHA-256. Suitable for integrity verification (detecting bit rot, bad disks, partial copies). Not cryptographic.
- **sha256** — SHA-256, cryptographic. Use when you need to verify file authenticity, not just integrity.

The hash is stored in the `.trashinfo` file as `X-Trashd-Hash=...`. Older entries may use `X-Trashd-SHA256=...` — both are read for backward compatibility.

### On restore

After restoring a file, trashd verifies the hash against the restored content. It tries both xxhash and sha256 (since the algorithm may have changed between trash and restore). If the hash doesn't match, a warning is printed:

```
trashd: warning: hash mismatch for restored file /home/user/data.csv
  expected: af8f72d9a92c0c4fceb70b3c89911f2b
  actual:   3cdfb8a99b35162b65d20bd3eda6cafa
  file may be corrupted — verify contents before use
```

The restore still succeeds — the warning is informational, not blocking. The user can decide whether to trust the file.

Changing `hash_algorithm` in the config does **not** require rehashing existing entries. Old hashes continue to verify correctly because restore tries both algorithms.

## Safety

### Fail-safe design

Every interception layer falls back to the real delete operation on any error:
- **Shim** — Calls real `rm` via `passthrough()` on parse errors, missing files, or excluded paths
- **Preload** — Returns the result of the real `unlink()`/`rmdir()` if trash fails
- **Seccomp** — Responds with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (execute real syscall)
- **Watchdog** — On supervisor crash, drains all pending notifications with `CONTINUE`

trashd will never block, hang, or prevent a deletion. If everything fails, the delete just works normally.

### Confirmation on empty

`trash empty` prompts for confirmation before permanently destroying all trash:

```
Permanently delete 142 items (1.3 GB)? [y/N]
```

Use `-y`/`--yes` to skip the prompt (for scripts).

### Bypass mechanisms

| Mechanism | Scope | How |
|-----------|-------|-----|
| `rm --permanent` / `rm --no-trash` | Single command | Shim strips flag, passes to real `rm` with `TRASH_BYPASS=1` |
| `TRASH_BYPASS=1` | Environment | Checked by shim, preload, and seccomp init |
| `bypass_processes` | Process tree | Walks `/proc/{pid}/stat` up to 10 levels, checks each ancestor's name |
| `bypass_paths` | Executable path | Matches `/proc/self/exe` against prefix list |
| `never_trash` | File path patterns | Glob matching (global + per-directory) |
| `only_trash` | File path whitelist | If set, only matching files are trashed |
| `max_file_size_mb` / `max_dir_size_mb` | Size limits | Files/directories exceeding the limit are real-deleted |

### Atomic operations

- **Trash entry IDs** — Claimed via `O_CREAT|O_EXCL` on the `.trashinfo` file. If two processes trash the same filename simultaneously, each gets a unique ID (appending timestamp + counter). Filenames are truncated to 223 bytes to stay within the 255-byte filesystem limit after adding the `.trashinfo` suffix.
- **`directorysizes` cache** — Written via temp file + atomic `rename()` per spec.
- **Operation log** — Append-only file, one write per operation.

### Symlink safety

All metadata operations use `symlink_metadata()` (equivalent to `lstat()`) — symlinks are never followed. Trashing a symlink removes the link itself, preserving the target. Dangling symlinks are trashed normally (not silently dropped). During cross-device directory copies, symlinks are recreated via `std::os::unix::fs::symlink()`, not followed.

### Orphan detection

Per the FreeDesktop spec: "If info file corresponding to file in $trash/files is unavailable, this is emergency case and MUST be presented as such."

`trash ls` scans both `info/` and `files/` directories. Entries in `files/` without matching `.trashinfo` are listed as orphaned:

```
2026-03-19 22:38    ? (orphaned: mysterious_file)    mysterious_file
```

`trash fsck` detects three types of problems:
- Orphaned `.trashinfo` (no matching file in `files/`)
- Orphaned files (no matching `.trashinfo` in `info/`)
- Corrupt `.trashinfo` (unparseable)

`trash fsck --fix` removes all detected problems.

## FreeDesktop.org Trash spec v1.0 compliance

trashd implements the complete [FreeDesktop.org Trash specification v1.0](https://specifications.freedesktop.org/trash/latest/):

### Directory structure
- `$XDG_DATA_HOME/Trash/` home directory trash with `files/` and `info/` subdirectories
- `$topdir/.Trash/$UID/` shared topdir trash (validated: must be a real directory, not a symlink, with sticky bit set)
- `$topdir/.Trash-$UID/` per-user topdir trash (fallback when shared trash validation fails)
- `$trash/directorysizes` cache (size, trashinfo mtime, percent-encoded name — updated via atomic rename)

### .trashinfo format
- First line validated as exactly `[Trash Info]` (files without this header are rejected)
- `Path=` — percent-encoded per RFC 2396. Absolute paths for home trash, relative paths (from topdir) for topdir trash. Relative paths validated to not contain `..`
- `DeletionDate=` — ISO 8601 `YYYY-MM-DDThh:mm:ss` in local time. DST ambiguity handled (uses latest time). DST gaps handled (shifts forward 1 hour)
- Duplicate keys: first occurrence wins (per spec)
- `Path=` value is not trimmed before decoding (percent-encoded spaces are meaningful)
- Unknown keys are ignored (per spec — allows future extension)

### Extended metadata (spec-compliant `X-` fields)
```ini
[Trash Info]
Path=/home/user/project/main.py
DeletionDate=2026-03-19T14:30:00
X-Trashd-Command=rm -rf project/
X-Trashd-PID=48231
X-Trashd-Size=4096
X-Trashd-Hash=a1b2c3...
```

### Interoperability

Desktop file managers (Nautilus, Dolphin, Thunar, Nemo) see the same trash and can restore files trashed by trashd, and vice versa. The extended `X-Trashd-*` fields are ignored by other implementations per spec.

## Operation log

Every trash, restore, purge, and empty operation is logged to `~/.local/share/Trash/.trashd/operations.log`:

```
2026-03-19T22:51:22 pid=20574 PURGE id=old_backup.tar.gz
2026-03-19T22:51:22 pid=20577 TRASH id=report.pdf path=/home/user/report.pdf cmd=rm report.pdf
2026-03-19T22:51:22 pid=20579 EMPTY count=3 filter=all
2026-03-19T22:51:22 pid=20582 EMPTY count=1 filter=older than 7d
2026-03-19T22:51:22 pid=20598 RESTORE id=report.pdf to=/home/user/report.pdf
```

View with `trash log` (default: last 20 lines) or `trash log -n 100`.

## Performance

### What's fast

- **Same-filesystem trash** — A single `rename()` syscall. Same speed as a normal delete.
- **LD_PRELOAD overhead** — A few string comparisons per `unlink()` call (skip-list check). Negligible for non-trashed files.
- **fanotify daemon** — Kernel delivers events asynchronously. No blocking overhead on the deleting process.
- **Hash (xxhash)** — XXH3-128 runs at ~10 GB/s. A 1 MB file hashes in ~100 microseconds.

### What's throttled

- **Auto-purge** — Scans all `.trashinfo` files, but only runs once per `auto_purge_interval_secs` (default 60 seconds). Controlled via a timestamp marker file at `~/.local/share/Trash/.trashd/last_purge`.
- **Directory size calculation** — Recursive walk capped at 10,000 files. Returns partial size if cap is hit.
- **Hash computation** — Only for files ≤ `sha256_max_size_mb` (default 1 MB). Large files skip hashing entirely.
- **Auto-compression** — Runs during auto-purge (already throttled). Only compresses files >7 days old and >1 KB.

### What's potentially slow

- **Cross-device trash** — Copies the entire file (same as `mv` across filesystems). Unavoidable.
- **SQLite index write** — One `INSERT` per trash operation with implicit fsync (~1-5 ms).

## Project structure

```
trashd/
├── crates/
│   ├── trashd-common/      # shared core library
│   │   ├── config.rs        # layered TOML config with pattern matching
│   │   ├── store.rs         # TrashStore: trash, restore, purge, empty, auto-purge
│   │   ├── trashinfo.rs     # .trashinfo parser/serializer (FreeDesktop spec)
│   │   ├── mounts.rs        # multi-partition trash directory discovery
│   │   ├── index.rs         # SQLite index (supplementary to .trashinfo)
│   │   ├── directorysizes.rs # $trash/directorysizes cache (spec v1.0)
│   │   └── oplog.rs         # operation log + desktop notifications
│   ├── trashd-cli/          # `trash` CLI (clap-based, 12 subcommands)
│   ├── trashd-shim/         # `rm` drop-in replacement
│   ├── trashd-preload/      # LD_PRELOAD .so (standalone, no SQLite)
│   ├── trashd-seccomp/      # seccomp supervisor + watchdog + BPF filter
│   └── trashd-daemon/       # fanotify filesystem monitor
├── config/
│   └── trashd.toml          # default config template
├── tests/
│   └── integration.sh       # 12 end-to-end integration tests
└── install/
    ├── profile.d/           # PATH shim + seccomp activation
    └── systemd/             # trashd-daemon.service
```

### Binaries produced

| Binary | Crate | Purpose |
|--------|-------|---------|
| `trash` | trashd-cli | CLI: ls, find, info, restore, undo, purge, empty, compress, du, status, log, fsck |
| `trashd-rm` | trashd-shim | Drop-in `rm` replacement (installed as `rm` in shim PATH) |
| `libtrashd_preload.so` | trashd-preload | LD_PRELOAD shared library (~870 KB, no SQLite) |
| `trashd-exec` | trashd-seccomp | Seccomp supervisor wrapper (three-process architecture) |
| `trashd-daemon` | trashd-daemon | fanotify filesystem monitor (systemd service) |

## Testing

### Unit tests

```bash
TRASH_BYPASS=1 cargo test    # 32 unit tests (store, trashinfo, globs)
```

`TRASH_BYPASS=1` is required when LD_PRELOAD is system-wide to prevent the preload from intercepting test operations.

### Integration tests

```bash
sudo ./tests/integration.sh  # 12 end-to-end tests (requires install)
```

Covers: Layer 1 shim, Layer 2 LD_PRELOAD, `--permanent` bypass, `TRASH_BYPASS=1` bypass, `trash undo`, `trash restore --to`, `trash purge`, `trash empty -y`, `*/.git/*` pattern skip, restore conflict detection, duplicate filename unique IDs, and `trash fsck` orphan detection.

## Requirements

- **Rust** (for building)
- **Linux 5.5+** (for seccomp user notification — Layer 4)
- **Linux 5.9+** (for fanotify FID reporting — Layer 3)
- **CAP_SYS_ADMIN** or root (for fanotify daemon)
- Layers 1 and 2 work on any Linux kernel

## License

MIT
