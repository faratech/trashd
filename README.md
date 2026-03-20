# trashd

A Linux recycle bin that actually works — in scripts, cron jobs, and at the desktop.

Unlike `safe-rm` (which only blocks deletes) or `trash-cli` (which requires calling `trash-put` instead of `rm`), trashd intercepts destructive commands transparently. Scripts that call `rm` get trash protection without any code changes.

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

**Layer 1** — PATH shim binaries shadow `rm`, intercepting it before the real binary runs. Works in shell scripts, cron, `find -exec`, anywhere that resolves commands via `$PATH`. Desktop notifications via `notify-send` when files are trashed in GUI sessions.

**Layer 2** — An `LD_PRELOAD` shared library hooks `unlink()`, `unlinkat()`, and `rmdir()` at the libc level. Catches deletions from any dynamically-linked program. Enabled system-wide via `/etc/ld.so.preload`. Defers to Layer 4 (seccomp) when active to avoid double interception.

**Layer 3** — A fanotify daemon monitors all filesystems for `FAN_DELETE` events. Detection/audit only — logs deletions that bypass the other layers. Runs as a systemd service. Requires Linux 5.9+.

**Layer 4** — A seccomp supervisor traps `unlink`/`unlinkat`/`rmdir` at the kernel syscall boundary. The most robust layer — catches statically-linked binaries, setuid programs, and raw syscalls. A watchdog process ensures crash recovery. Interactive shells are automatically wrapped via `/etc/profile.d/trashd.sh`. Requires Linux 5.5+.

## Install

```bash
git clone https://github.com/faratech/trashd.git
cd trashd
sudo ./install.sh
```

Requires Rust (cargo). The install script builds all binaries, installs them, enables all four layers, creates config at `/etc/trashd/config.toml`, and installs man pages and shell completions (bash, zsh, fish).

Start a new shell or run:
```bash
source /etc/profile.d/trashd.sh
```

To uninstall:
```bash
sudo ./install.sh --uninstall
```

## Usage

### Transparent interception (just use rm normally)

```bash
rm file.txt              # moved to trash, not deleted
rm -rf project/          # directory moved to trash
rm -i important.txt      # prompts before trashing (like real rm)
```

### Manage trash

```bash
trash ls                 # list trashed files (all partitions)
trash ls '*.py'          # filter by pattern
trash find ~/projects    # search by original path
trash info <id>          # show full metadata (command, PID, size, hash)
trash restore foo.txt    # restore to original location
trash restore foo --to . # restore to current directory
trash undo               # restore the most recent deletion
trash purge foo.txt      # permanently delete a specific entry
trash empty              # permanently empty all trash (prompts for confirmation)
trash empty -y           # skip confirmation prompt
trash empty --older 7d   # purge items older than 7 days
trash empty --dry-run    # preview what would be deleted
trash du                 # show largest items in trash by size
trash du -n 10           # show top 10 largest
trash compress           # compress items older than 7 days (zstd, native)
trash compress --older 3d # compress items older than 3 days
trash compress --dry-run # preview what would be compressed
trash status             # show size, count, per-partition breakdown
trash log                # show recent operations (audit trail)
trash log -n 50          # show last 50 operations
trash fsck               # check trash directory integrity
trash fsck --fix         # fix orphaned entries
trash --version          # show version
```

### Bypass trash when needed

```bash
rm --permanent file.txt         # real delete through the shim
rm --no-trash file.txt          # same thing
TRASH_BYPASS=1 rm file.txt      # real delete via env var
TRASH_BYPASS=1 ./deploy.sh      # disable for an entire script
```

### Seccomp supervisor (catch everything)

```bash
# Wrap a single command — catches static binaries, raw syscalls
trashd-exec ./deploy.sh

# Wrap a shell session
trashd-exec bash
```

### LD_PRELOAD (catch dynamic binaries)

```bash
# Per-command
LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so python3 cleanup.py

# System-wide (enabled by default after install)
# Configured via /etc/ld.so.preload

# Debug logging
TRASHD_PRELOAD_LOG=1 rm file.txt
```

## Multi-partition support

Files are always trashed on the same filesystem to avoid slow cross-device copies. Per the FreeDesktop.org spec:

- Same filesystem as `$HOME` → `~/.local/share/Trash/`
- Different filesystem → `$mountpoint/.Trash-$UID/` (or shared `$mountpoint/.Trash/$UID/` if sticky-bit dir exists)

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

Listing and restore work across all partitions automatically.

## Configuration

Layered config system:
1. Hardcoded defaults
2. `/etc/trashd/config.toml` — global (admin-managed)
3. `~/.config/trashd/config.toml` — per-user override
4. `.trashd.toml` — per-directory override (searched up to 5 parent levels)

Scalars: user overrides global. Lists (`never_trash`, `bypass_processes`): user extends global (admin patterns can't be removed).

```toml
[retention]
max_age_days = 30           # auto-purge after 30 days
max_size_gb = 10.0          # cap total trash size
disk_pressure_percent = 90  # purge oldest when disk > 90% full

# Paths that skip trash (real-deleted instead)
never_trash = [
    "/tmp/*", "/var/cache/*",
    "*.o", "*.pyc", "*.lock", "*.tmp",
    "node_modules/*", "*/.git/*",
]

# If set, ONLY these patterns are trashed (everything else real-deleted)
# never_trash still takes priority over only_trash
only_trash = ["*.py", "*.rs", "*.sql", "*.env"]

# Parent processes that bypass trash automatically
bypass_processes = ["apt", "dpkg", "cargo", "make", "npm", "git", "systemd"]

# Executable paths that bypass trash (prefix match)
bypass_paths = ["/opt/myapp/", "/usr/lib/systemd/"]

max_file_size_mb = 1024        # files over this size skip trash
max_dir_size_mb = 0            # directories over this size skip trash (0 = no limit)
hash_algorithm = "xxhash"      # "xxhash" (fast, default) or "sha256" (cryptographic)
sha256_max_size_mb = 1         # only hash files smaller than this
auto_purge_interval_secs = 60  # throttle auto-purge scans
```

### Per-directory overrides

Place a `.trashd.toml` in any project directory:
```toml
never_trash = ["build/*", "dist/*", "*.log"]
only_trash = ["src/*", "*.config"]
```

## Safety

- **Fail-safe** — Every layer falls back to real delete on error. Never blocks deletions.
- **Confirmation on empty** — `trash empty` prompts before destroying all trash. Use `-y` to skip.
- **Process bypass** — Package managers, git, systemd, and container runtimes automatically bypass trash via `/proc` tree walk. Configurable via `bypass_processes` and `bypass_paths`.
- **Never-trash / only-trash** — Exclude or include file types globally, per-user, or per-directory.
- **Atomic IDs** — Trash entry IDs claimed with `O_CREAT|O_EXCL` to prevent TOCTOU races.
- **Re-entrancy guard** — LD_PRELOAD uses a thread-local guard so internal ops don't re-enter hooks.
- **Symlink-safe** — Trashing a symlink removes the link, not the target. Symlinks inside directories are re-created during cross-device operations.
- **Interactive flags** — `-i` and `-I` work like real `rm`, prompting before deletion.
- **Ambiguous matches** — `trash restore` shows a numbered list with sizes and IDs when multiple entries match.
- **Hash verification** — File hashes (XXH3-128 or SHA-256) computed on trash, verified on restore. Warns on mismatch.
- **Watchdog failover** — If the seccomp supervisor crashes, the watchdog responds `CONTINUE` — graceful degradation to normal deletes, never hangs.
- **Signal forwarding** — `trashd-exec` forwards SIGINT/SIGTERM to the child process.
- **Operation log** — All trash/restore/purge operations logged to `~/.local/share/Trash/.trashd/operations.log`.
- **Desktop notifications** — GUI sessions get `notify-send` alerts when files are trashed via the shim.
- **Depth-limited copy** — Cross-device directory copies capped at 100 levels to prevent symlink loop crashes.

## Compression

Old trash items can be compressed to save disk space:

```bash
trash compress                # compress items older than 7 days
trash compress --older 3d     # compress items older than 3 days
trash compress --dry-run      # preview without compressing
```

Uses native zstd (built-in, no system dependency). Text files see 95%+ compression; binaries ~50%. Already-compressed files are automatically skipped. Files are compressed in-place and transparently — `trash restore` works normally on compressed items.

## FreeDesktop.org compliance

trashd implements the [FreeDesktop.org Trash specification v1.0](https://specifications.freedesktop.org/trash/latest/):

- `.trashinfo` metadata files with percent-encoded paths
- `$XDG_DATA_HOME/Trash/` home directory trash
- `$topdir/.Trash/$UID/` shared trash with sticky-bit validation
- `$topdir/.Trash-$UID/` per-user topdir trash fallback
- `$trash/directorysizes` cache per spec v1.0
- Topdir trash uses relative paths; home trash uses absolute paths
- First-occurrence wins for duplicate `Path=`/`DeletionDate=` keys
- `[Trash Info]` header validated as first line
- Orphaned files in `$trash/files/` detected and presented as emergency items
- Desktop file managers (Nautilus, Dolphin, Thunar) see the same trash

Extended metadata in spec-compliant `X-` fields:
```ini
[Trash Info]
Path=/home/user/project/main.py
DeletionDate=2026-03-19T14:30:00
X-Trashd-Command=rm -rf project/
X-Trashd-PID=48231
X-Trashd-Size=4096
X-Trashd-Hash=a1b2c3...
```

## Project structure

```
trashd/
├── crates/
│   ├── trashd-common/      # config, trash store, index, mounts, trashinfo, oplog, directorysizes
│   ├── trashd-cli/          # `trash` command (ls, find, info, restore, undo, purge, empty, compress, du, status, log, fsck)
│   ├── trashd-shim/         # `rm` drop-in replacement
│   ├── trashd-preload/      # LD_PRELOAD .so (hooks unlink/unlinkat/rmdir)
│   ├── trashd-seccomp/      # seccomp supervisor + watchdog (trashd-exec)
│   └── trashd-daemon/       # fanotify filesystem monitor (trashd-daemon)
├── config/
│   └── trashd.toml          # default config template
├── tests/
│   └── integration.sh       # end-to-end integration tests
└── install/
    ├── profile.d/           # PATH + seccomp setup for /etc/profile.d/
    └── systemd/             # trashd-daemon.service
```

## License

MIT
