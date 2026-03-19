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
           │
           ▼
┌──────────────────────────┐
│  Trash Store             │  FreeDesktop.org Trash spec
│  ~/.local/share/Trash/   │  + per-mountpoint .Trash-$UID/
└──────────────────────────┘
```

**Layer 1** — PATH shim binaries shadow `rm`, intercepting it before the real binary runs. Works in shell scripts, cron, `find -exec`, anywhere that resolves commands via `$PATH`.

**Layer 2** — An `LD_PRELOAD` shared library hooks `unlink()`, `unlinkat()`, and `rmdir()` at the libc level. Catches deletions from any dynamically-linked program — Python's `os.remove()`, Perl's `unlink`, Go's `os.Remove`, compiled C programs.

## Install

```bash
git clone https://github.com/faratech/trashd.git
cd trashd
sudo ./install.sh
```

Requires Rust (cargo). The install script builds, installs binaries, sets up PATH hooks, and creates a default config.

Start a new shell or run:
```bash
source /etc/profile.d/trashd.sh
```

### Manual install

```bash
cargo build --release
# Copy binaries wherever you like
cp target/release/trash /usr/local/bin/
cp target/release/trashd-rm /usr/local/lib/trashd/bin/rm
cp target/release/libtrashd_preload.so /usr/local/lib/trashd/
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
trash restore foo.txt    # restore to original location
trash restore foo --to . # restore to current directory
trash undo               # restore the most recent deletion
trash purge foo.txt      # permanently delete a specific entry
trash empty              # permanently empty all trash
trash empty --older 7d   # purge items older than 7 days
trash status             # show size, count, per-partition breakdown
```

### Bypass trash when needed

```bash
rm --permanent file.txt         # real delete through the shim
rm --no-trash file.txt          # same thing
TRASH_BYPASS=1 rm file.txt      # real delete via env var
TRASH_BYPASS=1 ./deploy.sh      # disable for an entire script
```

### LD_PRELOAD (catch everything)

```bash
# Per-command
LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so python3 cleanup.py

# Per-session
export LD_PRELOAD=/usr/local/lib/trashd/libtrashd_preload.so

# System-wide (use with care)
echo '/usr/local/lib/trashd/libtrashd_preload.so' >> /etc/ld.so.preload

# Debug logging
TRASHD_PRELOAD_LOG=1 rm file.txt
# stderr: [trashd-preload] trashed: /home/user/file.txt -> ...
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

Config lives at `~/.config/trashd/config.toml`:

```toml
[retention]
max_age_days = 30           # auto-purge after 30 days
max_size_gb = 10.0          # cap total trash size
disk_pressure_percent = 90  # purge oldest when disk > 90% full

# Paths that skip trash (real-deleted instead)
never_trash = [
    "/tmp/*",
    "/var/cache/*",
    "*.o",
    "*.pyc",
    "node_modules/*",
]

# Parent processes that bypass trash automatically
bypass_processes = [
    "apt", "dpkg", "yum", "dnf", "pacman",
    "pip", "cargo", "npm", "make",
]

# Files over this size skip trash
max_file_size_mb = 1024
```

The config is shared across the shim, CLI, and LD_PRELOAD layer.

## Safety

- **Process bypass** — Package managers (`apt`, `dpkg`, `cargo`, `make`, etc.) automatically bypass trash. Detected by walking `/proc` up the process tree.
- **Never-trash list** — Temp files, build artifacts, and virtual filesystems are real-deleted, not trashed.
- **Atomic IDs** — Trash entry IDs are claimed with `O_CREAT|O_EXCL` to prevent races between concurrent deletions.
- **Re-entrancy guard** — The LD_PRELOAD layer uses a thread-local guard so internal `rename()`/`mkdir()` calls don't re-enter the hooks.
- **Symlink-safe** — Trashing a symlink removes the link, not the target. Symlinks inside directories are re-created (not followed) during cross-device operations.
- **Interactive flags** — `-i` and `-I` work like real `rm`, prompting before deletion.
- **Ambiguous matches** — `trash restore` warns when multiple entries match and lists them with IDs.

## FreeDesktop.org compliance

trashd implements the [FreeDesktop.org Trash specification](https://specifications.freedesktop.org/trash-spec/latest/):

- `.trashinfo` metadata files with percent-encoded paths
- `$XDG_DATA_HOME/Trash/` home directory trash
- `$topdir/.Trash/$UID/` shared trash with sticky-bit validation
- `$topdir/.Trash-$UID/` per-user topdir trash fallback
- Desktop file managers (Nautilus, Dolphin, Thunar) see the same trash

Extended metadata in spec-compliant `X-` fields:
```ini
[Trash Info]
Path=/home/user/project/main.py
DeletionDate=2026-03-19T14:30:00
X-Trashd-Command=rm -rf project/
X-Trashd-PID=48231
X-Trashd-Size=4096
X-Trashd-SHA256=a1b2c3...
```

## Project structure

```
trashd/
├── crates/
│   ├── trashd-common/      # config, trash store, index, mounts, trashinfo
│   ├── trashd-cli/          # `trash` command (ls, restore, undo, purge, empty, status)
│   ├── trashd-shim/         # `rm` drop-in replacement
│   └── trashd-preload/      # LD_PRELOAD .so (hooks unlink/unlinkat/rmdir)
├── config/
│   └── trashd.toml          # default config
└── install/
    └── profile.d/           # PATH setup for /etc/profile.d/
```

## License

MIT
