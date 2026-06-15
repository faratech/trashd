# Changelog

## 0.1.1 (2026-06-15)

Bug-fix release from a full security/correctness audit. Hardens the data-loss
and cross-layer-consistency paths; no breaking changes.

### Fixed — data loss

- `fsck --fix` no longer deletes a recoverable data file when its `.trashinfo`
  is corrupt; the data is quarantined and reported instead.
- `TrashStore::open` no longer fails (forcing real `rm`) on transient SQLite
  lock contention — the index sets a busy timeout and is now optional.
- Restore decompresses in-trash, atomically, and reports failure instead of
  silently leaving a corrupted file with the trash copy already gone.
- Trashing no longer overwrites a pre-existing orphaned `files/<id>`.
- Auto-purge compresses via temp-file + atomic rename (no truncation on crash)
  and skips oversized files instead of reading them fully into memory.
- Compression is now recorded with an `X-Trashd-Compressed` marker; restore
  decompresses only marked entries, so a user's genuine `.zst` is left intact.
- Cross-device directory moves recreate FIFOs instead of dropping them.

### Fixed — security

- Restore validates destinations from untrusted `.trashinfo` (rejects `..` and
  topdir escapes; no-clobber rename) — blocks path-traversal overwrite.
- `self-update` requires the checksum (fails closed if absent), enforces HTTPS,
  caps the download size, and extracts/runs from a private `0700` temp dir.
- Topdir trash directories (`.Trash-$uid` / `.Trash/$uid`) are created `0700`.

### Fixed — cross-layer consistency

- The seccomp supervisor honors `bypass_processes` and no longer trashes a
  whole directory tree when it cannot confirm the directory is empty.
- The LD_PRELOAD layer honors `only_trash` and per-directory `.trashd.toml`,
  fixes `is_inside_trash` over-matching (which could permanently delete user
  files), checks the unlink result on cross-device symlink moves, preserves the
  caller's `errno`, and logs when a `dirfd` cannot be resolved.

### Fixed — spec / other

- `max_dir_size_mb` is enforced for directories with more than 10,000 files.
- `directorysizes` is refreshed on purge/restore/auto-purge and percent-encodes
  spaces; `fsck --fix` rebuilds the correct index file.

## 0.1.0 (2026-03-20)

Initial release.

### Features

- **4-layer interception architecture**
  - Layer 1: PATH shim (`trashd-rm`) — drop-in `rm` replacement
  - Layer 2: LD_PRELOAD (`libtrashd_preload.so`) — hooks unlink/unlinkat/rmdir
  - Layer 3: fanotify daemon (`trashd`) — system-wide deletion audit (Linux 5.9+)
  - Layer 4: seccomp supervisor (`trashd-exec`) — kernel-level syscall trapping with watchdog failover (Linux 5.5+)

- **CLI (`trash` command)**
  - `ls`, `find`, `info`, `restore`, `undo`, `purge`, `empty`, `status`, `log`, `fsck`
  - `--dry-run` for empty, `--version`, glob pattern filtering
  - Ambiguous match detection with helpful output
  - Per-partition status display

- **Configuration**
  - Layered config: `/etc/trashd/config.toml` → `~/.config/trashd/config.toml` → `.trashd.toml`
  - `never_trash` exclude list + `only_trash` whitelist
  - `bypass_processes` with `/proc` tree walk detection
  - Retention policy: max age, max size, disk pressure auto-purge
  - Configurable hashing: XXH3-128 (default) or SHA-256

- **FreeDesktop.org Trash spec compliance**
  - `.trashinfo` metadata with extended `X-Trashd-*` fields
  - `$topdir/.Trash/$UID/` with sticky-bit validation
  - `$topdir/.Trash-$UID/` per-user topdir fallback
  - Desktop file manager interoperability (Nautilus, Dolphin, Thunar)

- **Safety**
  - Fail-safe: every layer falls back to real delete on error
  - Atomic IDs via `O_CREAT|O_EXCL`
  - Symlink-safe: trashes the link, not the target
  - Hash verification on restore
  - Signal forwarding in seccomp supervisor
  - Operation audit log
