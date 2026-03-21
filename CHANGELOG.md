# Changelog

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
