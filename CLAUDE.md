# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

```bash
cargo build --release              # full workspace build
cargo build -p trashd-cli           # single crate
cargo test -p trashd-common --lib   # run tests (32 tests in store + trashinfo)
sudo ./install.sh                   # build + install all layers
sudo ./install.sh --uninstall       # remove everything (preserves trash contents)
```

Tests require `--test-threads=1` or the built-in mutex guard handles serialization automatically (tests share `XDG_DATA_HOME` env var). Test files are placed under `crates/trashd-common/target/test-trash/`, not `/tmp` (which is in the never-trash list).

## Architecture

Four interception layers feed into a shared trash store:

```
Layer 1: PATH shim (trashd-shim)       — shadows rm via PATH ordering
Layer 2: LD_PRELOAD (trashd-preload)   — hooks unlink/unlinkat/rmdir at libc level
Layer 3: fanotify daemon (trashd-daemon) — detection/audit only (Linux 5.9+)
Layer 4: seccomp supervisor (trashd-seccomp) — traps syscalls at kernel boundary (Linux 5.5+)
```

### Crate dependency graph

```
trashd-cli      → trashd-common
trashd-shim     → trashd-common
trashd-seccomp  → trashd-common
trashd-daemon   → trashd-common
trashd-preload  → (standalone — no trashd-common to avoid pulling in SQLite)
```

### trashd-common — shared core

- **`store.rs`** — `TrashStore` is the main API. `trash()` moves files, `restore()` brings them back (with hash verification), `list()` scans all trash dirs. Auto-purge is throttled via timestamp marker (`maybe_auto_purge()`). Cross-device moves use depth-limited `copy_tree()` which preserves symlinks/permissions, skips FIFOs/devices/sockets. Orphaned `.trashinfo` files are cleaned up on copy failure.
- **`config.rs`** — Layered TOML config: defaults → `/etc/trashd/config.toml` → `~/.config/trashd/config.toml` → per-directory `.trashd.toml`. Supports `never_trash` (exclude), `only_trash` (whitelist), and `bypass_processes`. `should_skip()` implements the full precedence: local `.trashd.toml` → global `never_trash` → global `only_trash`. Pattern matching extracted to `pattern_matches_any()`.
- **`mounts.rs`** — Multi-partition logic. `trash_dir_for_path()` picks same-device trash or topdir `.Trash-$UID/`. Checks `$topdir/.Trash/$UID/` with sticky-bit validation first (FreeDesktop spec §1.2.2a).
- **`index.rs`** — SQLite index. Written on trash/restore/purge but `list()` scans `.trashinfo` files as the authoritative source.
- **`trashinfo.rs`** — FreeDesktop.org `.trashinfo` parser/serializer. Extended `X-Trashd-*` fields. Writes `X-Trashd-Hash` (reads both `X-Trashd-Hash` and `X-Trashd-SHA256` for backward compat).
- **`oplog.rs`** — Append-only operation log at `~/.local/share/Trash/.trashd/operations.log`.

### trashd-preload — standalone by design

Does NOT depend on `trashd-common` to keep the `.so` small and avoid SQLite. Duplicates config parsing, trash directory selection, and trashinfo writing. Uses `OnceLock` for lazy one-time config load.

Key safety mechanism: thread-local `Cell<bool>` re-entrancy guard prevents internal `rename()`/`mkdir()` from re-entering hooked `unlink()`.

### trashd-seccomp — three-process architecture

`trashd-exec <command>` forks three processes:
1. **Child**: installs BPF seccomp filter, passes notification fd via SCM_RIGHTS, exec's command
2. **Supervisor**: reads notifications, moves files to trash, responds to kernel
3. **Watchdog**: holds `dup(fd)`, monitors supervisor. On crash: drains with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (graceful degradation), respawns supervisor.

Orchestrator forwards SIGINT/SIGTERM to child process.

BPF filter (`filter.rs`): architecture-specific — x86_64 traps `SYS_unlink`/`SYS_unlinkat`/`SYS_rmdir`; aarch64 traps only `SYS_unlinkat`.

Path arguments read from target memory via `process_vm_readv()` (`mem.rs`). Relative paths for `unlinkat` resolved via `/proc/{pid}/fd/{dirfd}`.

### trashd-daemon — fanotify monitor

Uses `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (Linux 5.9+). Parses `fanotify_event_info_fid` to extract parent dir handle + deleted filename. Resolves parent via `open_by_handle_at()` against cached mount fds. Detection/audit only.

## Key design decisions

- **Fail-safe**: every layer falls back to real delete on error. `respond_continue()` in seccomp, `passthrough()` in shim, real `unlink` in preload.
- **Atomic IDs**: `O_CREAT|O_EXCL` on `.trashinfo` file prevents TOCTOU races. Filename truncated to 223 chars to stay under filesystem limits.
- **Symlink-safe**: `normalize_path()` canonicalizes parent only. Symlinks are re-created during cross-device copies, not followed.
- **Process bypass**: `is_parent_bypassed()` walks `/proc/{pid}/stat` up the tree.
- **Cross-device cleanup**: orphaned `.trashinfo` + partial copy removed on failure.
- **Hash verification**: file hash (XXH3-128 or SHA-256) computed on trash, verified on restore.
- **Auto-purge throttling**: `maybe_auto_purge()` checks a timestamp marker file, skips if less than `auto_purge_interval_secs` since last run.
- **Config precedence**: `never_trash` always wins → `only_trash` narrows → per-directory `.trashd.toml` applies locally.

## Binaries

| Binary | Crate | Purpose |
|--------|-------|---------|
| `trash` | trashd-cli | CLI: ls, find, info, restore, undo, purge, empty, status, log |
| `trashd-rm` | trashd-shim | Drop-in `rm` replacement |
| `libtrashd_preload.so` | trashd-preload | LD_PRELOAD shared library |
| `trashd-exec` | trashd-seccomp | Seccomp supervisor wrapper |
| `trashd-daemon` | trashd-daemon | fanotify filesystem monitor |

## Bypass mechanisms

- `rm --permanent` / `rm --no-trash` — shim passes through to real rm
- `TRASH_BYPASS=1` — env var checked by shim, preload, and seccomp
- Config `bypass_processes` — auto-detected via `/proc` tree walk
- Config `never_trash` — glob patterns for paths/extensions that skip trash
- Config `only_trash` — whitelist mode (if set, only matching files are trashed)
- Per-directory `.trashd.toml` — project-level `never_trash`/`only_trash` overrides
