# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

```bash
cargo build --release              # full workspace build
cargo build -p trashd-cli           # single crate
TRASH_BYPASS=1 cargo test           # run all tests (bypass preload to avoid interference)
cargo test -p trashd-common --lib   # run just the 32 unit tests
sudo ./install.sh                   # build + install all layers + man pages + completions
sudo ./install.sh --uninstall       # remove everything (preserves trash contents)
sudo ./tests/integration.sh         # 12 end-to-end integration tests (requires install)
```

Tests require `TRASH_BYPASS=1` when LD_PRELOAD is system-wide (prevents the preload from intercepting test operations). Unit tests use a mutex guard for serialization (they share `XDG_DATA_HOME` env var). Test files are placed under `crates/trashd-common/target/test-trash/`, not `/tmp` (which is in the never-trash list).

## Architecture

Four interception layers feed into a shared trash store, all active by default after install:

```
Layer 1: PATH shim (trashd-shim)       — shadows rm via PATH ordering
Layer 2: LD_PRELOAD (trashd-preload)   — hooks unlink/unlinkat/rmdir (system-wide via /etc/ld.so.preload)
Layer 3: fanotify daemon (trashd-daemon) — detection/audit only (systemd service, Linux 5.9+)
Layer 4: seccomp supervisor (trashd-seccomp) — traps syscalls at kernel boundary (interactive shells, Linux 5.5+)
```

Layer 4 (seccomp) is the primary layer for interactive shells. Layer 2 (LD_PRELOAD) is the fallback for daemons/cron/non-interactive processes. The preload checks `TRASHD_SECCOMP_ACTIVE` env var and defers when seccomp is handling it.

### Crate dependency graph

```
trashd-cli      → trashd-common + zstd (native compression)
trashd-shim     → trashd-common
trashd-seccomp  → trashd-common
trashd-daemon   → trashd-common
trashd-preload  → (standalone — no trashd-common to avoid pulling in SQLite)
```

### trashd-common — shared core

- **`store.rs`** — `TrashStore` is the main API. `trash()` moves files (with dir size limit check, bypass_paths check), `restore()` brings them back (with hash verification), `list()` scans all trash dirs (detects orphaned files per spec). Auto-purge is throttled via `maybe_auto_purge()` timestamp marker. Cross-device moves use depth-limited `copy_tree()` (max 100 levels). `dir_size()` capped at 10,000 files. Topdir trash stores relative paths per FreeDesktop spec.
- **`config.rs`** — Layered TOML config: defaults → `/etc/trashd/config.toml` → `~/.config/trashd/config.toml` → per-directory `.trashd.toml`. Supports `never_trash`, `only_trash`, `bypass_processes`, `bypass_paths`, `max_dir_size_mb`. Pattern matching in `pattern_matches_any()` handles prefix, suffix, infix (`*/.git/*`), and exact patterns.
- **`mounts.rs`** — Multi-partition logic. `trash_dir_for_path()` picks same-device trash or topdir `.Trash-$UID/`. Checks `$topdir/.Trash/$UID/` with sticky-bit + symlink validation (FreeDesktop spec §1.2.2a).
- **`index.rs`** — SQLite index. Written on trash/restore/purge but `list()` scans `.trashinfo` files as the authoritative source.
- **`trashinfo.rs`** — FreeDesktop.org `.trashinfo` parser/serializer. Validates `[Trash Info]` header is first line. First-occurrence wins for duplicate keys. Path value not trimmed (percent-encoded spaces preserved). Extended `X-Trashd-*` fields. Writes `X-Trashd-Hash` (reads both `X-Trashd-Hash` and `X-Trashd-SHA256` for backward compat).
- **`directorysizes.rs`** — `$trash/directorysizes` cache per FreeDesktop spec v1.0. Atomic write via temp file + rename.
- **`oplog.rs`** — Append-only operation log. Desktop notification via `notify-send` (GUI sessions only).

### trashd-preload — standalone by design

Does NOT depend on `trashd-common` to keep the `.so` small and avoid SQLite. Duplicates config parsing, trash directory selection, and trashinfo writing. Uses `OnceLock` for config with periodic mtime-based change detection (logs when config changes).

Key safety mechanisms:
- Thread-local `Cell<bool>` re-entrancy guard prevents internal `rename()`/`mkdir()` from re-entering hooked `unlink()`
- Skips paths inside trash directories (prevents intercepting SQLite journal deletions)
- Defers to seccomp when `TRASHD_SECCOMP_ACTIVE=1` is set
- Sets `TRASH_BYPASS=1` checked on every call

### trashd-seccomp — three-process architecture

`trashd-exec <command>` forks three processes:
1. **Child**: installs BPF seccomp filter, passes notification fd via SCM_RIGHTS, exec's command
2. **Supervisor**: reads notifications, moves files to trash, responds to kernel
3. **Watchdog**: holds `dup(fd)`, monitors supervisor. On crash: drains with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (graceful degradation), respawns supervisor.

Orchestrator forwards SIGINT/SIGTERM to child process.

BPF filter (`filter.rs`): architecture-specific — x86_64 traps `SYS_unlink`/`SYS_unlinkat`/`SYS_rmdir`; aarch64 traps only `SYS_unlinkat`.

### trashd-daemon — fanotify monitor

Uses `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (Linux 5.9+). Resolves parent via `open_by_handle_at()` against cached per-mount O_PATH fds. Detection/audit only.

## Key design decisions

- **Fail-safe**: every layer falls back to real delete on error
- **Atomic IDs**: `O_CREAT|O_EXCL` on `.trashinfo`. Filename truncated to 223 chars for filesystem limits
- **Symlink-safe**: `normalize_path()` canonicalizes parent only. Symlinks re-created in cross-device copies
- **Process bypass**: walks `/proc/{pid}/stat` up the tree. Also checks `bypass_paths` against `/proc/self/exe`
- **Hash verification**: XXH3-128 (default) or SHA-256, computed on trash, verified on restore (tries both algorithms)
- **Auto-purge throttling**: `maybe_auto_purge()` skips if < `auto_purge_interval_secs` since last run
- **Config precedence**: `never_trash` always wins → `only_trash` narrows → `.trashd.toml` applies locally
- **Shim sets `TRASH_BYPASS=1`** when passing through to real rm (prevents LD_PRELOAD re-interception)
- **Confirmation required**: `trash empty` prompts by default, `-y` skips
- **Native zstd**: `trash compress` uses the `zstd` Rust crate (no system dependency)

## Binaries

| Binary | Crate | Purpose |
|--------|-------|---------|
| `trash` | trashd-cli | CLI: ls, find, info, restore, undo, purge, empty, compress, du, status, log, fsck |
| `trashd-rm` | trashd-shim | Drop-in `rm` replacement |
| `libtrashd_preload.so` | trashd-preload | LD_PRELOAD shared library |
| `trashd-exec` | trashd-seccomp | Seccomp supervisor wrapper |
| `trashd-daemon` | trashd-daemon | fanotify filesystem monitor |

## Bypass mechanisms

- `rm --permanent` / `rm --no-trash` — shim passes through to real rm (with `TRASH_BYPASS=1`)
- `TRASH_BYPASS=1` — env var checked by shim, preload, and seccomp
- Config `bypass_processes` — auto-detected via `/proc` tree walk (includes git, systemd, apt, cargo, etc.)
- Config `bypass_paths` — exe path prefix match for more precise control
- Config `never_trash` — glob patterns for paths/extensions that skip trash
- Config `only_trash` — whitelist mode (if set, only matching files are trashed)
- Config `max_file_size_mb` / `max_dir_size_mb` — size limits
- Per-directory `.trashd.toml` — project-level `never_trash`/`only_trash` overrides
