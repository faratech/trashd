# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

```bash
cargo build --release          # full workspace build
cargo build -p trashd-cli      # single crate
sudo ./install.sh              # build + install binaries, shim, preload, config
```

No test suite exists yet. No linter config. Standard `cargo clippy` and `cargo fmt` apply.

## Architecture

trashd is a multi-layer Linux recycle bin. Four interception layers feed into a shared trash store:

```
Layer 1: PATH shim (trashd-shim)     — shadows /usr/bin/rm via PATH ordering
Layer 2: LD_PRELOAD (trashd-preload) — hooks unlink/unlinkat/rmdir at libc level
Layer 3: fanotify daemon (trashd-daemon) — detection/audit only, cannot intercept
Layer 4: seccomp supervisor (trashd-seccomp) — traps syscalls at kernel boundary
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

The central library. All crates except `trashd-preload` depend on it.

- **`store.rs`** — `TrashStore` is the main API. `trash()` moves files, `restore()` brings them back, `list()` scans all trash dirs. Auto-purge runs after each `trash()` call enforcing retention policy. Cross-device moves use `copy_tree()` which preserves symlinks and permissions but skips FIFOs/devices/sockets.
- **`mounts.rs`** — Multi-partition logic. `trash_dir_for_path()` picks same-device trash (instant rename) or topdir `.Trash-$UID/` per FreeDesktop spec. Checks `$topdir/.Trash/$UID/` with sticky-bit validation first (spec §1.2.2a).
- **`config.rs`** — TOML config from `~/.config/trashd/config.toml`. Retention limits, never-trash globs, bypass process list, file size cap.
- **`index.rs`** — SQLite index at `~/.local/share/Trash/.trashd/index.sqlite`. Written on trash/restore/purge. `list()` scans `.trashinfo` files as the authoritative source (index is supplementary).
- **`trashinfo.rs`** — FreeDesktop.org `.trashinfo` parser/serializer with percent-encoded paths. Extended `X-Trashd-*` fields for command, PID, size, SHA-256.

### trashd-preload — standalone by design

Does NOT depend on `trashd-common` to keep the `.so` small (~870KB) and avoid SQLite. Duplicates config parsing, trash directory selection, and trashinfo writing with minimal deps. Uses `OnceLock` for lazy one-time config load. Has its own hardcoded skip list plus reads the shared TOML config.

Key safety mechanism: thread-local `Cell<bool>` re-entrancy guard. Internal `rename()`/`mkdir()` calls during trash operations must not re-enter the hooked `unlink()`.

### trashd-seccomp — three-process architecture

`trashd-exec <command>` forks three processes:
1. **Child**: installs BPF seccomp filter, passes notification fd to parent via SCM_RIGHTS, exec's the command
2. **Supervisor**: reads notifications from the fd, moves files to trash, responds to kernel
3. **Watchdog**: holds `dup(fd)`, monitors supervisor via `waitpid()`. On crash, drains pending notifications with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (graceful degradation to real deletes), then respawns supervisor.

The BPF filter (`filter.rs`) traps `SYS_unlink`, `SYS_unlinkat`, `SYS_rmdir` with `SECCOMP_RET_USER_NOTIF`. All other syscalls pass through. Architecture-specific (x86_64 and aarch64 have different syscall numbers; aarch64 has no `unlink`/`rmdir`, only `unlinkat`).

Path arguments are read from target process memory via `process_vm_readv()` (`mem.rs`). For `unlinkat` with relative paths, dirfd is resolved via `/proc/{pid}/fd/{dirfd}`.

### trashd-daemon — fanotify monitor

Requires `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (Linux 5.9+) to get path info for `FAN_DELETE` events. Parses extended `fanotify_event_info_fid` structs to extract parent directory handle + deleted filename. Resolves parent via `open_by_handle_at()`.

## Key design decisions

- **Fail-safe**: every interception layer falls back to real delete on error. `respond_continue()` in seccomp, `passthrough()` in the shim, real `unlink` in preload.
- **Atomic IDs**: trash entry IDs are claimed via `O_CREAT|O_EXCL` on the `.trashinfo` file to prevent TOCTOU races between concurrent deletions.
- **Symlink-safe**: `normalize_path()` canonicalizes only the parent directory, preserving the final path component. Trashing a symlink removes the link, not the target.
- **Process bypass**: `is_parent_bypassed()` walks `/proc/{pid}/stat` up the process tree checking each ancestor against the config's `bypass_processes` list.
- **Cross-device cleanup**: if `copy_tree` or `fs::copy` fails during a cross-device trash, the orphaned `.trashinfo` and partial copy are cleaned up before returning the error.

## Binaries produced

| Binary | Crate | Purpose |
|--------|-------|---------|
| `trash` | trashd-cli | CLI: ls, restore, undo, purge, empty, status |
| `trashd-rm` | trashd-shim | Drop-in `rm` replacement (installed as `rm` in shim PATH) |
| `libtrashd_preload.so` | trashd-preload | LD_PRELOAD shared library |
| `trashd-exec` | trashd-seccomp | Seccomp supervisor wrapper |
| `trashd-daemon` | trashd-daemon | fanotify filesystem monitor |

## Bypass mechanisms

- `rm --permanent` / `rm --no-trash` — shim passes through to real rm
- `TRASH_BYPASS=1` — env var checked by shim, preload, and (indirectly) seccomp
- Config `bypass_processes` — auto-detected via `/proc` tree walk (apt, cargo, make, etc.)
- Config `never_trash` — glob patterns for paths/extensions that skip trash
