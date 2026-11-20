# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

```bash
cargo build --release              # full workspace build
cargo build -p trashd-cli           # single crate
TRASH_BYPASS=1 cargo test           # run all tests (bypass preload to avoid interference)
TRASH_BYPASS=1 cargo test -p trashd-common --lib
sudo ./install.sh                   # build + install all layers + man pages + completions
sudo ./install.sh --uninstall       # remove all components (preserves trash; add --purge to delete trash too)
sudo ./tests/integration.sh target/release  # sandboxed end-to-end checks; no installation
sudo ./tests/install_regression.sh target/release  # install.sh inside the sandbox (tmpfs /etc, /usr/local)
sudo python3 tests/shim_regression.py target/release/trashd-rm
sudo env TRASH_BYPASS=1 python3 tests/sandbox.py --build-dir target/release -- \
  /usr/bin/python3 /tests/preload_policy.py /opt/trashd/lib/libtrashd_preload.so /opt/trashd/bin/trash   # preload policy suite
sudo env TRASH_BYPASS=1 python3 tests/sandbox.py --build-dir target/release -- \
  /usr/bin/python3 /tests/seccomp_regression.py                                                         # seccomp suite
python3 tests/rpm_files_check.py && python3 tests/packaging_lint.py   # packaging checks (no build needed)
tests/glibc_floor.sh 2.28 <artifacts>       # release artifacts are built with cargo zigbuild --target <triple>.2.28
```

Tests require `TRASH_BYPASS=1` when LD_PRELOAD is system-wide. Destructive unit tests use `TrashStore::open_isolated` with explicit temporary roots and configuration; `XDG_DATA_HOME` alone still exposes mounted trash through a production store. Never use `TrashStore::open()` for destructive unit tests.

Subprocess suites enter `tests/sandbox.py`, which requires Linux mount privileges and creates a disposable chroot in private mount/PID namespaces. It exposes system runtimes read-only, copies the requested built binaries, isolates HOME/XDG/configuration and `/proc`, and verifies external mounted trash sentinels remain unchanged. It fails closed if isolation cannot be established. Do not run legacy tests against installed binaries, source the installed profile, or empty host trash for test setup. Use `sudo env REQUIRE_SECCOMP=1 ...` to require a real seccomp notification listener; otherwise unsupported hosts report a skip. `TRASHD_TEST_NETWORK=1` enables the optional self-update network check. CI (`.github/workflows/ci.yml`) runs on pull requests to `main` and pushes to `main` only, with `--test-threads=1` and `REQUIRE_SECCOMP=1`.

Unit tests that need another filesystem, a private mount namespace or their own environment re-run themselves in a child process (`mounts::rerun_test`, `mounts::in_private_mounts`); several need root and skip without it. Two trashd-common tests bind a Unix socket and fail under a very long checkout path (`path must be shorter than SUN_LEN`).

## Architecture

Four interception layers feed into a shared trash store, all active by default after install:

```
Layer 1: PATH shim (trashd-shim)       — shadows rm via PATH ordering
Layer 2: LD_PRELOAD (trashd-preload)   — hooks unlink/unlinkat/rmdir (system-wide via /etc/ld.so.preload)
Layer 3: fanotify daemon (trashd) — detection/audit only (systemd service, Linux 5.9+)
Layer 4: seccomp supervisor (trashd-seccomp) — traps syscalls at kernel boundary (explicit commands/capable root shells, Linux 5.6+)
```

Automatic nonroot login shells use preload/shim to preserve privilege elevation; root wrapping uses `--preserve-privileges`. Layer 2 (LD_PRELOAD) is the fallback for daemons/cron/non-interactive processes. Preload requires ACTIVE and a cookie-specific filter proof after complete startup readiness.

### Crate dependency graph

```
trashd-cli      → trashd-common + zstd (native compression)
trashd-shim     → trashd-common
trashd-seccomp  → trashd-common
trashd   → trashd-common
trashd-preload  → (no trashd-common crate dependency; `#[path]`-includes its std-only modules)
```

### trashd-common — shared core

- **`store.rs`** (+ `store/listing.rs`, `store/cleanup.rs`) — `TrashStore` is the main API. `trash()` / `trash_at()` (pinned parent descriptor, used by the shim and the supervisor) move entries, `restore()` brings them back (with hash verification), `list()` scans all trash dirs (detects orphaned files per spec). Auto-purge is throttled via `maybe_auto_purge()` timestamp marker. Topdir trash stores relative paths per FreeDesktop spec. A cross-device move is a copy staged in the root's `.trashd/` **without** the root lock and published under it (`copy_into_claim`): meanwhile the claimed sidecar is flocked (purge/fsck treat a locked data-less sidecar as in flight) and the stage is covered by a shared lease on `.trashd/copy.lock`; the source is retired after the lock is released, under the entry lock. Purge detaches entries into `.trashd/purging-*` under the lock and deletes them after releasing it: purge, restore and source retirement never unlink under the root lock, because under `trashd-exec` an unlink traps into a supervisor that may be waiting for that lock.
- **`store_lock.rs`** — `RootMutationGuard`: the per-root `.trashd/store.lock`, plus the `files/`, `info/` and `.trashd/` descriptors it validated (no symlink followed, owner, mode 0700, same device). Every mutation goes through those descriptors, never through a path below the root again. Acquisition polls `flock(LOCK_NB)` for `ROOT_LOCK_WAIT` (10 s), then fails with `EBUSY`, which every layer reports as a busy file and never turns into a real delete. The lock is unlocked explicitly on drop (a forked child may hold the descriptor).
- **`fdops.rs`** — pinned-descriptor primitives (`open_dir_nofollow_at`, `rename_noreplace_at`, `create_excl_at`, `fchmod_pinned_dir`, `stat_nofollow_at`, `on_nosuid_filesystem`, …) shared with the preload and the supervisor.
- **`config.rs`** — Layered TOML config: defaults → `/etc/trashd/config.toml` → `~/.config/trashd/config.toml` → per-directory `.trashd.toml`. Supports `never_trash`, `only_trash`, `bypass_processes`, `bypass_paths`, `max_file_size_mb`, `max_dir_size_mb`, `retention.*` (`auto_compress` is opt-in, default false). `pattern_policy.rs` holds pattern normalization and validation (shared with the preload); `never_trash_covers_tree()` tells the shim when a `*`-tailed or `*/component` pattern lets it delete a whole tree in one pass. Diagnostics go through `report_note`, never `eprintln!` (a failing stderr must not panic the supervisor) and never quote the config file.
- **`mounts.rs`** — Multi-partition logic. `trash_dir_for_path()` picks same-device trash or topdir `.Trash-$UID/`. Checks `$topdir/.Trash/$UID/` with sticky-bit + symlink validation (FreeDesktop spec §1.2.2a). Another user's FUSE mount is never probed or selected; automatic retention skips network and FUSE mounts. A root whose `info/` is missing is still enumerated (its data shows as orphans).
- **`trashinfo.rs`** — FreeDesktop.org `.trashinfo` parser/serializer. Validates `[Trash Info]` header is first line. First-occurrence wins for duplicate keys. Path value not trimmed (percent-encoded spaces preserved). Extended `X-Trashd-*` fields. Writes `X-Trashd-Hash` (reads both `X-Trashd-Hash` and `X-Trashd-SHA256` for backward compat).
- **`directorysizes.rs`** — `$trash/directorysizes` cache per FreeDesktop spec v1.0. Atomic write via temp file + rename.
- **`oplog.rs`** — Append-only operation log. Desktop notification via `notify-send` (GUI sessions only).

### trashd-preload — standalone by design

Does NOT link `trashd-common` (the `.so` stays small and has no heavy dependencies). It duplicates the trash/copy logic and trashinfo writing, but `#[path]`-includes the std-only modules of trashd-common so policy cannot drift: `config_file`, `fdops`, `legacy_config`, `local_trust`, `mounts`, `pattern_policy`, `proc_stat`, `seccomp_identity`, `store_lock`, `trash_id`. A module shared this way must stay std-only (plus `libc`) and compile in both crates, tests included. Config is published through atomics (no `OnceLock`: a fork during the first load must not leave a child waiting) with periodic mtime-based change detection.

Key safety mechanisms:
- Thread-local `Cell<bool>` re-entrancy guard prevents internal `rename()`/`mkdir()` from re-entering hooked `unlink()`
- An operand is a name in a directory pinned once (`Operand`): checks, move, copy and retirement all act on (parent descriptor, name), never on the absolute path again
- Skips paths inside trash directories; a process that trashed into a root gets `EBUSY` for real deletes inside that root
- Defers to seccomp only with `TRASHD_SECCOMP_ACTIVE=1` and a cookie-specific filter proof
- `TRASH_BYPASS=1` is checked on every call
- In an `AT_SECURE` program (setuid, setgid, file capabilities) it ignores `HOME`, `XDG_*` and `TRASHD_PRELOAD_LOG`, reads only `/etc/trashd/config.toml`, and uses only the effective user's passwd home
- Cross-device: only regular files and symlinks are copied (staged in `.trashd/` without the store lock, published under it); a file the trash cannot copy fails the delete (`EACCES`/`EIO`/`EBUSY`) instead of being deleted for real, while a store that cannot be used at all (no home, full, out of descriptors) lets the real delete run

### trashd-seccomp — supervisor and ancestor broker

`trashd-exec <command>` runs five processes: wrapper → keeper → {command, watchdog → supervisor}.
1. **Child**: installs the BPF seccomp filter, passes the notification fd via SCM_RIGHTS, waits for startup acknowledgement, then sets `TRASHD_SECCOMP_ACTIVE=1` plus a session cookie and execs the command. Failed setup clears the flag so preload can protect the fallback.
2. **Keeper** (the orchestrator): remains the target's ancestor/subreaper and brokers process-memory reads and descriptor duplication for the supervisor, preserving Yama `ptrace_scope=1` restrictions. It forwards signals through pidfds and reports the command's status once the command and every descendant still in its session have exited; descendants that left the session (`setsid` daemons) keep it running, detached and still protected. `SignalWait` forces the default SIGCHLD disposition while waiting (an inherited `SIG_IGN`, e.g. from WSL's `login`, makes the kernel reap children and once spun this loop at 100% CPU) and restores the inherited one for the command. On setup failure it reaps the filtered child and execs the command in place — no resident wrapper in fallback mode.
3. **Wrapper**: the process the shell started. Relays signals to the keeper and exits with the status the keeper reports.
4. **Supervisor**: reads notifications, obtains pathname bytes through the keeper's broker, resolves through pinned descriptors (`pin.rs`), moves entries with `TrashStore::trash_at`, and responds to the kernel. `Decision::Decline` hands a delete back (the preload trashes in-process, anything else the kernel runs); policy exclusions `Continue`; the trash itself and a busy trash lock answer `EBUSY`.
5. **Watchdog**: holds a duplicate notification fd and respawns a dead supervisor, which receives the queued notifications; after repeated failures it answers the queue through a decline handler. Supervisor and watchdog ignore job signals (SIGTERM included) and are torn down with SIGKILL once the command exits.

BPF filter (`filter.rs`): architecture-specific — x86_64 traps `SYS_unlink`/`SYS_unlinkat`/`SYS_rmdir`; aarch64 traps only `SYS_unlinkat`. Both trap `landlock_restrict_self`. Compat ABIs (i386/x32, AArch32) are not trashed: their deletes, `io_uring` and `landlock_restrict_self` fail with `ENOSYS`.

The protected-mode paths need a real notification listener: they skip on WSL and run in CI with `REQUIRE_SECCOMP=1`.

### trashd — fanotify monitor

Uses `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (Linux 5.9+) and watches `FAN_DELETE` only. Resolves the parent via `open_by_handle_at()` with a directory fd opened per lookup on the mount whose fsid matches (no fds are held, so `umount` works). Each lookup still opens the mount for a few microseconds, during which an `umount` reports busy, so lookups are kept few: none for a directory the same batch shows removed, and a decoded path is reused for 20 ms (`HandleCache`). `tests/daemon_umount_race.py` (via `tests/sandbox.py --loop-device MIB`) measures that race; it is opt-in and no CI job runs it. With nothing markable it idles and re-scans mounts each second. Detection/audit only. Without fanotify (old kernel, no capability) it exits with status 78 and systemd does not restart it. FUSE and virtual filesystems are never marked; btrfs subvolume mounts cannot be marked (one startup warning); events of mounts that share an fsid are logged by name only.

## Key design decisions

- **Failure handling**: a trash that cannot be used at all (no home, full, read-only) falls back to real deletion; a trash that is unsafe, busy (`EBUSY` after the lock wait) or cannot copy the operand fails the delete and keeps the file. Invalid shim arguments fail without deleting; a filtered target is released only after its supervisor is ready.
- **Pinned descriptors**: once a root is locked, its `files/`, `info/` and `.trashd/` are reached only through the descriptors the lock validated (`fdops.rs`); a FUSE or NFS server can answer every path lookup differently.
- **Atomic IDs**: `O_CREAT|O_EXCL` on `.trashinfo`. Ids are sized to the trash filesystem's `NAME_MAX` (`trash_id.rs`) and claimed again shorter on `ENAMETOOLONG`
- **Symlink-safe**: `normalize_path()` canonicalizes parent only. Symlinks re-created in cross-device copies
- **Process bypass**: walks `/proc/{pid}/stat` up the tree (the deleting process and up to ten ancestors), matching both the exe basename and the kernel comm. `bypass_paths` is matched against the deleting process's own executable, which each layer looks up itself (the preload its process, the shim its caller, the supervisor its target via `/proc/{pid}/exe`); the store never matches it against its own executable
- **Hash verification**: XXH3-128 (default) or SHA-256, computed on trash; restore selects the stored digest's algorithm for one successful verification pass
- **Auto-purge throttling**: `maybe_auto_purge()` skips if < `auto_purge_interval_secs` since last run
- **Config precedence**: `never_trash` always wins → `only_trash` narrows → `.trashd.toml` applies locally
- **Shim sets `TRASH_BYPASS=1`** when passing through to real rm (prevents LD_PRELOAD re-interception)
- **Confirmation required**: `trash empty` prompts by default, `-y` skips
- **Native zstd**: `trash compress` uses the `zstd` Rust crate (no system dependency). Automatic compression during retention is opt-in (`retention.auto_compress`): other file managers restore the stored bytes as they are
- **Exclusions are per path**: `never_trash` is a verdict for one path, never for what a directory holds; the shim sweeps a tree entry by entry unless a pattern covers the whole tree
- **CHANGELOG**: every fix gets a line under `## Unreleased` citing its issue number

## Binaries

| Binary | Crate | Purpose |
|--------|-------|---------|
| `trash` | trashd-cli | CLI: ls, find, info, restore, undo, purge, empty, compress, du, status, log, fsck |
| `trashd-rm` | trashd-shim | Drop-in `rm` replacement |
| `libtrashd_preload.so` | trashd-preload | LD_PRELOAD shared library |
| `trashd-exec` | trashd-seccomp | Seccomp supervisor wrapper |
| `trashd` | trashd | fanotify filesystem monitor |

## Bypass mechanisms

- `rm --permanent` / `rm --no-trash` — shim passes through to real rm (with `TRASH_BYPASS=1`)
- `TRASH_BYPASS=1` — env var checked by shim, preload, and seccomp
- Config `bypass_processes` — auto-detected via `/proc` tree walk (includes git, apt, cargo, etc.; systemd/systemctl are deliberately excluded)
- Config `bypass_paths` — exe path prefix match for more precise control
- Config `never_trash` — glob patterns for paths/extensions that skip trash
- Config `only_trash` — whitelist mode (if set, only matching files are trashed)
- Config `max_file_size_mb` / `max_dir_size_mb` — size limits
- Per-directory `.trashd.toml` — project-level `never_trash`/`only_trash` overrides
