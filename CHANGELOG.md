# Changelog

## 0.1.6 (2026-09-29)

Release from the 2026-09-28/29 analysis and remediation pass: 47 issues filed,
verified, and closed across six review rounds. Fixes below; all were confirmed
reproducible against 0.1.5 on a live system before fixing.

### Fixed — shim (rm)

- Operands whose final component is `.` or `..` are refused like GNU rm;
  `rm -rf ..` no longer trashes the caller's working directory while
  reporting success, and paths ending in `..` resolve to the parent instead
  of silently collapsing to the directory itself.
- `--permanent`/`--no-trash` are only stripped before `--`, so files literally
  named like the bypass flags can be permanently deleted.
- `rm -f -i missing` exits 0 silently: ignore-missing follows GNU semantics
  (set by `-f`, never cleared by interaction flags).
- `--preserve-root=all` refuses mount-point operands.
- Real-rm discovery probes every candidate (stash, PATH, /usr/bin/rm) for
  shim copies and refuses to recurse if only shim copies exist; a shim-copy
  probe no longer forks without bound under TRASH_BYPASS=1.
- The real-rm stash is located relative to the shim itself, so custom-prefix
  installs work.

### Fixed — preload

- An empty pathname falls through to the real syscall (ENOENT) instead of
  trashing the caller's working directory or dirfd.
- Only the caller's own `.Trash-<uid>` matches the trash-internal skip, so
  lookalike directories are trashed, not permanently deleted.
- `max_dir_size_mb` is parsed and enforced (bounded walk), matching the other
  layers.
- Cross-device copies open sources with O_NOFOLLOW|O_NONBLOCK and re-verify
  identity, so a swapped FIFO cannot hang the host process and a swapped
  symlink is not read through.
- `TRASHD_SECCOMP_ACTIVE=1` only defers interception when the process really
  runs under a seccomp filter; a leaked export no longer disables protection
  on unfiltered hosts.

### Fixed — trash store and restore

- Cross-device removal uses raw syscalls: under a system-wide LD_PRELOAD the
  source is no longer re-intercepted and captured twice.
- Auto-purge re-validates entries before compression, counts only successful
  purges, relieves disk pressure only on the pressured filesystem, and sizes
  foreign directory entries by their real (capped) tree size.
- Undo restores the resolved newest entry, working across trash roots that
  hold the same ID.
- Orphaned entries are detected per trash root, so recoverable data is listed
  even when another root holds the same ID.
- `.trashinfo` decoding is plain percent-decoding: percent-encoded dot
  segments cannot bypass traversal rejection, Path values keep literal
  whitespace, and `file://host` forms cannot invent paths.
- Long-running supervisors no longer leak a descriptor when the trash volume
  fills, and raced FIFO/symlink swaps cannot block a deletion forever.
- The trash index database is owner-only (0600).

### Fixed — seccomp layer

- io_uring, non-native architectures, and x32-numbered syscalls are refused
  with ENOSYS instead of silently allowing permanent deletes.
- Notifications are validated before target memory is read (PID-reuse hardening).
- A supervisor can no longer outlive the watchdog holding the notification fd.
- A dead broker no longer SIGKILLs the wrapped command — its real exit status
  is returned — and supervisor respawns are rate-limited.

### Fixed — daemon, CLI, packaging

- Deletion events resolve file handles only against the filesystem the event
  came from, and remounts at the same path are re-marked.
- `trash config add` reports a readable error instead of panicking on a
  non-array list value; `trash ls --after` bounds-checks magnitudes instead
  of overflowing.
- `trash self-update --check` no longer offers downgrades from the cache,
  compares versions suffix-aware, and reinstalls under the original PREFIX.
- `trash fsck` no longer misclassifies data with a dangling sidecar symlink
  as orphaned and offered for deletion.
- Non-UTF-8 names are accepted by `ls`, `find`, `info`, `restore`, and
  `purge` on the command line.
- The CLI, shim, and daemon die quietly on SIGPIPE like GNU tools instead of
  panicking with exit 101.
- install.sh and `make install` template the real prefix into the profile
  script (custom-prefix installs activate all layers; metacharacter prefixes
  survive), `make build` no longer runs `cargo update`, and the release
  workflow hardens interpolation and fails on missing attestations.


## 0.1.5 (2026-09-27)

- Accept legacy configuration files that placed global settings under
  `[retention]`, preserving policy values in both the common and preload loaders.
  Explicit top-level settings take precedence.
- Expose the monitoring daemon as `trashd` on PATH and support `trashd --version`.
- Remove the daemon PATH entry during uninstall.

## 0.1.4 (2026-09-27)

### Fixed — deletion and restore safety

- The `rm` shim now reports an error and leaves files in place if the trash
  store cannot be opened or a trash operation fails. Explicit `--permanent`
  remains available for intentional permanent removal.
- Trash roots and their `files`/`info` directories are checked for ownership,
  symlinks, and private permissions before use. Unsafe mount trash locations
  fall back to the home trash; read and destructive scans skip unsafe stores.
  The preload hook returns `EACCES` for an unsafe store instead of deleting.
- Restore pins the destination and source directories, refuses to overwrite a
  newly created destination, and copies across filesystems through exclusively
  claimed entries. Failed copies keep the trash source and avoid removing
  entries that another process replaced or added.
- Compressed restore bounds decompression memory and output, retains corrupt
  zstd payloads for recovery, and clears a stale compression marker when the
  stored content is still plain text.
- Seccomp path handling confines absolute paths to the target root and relative
  paths to the pinned base. When pinning, resolution, or storage fails, the
  target's own syscall runs in its namespace; the supervisor no longer retries
  a deletion through a path in its host namespace.

### Fixed — installation and diagnostics

- Source installs build with the committed `Cargo.lock` in a private staging
  directory. Under `sudo`, compilation runs as the invoking non-root account;
  the installer no longer updates Rust or dependencies during installation.
  CLI man page and completion generation honors `CARGO_TARGET_DIR`.
- The self-update check cache uses a private, validated path and an atomic
  marker replacement, rejecting symlinked directories without writing through
  them or falling back to a shared temporary location.
- Deletion and mount logs escape arbitrary filename and process-name bytes on
  one line, and the operation log is restricted to mode `0600`.

### Dependencies and tooling

- Pin Rust 1.98.1 for local builds and release/dependency workflows while
  retaining Rust 1.97 as the minimum supported version.
- Update `dirs` to 7 and `zstd` to 0.14, along with compatible locked
  dependencies. The weekly dependency workflow validates its lockfile before
  opening an update pull request.
- Update the README's install, fallback, and trash-directory guidance to match
  these changes.

## 0.1.3 (2026-08-22)

Bug-fix release from a 16-agent adversarially-verified security audit (52
confirmed findings, all fixed) plus a full fd-based rewrite of the seccomp
supervisor's path handling. No breaking changes; note the two deliberate
behavior changes flagged below.

### Fixed — data loss

- `rm --permanent` can no longer fork-bomb when a stale install stashed the
  shim itself as the "real" rm (both the installer and the shim now detect it).
- Trashing the trash directory itself, anything inside it, or an ancestor is
  refused — `rm -rf ~/.local/share/Trash` can no longer destroy the store.
- GNU rm's `--preserve-root` guard is actually enforced (`rm -rf /` fails).
- Size-limit (`max_file_size_mb` / `max_dir_size_mb`) and trash-self refusals
  no longer escalate to permanent deletion; the file is left untouched.
- A failed removal of the original after a successful cross-device copy keeps
  the complete trash copy instead of rolling it back (no more losing the only
  surviving copy of partially-deleted trees).
- Auto-purge retention accounting uses recorded tree sizes for directories
  (the old ~4 KB inode-size estimate over-purged far past configured limits)
  and never follows symlinks.
- Orphaned entries (no `.trashinfo`) can no longer hijack `trash undo` or be
  restored to a bogus `(orphaned: …)` path in the CWD.
- Non-UTF-8 filenames survive a trash/restore round-trip byte-exact (raw-byte
  percent-encoding); non-UTF-8 argv no longer panics the shim.

### Fixed — security

- seccomp supervisor: race-free fd-pinned interception (#6). The target's
  root/cwd/dirfd are pinned via pidfd_open/pidfd_getfd, prefixes resolve in a
  single openat2 walk (RESOLVE_IN_ROOT for absolute paths), and moves happen
  with renameat against pinned inodes — sibling renames can no longer divert a
  delete to different content, and chrooted/absolute-path walks stay inside
  the pinned root. Legacy path flow remains as fallback.
- The supervisor honors `TRASH_BYPASS=1` by reading the target's environ;
  `bypass_paths` is checked against the trapping process's executable.
- `systemd`/`systemctl` removed from the default bypass list — ancestor-name
  matching silently disabled ALL interception under systemd-launched sessions.
- Unrecognized glob syntax no longer falls through to exact-match: full glob
  engine (`?`, `[...]`, `**`) in every layer, brace patterns rejected loudly
  at load (an inert `only_trash` whitelist used to real-delete everything).
- install.sh stages binaries/.so atomically (temp + rename), ensures a
  trailing newline before appending to `/etc/ld.so.preload`, resolves the real
  rm via `which -a` skipping trashd paths, and heals poisoned real-rm stashes.

### Fixed — correctness

- Glob matcher rewritten (iterative, backtracking): fixes an inverted-slice
  panic on patterns like `abc*b*bc`, adds classes/ranges/negation.
- Watchdog forks its own supervisor so `waitpid` targets a child — kills the
  ECHILD fake-failover that ran two supervisors on one notification fd.
- Cross-device FIFOs are recreated via mkfifo instead of blocking forever;
  device nodes/sockets skip to the real unlink instead of unbounded copies.
- copy_tree applies source directory permissions after populating (read-only
  trees round-trip across filesystems); restore decompression never follows
  trashed symlinks; compress never dereferences/replaces trashed symlinks.
- Compression marker is recorded before data swap with tolerant decode-on-
  mismatch; `trash compress` streams zstd (bounded memory, any entry size);
  hashing streams in chunks instead of slurping whole files.
- trashinfo parser: lexical `..` rejection before decoding, URL decoder only
  for absolute values (`localhost/x` stays relative), first-wins X-Trashd-*
  keys, control chars stripped from commands.
- Exact-ID matches spanning multiple partitions raise AmbiguousMatch;
  purge/empty keep `.trashinfo` when data removal fails; `.trashd.toml`
  discovery walks to the filesystem root (not 5 levels).
- Preload: TOCTOU dev/ino re-check before rename, dlsym caching,
  /proc/mounts octal unescaping, uid-private HOME fallback instead of /tmp,
  partial-copy cleanup, async-signal-safety caveat documented.
- Daemon: renames no longer logged as deletions, FAN_Q_OVERFLOW warns loudly,
  DELETE_SELF events resolve via DFID records, new mounts picked up at runtime.
- install.sh atomic artifact replacement; fsck --fix requires confirmation
  before destroying orphaned data; self-update uses sha2 and numeric version
  comparison (no more offered downgrades).

### Changed

- Rust toolchain 1.97.0 → 1.98.0; 69 lockfile-only dependency bumps.

## 0.1.2 (2026-07-11)

- Upgrade the workspace to Rust 1.97 and Rust edition 2024
- Refresh all compatible direct and transitive dependencies
- Pin CI, releases, formatting, and linting to the Rust 1.97 toolchain

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
