# Changelog

## Unreleased

This round fixes a privilege boundary in the root seccomp supervisor,
several ways trashd-exec could end a login or lose protection mid-command,
rm parity gaps, unsafe compression, and misleading daemon audit paths. It
also removes most of the per-deletion system calls and fsyncs that remained
in the preload, the shim and the supervisor. Existing trash contents are
preserved.

### Fixed

- The seccomp supervisor honors Landlock domains a target installs after
  startup: it records each `landlock_restrict_self` and declines those
  threads' deletes to their own credentials, so a policy-forbidden removal
  is refused natively instead of renamed with supervisor credentials.
  Records persist with the orchestrator across supervisor restarts (#390).
- `trash fsck` reports directory entries it could not read and fails the
  check instead of discarding the error and claiming clean trash (#398).
- Trash naming no longer exhausts a fixed same-second counter range: after
  the first timestamped ID, preload and store claims advance to PID- and
  sequence-unique IDs, so collisions never turn a delete permanent (#399).
- Directory-size cache maintenance scans rows one at a time instead of
  building a full entry map to test membership or validate the cache,
  while checked reads still validate every row (#400).
- Text and JSON `ls` output reports write and final-flush failures with a
  normal error exit, including empty listings (#380).
- The fanotify daemon passes raw Unix mount paths to `statfs` and
  `fanotify_mark`, so a non-UTF-8 mount point is monitored (#381).
- Preload cross-device copies keep the publication lock through source
  retirement and refuse changed sources instead of deleting newer data.
  Copying is bounded to the verified source size, and rollback removes only
  the copy this operation created (#382).
- Copied-source retirement under preload and seccomp no longer deadlocks
  against its own publication lock. The caller performs the native unlink,
  preserving kernel permission checks and existing syscall allowlists
  (#393). Update the wrapper and preload together and restart wrapped
  sessions so they receive the new filter.
- Cross-device restore preserves source edits made after copying and rolls
  back only the destination it created. Files changed before opening are
  rejected before any copy is created, using the existing metadata checks
  (#396).
- Maintenance reclaims unpublished copies left by killed cross-device
  operations, compression and decompression. Locked stage announcements
  preserve active writers and unrelated state, and cleanup never traverses
  a mount in a partial copy (#383, #388, #389).
- Status and size retention count foreign directory trees beyond 10,000
  entries. Forged recorded sizes remain capped by measured data (#384).
- Out-of-range local deletion dates are rejected instead of panicking an
  entire listing or retention scan (#385).
- Compression and decompression recheck the opened data's content and
  metadata version before publication, preserving same-inode edits made
  during encoding or a lock wait. Input reads remain bounded if a writer
  keeps growing the file (#386).
- Seccomp records and applies policy to a verified physical path for
  chrooted processes. Hidden parents, overmounted files and differing
  policy visibility defer to in-process protection; ordinary namespace
  clones with the same visible paths remain protected (#387).
- A privileged supervisor no longer performs trapped deletes for targets
  whose filesystem UID/GID, groups or effective capabilities differ from
  its own (users reached via su/sudo inside a wrapped root session,
  processes that dropped capabilities); the kernel judges their syscall
  instead (#311).
- trashd-exec execs commands with SIGPIPE at its default (#312), runs the
  command unprotected instead of exiting 1 when protection cannot start
  (unreadable cwd, broken trash, supervisor timeout) (#313), accepts
  non-UTF-8 arguments (#314), keeps its workers alive through Ctrl-C and
  other job signals, no longer forwards a terminal signal twice, forwards
  QUIT/USR1/USR2 instead of dying of them, and ends by re-raising the
  command's terminating signal (#321).
- trashd-exec workers can no longer kill the command through a panic or a
  failed stderr write, release the launch directory, and re-identify
  trashd's own binaries after an update (#323); the orchestrator survives
  descriptor exhaustion from many adopted descendants (#325).
- The shim passes bypassed callers through before opening the store
  (#315), ignores ENOTDIR operands under `-f`, refuses `-d` on an
  unlistable non-empty directory like rm, prompts for every entry under
  `-ri` (#316), and sends one desktop notification per invocation (#317).
  An unusable `.trashd.toml` is reported once per file (#318). Under
  `-ri`, each fully confirmed subtree is one trash entry that undo
  restores whole, prompts show the operand's own paths, and `-di` confirms
  an unlistable empty directory (#342). Answers are carried out only on
  the entries confirmed: anything that appears meanwhile stays, and the
  prompts, file-kind names, `-I` wording and yes rule follow GNU rm
  (#351, #355).
- Trash roots on mounts listed past the first 4 KB of /proc/mounts are
  found again (#354).
- The preload no longer uses openat2, which killed processes under
  seccomp allowlists that predate it; a reader holding the SQLite cache
  open no longer stalls deletions; `-ri --one-file-system` asks about
  other filesystems as GNU rm does (#357).
- `rm --one-file-system` holds mount points as busy, as GNU rm does: a
  bind-mounted file no longer lets its directory be moved into the trash
  with the live mount inside, and overlayfs files that report their
  layer's device are removed like any other (#358), including bind mounts
  from the same filesystem and on kernels before 5.8 (#359, #360). An
  accepted empty btrfs subvolume is removed if still empty, and a seccomp
  profile that refuses statx no longer stops `-ri` (#360, #361). Mounted
  directories still honor the size limit and trash refusals, and a bind
  made over a confirmed entry during the prompts never travels into the
  trash (#361).
- Plain `rm -r` of a directory holding a mount no longer carries the live
  mount into the trash: the tree moves whole or not at all, so it is
  refused and nothing moves; a mounted operand is emptied into its own
  trash instead of refused (#366). No walk empties a mount nobody named
  (only `-i` asks), nothing configured out of the trash under a trashed
  operand is deleted for good, and files on a read-only filesystem or in
  an unwritable directory are no longer copied into the trash only to
  stay where they are (#368). A mount too deep or behind an unreadable
  directory for the walk is found in the mount table, and no tree is
  copied across filesystems when a directory inside it that holds entries
  is unwritable, immutable or sticky against the user, or when anything in
  it is immutable or append-only (#370, #371, #372). No stat of trashd's
  triggers an automount (#372).
- Cross-device trash and restore retire every hard link in a copied tree.
  Removing one link no longer makes the remaining links appear changed;
  content and version checks still preserve files edited during retirement
  (#373).
- Immutable and append-only entries are also refused before a cross-device
  copy when a container blocks statx or its attributes are unavailable.
  If inode flags cannot be examined, the copy fails before publishing data
  (#374).
- A mount point operand (`rm -d`, asked about first under `-i`;
  `rmdir(2)` under the preload; a bind-mounted file from any filesystem)
  is reported busy like GNU rm: no `.Trash-$UID` is left on the mounted
  filesystem and no copy is stranded in the trash (#368, #369).
- Real `rm -r` of an excluded tree walks it by descriptor, so a directory
  swapped for a symlink is never followed out of the tree. Like rm, it
  removes everything it can instead of stopping at the first failure, and
  reports each entry that stays once, without Rust's "(os error N)". A
  mount inside stays as it is, busy (GNU rm empties it) (#368, #369). It
  needs no read access to the tree's parent, removes empty directories it
  cannot list and has no depth cap, as rm, and reads huge directories in
  batches instead of listing them whole (#370, #371).
- Purging never deletes through a mount point that travelled into the
  trash with its directory (nor changes its mode, nor leaves its siblings
  behind), and a bind alias of the trash, its directories or an ancestor
  of it is refused like the trash itself (#362, #363).
- A real-rm probe that could not start or was killed is no longer
  remembered (one made every later passthrough refuse to run), and the
  probe cache never creates root-owned directories in a user's home under
  `sudo -E` (#339).
- The supervisor lets the kernel judge deletes by targets in another user
  namespace, whose mapped root looks like real root (#341). Deletes it
  will not perform with its own credentials (a user switched with su,
  runuser or setpriv, dropped capabilities) are trashed by the preload
  in-process instead of being deleted, as are deletes while the
  supervisor is being replaced (#349) or cannot trash them itself (no
  store, a cross-device or namespaced target) (#355).
- trashd-exec answers a notification even when handling it panics, reads
  status files with non-UTF-8 command names, survives a full descriptor
  table without killing the command, and forwards ALRM, timer,
  resource-limit and real-time signals instead of dying of them (#350).
- `self-update` unpacks only under directories no other user can modify
  (#343).
- `rm -r --one-file-system <dir>` records an absolute `Path=` (#310).
- Preload hooks no longer consult NSS when `HOME` is unset, except for
  users `/etc/passwd` does not list, who now get the same home trash as
  the CLI (#303, #346). A
  dirfd-relative delete is trashed only when the resolved path names the
  caller's inode (#304). The passwd-home fallback trash records absolute
  paths (#305).
- The trash-root authentication cache no longer drops roots under lock
  contention (#309).
- `trash compress` leaves hard-linked data, files with extended attributes
  and other tools' entries alone, and stages attempts outside `files/` so
  an interrupted run strands nothing there (#327).
- Ambiguous selectors list exactly the matching entries, and
  `restore --all` no longer treats exact names with brackets as globs
  (#328); `restore --all <name>` restores every copy trashed under that
  name again (#340). `trash undo` restores the latest of same-second
  deletions, also after compression and on coarse filesystem clocks: new
  sidecars record a nanosecond deletion stamp (`X-Trashd-DeletedNs`)
  (#329, #345).
- `trash config add/remove/set` edit legacy `[retention]` settings where
  they apply (#330). `self-update` works with a noexec `TMPDIR` (#331).
- `trash fsck` exits 1 when it finds problems, when `--fix` leaves any, or
  when a root cannot be checked or read (#332, #347). `ls` handles a symlinked home,
  rejects bad time filters before scanning, and more output is escaped;
  `status` totals cannot wrap (#333).
- The daemon logs paths through real mounts rather than bind mounts, keeps
  directory paths for `rm -rf` records even when it reads behind (with
  `FAN_REPORT_TARGET_FID`, Linux 5.17+), and no longer stalls every second
  on a hung network mount (#326, #344).
- A concurrent `trash compress` no longer sweeps another run's staged
  file (#348). Retention compression keeps the original atime, the daemon
  log stays in event order, and the real-rm probe cache works through a
  symlinked cache directory (#352).
- An interrupted cross-device trash or restore no longer leaves truncated
  data under the final name: copies are staged under a hidden name and
  published without replacing anything; interrupted decompression no
  longer leaves an orphaned entry (#334).
- Purge, `empty` and retention remove trees containing read-only
  directories (Go module caches, Bazel/Nix outputs) and entries whose data
  the owner cannot read; oversized sidecars and caches are rejected instead
  of being read into memory (#335).
- Trashed directories record their full size beyond 10,000 files, so the
  size limit and `trash status` count large trees (#336).
- Patterns treat an unterminated `[` as a literal and accept `\` escapes,
  like fnmatch(3) (#337).
- Cross-device copies keep sparse files sparse and hard links linked (#338).

### Performance

- Common cross-device copies stop at the captured source size, including
  sparse extents and filesystems without extent queries. Appends cannot
  prolong copy work past that bound while the publication lock is held,
  and empty copies skip extent queries entirely (#395).
- Purge and unpublished-stage cleanup read directory entries in batches.
  Purge shares one read buffer across its iterative walk; wide directories
  and deep trees no longer require whole-directory name lists or a buffer
  at every ancestor (#391). On a warm tmpfs with 100,000 filenames of 220
  bytes, peak purge memory falls from about 29.5 to 3.5 MiB and median time
  from 856 to 810 ms against 1c76f33 (four alternating pairs).
- JSON listings stream directly to a buffered writer instead of holding a
  second representation of every entry and the complete output string.
  A 20,000-entry sandbox listing keeps identical output while reducing peak
  memory from about 55 to 21 MiB (median of four alternating pairs, #380).
- Foreign-tree accounting uses batched descriptor-relative walks, stops
  at a recorded-size ceiling, and reuses each measurement within a retention
  pass instead of walking selected victims twice (#384).
- Manual compression rejects entries younger than its age filter before
  inspecting their data or extended attributes (#386). Against 96d8a97,
  a 6,000-entry no-eligible-entry scan drops from 48,174 to 36,171 syscalls
  and from 120.3 to 92.1 ms median (40 alternating samples per build).
- Selector commands retain their resolved matches instead of rescanning
  them for `restore --all` or ambiguity output (#376). In a 6,000-entry
  sandbox, no-match `restore --all` drops from 66,207 to 36,155 syscalls;
  ambiguous selectors drop from about 72,300 to 36,200.
- Directory-size cache rebuilds skip unrelated regular files using
  directory-entry types, with metadata fallback when needed and fresh
  checks for candidate directories (#377). Purging an empty directory
  among 6,000 regular files takes 220 instead of 6,211 syscalls.
- `find` and `du` keep sidecar freshness checks but skip unused data inode
  stats; find queries and ls date filters retain and sort only matching
  results after orphan bookkeeping (#378). A 6,000-entry find/du scan
  saves about 6,000 syscalls. Buffered find/du output still reports write
  and flush failures.
- Cross-device trash collects retirement snapshots during its permission
  preflight instead of walking the tree again (#379). A 6,000-file copy
  takes 174,319 instead of 180,328 syscalls; mount surveys, copy-time
  validation and source-retirement guards stay in place. Partial statx
  results fall back to complete metadata, and inode-flag checks also work
  when statx is blocked after the process has already used it.
- Untraced paired checks on the 6,000-entry sandbox (40 alternating samples
  per build) reduce median no-match find from 98.7 to 76.7 ms, no-match
  `restore --all` from 166.8 to 97.1 ms, and directory purge from 28.8 to
  13.4 ms. Ordinary and cross-device trash show no reproducible slowdown.
  These measurements depend on the fixture and host.
- Removed the unused SQLite index and its dependency, including cache writes
  on trash, restore and purge, and the `fsck --fix` rebuild. All lookups still
  use `.trashinfo` files; existing cache files are left untouched (#375).
  Against 431c859, a warm single-file shim `rm` takes 139 instead of 222
  syscalls (40 alternating samples: median 2.22 instead of 3.06 ms).
- Passthroughs reuse real-rm probe verdicts (~7.6 ms -> ~4.7 ms on the dev
  host) (#324).
- Bypass ancestry walks read comm and parent from one bounded stat read:
  4 syscalls per ancestor instead of 15 (#302).
- A steady-state preload deletion costs ~40 syscalls instead of ~65: path
  resolution keeps canonical prefixes (#304), the store lock is taken
  optimistically, the sidecar is written through its claim, a validated
  home ancestry is reused for five seconds and the deletion date comes from
  the hook's single clock sample (#305). Config reads drop a redundant
  fstat and seek (#308). The preload no longer links chrono or dirs.
- Store mutations reuse a validated root path chain, lock before repairing,
  canonicalize only relative components and write sidecars through their
  claim (~94 -> ~62 syscalls per extra shim operand) (#307). Trashing a
  directory updates one directorysizes row instead of rebuilding the cache
  (#322).
- The supervisor answers before running retention (#319), stops its bypass
  walk at the orchestrator's cached ancestry, and drops repeated
  view-identity, revalidation, realpath and environ work per delete (#320).
- Preload hooks rule out excluded, missing and trash-internal paths before
  walking the process tree (an excluded unlink: 53 -> 10 syscalls). `ls`
  and `undo` skip unused data stats and mount points are stat'ed once
  (300 entries: `ls` 2,384 -> 1,719, `undo` 2,261 -> 1,892 syscalls); the
  store lock, retention throttle and passthroughs
  (exec in place) do less (#353).
- Bypassed processes check their cached verdict before any path work
  (3,000-file `rm -rf` under make: 21,179 -> 12,181 syscalls); display
  listings skip a per-entry re-stat and the mount scan skips kernel
  pseudo-filesystems (`ls` with 300 entries: 2,382 -> 1,417) (#354).
- Where statx cannot tell mount roots (before Linux 5.8), purging asks
  only directories, once per level, instead of every entry (#364); one
  path's statx failure no longer disables statx for the process (#365),
  and mount IDs come from file handles before devices are compared, with
  no /proc needed (#367).
- Measuring a trashed tree looks entries up relative to their directory
  instead of by absolute path, and directory listings read getdents64
  straight from the descriptor (a 50-deep tree of 5,000 files:
  38.2 -> 21.3 ms; 50 directories of 100 files: 5,873 -> 5,588 syscalls),
  which also speeds up purging trees (#368).
- The daemon refreshes mounts only when the mount table changes (#326),
  and decodes each directory handle, names each deleting process and
  writes its log once per batch (a 1,011-entry `rm -rf`: ~8,300 -> ~770
  daemon syscalls) (#344).
- Purges use raw syscalls instead of hooked libc wrappers (emptying 5,000
  files: ~76,600 -> ~5,800 syscalls) and delete detached directory trees
  after releasing the trash-root lock, so a large purge no longer stalls
  every delete (#335).
- Retention no longer re-reads and re-encodes incompressible data on every
  run, sizes entries only when a size limit is set, and refreshes
  directorysizes only where a removal changed it; snapshot retirement is
  no longer quadratic; trashing a directory walks it once (#336).

## 0.1.12 (2026-10-21)

This release reduces system calls in trash scans, preload interception,
seccomp handling, restore, logging and optional-index maintenance. It also
fixes Rustup cleanup flooding the trash and a restore deadlock involving
trusted symlinked trash ancestors. Existing trash contents are preserved.

### Fixed

- Rustup and rustup-init now bypass trash like other package/build tools,
  preventing toolchain cleanup from publishing tens of thousands of rustdoc
  backup entries. Existing entries are not automatically purged (#282).
- Preload recognizes the physical home trash when its configured parent
  contains trusted symlinks. Restore can remove its own metadata without
  re-interception and waiting on its own root lock. Symlink ownership and
  target ancestry are authenticated; the final Trash directory must still
  be a real, private directory (#289).

### Performance

- `trash status` totals entries in one pass, reusing file metadata and
  discovering trash roots once. It no longer builds or sorts a complete
  listing or checks every data file a second time (#281).
- Large trash listings read sidecars through one validated descriptor
  snapshot, avoiding redundant metadata queries, seeks and EOF probes while
  retaining replacement and modification checks (#281).
- Long interactive `trash status` and `trash ls` scans show delayed progress
  on stderr. Fast commands, redirected output and JSON remain quiet (#281).
- Listing and fsck reuse exact deletion-date conversions within each scan,
  avoiding a clock read for every repeated timestamp. The bounded cache
  retains Chrono's DST, ambiguous-time and historical-offset behavior;
  standalone parsing is unchanged (#288).
- Read-only store operations no longer initialize SQLite or create its
  journal and shared-memory files. The optional index opens on demand for
  mutations; sidecars remain the authoritative source (#293).
- Global `never_trash` rules run before local-policy ancestor walks. Preload
  also skips unnecessary source metadata checks on these excluded paths.
  Local policies remain fresh for every other operand (#285).
- Ordinary paths avoid mount-table reads when they cannot be inside a
  mounted trash root. Authenticated home-trash cleanup checks its current
  ownership, mode and inode before consulting mounts. Enumeration observes
  the home device once per scan; removable filesystems are not pinned (#284).
- Preload reuses its existing time sample for configuration change notices,
  makes immutable config access free of clock reads, and samples the PID
  once per eligible hook. Parent changes and forked children are still
  detected; explicit bypass adds no PID or clock calls (#283, #298).
- Existing directory preparation reuses its successful metadata lookup.
  Creation and permission repair still trigger fresh validation, and source
  replacement is checked before publication (#297).
- Seccomp skips pathname capture and broker work for bypassed processes,
  bypassed environments and invalid unlinkat flags. Protected operations
  retain one captured pathname and the pinned mutation path (#286).
- Seccomp reads process name and parent from one fresh procfs stat record,
  stops immediately on an executable match, and avoids redundant executable
  lookups. Script names and non-leader thread names remain covered (#287).
- Seccomp opens the target cwd only for operations that use it. The target
  root remains pinned for policy and recorded-path validation, and the full
  startup readiness probe remains intact (#296).
- Forced single-entry restore resolves the trash entry once, retaining its
  mutable snapshot through conflict handling instead of rescanning every
  sidecar. Existing destinations and occupied suffixes are preserved (#292).
- Ordinary exact IDs and absolute trash selectors enumerate directory names
  but read only matching sidecars. Every root is checked for ambiguity;
  filename, glob and raw-name collision cases retain full resolution.
  Home read errors and foreign-root warnings are preserved (#299).
- Single-file and symlink restores and purges avoid rebuilding the complete
  directory-size cache when the removed raw name has no cached row. Directory
  removal, stale rows and malformed or unusable caches retain full refresh;
  batch maintenance is unchanged (#300).
- Locked mutations reuse the data and sidecar metadata they just validated.
  Fresh checks remain after encoding, decompression and lock waits, with
  final pinned-source identity checks before mutation (#294).
- Operation-log appends create parent directories and repair permissions
  only when necessary. Each append still reopens and validates the current
  regular file. Log tails use positioned reads without EOF or per-chunk
  seeks, preserving bounded I/O and line semantics (#290, #291).
- The rebuildable SQLite cache uses `synchronous=NORMAL` only when SQLite
  confirms WAL mode. Cache commits avoid per-entry syncs; SQLite still syncs
  checkpoints, and non-WAL fallback retains `FULL`. A system crash or power
  loss can roll back recent cache rows; files and sidecars remain
  authoritative, with their durability operations unchanged (#295).

### Measurement and validation

Fixed-workload profiling includes process startup. Timings depend on
filesystem, cache warmth and system load; syscall counts describe the
specific fixtures rather than a universal speed guarantee.

- Published 0.1.11 versus the optimized CLI on 6,000 entries reduces
  `trash status` calls from 72,431 to 36,180 (50% fewer), JSON listing from
  66,399 to 36,197 (45% fewer), and exact `trash info` lookup from 66,398
  to 191 (99.7% fewer), with identical command output.
- A long-lived process performing 50 unlinks and 50 empty-directory removals
  uses about 35% fewer calls when protected and 67% fewer when excluded.
  Explicit bypass retains its fast path; native controls are unchanged.
- Parsing 6,000 identical deletion timestamps reduces clock reads from
  6,003 to 4. Unique timestamps retain their original clock-read count.
- Exact lookup on 6,000 entries reads one sidecar instead of 6,000. Combined
  lookup and cache-maintenance changes reduce a single-file restore in the
  store harness from about 42,449 calls to 423.
- A 50-entry store-harness trash or empty workload makes 4 sync calls instead
  of 54. Read-only startup performs no SQLite page writes or locking.
- One hundred log appends reduce calls from 1,116 to 819; one hundred log
  tail reads reduce calls from 708 to 508 and make no seek calls.

Regressions cover mixed home/foreign stores, raw filenames and orphans,
replacement and permission changes, historical timezones and DST, fresh
local policies, forked sidecar PIDs, symlinked home paths, restore conflicts,
legacy cache preservation, and log privacy and malformed-file handling.
Destructive checks run in disposable filesystems.

`tests/syscall_bench.py` compares current and previous native CLI/shim/preload
artifacts in the same sandbox, verifies output and recovered payloads, and
emits JSON call counts after confirming external trash sentinels are intact.
It reports measurements without imposing machine-dependent timing gates.

Rust 1.99.1 and all dependency versions remain unchanged from 0.1.11, where
they were updated and verified current.

## 0.1.11 (2026-10-21)

This release fixes all 14 findings from the bug and performance bash
(#266–#279). It prevents malformed metadata from hanging commands, preserves
distinct Unix filenames during listing and repair, restores rm flag
compatibility, and reduces memory use and filesystem work in common paths.

### Data preservation and repair

- **Distinct non-UTF-8 filenames remain visible.** Trash listing tracks raw
  filename bytes, so names that produce the same replacement characters on
  screen no longer hide each other's orphaned data. A display ID matching
  multiple entries is rejected as ambiguous even within one trash root;
  unique original names still select individual entries (#267).
- **Repair confirmations apply to the exact file shown.** `trash fsck --fix`
  matches snapshots by raw filesystem path and constructs sidecar names
  without lossy conversion. Previously, confirming one orphan and declining
  another with a colliding display name could delete the declined file.
  Valid non-UTF-8 sidecars are no longer falsely reported as missing (#271).

### Commands stay responsive with malformed metadata

- **Trashinfo and directory-size metadata:** listing, repair and index
  rebuilding open `.trashinfo` without following symlinks or waiting for
  FIFO writers, then require a regular file before reading. Payloads with
  unusable sidecars remain discoverable as orphans. A FIFO `directorysizes`
  cache is ignored and can be replaced normally (#266).
- **Operation log:** a FIFO or other nonregular `operations.log` cannot hang
  `trash log` or a trash, restore or purge that has already changed the data.
  Log writes fail promptly, and a symlink log cannot redirect writes or
  permission changes to an unrelated file (#275).
- **Retention state:** `auto_purge.lock` and `last_purge` are opened without
  blocking on special files. Marker timestamps are updated through a
  validated descriptor; a symlink marker can no longer truncate its target.
  Existing contention handling and purge throttling remain in effect (#277).
- **Global and user configuration:** FIFO configuration files cannot hang
  CLI startup, configuration editing or the first preloaded deletion.
  Descriptor type checks preserve support for symlinked dotfiles; an
  unreadable configuration is refused by the editor instead of overwritten
  (#278).
- **Update-check cache:** a FIFO `last-update-check` record is ignored
  promptly, allowing `trash self-update --check` to proceed to its normal
  update check (#279).

### rm compatibility

- `rm -d` accepts regular files and symlinks as well as empty directories.
  Nonempty directories still require recursive removal. The same behavior
  applies to protected operands and paths excluded from trash (#268).
- Accepted abbreviations of the shim's custom bypass flags, such as
  `--perm` and `--no-t`, are removed before invoking the real rm (#272).
- Custom bypass flags also work when `TRASH_BYPASS=1` is set. Unknown or
  ambiguous options continue to reach the real rm on that bypass path, and
  arguments after `--`, including raw-byte filenames resembling options,
  remain literal operands (#276).

### Performance

- **Bounded log tails:** `trash log -n N` reads backward in chunks until it
  has the requested records. `-n 0` avoids reading the log. Chronological
  output, CRLF, unterminated final records and UTF-8 across chunk boundaries
  are preserved. Large histories no longer cause false empty results when
  whole-file allocation fails (#269).
- **One successful verification pass:** restore selects XXH3-128 or SHA-256
  from the stored digest format, avoiding an unnecessary second full-file
  scan. Existing digests remain valid after changing the configured
  algorithm, and corruption and unreadable-file warnings are retained
  (#274).
- **Less per-deletion procfs work:** preload obtains its current parent with
  `getppid()` instead of opening and parsing `/proc/self/stat` on every
  hook. Reparenting detection and periodic ancestry refresh remain intact
  (#270).
- **One pathname capture per seccomp notification:** display-path resolution
  reuses the captured bytes, removing a redundant broker round trip and
  remote-memory read while keeping display and mutation based on the same
  pathname capture (#273).
- **Less repair and retention work:** report-only fsck and clean repair
  checks skip unnecessary store snapshots; orphan repair uses direct path
  lookups instead of repeated linear searches (#271). A recent regular
  retention marker skips opening and locking the retention state file;
  due runs still acquire the lock and recheck the marker (#277).

Measured with isolated fixtures on the development host:

| Probe | Before | After |
| --- | --- | --- |
| One-record tail of a 179,200,062-byte log, debug peak RSS | 458,456 KiB | 6,568 KiB |
| Same tail under a 128 MiB address-space limit | Incorrect empty result | Correct latest record |
| Successful verification of an 8 MiB hashed file | 16 MiB read | 8 MiB read |
| `/proc/*/stat` opens for 100 preload unlinks | 102 | 2 |
| Report-only fsck of 500 valid entries | Repeated store enumeration | 500 sidecar reads, one per entry |

These fixtures measure specific memory and I/O costs. Runtime gains depend
on workload, storage and build profile. Corruption diagnostics can still
compute an additional digest, and requesting all log records requires
reading the full history.

### Toolchain, dependencies and release artifacts

- Rust is pinned to **1.99.1** for local builds, CI, dependency updates and
  releases. Source requirements and packaging metadata now agree.
- Refreshed all Cargo dependencies, including libc 0.2.191, zstd 0.14.3,
  zstd-safe 8.2.0, zstd-sys 2.1.2, rustls 0.23.46, rustls-webpki 0.103.16,
  webpki-roots 1.0.10, ureq-proto 0.6.5, cc 1.9.0, crc32fast 1.5.3,
  deranged 0.5.9, equivalent 1.0.3 and find-msvc-tools 0.1.15.
- Updated workflow dependencies to checkout v7, upload-artifact v7,
  download-artifact v8 and create-pull-request v8. Cross-builds use Zig
  0.17.0 with cargo-zigbuild 0.23.4.
- Linux x86_64 and aarch64 tarballs retain the **glibc 2.28** compatibility
  floor, SHA-256 checksum files and GitHub build attestations. Archives now
  include this changelog, and GitHub Actions publishes the version's full
  release notes alongside installation and verification instructions.

### Validation and upgrading

Regression coverage includes special metadata files, raw-name collisions,
repair consent, configuration symlinks, rm option forwarding, log line and
chunk boundaries, bounded log I/O, both digest formats, and retention
locking and throttling. Validation covers workspace tests, formatting,
Clippy with warnings denied, release builds, installer and CLI/preload
sandboxes, and protected seccomp interception under Yama restrictions in CI.

Existing trash entries and metadata formats remain supported; no store
migration is required. Upgrade all components together. Restart long-lived
processes to load the updated preload library.

## 0.1.10 (2026-10-12)

### Fixed

- All 24 bugs from the post-0.1.9 audit (#229, #243–#265), including a
  cross-device trash that could permanently destroy both copies of a file
  when a purge raced it (#243), a preload process-bypass verdict cached
  for a process's whole lifetime (#249), and partial trees left behind by
  failed cross-device copies (#244). Every fix ships with a regression
  test; the full list is in the commit history and the closed issues.

### Changed

- Rust toolchain updated to 1.99.0 (latest stable) and all dependencies
  updated to their latest releases (clap 4.6.7, chrono 0.4.45, rusqlite
  0.40.2, ureq 3.4.2, zstd 0.14.2, and the rest). CI's Clippy gate now
  passes with `--all-targets`.

## 0.1.9 (2026-10-03)

### Fixed

- The rm shim resolves a trailing-slash symlink operand (`rm -rf link/`) to
  the directory it actually removes. Policy was checked on the link's own
  location while deletion went through it, so a link in never-trash `/tmp`
  permanently deleted its target, and a link to `/` passed the lexical
  preserve-root check. Preserve-root now compares device and inode like GNU
  rm (#190).
- Releases are built against a glibc 2.28 floor (`cargo zigbuild`), CI and
  release fail when an artifact needs newer glibc symbols, and `install.sh`
  test-loads the preload and every binary before changing anything. The
  preload previously required GLIBC_2.34, which would stop every program on
  older distributions once registered in `/etc/ld.so.preload` (#191).
- Cross-device trashing copies through pinned descriptors and retires only
  what it copied: files created or changed during the move, a tree or file
  replaced meanwhile, and nodes the copy cannot reproduce (sockets, devices)
  were permanently deleted by the path-based cleanup (#192). Copies are
  synced before the source is removed, keep their owner (set-id bits are
  dropped when the owner cannot be preserved, #203), and are only attempted
  for `EXDEV`/unsupported `RENAME_NOREPLACE`, never for permission errors
  that left stray duplicates (#204).
- Retention never trusts a topdir sidecar's `X-Trashd-Size` beyond the tree
  actually on disk, and size sums saturate: one forged entry on removable
  media made auto-purge empty every trash root (#193).
- The preload lets the real delete run when no trash can be created (service
  accounts with a missing or root-owned home) instead of failing with
  `EACCES`; root with another user's `HOME` uses its own home trash (#194).
- Under trashd-exec, relative paths that escape the cwd resolve normally for
  targets sharing the supervisor's root mount and mount namespace, trashes
  on other filesystems (or without `RENAME_NOREPLACE`) are filled by copying,
  and trashd's own CLI and shim are never intercepted. These deletes used to
  be handed back to the kernel and became permanent because the preload had
  deferred (#195).
- A failed cross-device restore removes its partial destination with a raw
  syscall: through the hooked libc wrapper the preload trashed it or blocked
  on the trash-root lock the restore was holding (#196).
- The fanotify daemon no longer keeps a descriptor open on every watched
  mount, which made `umount` fail with `EBUSY` (#197), and resolves file
  handles through a regular directory descriptor: current kernels reject
  `O_PATH` mount descriptors, leaving every audited path unresolved (#240).
- A per-directory `.trashd.toml` only counts when it is a regular file owned
  by the deleting user or root that no one else can write; it is read without
  following symlinks or blocking, and diagnostics never echo its content. The
  root daemon never reads per-directory files: a symlink to `/etc/shadow`
  leaked through parse errors into the journal (#198, #207).
- `trash self-update` refuses prefixes other users can modify and
  package-managed `/usr` instead of installing system-wide there (#199).
- The login hook re-execs the running shell, and only after `trashd-exec
  --version` succeeds: an empty or stale `SHELL` (docker exec, `env -i`)
  ended every root login (#200). `trashd-exec --version` is answered instead
  of being run as a command (#234).
- Disk-pressure retention only purges entries at least an hour old: every run
  purged at least one entry, even the one an `rm` had just trashed (#201).
- Auto-compression only touches trashd's own entries (other tools' entries
  stay readable to them), skips files with extended attributes, keeps
  timestamps, and changes a sidecar only by its `X-Trashd-Compressed` line.
  Writing back the listed metadata turned relative topdir `Path=` values
  absolute and broke restore after a remount (#202, #218).
- The preload only copies on `EXDEV` (or unsupported `RENAME_NOREPLACE`) and
  removes its verified copy when the original cannot be unlinked; a retry
  loop over a read-only mount filled the trash with duplicates (#205).
- The preload no longer pins trash-root descriptors, which kept removable
  media busy, and never holds its lock across syscalls (#206).
- Preload diagnostics can no longer abort the host process (`eprintln!`
  panics on `EPIPE`) or raise `SIGPIPE` in it; the "config changed" note
  only appears with `TRASHD_PRELOAD_LOG=1` (#208).
- `restore`, `purge` and `info` match non-UTF-8 names byte for byte instead
  of through a lossy conversion that could select another entry (#209), and
  accept an entry's trashed path, which stays unique when two partitions hold
  the same ID (#210). `trash ls --json` reports it as `trashed_path`.
- `trash config add/remove only_trash` start from the inherited whitelist
  instead of silently replacing it, and `trash config edit` creates a fully
  commented template instead of pinning every default (#211).
- `trash fsck --fix` compares sidecar names byte for byte and leaves sidecars
  of in-flight trash operations alone; it deleted valid sidecars of
  non-UTF-8 entries (#212).
- The RPM spec packages the daemon binary and requires Rust 1.97 and
  systemd-rpm-macros; CI checks `%files` against `make install` (#213).
- `trash self-update` verifies the release's build attestation with
  `gh attestation verify` before running the installer as root, or requires
  `--allow-unverified` (#214).
- Uninstall removes per-user files as each home's owner and never through a
  symlinked component (#215), warns instead of aborting on files it cannot
  remove (read-only `/usr`, #241), and the installer no longer aborts where
  `systemctl` exists but systemd is not running (#216).
- `trash empty` purges exactly the entries its prompt showed (#217).
- A filesystem mounted at two paths (bind mounts) is listed and purged once,
  not once per mount point (#219).
- Concurrent processes no longer run the same auto-purge at once; a run in
  progress makes the others skip (#220).
- An unreadable trash root other than the home trash (a stale mount, a
  permission change) is skipped with a warning instead of failing `trash ls`
  for every root and aborting retention (#221).
- A home trash behind a symlinked ancestor owned by root or the user
  (ostree's `/home`, a stowed `~/.local`) is usable again; symlinks owned by
  other users are still refused (#222).
- A symlink operand is sized as the link, not as its target; the 10,000-entry
  size cap only flags trees that exceed it; and percent-decoding of `Path=`
  takes exactly two hex digits, keeping a stray `%` literal (#223).
- `bypass_processes` also matches script names such as `pip` or `npm`, whose
  executable is `python3` or `node` (#224).
- The preload retries under a fresh id when another FreeDesktop tool takes the
  trash name between the claim and the move; `unlink` failed with `EEXIST`,
  which callers never expect (#225).
- The seccomp supervisor judges `never_trash` and records `Path=` from the
  pinned parent directory, not from the spelling the program used: a path
  such as `/proc/self/cwd/x` matched `/proc/*` and was deleted permanently,
  or was recorded at the supervisor's own working directory (#226).
- `trashd-cleanup.timer` is installed by `install.sh`, `make install` and the
  RPM as a disabled per-user unit, for the install prefix. Its service passes
  `-y`: without it the prompt read `/dev/null` and nothing was purged (#227).
- The fanotify daemon no longer watches `FAN_DELETE_SELF`, which added a
  second, unresolvable record per delete; it reads event headers without
  assuming alignment, stops at a record that overruns the read, and skips
  FID records rather than letting them hide the name. With nothing markable
  it now waits for a filesystem instead of exiting into a `Restart=always`
  loop (#228).
- Uninstall removes only trashd's entries from `/etc/ld.so.preload`, keeping
  other libraries listed on the same line, and only the man pages it
  installed (a `trash-*.1` glob removed trash-cli's). `make install` no
  longer compiles (run `make` first, without sudo), `make uninstall` stops
  and disables the daemon, and the README no longer claims that packages
  register the preload (#229).
- `trash config` refuses to edit a config it cannot read instead of
  replacing it, writes atomically (through a symlinked config to its target),
  rejects values the next load would reject (integers above `i64::MAX`,
  non-finite or negative sizes, percentages above 100), and runs `$EDITOR`
  through the shell so it can carry arguments. Absolute times that a DST
  change repeats or skips are accepted, and `ls`, `find` and `info` escape
  control and bidi characters from sidecars (#230).
- After the original command exits, `trashd-exec` forwards hangups only to
  descendants still in its session, not to daemons that left it with
  `setsid()` (#231), and finds its children through `/proc/*/stat` on kernels
  without `CONFIG_PROC_CHILDREN` (#232).
- Desktop notifications are reaped on a background thread instead of leaving
  a zombie per delete in long-lived processes (#233).
- A failed seccomp filter install (as on every WSL root login) prints one
  line instead of three (#235).
- Releases compute their version once for every build leg (#236), the quick
  installer installs the release it was published with (#237), and the tag
  points at the built commit rather than wherever `main` is by then (#238).
  The weekly dependency update runs the sandboxed integration, preload and
  seccomp suites before opening its PR, and the PR text no longer claims CI
  ran on it (#239).
- `trashd-exec` no longer spins at 100% CPU (or hangs) when it inherits
  `SIGCHLD=SIG_IGN`, as root login shells do under WSL's `login`. The kernel
  reaped its children itself, leaving a permanently readable pidfd in the wait
  loop and the original exit status unobservable. The wrapper now waits with
  the default disposition, restores the inherited one for the command, and
  drops any target it can no longer reap (#184).
- Seccomp fallback (for example `EBUSY` from WSL's own notification listener)
  execs the command in place instead of keeping a resident wrapper. A terminal
  now closes on `exit` even while daemons the shell started keep running, and
  signals and exit status are native (#185).
- The seccomp supervisor, its passthrough mode and the watchdog's emergency
  passthrough exit once every filtered task has exited, instead of spinning on
  immediate `ENOENT` from the orphaned listener. The watchdog no longer
  respawns supervisors for a finished listener, and starts with an unblocked
  signal mask so teardown `SIGTERM` always reaches it (#186).
- The rm shim and `trash` CLI reset `SIGCHLD` to the default: an inherited
  `SIG_IGN` made the shim reject the genuine `rm` as a shim copy and made
  `trash config edit`/`self-update` report failure for successful children (#187).
- The fanotify daemon re-scans mounts at most once per second instead of after
  every drained batch of events (#188).
- The seccomp regression's setuid probe keeps the `id` basename so multi-call
  coreutils (uutils) can run it (#189).

## 0.1.8 (2026-09-30)

### Fixed

- Seccomp setup failures, including inherited-listener `EBUSY`, launch a fresh
  fallback process without carrying newly applied `NoNewPrivs`. Startup now
  checks memory and filesystem capabilities before releasing the command.
- Seccomp notifications from worker threads pin the correct task and directory
  descriptors; canceled notifications are rechecked before trash publication.
- Preload verifies a cookie-specific filter proof before deferring to seccomp,
  normalizes physical parent paths, authenticates actual trash roots, and lets
  the kernel reject invalid `unlinkat` flags without mutating files.
- A shared persistent store lock coordinates writers, fsck, restore, purge,
  retention, and compression. Operations revalidate entry identity and metadata
  before committing, protecting active reservations and reused IDs.
- Cross-device copies preserve complete recovery data when source cleanup fails,
  avoid nested interception deadlocks, and never merge into an existing entry.
- The rm shim implements GNU `--one-file-system` partial-removal behavior and
  rejects terminal-dot directory operands before path normalization.
- The disposable seccomp test sandbox uses an owned home for its unprivileged
  user and covers fallback privileges, threaded descriptors, and copy cleanup.

### Changed

- Automatic nonroot login shells use preload/shim to preserve sudo and setuid
  behavior. Root shell wrapping uses `--preserve-privileges`; explicit wrapping
  documents its normal `NoNewPrivs` restriction.
- All components must be upgraded together to share the store mutation lock.
  Existing trash metadata remains compatible; no migration is required.

Issues: #108, #128, #173–#183.

## 0.1.7 (2026-09-29)

Release from the 2026-09-29 analysis and remediation pass: 41 issues filed,
verified, and closed.

### Fixed — daemon

- Directory deletions are audited again: the fanotify marks were missing
  `FAN_ONDIR`, so the kernel dropped every event carrying FS_ISDIR and
  `rmdir`/`rm -rf` of directory-only trees logged nothing while the daemon
  reported healthy monitoring.
- One mount point with a non-UTF-8 byte no longer empties the entire mount
  list at startup (fatal crash-loop under systemd); `/proc/mounts` is parsed
  as raw bytes, matching the kernel's escaping rules.

### Fixed — preload

- glibc `remove()` is interposed directly: it calls the hidden
  `__unlink`/`__rmdir` aliases, which interposing `unlink`/`rmdir` cannot
  reach, so deletions through `remove()` bypassed the trash entirely.
- `/proc/mounts` parsing is byte-safe; a single odd mount point no longer
  silently loses the trash location for every filesystem.
- The preload's duplicated local-config walk stops at a present-but-broken
  `.trashd.toml` like the common crate, instead of inheriting an ancestor's
  narrower whitelist and permanently deleting.

### Fixed — trash store and restore

- `trash_at` persists the post-move identity refresh (size/hash drop) to the
  `.trashinfo` sidecar, so a raced entry no longer carries a stale hash that
  warns on every restore; the recursive directory size keeps its pre-move
  value in listings.
- A failed `mkfifo` during a cross-device FIFO trash now aborts the move
  before the source is removed, instead of reporting success with no data
  file (also in directory copies).
- Pattern-filtered listings no longer re-synthesize a filtered-out entry's
  own data file as a fake "orphaned" copy, and `trash restore <id> --all`
  no longer fails on healthy entries with the "run fsck" advice.
- `trash compress` refuses entries larger than restore's decompression bound
  (min(`max_file_size_mb`, 4 GiB)), so compressed entries can no longer
  become permanently unrestorable.

### Fixed — config and logging

- A present-but-broken `.trashd.toml` warns and applies no local policy
  instead of silently inheriting an ancestor's narrower whitelist (which
  could turn "trash it" into a real delete).
- Legacy `[retention]` promotion prints a note per applied key: a misplaced
  policy key is applied compatibly but never silently, restoring the loud
  rejection an earlier release intended.
- Operation-log fields are escaped like the daemon log, so filenames
  containing newlines cannot forge log records.

### Fixed — CLI

- `trash config set/add/remove` refuse to rewrite the user config when the
  existing file does not parse, instead of silently discarding every
  pre-existing setting; a scalar `retention` key errors instead of
  panicking.
- `trash ls --after/--before` accept the documented minute-precision form
  (`2026-03-20T14:00`).
- `trash empty` propagates listing errors instead of printing "Nothing to
  empty." and exiting 0 when nothing could be listed.
- `trash info` resolves targets through `find_entry`, refusing ambiguous
  cross-root IDs exactly like restore/purge, and surfaces listing errors
  instead of reporting "not found".

### Fixed — shim (rm)

- `rm -d` on a non-directory fails with "Not a directory" like GNU rm
  instead of silently trashing the file, and an excluded empty directory
  falls back to rmdir semantics.

### Fixed — seccomp layer

- The watchdog closes the same fork→prctl race the supervisor guard covers:
  an orchestrator killed in the window no longer leaves an orphaned
  watchdog+supervisor pair holding the notification fd forever.

### Fixed — install and packaging

- The release workflow reuses the build job's version instead of
  recomputing a date-based one, so a UTC-midnight straddle can no longer
  publish a release whose quick installer requests nonexistent assets.
- `make test` and the PKGBUILD `check()` run under `TRASH_BYPASS=1`.
- The RPM spec passes `PREFIX=%{_prefix}` to `%make_install` (files staged
  under /usr/local previously failed the %files match) and both packaging
  specs track the current version.
- The RPM spec can build again: `make install` stages the systemd unit to
  UNITDIR (`/usr/lib/systemd/system`), matching the spec's `%{_unitdir}`
  `%files` entry.
- `make install` matches install.sh's daemon layout (LIBDIR + BINDIR
  symlink), templates the unit's `ExecStart` for the actual prefix (no more
  `status=203/EXEC` on make/PKGBUILD/custom-prefix installs), and registers
  the LD_PRELOAD layer on native installs.
- `make install` no longer resets an existing `/etc/trashd/config.toml`,
  and the PKGBUILD marks it `backup=()`.
- `make uninstall` removes the `/etc/ld.so.preload` registration before
  deleting the `.so`, so a Makefile-only install/uninstall cycle no longer
  leaves every dynamic process printing an ld.so error.
- `TRASHD_VERSION` is read at build-script runtime and tracked, so rebuilds
  in an existing target dir pick up version changes; the shim and daemon
  print the same release version as the CLI.
- install.sh honors `PREFIX` for fish completions, and `--uninstall`
  removes completions from the Makefile/system locations too.

### Fixed — CLI (continued)

- `trash config`, `trash log`, and `trash self-update` no longer open the
  trash store first: read-only commands no longer fail on a broken or
  foreign-uid trash home, create the trash tree as a side effect, or break
  the recovery path `trash self-update`.
- `trash self-update` never silently orders cross-scheme version strings
  (a semver release after a date-based release read as "up to date"), and
  the tarball download gets its own 15-minute budget instead of the API
  call's 30-second global timeout.
- `trash fsck` checks every trash root (per-partition corruption previously
  got a false all-clear) and reports `--fix` removal failures instead of an
  unconditional "removed"; the index rebuild stays home-only, matching the
  one index the store actually serves.
- `trash restore --force` builds conflict siblings from a normalized base,
  so a trailing-slash `--to backup/` yields `backup.1`, not a hidden
  `backup/.1` inside the directory.

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
- Restore and the compressors serialize on an entry flock: a compressor can
  no longer swap zstd bytes into restore's publish window (which published
  compressed bytes as the restored file), and a purge can no longer strip
  the sidecar of an in-flight trash — young data-absent sidecars get a
  grace window and a completed move re-ensures its sidecar.
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
