# Changelog

## 0.1.15 (2026-11-20)

Security and robustness release from the 2026-11-20 audit (#441–#556) and
the remaining open issues (#402–#439). Every store change now goes through
directory descriptors its lock validated, a busy trash fails a delete
instead of waiting forever, and seccomp's protected mode has full CI
coverage. Install the wrapper and preload from the same release and
restart existing wrapped sessions.

### Changed

- Automatic zstd compression during retention is opt-in
  (`retention.auto_compress`, default `false`). GNOME Files, Dolphin and
  other spec implementations restore an entry's stored bytes as they
  are, so an auto-compressed entry came back from them as zstd data.
  `trash compress` and `trash restore` are unchanged. (#538)

- The preload limits each file by `max_file_size_mb` alone, as the shim
  and the supervisor do; `max_dir_size_mb` bounds directories. A
  standalone file between the two caps was deleted for real by the
  preload and trashed by the other layers. A tree removed through the
  preload is therefore trashed file by file even when it exceeds
  `max_dir_size_mb`; the #412 entry above overstated what its per-file
  check did. (#454, #548, #487)

- Automatic retention no longer stats network or FUSE mounts (NFS,
  CIFS/SMB, 9p, sshfs and the like). A dead server or an unresponsive
  FUSE daemon hung `rm` and every delete in a wrapped root session.
  `trash ls`, `trash empty` and `trash status` still include those
  trashes. (#511)

### Performance

- The recorded deleting command in each `.trashinfo` is capped at 256
  bytes on write and on parse. A batch `rm` of 1,000 files previously
  copied the full argv into every sidecar (43 MB of sidecars for 2 KB of
  payload, and ~48 MB RSS to list them); it now writes ~0.5 MB total.
- Age-based purge (`trash empty --older`, auto-purge) filters entries
  from their sidecars before statting data inodes, so a mostly-young
  trash no longer pays a stat and a retained entry per file.
- Mount-table reads are cached per thread for one second (keyed by
  mount-namespace identity); the fanotify daemon keeps uncached reads
  for its own change detection.
- `trash du` partitions for its top-N rows in O(N) instead of sorting
  every entry; `trash log` and shim `-v` output are buffered instead of
  one write syscall per entry; hashing uses a 64 KiB buffer.
- The seccomp supervisor samples config mtimes at most every 250 ms
  (was two stats per trapped delete) and keys them at nanosecond
  resolution, so same-second config edits are no longer missed.
- Release builds strip symbols and use thin LTO with one codegen unit:
  installed binaries and the preload library shrink 25–36%.

- `rm -r` of a directory that a `never_trash` pattern excludes along
  with everything below it (`/tmp/*`, `*/node_modules`) deletes the tree
  in one pass again, as before the per-entry sweep for excluded
  directories: 20,200 entries in about 0.2 s instead of 0.8 to 1.9 s.
  Exclusions that name only the directory itself (`*~`, an `only_trash`
  miss) are still swept entry by entry. (#448, #553)

### Fixed

- The preload's permission grant for an unreadable empty directory
  (#410) also checks that the name still holds a directory, not only
  the same device and inode number: ext4 can hand a removed directory's
  inode number straight to a symlink created in its place, and the
  delete then failed with `EACCES` instead of reaching the kernel.

- Restore's move out of `files/`, `trash compress`'s marker and data
  publication, and the `directorysizes` cache (read, rebuild and the
  per-directory record) also go through the descriptors the trash lock
  validated. They were the last store mutations still reached by path,
  so a FUSE or NFS server could still swap `files/` or `info/` for a
  symlink after the lock's check. (#508 follow-up)

- `tests/packaging_lint.py` checks the Makefile's man page list against
  the pages `build.rs` generates, and the install regression covers a
  `PREFIX` with a space or a tab; #424 and #425 had no direct test.

- The shim honors `--preserve-root`/`--no-preserve-root` in command-line
  order (the last flag wins, as in GNU rm) and refuses abbreviated
  `--no-preserve-root` spellings that GNU rejects. (#430, #431)
- The shim prompts before removing a write-protected file the way GNU rm
  does when prompting is enabled and `-f` is absent, accepts GNU
  `--interactive` synonyms and unambiguous abbreviations (`no`, `none`,
  `yes`, `al`, …), diagnoses an empty-string operand without aborting the
  remaining operands, prints one `removed …` line per entry to stdout under
  `-v`, and no longer panics with exit 101 when stderr or the prompt cannot
  be written (a full `/dev/full` no longer turns a completed trash into a
  reported failure). (#432, #433, #434, #435, #436)
- An empty `only_trash` pattern is dropped at load time with a loud
  warning; the whitelist `[""]` previously matched nothing and made every
  deletion permanent. (#402)
- A trash root whose `info/` directory is missing no longer reads as an
  empty store: its stranded `files/` data is listed as orphans and can be
  purged by `trash empty`. (#403)
- Orphaned entries age by the data file's mtime instead of a synthetic
  "now" deletion date, so age-based retention and `empty --older` can
  retire them. (#404)
- `trash empty` exits non-zero when a selected entry cannot be deleted,
  instead of printing "Nothing to empty." and reporting success to scripts
  and timers. Already-vanished entries still count as success. (#409)
- First-occurrence-wins in `.trashinfo` parsing holds even when the first
  duplicate value is malformed: a later well-formed duplicate can no
  longer slip in a size, deletion date, PID or nanosecond stamp. (#413)
- A directory replaced between metadata read and rename is re-surveyed on
  the seccomp trash path, so the sidecar records the tree's real size
  instead of the replacement inode's ~4 KiB. (#414)
- `compress --dry-run` applies the same keep/discard decision as the real
  run (through the same code path), so incompressible files are no longer
  reported as "would be compressed". (#415)
- `trash undo` escapes control characters in restored paths, matching
  `trash restore`, so trashed filenames cannot inject terminal escape
  sequences. (#416)
- `trash ls` with a pattern or date filter that matches nothing now says
  so instead of "Trash is empty."; the unfiltered message is unchanged.
  (#417)
- `self-update` ignores a relative `XDG_CACHE_HOME` (as the XDG spec
  requires) instead of creating the marker directory under the current
  working directory. (#418)
- `trash config add` accepts literal values for `bypass_paths` and
  `bypass_processes` (they are prefix/exact matched, not globs) while
  still rejecting brace patterns in the glob lists and empty values
  everywhere. (#419)
- The preload's cross-device copy preserves timestamps, `user.*` xattrs
  and sparseness (SEEK_DATA/SEEK_HOLE), matching the store's own copy, so
  restored files keep their metadata and large sparse files no longer
  expand on the trash filesystem. (#405)
- `rmdir`/`unlinkat(AT_REMOVEDIR)` of an unreadable empty directory is no
  longer declined into permanent deletion, in both the preload and the
  seccomp supervisor: an owned target is scanned under a temporary
  read/write grant that is restored afterwards, and only a
  positively-confirmed empty directory is trashed — a non-empty one
  answers `ENOTEMPTY` with its contents untouched. (#410, #411)
- The preload enforces `max_dir_size_mb`/`max_file_size_mb` on every
  intercepted deletion with exact byte comparison (no integer
  truncation), so oversized trees cannot sneak past the cap during
  `rm -rf`. (#412)
- The seccomp supervisor reloads its configuration (and store) when the
  config file changes mid-session, matching the preload's mtime-based
  reload, so long-lived wrapped sessions see config edits. (#437)
- Isolated stores (`TrashStore::open_isolated`) refuse to purge or empty
  entries resolved in another store's trash root, the same boundary
  restore already enforced; retention over roots given explicitly still
  crosses roots. (#428)
- Directory trees nested deeper than the old 100-level survey cap are
  recorded with their real size — the survey walk is now iterative and
  self-limits by the descriptor limit instead of a depth cap. (#429)
- The fanotify daemon strips the kernel's ` (deleted)` marker from
  resolved audit paths and no longer poisons its handle cache when a
  process holds a deleted directory open. (#438)
- The operation log rotates at 1 MiB, keeping one previous generation
  (`operations.log.1`); `trash log` reads across the rotation boundary.
  (#439)
- Install/packaging: bash completions fall back to the PREFIX completions
  directory when `/etc/bash_completion.d` does not exist; the fanotify
  unit installs whenever `/etc/systemd` exists (only enable/start needs a
  running systemd); RPM `%post`/`%postun` and Arch
  `post_install`/`post_remove` hooks now register and unregister the
  LD_PRELOAD entry; preload registration switches between flat and `$LIB`
  entry forms instead of freezing the first one; installers refuse
  PREFIX/path values containing whitespace or colons; the profile hook
  and every `make install`/`uninstall` destination are quoted against
  spaces; `make uninstall` removes the full fixed man-page set even after
  `make clean`; the daemon unit wants `multi-user.target` (with legacy
  `default.target.wants` links cleaned) so uninstalls stop both
  uninstallers' symlink removal; uninstall sweeps user-enabled timer
  symlinks per home; and uninstall/purge enumerate homes from
  `getent passwd` instead of only `/home/*` and `/root`.
  (#406, #407, #408, #420, #421, #422, #423, #424, #425, #426, #427)

- Retention no longer purges an entry published while a listing ran
  between its `info/` and `files/` passes. The entry looked like an
  orphan dated by its data's old mtime, and auto-purge deleted it along
  with its valid sidecar. Orphans now age from their arrival in `files/`
  (`max(mtime, ctime)`), the orphan pass skips data whose sidecar parses
  by then, and a purge under the root lock refuses an orphan whose
  sidecar parses. Entries torn by a crash are kept the same way. (#534,
  #554, #522)

- Legacy sidecars larger than the 64 KiB read cap (a full argv in
  `X-Trashd-Command`) are read line by line with the command capped, so
  they keep their real path and date instead of turning their data into
  an orphan that retention purged. A sidecar that still cannot be parsed
  keeps its data listed, and neither retention nor `empty --older`
  purges it. (#556)

- An operand larger than `retention.max_size_gb` whose trash is on the
  home filesystem is refused (`rm` keeps it; use `rm --permanent`).
  Before, it was trashed and size trimming then purged every older entry
  to make room. Trimming purges only entries at least an hour old,
  leaves an entry larger than the whole cap out of the excess, and
  purges nothing when the eligible entries cannot bring the trash under
  the cap. (#519)

- Size trimming counts and purges only trashes on the home filesystem,
  measures other trashes by allocated size, and orders future
  `DeletionDate`s as now, so a sparse file or a forged date on removable
  media can no longer empty the home trash. Cross-device trashing
  fdatasyncs the new sidecar and fsyncs `info/` before retiring the
  source, where the trash copy becomes the only copy. (#520, #522)

- install.sh and `make install` put the optional i686 preload where this
  host's loaders actually expand `$LIB` (as `ld.so --list-diagnostics`
  reports it, glibc 2.33+) and register the `$LIB` entry only then;
  everywhere else they register the 64-bit library alone. The fixed
  `lib64/` + `lib/` layout could not be resolved on Debian/Ubuntu
  (`lib/<triplet>`) and loaded the wrong ELF class on Arch, so every
  process printed a preload error and ran without Layer 2. A `$LIB`
  entry that does not load cleanly after registration is replaced by the
  flat entry, and stale per-ABI trees are deleted only after no entry
  names them. (#469, #550, #470, #406)

- install.sh and `make install` set umask 022 and create the trashd tree
  and `/etc/trashd` with mode 0755, so `/etc/ld.so.preload` is left at
  0644 even when sudo carries a hardened 027/077 umask. The package
  scriptlets also chmod the list after registering. Before this, an
  unreadable list or tree silently turned off Layers 1 and 2 for every
  non-root user. (#473)

- The Arch package ships its scriptlets in `packaging/trashd.install`
  (`install=` in the PKGBUILD). pacman never ran the functions written
  into the PKGBUILD, so the package never registered the preload. Both
  packages now drop the entry before their files are erased (RPM
  `%preun` on erase, Arch `pre_remove`) instead of afterwards, when it
  already named a deleted library. (#474, #549, #477, #551,
  #408)

- `make install` probes the built preload and binaries with the host's
  loader before copying anything, as install.sh does (#191). A preload
  built against a newer glibc than the host's no longer reaches
  `/etc/ld.so.preload`, where it would stop every dynamically linked
  program. Its `/etc/ld.so.preload` rewrites are single `&&` chains: a
  failed awk no longer replaces the list with a partial copy, and
  uninstall stops before deleting a library that is still registered.
  (#475, #471)

- The root login hook no longer wraps a shell given a `-c` command, or a
  non-login interactive shell. `bash -lic 'cmd'` used to discard `cmd`
  and exit 0 (or run its stdin as root commands), and Fedora's
  `/etc/bashrc` turned every interactive root bash into a login shell. A
  busybox login shell is re-executed as `busybox sh -l`; `busybox -l`
  failed with "applet not found" and ended the login. (#476, #472)

- install.sh and the Makefile refuse a `PREFIX` containing a backslash.
  `awk -v` unescaped it, so reinstalls duplicated the entry and
  uninstall left it naming a deleted library. (#480)

- Source installs stage the build under `$TMPDIR` instead of a hardcoded
  `/tmp`. They stop with a clear message before any change if the stage
  is mounted `noexec`, and as root they accept only a `TMPDIR` that
  nobody but root can modify. (#479)

- `trash self-update` run as root starts the installer with a cleared
  environment and always an explicit, validated `PREFIX`. Before, a
  `PREFIX` inherited through `su` or `sudo -E` decided where root
  installed the library every process loads, bypassing the
  root-owned-prefix check (#199). (#441)

- The fanotify daemon exits with status 78 when fanotify cannot run at
  all (kernel older than 5.9, no `CAP_SYS_ADMIN`, or no fanotify). The
  unit's `RestartPreventExitStatus=78` stops `Restart=always` from
  relaunching it every 5 seconds forever. (#464)

- The daemon unit raises journald's per-unit rate limit from 10,000 to
  100,000 lines per 30 s, because one large `rm -rf` dropped most of its
  DELETE audit lines. The limit stays finite so local users cannot flood
  the journal. (#461)

- The release workflow builds with a read-only token that is not
  persisted into `.git/config`. Provenance is attested in a separate job
  that runs no build code, and only the release job, which builds
  nothing, can write releases and tags. CI's checkout no longer persists
  its token either. (#478)

- The shim asks about a write-protected file only when stdin is a
  terminal and `-f` is not in effect, as GNU rm and POSIX do: `xargs rm`
  and `while read` loops no longer keep read-only files with exit 0 or
  swallow the caller's piped input; `-i` still asks without a terminal.
  (#512)

- The shim decides "write-protected" with the kernel's own check
  (`faccessat(W_OK, AT_EACCESS)`), like GNU rm: files writable through a
  supplementary group or an ACL are no longer asked about, and a file
  whose group bits deny the user is. (#513)

- `rm -d` of a directory the user cannot list, and the last step of a
  walk over an excluded directory, remove with rmdir(2) only: a regular
  file swapped in meanwhile is refused with "Not a directory" instead of
  being permanently unlinked. (#514)

- Passthrough (`--permanent`, `TRASH_BYPASS=1`, bypassed callers,
  `--help`) runs the real rm as `rm`, so GNU's usage lines, `Try 'rm
  --help'` hints and `-i` prompts no longer show the internal stash
  path. (#515)

- `--preserve-root=all` is no longer dropped by a later plain
  `--preserve-root` (an alias plus an explicit flag): mount-point
  operands stay refused instead of being emptied into the trash. (#516)

- `rm -ri` no longer refuses trees of more than 256 directories after
  every question was answered: the walk raises its soft open-file limit
  toward the hard limit (up to 65536, about 21,800 directories) while it
  plans, and restores it before spawning anything. (#517)

- `rm -f` of a file that another process removes while the shim is
  trashing it exits 0 silently, and plain `rm` reports GNU's "No such
  file or directory"; neither prints the misleading "refusing permanent
  removal; use --permanent" hint any more. (#518)

- The shim no longer deletes a directory tree for real because of the
  directory's own name. A directory excluded by an `only_trash` miss
  (`rm -r src` with `only_trash = ["src/*"]`, any project directory with
  `only_trash = ["*.rs"]`) or by a `never_trash` suffix (`rm -rf
  thesis~`, `export.tmp/`) is emptied entry by entry: entries that may
  be trashed are trashed, entries excluded themselves are deleted for
  real, and the emptied directories are removed, as `rm -ri`, the
  preload and the supervisor already judged each entry. Whitelisted
  files inside were destroyed with exit 0. The store now says why it
  excludes a path (`TrashError::Excluded { path, kind }`). (#448, #553,
  #544)

- The preload drops an empty `only_trash` pattern like the other layers:
  the #402 fix had not reached it, so `only_trash = [""]` still made
  every delete it handled permanent. Both layers now share one set of
  pattern rules. (#455, #547)

- Patterns written for a directory or relative to `.` are normalized at
  load time and by `trash config add`: `src/` means `src/*`, and
  `./build/*` means `build/*`. Patterns that can never match a path
  (`a//b`, `a/./b`) and `/` or `~/` on their own are rejected with a
  warning; as a whitelist's only entry such a pattern made every delete
  permanent. (#450)

- `~/` patterns match the home directory both as written and with its
  symlinks resolved. With a home reached through a symlink, `only_trash
  = ["~/projects/*"]` matched nothing and every delete was permanent.
  (#451)

- Without any configuration directory (no usable `XDG_CONFIG_HOME` or
  `HOME` and no passwd entry), the user config is no longer read from or
  written to `./~/.config/trashd/config.toml` under the current
  directory. (#452)

- A config value of the wrong type drops only that key, with a warning,
  in trashd-common and the preload alike. trashd-common used to drop the
  whole layer over a key the preload does not read (`sha256_max_size_mb
  = 0.5`), so the layers ran different policies. (#460)

- Trash ids fit the trash filesystem's own name limit (143 bytes on
  eCryptfs, not an assumed 255), and a name the filesystem still refuses
  as too long is claimed again shorter. The preload turned that refusal
  into a permanent delete. (#459)

- The shim and the preload use a mount's topdir trash only for files on
  that mount's own filesystem, as the supervisor already did. A file in
  a nested btrfs subvolume went to a topdir trash that `trash ls`,
  `restore`, `undo` and retention never list. (#456)

- `bypass_paths` is matched against the program that ran `rm`, not
  against the shim itself: a prefix covering trashd's install directory
  (`/usr/local/`) made every shim delete permanent. (#457)

- A recursive removal of an ancestor of the trash no longer destroys it.
  Once a process has trashed into a trash, the preload refuses (`EBUSY`)
  to delete anything in that trash for real, so `rm -rf ~/.local/share`
  keeps both the entries it just moved there and the older ones. The
  supervisor answers `EBUSY` for the trash root, its `files/` and
  `info/`, and their ancestors instead of letting the kernel delete
  them. The store refuses the trash and its ancestors even where policy
  excludes them (`rm -rf ~/.local` under a whitelist). Emptying tools
  run as their own processes and keep working. (#458)

- A `trash empty`, `purge` or `restore`, or a cross-device `rm`, inside
  a `trashd-exec` session no longer hangs the whole session when another
  process deletes a file at the same time. These operations unlinked
  while holding the trash root lock, and each unlink traps into the
  session's supervisor, which may itself be waiting for that lock. Purge
  and restore now move data and sidecars into the root's private state
  directory under the lock and delete them after releasing it. Restore
  copies across filesystems, and both copy fallbacks retire their
  source, without the root lock; an entry lock keeps purges away from
  the fresh copy. A long cross-device restore no longer holds every
  trash writer of the user. (#521, #539)

- A file another process held an `flock` on when it was deleted no
  longer blocks trashd forever. `trash purge`, `empty`, `restore` and
  `compress` (including `--dry-run`) wait up to 5 seconds for the entry
  and then report it busy, and retention skips it until its next pass.
  In a seccomp supervisor, retention stalled every delete of the session
  behind such an entry. (#526, #447)

- The operation log caps the recorded command at 256 bytes, as sidecars
  do. The shim records its whole argv for every operand, so one `rm` of
  thousands of files wrote gigabytes of log under the root lock, and its
  rotations erased all earlier history. Trash records are now written
  after the root lock is released. (#536)

- Log rotation retires only the log it measured. It runs under a lock on
  the log, and a writer whose log another writer already rotated appends
  to the new one. Before, it renamed the new log over
  `operations.log.1`, deleting the previous generation and losing its
  own record. (#541)

- `trash empty` no longer fails with "deletion jobs still need cleanup"
  when its sweep of detached deletion jobs races another process still
  removing the same tree. A directory the other remover deleted first
  counts as removed. (#535)

- Error messages and `trash compress --dry-run` lines escape control
  characters in recorded paths and trash IDs, as listings already did. A
  crafted `.trashinfo` on removable media (`Path=...%1B]52;...%07`)
  could write to the clipboard or rewrite the screen through `trash
  restore`, `undo`, `purge` or `empty` errors; the store's restore,
  purge and empty warnings are escaped too. (#442)

- `trash empty` exits non-zero when a confirmed entry changed while the
  prompt waited (it was compressed, or its sidecar was rewritten or
  touched). Such an entry was counted as already gone; it is kept and
  reported. An ID reused by a different entry still counts as gone.
  (#523, #543)

- `trash compress` exits non-zero when every compression attempt failed
  (for example an unwritable state directory or a full disk), instead of
  printing "Nothing to compress." and exiting 0; partial failures end
  with a count of the items that could not be compressed. (#443)

- `trash compress --dry-run` measures the compressed size without
  writing a full compressed copy of each candidate into the trash's
  state directory, so it needs no free space or write access there and
  leaves nothing behind when interrupted. (#490)

- `trash config set/add/remove` edit the file in place and keep
  comments, blank lines and key order, including the commented template
  `trash config edit` seeds; they previously rewrote the file from a
  parsed table and dropped them all. Settings promoted from a legacy
  `[retention]` table move with their comments. (#446)

- The audit daemon names btrfs subvolume mounts it cannot monitor in one
  prominent warning, and its status line reports them as not monitored.
  The kernel refuses whole-filesystem fanotify marks on subvolumes
  (`EXDEV`), and the default `/` and `/home` on Fedora, openSUSE and
  Ubuntu-on-btrfs are subvolumes; the other layers still protect them.
  (#463)

- The audit daemon keeps every directory it learned from one read until
  that read's deletions are logged. When a read carried more removed
  directories than the 4,096-entry cache holds, the outermost were
  evicted first and their entries were logged as bare names. (#468)

- A trash root is changed only through the directory descriptors its
  lock validated: `files/`, `info/` and `.trashd/` are opened without
  following a symlink, must be owned by the user with mode 0700 and must
  be on the root's own device. Entry validation, the entry lock, purge,
  restore's sidecar removal, new-entry claims, renames, cross-device
  copies and sidecar rewrites all go through them, and topdir trashes
  are listed through the same kind of descriptor. A FUSE or NFS server
  could answer `files` with a private directory for the lock's check and
  with a symlink to `/etc` for every later lookup. Routine retention
  running as root then purged files there, and a root delete on such a
  mount published its copy in `/etc/sudoers.d`. (#508, #509)

- Another user's FUSE mount (its `user_id=` mount option is not the
  caller's, or is missing) never holds a topdir trash: neither the store
  nor the preload probes or selects one there, and deletes on it are
  copied to the home trash. A regular file copied off a `nosuid`
  filesystem keeps no set-id bits, file capabilities or `trusted.*`
  attributes. (#508, #509)

- Repairing a trash directory's mode (store, mount discovery and the
  preload) goes through a descriptor of the directory just checked. It
  used chmod(2) of the path, which followed a symlink swapped in after
  the check and could chmod `/` or a setuid binary to 0700. (#510)

- Purge opens up a directory lacking u+rwx only through a pinned
  descriptor of the directory it statted. Its path-following retry
  chmodded whatever a racing process had swapped in, such as
  `/etc/passwd`, to 0700. (#528)

- The fanotify daemon never marks or statfs's FUSE filesystems. Their
  marks always fail, but only after the kernel has asked the server for
  statfs, and a hostile or dead server never answers, which stalled the
  daemon. Its startup resolution list now comes from the mounts it
  marked rather than a statfs of every mount. (#462)

- When two mounted filesystems share an fsid (a cloned or snapshotted
  ext4 keeps its UUID), the daemon no longer decodes deletion handles on
  whichever one sorted first, which could log a path on the wrong
  filesystem or stop at its ESTALE. Such deletions are logged by file
  name only, after one warning naming the fsid. (#466)

- trashd-exec's workers ignore SIGTERM like the other job signals and
  are torn down with SIGKILL. A process-group SIGTERM (bash `kill %1`,
  GNU `timeout`, a systemd stop) ended both workers while the command
  ran its cleanup, whose deletes then failed with ENOSYS. (#493)

- trashd-exec no longer forwards a signal that a member of the command's
  own process group sent to the whole group (`kill 0`, `trap 'kill 0'
  EXIT`). The command received it twice, which many tools take as "force
  quit". A group signal sent from outside the job still cannot be told
  from one sent to the wrapper alone. (#498)

- A wrapped root login no longer hangs `exit` (ssh, `sudo -i`, `su -`)
  while a setsid daemon it started (tmux, ssh-agent, gpg-agent, a SysV
  service) is alive. A keeper process reports the command's status once
  only descendants outside the session remain, and keeps protecting them
  until they exit. (#495)

- 32-bit programs (i386 and x32 on x86-64, AArch32 on aarch64) run under
  trashd-exec; every one of their syscalls used to fail with ENOSYS.
  Only their deletes, io_uring and landlock_restrict_self calls are
  refused. (#496)

- The seccomp supervisor no longer hangs on a lost broker reply.
  Requests carry no descriptor (an orchestrator at its descriptor limit
  could not receive one), replies are matched by request id, and a
  request times out after 5 seconds. (#494)

- Watchdog failover hands queued deletes to the replacement supervisor
  instead of continuing them, which was a permanent delete for static
  and raw-syscall callers. Only repeated rapid supervisor deaths decline
  the queue. (#497)

- The seccomp supervisor's launch-time store defers retention until the
  trapped syscall is answered, as reloaded stores already did. (#499)

- A config load can no longer panic on a failing stderr, and a panicking
  config reload keeps the previous store serving, so the dequeued delete
  is still answered. (#500, #449)

- The supervisor lends its credentials only to targets with the same
  SELinux/AppArmor/Smack label. A confined process with root's
  credentials no longer has deletions its policy denies carried out
  under the supervisor's label. (#503)

- Config reloads in a seccomp session follow symlink retargets and files
  with normalized mtimes (Nix, home-manager), keyed on the link's and
  the file's identity, size and ctime. (#501)

- A scoped openat2 lookup that fails with a transient EAGAIN is retried
  up to 16 times instead of declining the delete. (#505)

- A parent directory on a lazily unmounted or overmounted mount is no
  longer trusted at its /proc readlink spelling, which misdirected
  policy, the trash choice and Path=. (#506)

- An entry swapped for a directory, file or populated tree after the
  supervisor's unlink/rmdir checks gets the kernel's
  EISDIR/ENOTDIR/ENOTEMPTY instead of being trashed with success. (#507)

- The walk that sizes a directory when it is trashed holds one
  descriptor per level instead of one per subdirectory. A directory with
  more subdirectories than the descriptor limit (a cargo registry, a
  photo library) recorded a fraction of its size in `X-Trashd-Size` and
  `directorysizes` for the life of the entry, which hid it from the size
  cap, `trash du` and `trash status`. A walk that still runs out of
  descriptors records no size, and accounting measures the tree itself.
  (#527)

- Directories can be trashed when the trash is on a filesystem without
  `RENAME_NOREPLACE` (NFS, 9p, FUSE without rename2). The copy fallback
  published into `files/` with the same flag and then refused every
  directory, each time after a full copy. The staged copy is now renamed
  over an empty directory created exclusively for it in the private
  `files/`. Restoring a directory onto such a filesystem is still
  refused. (#529)

- A compressed entry restores whatever `max_file_size_mb` is set to
  later. Restore bounded decompression by the current setting, which
  only limits what may enter the trash: lowering it left larger
  compressed entries unrestorable, and automatic compression never
  looked at it. The bound is now the size the entry recorded when it was
  trashed (at least 64 MiB, at most 4 GiB), and `trash compress` leaves
  alone data larger than that. (#524, #555, #444)

- `trash restore --force` keeps a recorded path's confinement when it
  retries under a `.N` name: the retry stays below the entry's topdir
  and follows no symlinked ancestor. The retry was treated as a
  destination the user chose, so a crafted sidecar with an empty `Path=`
  on removable media restored its data beside the mount point
  (`<topdir>.1`). A recorded path that names the topdir itself is
  refused. (#525, #445)

- A failed cross-device copy removes everything it copied, read-only
  directories included (0555 trees such as Go module caches). A failed
  restore left a hidden `.trashd-copy-*` tree beside the destination on
  every attempt. (#530)

- Cross-device copies keep the `user.*` extended attributes of read-only
  files and directories: attributes are copied before the mode is
  applied. (#531)

- A restore that has to copy makes its destination durable (an fsync of
  the directory, a syncfs for a tree) before it removes the trash copy,
  and keeps the trash copy if that fails. A crash could keep the removal
  and lose the restored name. (#533)

- A trash root whose `info/` is missing is enumerated on every mount,
  and `trash empty`, retention and `trash fsck --fix` put `info/` back
  before purging. The #403 fix listed the stranded data, but the root
  lock refused the root, so it could never be removed, and such roots on
  other mounts were not listed at all. (#537)

- `trash undo` and `trash ls` order entries by the exact deletion
  instant (`X-Trashd-DeletedNs`) before the local-time `DeletionDate`,
  so entries deleted across a DST fall-back or a time zone change keep
  their real order and `undo` restores the one deleted last. (#540)

- A `directorysizes` rebuild measures trees deeper than 100 levels (it
  wrote a size of 0 for them), and rows count the directories' own
  blocks, as `du -B1` does. (#542)

- When an operand is replaced by one of another type between sizing and
  the move, the entry records the size of what landed, and gets a
  `directorysizes` row only if a directory landed. (#492)

- The preload ignores `HOME`, `XDG_*` and `TRASHD_PRELOAD_LOG` in a
  setuid, setgid or file-capability program, where `/etc/ld.so.preload`
  loads it too and the environment is the invoker's. It reads only
  `/etc/trashd/config.toml` there and prepares a trash only below the
  effective user's existing passwd home. `XDG_CONFIG_HOME` naming a
  symlink to `/etc/shadow` had a setuid-root program print root's line
  of it, and `XDG_DATA_HOME=/etc/nologin` had it create that directory.
  (#481, #546, #545)

- A bad-config warning (store, shim, supervisor and preload) gives the
  line, the column and the parser's message, never the parser's own
  rendering, which quotes the source line it stopped at. (#545, #481)

- The preload checks, moves, copies and removes an entry as a name in
  the directory the caller named: its directory descriptor, or the
  directory its pathname led to, opened once. It used the absolute path,
  with every directory resolved again after the checks, so a directory
  swapped for a symlink in mid-delete had root move the entry of that
  name elsewhere (`/etc/shadow`) into its trash, or unlink it for good
  after a cross-device copy. On x86-64 a copied source is still removed
  with `unlink`, through the descriptor's `/proc` link. (#482)

- Deletions relative to a directory descriptor (`rm -r`, `find -delete`,
  `shutil.rmtree`) are trashed where the descriptor's `/proc` link
  cannot be read: no `/proc` in a chroot, or a path longer than
  `PATH_MAX`. The preload then finds the directory's path by walking up
  through `..`. It used to give up, and the kernel deleted the entries
  for good. (#488)

- A cross-device delete through the preload fails and keeps the file
  when the trash cannot copy it: `EACCES`/`EPERM` for a file the
  deleting user may not read (unlink needs no permission on the file
  itself), `EIO` for a copy that cannot be synced. Both fell through to
  the real unlink. An owner or timestamps the copy cannot reproduce no
  longer fail it: root in a user namespace lost a file whose group the
  namespace does not map to `fchown`'s EINVAL. Such a copy keeps no
  set-id bits. (#485, #489)

- A trash root's lock is released when its guard is dropped, not when
  its last descriptor closes. A child forked by another thread during a
  delete (a fork pool worker that never execs) kept the trash locked for
  as long as it lived, and every writer of that trash waited. (#483)

- The preload publishes its config, its `dlsym` results and its seccomp
  verdict through atomics instead of `OnceLock`. A child forked while
  another thread loaded the config waited forever on its first deletion.
  (#484)

- A process out of descriptors, locks, memory or disk space while the
  preload locks a trash (`EMFILE`, `ENFILE`, `ENOMEM`, `ENOLCK`,
  `ENOSPC`, `EDQUOT`, `EROFS`) gets the real delete, as when the trash
  cannot be created. `unlink` used to fail with an errno it never
  returns, which also kept a user from freeing a full disk. (#486)

- The scan grant for `rmdir` of an unreadable directory (#410 in the
  preload, #411 in the seccomp supervisor) is made, used and undone
  through a pinned descriptor of the directory that was examined. Both
  layers changed the mode by name, which follows a symlink: whoever
  could rename entries in the parent swapped the directory for a link to
  one of the caller's own files, which was then chmodded to the
  directory's mode. The supervisor also left the grant on a directory
  that policy excluded or that it declined to trash. Where the preload
  cannot change the mode through a descriptor, `rmdir` now fails with
  `EACCES` instead of removing the directory for real. (#552, #491,
  #502, #504)

- A delete that has to copy its operand into the trash (another
  filesystem, or one without `RENAME_NOREPLACE`) no longer holds the
  trash's lock while it copies. One large tree, or a copy stopped with
  Ctrl-Z, made every other delete of the user wait: `rm` in another
  terminal, a wrapped root shell, the preload inside any program's
  `unlink()`. The copy is staged without the lock and published under
  it, in the store (shim, CLI, supervisor) and in the preload's file
  copy. Until then the entry's `.trashinfo` is locked, so `trash empty`,
  retention and `trash fsck` leave the entry alone however long the copy
  takes, and `.trashd/copy.lock` keeps cleanup from taking the staged
  copy for an abandoned one. (#539)

- Nothing waits for a trash's lock without end. A writer that finds it
  held for 10 seconds reports the trash busy and deletes nothing: `rm`
  says `Device or resource busy`, the preload fails the delete with
  `EBUSY`, and the seccomp supervisor answers `EBUSY` instead of
  declining, which lets the kernel delete for good. Every layer used to
  block in `flock` for as long as the holder lived or stayed stopped. A
  process that has waited the 10 seconds once waits 250 ms for the same
  lock until it gets it again. (#539)

- The store's remaining warnings (a source that could not be removed
  after its copy, restore and purge notes, operation-log failures) are
  written without `eprintln!`, which panics when stderr fails; in the
  seccomp supervisor that panic ended the session's protection. (#500)

- The unlocked cleanup sweep opens a trash's `.trashd` like the store's
  other directories, following no symlink in the trash root and staying
  on its device, and a purge reads the age of a sidecar without data
  through the `info/` its lock validated. (#508)

- The audit daemon opens a filesystem for far fewer handle lookups. Each
  lookup opens the mount for a few microseconds, and an `umount` at that
  instant fails with `target is busy`. The daemon no longer decodes a
  directory that the same read of events shows removed (thousands of
  lookups for the backlog of one `rm -rf`), and it reuses a decoded
  directory path for 20 ms instead of decoding it again in every batch,
  so a rename can take that long to show in logged paths. With the
  daemon stopped during an `rm -rf` of 15,000 entries, the `umount` that
  followed failed in 50 of 130 runs before and 1 of 130 after; without
  the daemon it never failed. A directory is still looked up once when
  it is first seen, so on a busy host an `umount` right after removing a
  tree of many small directories can still fail. (#467)

- `tests/sandbox.py --loop-device MIB` gives a suite an empty loop
  device as `/dev/trashd-test-loop`. A terminated runner (SIGTERM,
  SIGHUP) now cleans up like an interrupted one, and a killed runner
  takes its sandbox with it, so neither leaves a loop device, mount or
  image behind. `tests/daemon_umount_race.py` is the opt-in experiment
  behind #467; no CI job runs it. (#467)

- `install.sh` reports a started daemon as "auditing deletions on the
  filesystems it can mark; see journalctl -u trashd" instead of
  "monitoring deletions", and the README's architecture diagram no
  longer says it watches all deletions system-wide. btrfs subvolume
  mounts, tmpfs, overlay and FUSE are not audited. (#463 follow-up)

- The seccomp unit test `forwards_hup_int_term_without_recycled_pids`
  fails when an assertion in its forked case fails. The panic used to
  end the forked process with status 0, so no assertion there could fail
  the test.

### Documentation

- Rewrote `README.md` to be reader-first: a 30-second demo and quick start
  precede the internals, every `trash` subcommand and flag is now in a
  complete reference table, and configuration, environment variables,
  retention, safety limits, troubleshooting, and advanced wrapping each
  have a dedicated section. Deep implementation detail moved into collapsed
  deep dives so the main flow stays scannable on GitHub. Corrected the
  cron coverage description (Layer 2, not the PATH shim) and the install
  verification example (`/tmp` is never-trashed by default).
- Expanded `CONTRIBUTING.md` with layered architecture notes, tiered test
  instructions, and testing rules; fixed the "adding a CLI subcommand"
  steps (the `Commands` enum lives in `src/cli.rs`, handlers in
  `src/commands/`). Clarified merge semantics in `config/trashd.toml`.

## 0.1.14 (2026-10-22)

Stabilization release for deletion security boundaries, syscall compatibility,
no-clobber publication, and interrupted cleanup. Install the wrapper and preload
from the same release and restart existing wrapped sessions.

### Fixed

- Landlock setup is tracked before the kernel continues it in every
  notification path, including watchdog recovery and supervisor fallback.
  A shared session flag survives worker replacement without a task-record
  limit or dependence on live ancestry. After any restriction attempt,
  including a failed attempt, all session deletions use the target's own
  security context: preload handles them in process, and direct syscalls
  receive their native kernel checks.
- Preload supervisor handoff preserves native `unlink` and `rmdir` syscalls
  on x86-64, including libc `remove`, so application seccomp policies do not
  encounter a substituted `unlinkat`. Update the wrapper and preload
  together and restart wrapped sessions to use the complete protocol.
- Staged directory copies refuse publication if atomic no-replace rename
  is unavailable, retaining the source and any competing destination.
- `trash empty`, including the scheduled age-filtered cleanup command,
  retries unfinished purges even when no ordinary entries are selected.
  Status reports pending deletion jobs, and cleanup failures return an
  error for retry. Dry runs and the ordinary confirmed selection are
  preserved. Cleanup helpers now live in a separate store module.
- Interactive deletion plans have explicit descriptor, memory and depth
  budgets and refuse an oversized operand before mutation. Pinned
  directory identities remain protected, and sorted filename lookup
  removes quadratic verification work in wide directories.

## 0.1.13 (2026-10-22)

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
