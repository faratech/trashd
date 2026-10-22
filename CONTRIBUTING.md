# Contributing to trashd

Thanks for helping make deletions safer. This guide gets you from clone to a mergeable pull request. For what trashd does and how the layers fit together, start with the [README](README.md); this file is only about working on the code.

## Getting started

You need Linux and Rust (the workspace pins the toolchain in `rust-toolchain.toml` — `rustup` honours it automatically, including the `clippy` and `rustfmt` components).

```bash
git clone https://github.com/faratech/trashd.git
cd trashd
cargo build                        # debug build of the whole workspace
TRASH_BYPASS=1 cargo test --workspace
```

`TRASH_BYPASS=1` matters whenever trashd's `LD_PRELOAD` layer is installed system-wide on your machine: without it, the preload can intercept the tests' own file deletions. If you have trashd installed, keep the prefix on test commands.

## The one-paragraph architecture

Four interception layers feed one shared trash store (FreeDesktop.org Trash spec):

- `trashd-shim` (`trashd-rm`) — an `rm` replacement on `PATH` (Layer 1).
- `trashd-preload` (`libtrashd_preload.so`) — `LD_PRELOAD` hooks for `unlink`/`unlinkat`/`rmdir`/`remove` (Layer 2). **Standalone by design:** it must never depend on `trashd-common`, so the `.so` stays small enough to load into every process. It deliberately duplicates config parsing and trash-directory selection — if you change either in `trashd-common`, mirror the change here or the layers will disagree.
- `trashd` (in `crates/trashd-daemon/`) — a fanotify audit daemon; it observes deletions but never intercepts (Layer 3).
- `trashd-seccomp` (`trashd-exec`) — a seccomp user-notification supervisor (child + supervisor + watchdog + ancestor broker) trapping raw delete syscalls (Layer 4).

Everything else — policy, config, the store — lives in `trashd-common`, and the user-facing `trash` CLI lives in `trashd-cli`. The README's [How it works](README.md#how-it-works) section (including the collapsed deep dives) is the detailed tour; [CLAUDE.md](CLAUDE.md) records the invariants maintainers rely on.

## Code style

- Run `cargo fmt` before committing; CI checks `cargo fmt --all -- --check`.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass. CI is the source of truth if your local clippy disagrees.
- No `.unwrap()` in library code — propagate with `?` or return a typed error. (Tests and build scripts are exempt by convention, not by lint.)
- Prefer the codebase's existing helpers and error types over new abstractions; match the naming and shape of sibling code.

## Running tests

Tests come in three tiers. Run the tiers your change touches; run all of them before opening a PR.

```bash
# Tier 1 — unit tests (fast, no privileges)
TRASH_BYPASS=1 cargo test --workspace
TRASH_BYPASS=1 cargo test -p trashd-common --lib        # one crate

# Tier 2 — build, then sandboxed end-to-end suites (need sudo for mount namespaces)
cargo build --release --locked
sudo ./tests/integration.sh target/release              # CLI + shim behaviour
sudo ./tests/install_regression.sh target/release       # install.sh inside the sandbox
sudo python3 tests/shim_regression.py target/release/trashd-rm

# Tier 3 — seccomp under realistic Yama restrictions
sudo env TRASH_BYPASS=1 REQUIRE_SECCOMP=1 python3 tests/sandbox.py --build-dir target/release -- \
  /usr/bin/python3 /tests/seccomp_regression.py
```

Use `target/debug` instead of `target/release` if that is what you built. Handy environment switches:

| Variable | Effect |
| --- | --- |
| `TRASH_BYPASS=1` | Keep an installed preload layer out of the tests (see above) |
| `REQUIRE_SECCOMP=1` | Make an unavailable seccomp notification listener a failure instead of a skip — set it on hosts that support listeners |
| `TRASHD_TEST_NETWORK=1` | Enable the opt-in self-update network check |

Pass variables through `sudo` explicitly (`sudo env VAR=1 …`), as in Tier 3 — plain `sudo VAR=1 cmd` does not forward them.

### Testing rules that will otherwise bite you

- **Never use `TrashStore::open()` in destructive unit tests.** Use `TrashStore::open_isolated` with an explicit temporary trash root and configuration. `open_isolated` disables mount discovery and ambient config; setting `XDG_DATA_HOME` alone still exposes mounted trash through a production store, so "isolated by env var" tests can delete real trash.
- **Subprocess suites run inside `tests/sandbox.py`** — a disposable chroot in private mount/PID namespaces with isolated `HOME`/XDG, read-only system runtimes, only the requested built binaries copied in, and sentinels proving mounted trash outside the sandbox is untouched. They need Linux mount privileges (usually `sudo`) and fail closed if isolation cannot be established. Do not work around a sandbox failure by running suites against installed binaries.
- **Never source the installed profile (`/etc/profile.d/trashd.sh`) and never empty host trash to set up a test.** If a suite seems to need that, the suite is wrong — please file it.
- Release artifacts must honour the glibc 2.28 floor (`cargo zigbuild --target <triple>.2.28`); `tests/glibc_floor.sh 2.28 <artifacts>` verifies it and runs in CI.

## Project structure

| Crate (directory) | Binary | What it is |
| --- | --- | --- |
| `trashd-common` (`crates/trashd-common/`) | — | Core library: `store`, `config`, `mounts`, `trashinfo`, `directorysizes`, `oplog` |
| `trashd-cli` (`crates/trashd-cli/`) | `trash` | User CLI; subcommands live in `src/commands/`, argument definitions in `src/cli.rs` |
| `trashd-shim` (`crates/trashd-shim/`) | `trashd-rm` | Drop-in `rm` replacement (Layer 1) |
| `trashd-preload` (`crates/trashd-preload/`) | `libtrashd_preload.so` | `LD_PRELOAD` hooks (Layer 2); standalone, no `trashd-common` dependency |
| `trashd-seccomp` (`crates/trashd-seccomp/`) | `trashd-exec` | Seccomp supervisor + watchdog + broker + BPF filter (Layer 4) |
| `trashd` (`crates/trashd-daemon/`) | `trashd` | fanotify audit monitor (Layer 3) |

## Pull requests

1. Fork and create a feature branch.
2. Make your changes, with tests (see below).
3. Run `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `TRASH_BYPASS=1 cargo test --workspace`, and the sandboxed suites your change touches.
4. Note user-visible changes in [CHANGELOG.md](CHANGELOG.md) and update the [README](README.md) if behaviour, flags, config keys, or install steps changed.
5. Open a PR against `main` describing what changes for the user, not just what changed in the code.

Keep PRs to one concern where you can; a fix that also renames half the store is harder to review than two PRs.

## Testing expectations for changes

- Bug fixes should come with a regression test that fails without the fix. Behaviour changes should update the tests that encode the old behaviour — do not weaken or skip a failing test to make a change pass; if an existing test's contract really must change, say so in the PR and why.
- New interception behaviour needs coverage at the layer it lives in, plus a sandboxed end-to-end check when it affects what a user observes (a file trashed, restored, or really deleted).
- Documentation-only changes need no tests, but command examples in docs must match the real CLI — check `--help` output and `crates/trashd-cli/src/cli.rs` before publishing a new example.

## Adding a new CLI subcommand

1. Add the variant to the `Commands` enum in `crates/trashd-cli/src/cli.rs` (with doc comments — they become `--help` text).
2. Write the handler as `crates/trashd-cli/src/commands/<name>.rs` and register it in `crates/trashd-cli/src/commands/mod.rs`.
3. Dispatch it in `crates/trashd-cli/src/main.rs`. Note the split there: store-independent commands (`log`, `config`, `self-update`) are handled *before* the store opens, so they keep working when the trash is broken — put yours on the correct side of that line.
4. Mirror the command in `build_cli()` in `crates/trashd-cli/build.rs` — that definition generates the shell completions (bash/zsh/fish) and man pages, and CI fails if they are missing.
5. Update the README's command reference and add tests.

## Reporting bugs

Open an issue at https://github.com/faratech/trashd/issues with:

- trashd version (`trash --version`)
- Linux kernel version (`uname -r`) and distribution
- Steps to reproduce (the exact command, and whether it ran in a shell, script, cron job, or service)
- Expected vs. actual behaviour
- When interception is involved: the same command re-run with `TRASHD_PRELOAD_LOG=1`, plus relevant `trash log` output

Deletion bugs — a file trashed that should not be, or really deleted that should have been trashed — are the highest-value reports this project gets. Please do not sit on one because the repro is flaky; a partial repro with logs beats silence.
