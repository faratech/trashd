# Contributing to trashd

## Getting started

```bash
git clone https://github.com/faratech/trashd.git
cd trashd
cargo build
TRASH_BYPASS=1 cargo test --workspace
```

## Code style

- `cargo fmt` before committing
- `cargo clippy -- -D warnings` must pass
- No `.unwrap()` in library code — use `?` or return errors

## Running tests

```bash
TRASH_BYPASS=1 cargo test -p trashd-common --lib
TRASH_BYPASS=1 cargo test --workspace
cargo build --workspace
sudo ./tests/integration.sh target/debug
sudo python3 tests/shim_regression.py target/debug/trashd-rm
```

Store tests use `TrashStore::open_isolated` with an explicit temporary trash root and configuration. This constructor disables mount discovery and ambient configuration; setting `XDG_DATA_HOME` alone does **not** isolate a production store from trash on other mounts. Do not use `TrashStore::open()` in destructive unit tests. `TRASH_BYPASS=1` prevents any installed preload library from interfering with fixture cleanup.

Subprocess suites automatically enter `tests/sandbox.py`: a disposable root in private mount and PID namespaces, with isolated HOME/XDG paths, read-only system runtimes, and explicit built binaries. They require Linux mount privileges (usually `sudo`), fail before testing when unavailable, and verify that mounted trash sentinels outside the sandbox remain unchanged. No installation is required. Never source the installed trashd profile or empty the host trash to prepare tests.

Use `target/release` instead of `target/debug` after `cargo build --workspace --release`. Set `REQUIRE_SECCOMP=1` on hosts that support seccomp notification listeners to make an unavailable listener a failure. The self-update network check is opt-in with `TRASHD_TEST_NETWORK=1`; pass these variables through `sudo` explicitly, for example `sudo env REQUIRE_SECCOMP=1 ./tests/integration.sh target/release`.

## Project structure

| Crate | What it is |
|-------|-----------|
| `trashd-common` | Core library: store, config, index, mounts, trashinfo, oplog |
| `trashd-cli` | `trash` CLI binary |
| `trashd-shim` | `trashd-rm` binary (drop-in `rm` replacement) |
| `trashd-preload` | `libtrashd_preload.so` (LD_PRELOAD hooks) |
| `trashd-seccomp` | `trashd-exec` binary (seccomp supervisor + watchdog) |
| `trashd` | `trashd` binary (fanotify monitor) |

`trashd-preload` is standalone (no `trashd-common` dependency) to keep the `.so` small and avoid SQLite. It duplicates some logic from `trashd-common` — if you change config parsing or trash directory selection, update both.

## Pull requests

1. Fork and create a feature branch
2. Make your changes
3. Run `cargo fmt`, `cargo clippy`, `TRASH_BYPASS=1 cargo test --workspace`, and the sandboxed integration suite
4. Open a PR against `main`

## Adding a new CLI subcommand

1. Add the variant to `Commands` enum in `crates/trashd-cli/src/main.rs`
2. Add a match arm in `main()`
3. Write the handler function
4. Update `build_cli()` in `crates/trashd-cli/build.rs` (for completions/man pages)

## Reporting bugs

Open an issue at https://github.com/faratech/trashd/issues with:
- trashd version (`trash --version`)
- Linux kernel version (`uname -r`)
- Steps to reproduce
- Expected vs actual behavior
