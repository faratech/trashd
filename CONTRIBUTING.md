# Contributing to trashd

## Getting started

```bash
git clone https://github.com/faratech/trashd.git
cd trashd
cargo build
cargo test --workspace
```

## Code style

- `cargo fmt` before committing
- `cargo clippy -- -D warnings` must pass
- No `.unwrap()` in library code — use `?` or return errors

## Running tests

```bash
cargo test -p trashd-common --lib   # core tests (32 tests)
cargo test --workspace              # all workspace tests
```

Tests use isolated temp directories (not `/tmp`, which is in the never-trash list). A mutex serializes tests that share `XDG_DATA_HOME`.

## Project structure

| Crate | What it is |
|-------|-----------|
| `trashd-common` | Core library: store, config, index, mounts, trashinfo, oplog |
| `trashd-cli` | `trash` CLI binary |
| `trashd-shim` | `trashd-rm` binary (drop-in `rm` replacement) |
| `trashd-preload` | `libtrashd_preload.so` (LD_PRELOAD hooks) |
| `trashd-seccomp` | `trashd-exec` binary (seccomp supervisor + watchdog) |
| `trashd-daemon` | `trashd-daemon` binary (fanotify monitor) |

`trashd-preload` is standalone (no `trashd-common` dependency) to keep the `.so` small and avoid SQLite. It duplicates some logic from `trashd-common` — if you change config parsing or trash directory selection, update both.

## Pull requests

1. Fork and create a feature branch
2. Make your changes
3. Run `cargo fmt`, `cargo clippy`, `cargo test --workspace`
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
