#!/usr/bin/env python3
"""Run preload policy regressions in the disposable integration sandbox.

Build first: cargo build -p trashd-preload -p trashd-cli
Run as a user able to create a mount namespace:
  TRASH_BYPASS=1 python3 crates/trashd-preload/tests/policy.py \
    target/debug/libtrashd_preload.so target/debug/trash

The shared tests/sandbox.py runner creates a private mount/PID namespace and
chroot, exposing runtime files read-only. All victims and trash live inside
that disposable root. No installed configuration or user trash is accessed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import unquote_to_bytes


def run():
    library, cli = (str(Path(p).resolve()) for p in sys.argv[1:3])
    if os.environ.get("TRASHD_TEST_SANDBOX") != "1":
        runner = Path(__file__).resolve().parents[3] / "tests" / "sandbox.py"
        env = dict(os.environ, TRASH_BYPASS="1")
        result = subprocess.run(
            [sys.executable, str(runner),
             "--binary", f"libtrashd_preload.so={library}",
             "--binary", f"trash={cli}", "--", "/usr/bin/python3",
             "/tests/preload_policy.py", "/opt/trashd/lib/libtrashd_preload.so",
             "/opt/trashd/bin/trash"], env=env
        )
        return result.returncode

    # Verifies both the runner's token and private tmpfs root, before any
    # fixture deletion. An inherited environment marker alone is insufficient.
    from sandbox import require_sandbox
    require_sandbox()

    with tempfile.TemporaryDirectory(prefix="preload-policy-", dir="/work") as temporary:
        root = Path(temporary)
        count = 0

        def case(name, config, size=1, trashed=True, command=None, filename="victim",
                 local=None, warning=None):
            nonlocal count
            count += 1
            fixture = root / name
            fixture.mkdir()
            data = fixture / "data"
            data.mkdir()
            config_dir = fixture / "config" / "trashd"
            config_dir.mkdir(parents=True)
            (config_dir / "config.toml").write_text(config)
            if local is not None:
                (fixture / ".trashd.toml").write_text(local)
            victim = os.path.join(os.fsencode(fixture), os.fsencode(filename))
            with open(victim, "wb") as stream:
                stream.truncate(size)
            env = dict(os.environ, LD_PRELOAD=library,
                       XDG_DATA_HOME=str(data), XDG_CONFIG_HOME=str(config_dir.parent),
                       HOME=str(fixture))
            env.pop("TRASH_BYPASS", None)
            env.pop("TRASHD_SECCOMP_ACTIVE", None)
            arguments = command(victim) if command else ["/usr/bin/unlink", victim]
            result = subprocess.run(arguments, env=env, capture_output=True)
            assert result.returncode == 0, (name, result.stderr)
            if warning is not None:
                assert warning in result.stderr, (name, result.stderr)
            assert not os.path.lexists(victim), name
            records = list((data / "Trash" / "info").glob("*.trashinfo"))
            assert len(records) == int(trashed), (name, records, result.stderr)
            if records:
                original = next(line.removeprefix("Path=") for line in
                                records[0].read_text().splitlines() if line.startswith("Path="))
                assert unquote_to_bytes(original) == victim, (name, original, victim)
            print(f"PASS {name}")
            return records, victim, env

        for size in [1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1]:
            case(f"size-{size}", "max_file_size_mb = 1\n", size=size,
                 trashed=size <= 1024 * 1024)
        case("unlimited-zero", "max_file_size_mb = 0\n", size=2 * 1024 * 1024)
        case("executable-bypass", f'bypass_paths = [{json.dumps(str(Path("/usr/bin/unlink").resolve()))}]\n', trashed=False)
        case("unrelated-executable", 'bypass_paths = ["/nonexistent/program"]\n')
        case("self-bypass", 'bypass_processes = ["unlink"]\n', trashed=False)
        shell_name = Path("/bin/sh").resolve().name
        ancestor_rule = f"bypass_processes = [{json.dumps(shell_name)}]\n"
        case("ancestor-bypass", ancestor_rule, trashed=False,
             command=lambda victim: ["/bin/sh", "-c",
                                     '/usr/bin/unlink "$1"; result=$?; exit "$result"',
                                     "bypass-parent", victim])
        case("unrelated-process", ancestor_rule)
        case("glob-suffix", 'only_trash = ["*.py*"]\n', filename="script.py.backup")
        case("glob-class", 'only_trash = ["*.[ch]"]\n', filename="main.c")
        case("glob-directory", f'only_trash = ["{root}/glob-*/vict*"]\n')
        case("glob-nonmatch", 'only_trash = ["*.[ch]"]\n', filename="main.rs", trashed=False)
        case("local-relative", 'only_trash = ["*.txt"]\n', filename="script.py.backup",
             local='only_trash = ["local-relative/*.py*"]\n')
        case("global-veto", 'never_trash = ["file?.c"]\n', filename="file1.c", trashed=False,
             local='only_trash = ["*.[ch]"]\n')
        # A policy key nested under [retention] (legacy layout) is still
        # applied — but loudly, not silently (#150).
        case("legacy-retention-promoted", '[retention]\nonly_trash = ["*.txt"]\n',
             trashed=False, warning=b"applied from [retention]")
        # A genuinely malformed config keeps the loud "bad config" diagnostic
        # and falls back to the default (trash everything) policy.
        case("malformed-config", 'only_trash = ["*.txt"\n', warning=b"bad config")

        # A PRESENT-but-broken nearest .trashd.toml stops the ancestor walk
        # (#136): the deletion must follow the DEFAULT policy (trashed), not
        # inherit the ancestor's narrower whitelist (which would real-delete).
        walk_root = root / "broken-local-walk"
        walk_data = walk_root / "data"
        walk_config = walk_root / "config" / "trashd"
        walk_config.mkdir(parents=True)
        (walk_config / "config.toml").write_text("")
        (walk_root / ".trashd.toml").write_text('only_trash = ["*.py"]\n')
        sub = walk_root / "sub"
        sub.mkdir()
        (sub / ".trashd.toml").write_text("only_trash = [")  # broken TOML
        walk_victim = os.path.join(os.fsencode(sub), b"main.rs")
        with open(walk_victim, "wb") as stream:
            stream.truncate(1)
        count += 1
        walk_env = dict(os.environ, LD_PRELOAD=library,
                        XDG_DATA_HOME=str(walk_data), XDG_CONFIG_HOME=str(walk_config.parent),
                        HOME=str(walk_root))
        walk_env.pop("TRASH_BYPASS", None)
        walk_env.pop("TRASHD_SECCOMP_ACTIVE", None)
        walk_result = subprocess.run(["/usr/bin/unlink", walk_victim],
                                     env=walk_env, capture_output=True)
        assert walk_result.returncode == 0, ("broken-local-walk", walk_result.stderr)
        assert b"ignoring broken" in walk_result.stderr, ("broken-local-walk",
                                                          walk_result.stderr)
        assert not os.path.lexists(walk_victim), "broken-local-walk"
        walk_records = list((walk_data / "Trash" / "info").glob("*.trashinfo"))
        assert len(walk_records) == 1, ("broken-local-walk must trash, not inherit "
                                        "the ancestor whitelist", walk_records)
        print("PASS broken-local-walk")

        # glibc implements remove() with the hidden __unlink/__rmdir aliases,
        # which interposing unlink/rmdir cannot see: without a direct hook the
        # deletion below would be permanent with no trashinfo.
        remove_script = (
            "import ctypes, os, sys\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "libc.remove.restype = ctypes.c_int\n"
            "rc = libc.remove(ctypes.c_char_p(os.fsencode(sys.argv[1])))\n"
            "sys.exit(0 if rc == 0 else 1)\n"
        )
        case("libc-remove", "",
             command=lambda victim: ["/usr/bin/python3", "-c", remove_script,
                                     os.fsdecode(victim)])
        python_name = Path("/usr/bin/python3").resolve().name
        case("libc-remove-excluded", f'bypass_processes = [{json.dumps(python_name)}]\n',
             trashed=False,
             command=lambda victim: ["/usr/bin/python3", "-c", remove_script,
                                     os.fsdecode(victim)])

        records, victim, env = case("raw-name", "", filename=b"name-\xff \n%?#")
        restore_env = dict(env, TRASH_BYPASS="1")
        restore_env.pop("LD_PRELOAD", None)
        result = subprocess.run([cli, "restore", records[0].name.removesuffix(".trashinfo")],
                                env=restore_env, capture_output=True)
        assert result.returncode == 0, result.stderr
        assert os.path.exists(victim), ("raw-name restore", victim)
        assert not records[0].exists()
        result = subprocess.run(["/usr/bin/unlink", victim], env=env, capture_output=True)
        assert result.returncode == 0, result.stderr
        records = list((Path(env["XDG_DATA_HOME"]) / "Trash" / "info").glob("*.trashinfo"))
        assert len(records) == 1
        with open(victim, "wb") as stream:
            stream.write(b"original conflict")
        result = subprocess.run([cli, "restore", records[0].name.removesuffix(".trashinfo"), "--force"],
                                env=restore_env, capture_output=True)
        assert result.returncode == 0, result.stderr
        with open(victim, "rb") as stream:
            assert stream.read() == b"original conflict"
        with open(victim + b".1", "rb") as stream:
            assert stream.read() == b"\x00"
        assert not records[0].exists()
        print(f"PASS raw-name CLI restore and --force; {count} isolated deletion cases passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: policy.py /path/to/libtrashd_preload.so /path/to/trash")
    raise SystemExit(run())
