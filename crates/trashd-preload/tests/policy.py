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

        def focused_fixture(name):
            fixture = root / name
            fixture.mkdir()
            data = fixture / "data"; data.mkdir()
            environment = dict(os.environ, LD_PRELOAD=library, HOME=str(fixture),
                XDG_DATA_HOME=str(data), XDG_CONFIG_HOME=str(fixture / "config"), TRASH_BYPASS="0")
            environment.pop("TRASHD_SECCOMP_ACTIVE", None)
            environment.pop("TRASHD_SECCOMP_COOKIE", None)
            return fixture, data, environment

        for name, spelling in [("dot-parent", "./victim"), ("dotdot-parent", "child/../victim"),
                               ("excluded-spelling", "/tmp/../work/{relative}/victim")]:
            fixture, data, environment = focused_fixture(name)
            (fixture / "child").mkdir()
            victim = fixture / "victim"; victim.write_bytes(b"roundtrip")
            operand = spelling.format(relative=str(fixture.relative_to("/work")))
            result = subprocess.run(["/usr/bin/unlink", operand], cwd=fixture, env=environment, capture_output=True)
            assert result.returncode == 0, result.stderr
            records = list((data / "Trash/info").glob("*.trashinfo"))
            assert len(records) == 1 and not victim.exists(), (name, result.stderr)
            restored = subprocess.run([cli, "restore", records[0].stem], env=dict(environment, TRASH_BYPASS="1"), capture_output=True)
            assert restored.returncode == 0 and victim.read_bytes() == b"roundtrip", (name, restored.stderr)
        print("PASS: normalized parents use consistent policy and restorable metadata")

        fixture, data, environment = focused_fixture("physical-parent")
        (fixture / "target/sub").mkdir(parents=True)
        (fixture / "alias").symlink_to("target/sub", target_is_directory=True)
        victim = fixture / "target/victim"; victim.write_bytes(b"physical")
        result = subprocess.run(["/usr/bin/unlink", "alias/../victim"], cwd=fixture, env=environment, capture_output=True)
        assert result.returncode == 0 and not victim.exists(), result.stderr
        records = list((data / "Trash/info").glob("*.trashinfo"))
        assert len(records) == 1 and ("Path=" + str(victim)) in records[0].read_text()
        print("PASS: symlinked parents follow kernel resolution")

        fixture, data, environment = focused_fixture("raw-final-symlink")
        target = fixture / "target"; target.write_bytes(b"target survives")
        link = os.fsencode(fixture) + b"/link-\xff"
        os.symlink(os.fsencode(target), link)
        result = subprocess.run(["/usr/bin/unlink", link], env=environment, capture_output=True)
        assert result.returncode == 0 and target.read_bytes() == b"target survives", result.stderr
        records = list((data / "Trash/info").glob("*.trashinfo"))
        assert len(records) == 1
        restored = subprocess.run([cli, "restore", records[0].stem], env=dict(environment, TRASH_BYPASS="1"), capture_output=True)
        assert restored.returncode == 0 and os.path.islink(link), restored.stderr
        assert os.readlink(link) == os.fsencode(target)
        print("PASS: raw-byte final symlink survives trash/restore")

        for marker in [None, "invalid", "0123456789abcdef0123456789abcdef"]:
            fixture, data, environment = focused_fixture("marker-" + str(marker))
            environment["TRASHD_SECCOMP_ACTIVE"] = "1"
            if marker is not None: environment["TRASHD_SECCOMP_COOKIE"] = marker
            victim = fixture / "victim"; victim.write_bytes(b"recoverable")
            result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment, capture_output=True)
            assert result.returncode == 0 and len(list((data / "Trash/info").glob("*.trashinfo"))) == 1, result.stderr
        print("PASS: unrelated inherited filters and stale markers retain preload")

        fixture, data, environment = focused_fixture("invalid-flags")
        victim = fixture / "victim"; victim.write_bytes(b"untouched")
        code = "import ctypes,errno,os,sys; c=ctypes.CDLL(None,use_errno=True); r=c.unlinkat(-100,ctypes.c_char_p(os.fsencode(sys.argv[1])),1024); assert r==-1 and ctypes.get_errno()==errno.EINVAL"
        result = subprocess.run(["/usr/bin/python3", "-c", code, str(victim)], env=environment, capture_output=True)
        assert result.returncode == 0 and victim.read_bytes() == b"untouched", result.stderr
        assert not list((data / "Trash/info").glob("*.trashinfo"))
        print("PASS: unsupported unlinkat flags leave data and metadata untouched")

        # Exercise published-copy cleanup failure even without a usable
        # listener. Both filters affect only a sandbox child; errno denial
        # takes precedence over any inherited notification filter.
        import errno
        from seccomp_regression import force_install_error
        renameat2 = {"x86_64": 316, "aarch64": 276}[os.uname().machine]
        unlink_nr = {"x86_64": 87, "aarch64": 35}[os.uname().machine]
        def deny_move_and_cleanup():
            # EXDEV is the cross-device case that takes the copy path.
            force_install_error(errno.EXDEV, renameat2)()
            force_install_error(errno.EACCES, unlink_nr)()
        for is_link in [False, True]:
            fixture, data, environment = focused_fixture("cleanup-failure-" + str(is_link))
            victim = fixture / "victim"
            if is_link:
                target = fixture / "target"; target.write_bytes(b"complete recovery")
                victim.symlink_to(target)
            else: victim.write_bytes(b"complete recovery")
            code = "import errno,os,sys\ntry: os.unlink(sys.argv[1])\nexcept OSError as e: assert e.errno==errno.EACCES\nelse: raise AssertionError('cleanup should fail')"
            result = subprocess.run(["/usr/bin/python3", "-c", code, str(victim)], env=environment,
                capture_output=True, preexec_fn=deny_move_and_cleanup, timeout=10)
            assert result.returncode == 0 and victim.read_bytes() == b"complete recovery", result.stderr
            assert victim.is_symlink() == is_link
            # The injected filter fails EVERY unlink, including the removal of
            # the now-redundant copy (#205), so one may remain here; it must
            # then be complete, never a sidecar without its data.
            records = list((data / "Trash/info").glob("*.trashinfo"))
            for record in records:
                stored = data / "Trash/files" / record.stem
                assert stored.read_bytes() == b"complete recovery"
                assert stored.is_symlink() == is_link
        print("PASS: failed source cleanup returns errno and never leaves a partial entry")

        for dirname in [".Trash", f".Trash-{os.geteuid()}"]:
            fixture, data, environment = focused_fixture("lookalike-" + dirname)
            folder = fixture / dirname; folder.mkdir()
            victim = folder / "victim"; victim.write_bytes(b"recoverable")
            result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment, capture_output=True)
            assert result.returncode == 0 and len(list((data / "Trash/info").glob("*.trashinfo"))) == 1, result.stderr
        print("PASS: nested trash lookalikes remain ordinary protected data")

        # Service accounts (home /nonexistent, or a root-owned home) cannot
        # create a trash. Their deletes must run, not fail with EACCES (#194).
        # A failed cross-device restore rolls back its partial destination
        # while holding the trash-root lock. That cleanup must be a raw
        # syscall: through the hooked libc wrapper the preload in the CLI
        # trashed the half-written file or blocked on the held lock (#196).
        fixture, data, environment = focused_fixture("restore-rollback")
        victim = fixture / "large"
        victim.write_bytes(b"r" * (1024 * 1024))
        result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment, capture_output=True)
        assert result.returncode == 0 and not victim.exists(), result.stderr
        tiny = fixture / "tiny"
        tiny.mkdir()
        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "size=64k,mode=755", "none", str(tiny)], check=True)
        try:
            entries_before = sorted(p.name for p in (data / "Trash/info").iterdir())
            restore_env = dict(environment)
            restore_env.pop("TRASH_BYPASS", None)
            try:
                result = subprocess.run([cli, "restore", entries_before[0].removesuffix(".trashinfo"),
                                         "--to", str(tiny / "large")],
                                        env=restore_env, capture_output=True, timeout=20)
            except subprocess.TimeoutExpired:
                raise AssertionError("restore rollback deadlocked")
            assert result.returncode != 0, "restore into a full filesystem must fail"
            assert not (tiny / "large").exists(), "partial destination left behind"
            assert not list(tiny.glob(".Trash*")), "rollback cleanup was trashed"
            assert sorted(p.name for p in (data / "Trash/info").iterdir()) == entries_before
        finally:
            subprocess.run(["/usr/bin/umount", str(tiny)], check=True)
        print("PASS: failed restore rolls back without re-interception")

        # When the copy succeeds but the source cannot be removed (read-only
        # mount, unwritable parent), the verified copy is a pure duplicate:
        # it must not stay behind in the trash (#205).
        fixture, data, environment = focused_fixture("readonly-source")
        source = fixture / "source"
        source.mkdir()
        (source / "victim").write_bytes(b"read-only data")
        readonly = fixture / "readonly"
        readonly.mkdir()
        subprocess.run(["/usr/bin/mount", "--bind", str(source), str(readonly)], check=True)
        subprocess.run(["/usr/bin/mount", "-o", "remount,bind,ro", str(readonly)], check=True)
        try:
            result = subprocess.run(["/usr/bin/unlink", str(readonly / "victim")], env=environment, capture_output=True)
            assert result.returncode != 0, "unlink on a read-only mount reported success"
            assert (readonly / "victim").read_bytes() == b"read-only data"
            assert not list((data / "Trash/info").glob("*.trashinfo")), "stray recovery sidecar"
            assert not list((data / "Trash/files").iterdir()), "stray recovery copy"
        finally:
            subprocess.run(["/usr/bin/umount", str(readonly)], check=True)
        print("PASS: failed source removal leaves no duplicate in the trash")

        # Preload diagnostics run inside arbitrary programs. With stderr on a
        # closed pipe they must neither raise SIGPIPE in the host nor abort it
        # (eprintln! panics on EPIPE inside an extern "C" hook) (#208).
        import signal
        for disposition in [signal.SIG_DFL, signal.SIG_IGN]:
            fixture, data, environment = focused_fixture(f"closed-stderr-{int(disposition)}")
            config_dir = fixture / "config" / "trashd"
            config_dir.mkdir(parents=True)
            (config_dir / "config.toml").write_text('only_trash = ["*.txt"\n')  # malformed: warns
            victim = fixture / "victim"
            victim.write_bytes(b"data")
            reader, writer = os.pipe()
            os.close(reader)
            try:
                result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment,
                                        stdout=subprocess.DEVNULL, stderr=writer,
                                        preexec_fn=lambda: signal.signal(signal.SIGPIPE, disposition))
            finally:
                os.close(writer)
            assert result.returncode == 0, (disposition, result.returncode)
            assert not victim.exists()
        print("PASS: diagnostics never kill or abort the host on a closed stderr")

        # A .trashd.toml another user owns (a shared directory, a USB stick)
        # must not turn this user's deletes into permanent ones (#207).
        fixture, data, environment = focused_fixture("foreign-local-config")
        local = fixture / ".trashd.toml"
        local.write_text('never_trash = ["*"]\n')
        os.chown(local, 65534, 65534)
        victim = fixture / "victim"
        victim.write_bytes(b"recoverable")
        result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment, capture_output=True)
        assert result.returncode == 0 and not victim.exists(), result.stderr
        assert len(list((data / "Trash/info").glob("*.trashinfo"))) == 1, "foreign policy applied"
        print("PASS: foreign-owned local policy is ignored")

        root.chmod(0o755)  # the temporary root is 0700; uid 65534 must reach it
        shared = root / "service-account"
        shared.mkdir()
        shared.chmod(0o1777)
        for home in ["/nonexistent", "/"]:
            victim = shared / f"victim-{len(home)}"
            victim.write_bytes(b"service data")
            os.chown(victim, 65534, 65534)
            environment = {"PATH": "/usr/bin:/bin", "HOME": home, "LD_PRELOAD": library}
            result = subprocess.run(
                ["/usr/bin/unlink", str(victim)], env=environment, capture_output=True,
                preexec_fn=lambda: (os.setgroups([]), os.setgid(65534), os.setuid(65534)))
            assert result.returncode == 0 and not victim.exists(), (home, result.stderr)
        print("PASS: accounts without a usable home trash delete normally")

        # Root with another user's HOME (sudo -E, setuid tools) must not write
        # into that user's tree, nor fail: it uses its own home trash (#194).
        victim = shared / "root-victim"
        victim.write_bytes(b"root data")
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/home/nobody", "LD_PRELOAD": library}
        result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment, capture_output=True)
        assert result.returncode == 0 and not victim.exists(), result.stderr
        own_records = list(Path("/root/.local/share/Trash/info").glob("root-victim*.trashinfo"))
        assert len(own_records) == 1, own_records
        assert not Path("/home/nobody/.local").exists(), "wrote into another user's home"
        print("PASS: root with a foreign HOME trashes into its own home")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: policy.py /path/to/libtrashd_preload.so /path/to/trash")
    raise SystemExit(run())
