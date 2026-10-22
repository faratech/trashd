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
            os.makedirs(os.path.dirname(victim), exist_ok=True)
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
        # Rustup retires many toolchain files under ~/.rustup/tmp; those
        # housekeeping deletes must bypass by default (#282). Execute real
        # scripts bearing each process name, rather than changing argv[0].
        # A similarly named unrelated process must still protect its data.
        proxy_dir = root / "process-proxies"
        proxy_dir.mkdir()
        for name in ["rustup", "rustup-init", "rustup-helper"]:
            proxy = proxy_dir / name
            proxy.write_text("#!/usr/bin/python3\nimport os,sys\n"
                             "assert open('/proc/self/comm').read().rstrip('\\n') "
                             "== os.path.basename(sys.argv[0])\n"
                             "os.unlink(sys.argv[1])\n")
            proxy.chmod(0o755)
            case(f"default-{name}-housekeeping", "", filename=".rustup/tmp/toolchain-backup",
                 trashed=name == "rustup-helper",
                 command=lambda victim, proxy=proxy: [str(proxy), victim])
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
        # Repeated calls in one process must see local-policy changes at
        # once. Sharing the hook's clock sample must not cache exclusions or
        # whitelist verdicts between deletions (#283, #285).
        live_policy = (
            "import os,sys\nfrom pathlib import Path\n"
            "victim=Path(sys.argv[1]); policy=victim.parent/'.trashd.toml'\n"
            "records=Path(os.environ['XDG_DATA_HOME'])/'Trash/info'\n"
            "policy.write_text('only_trash = [\\\"*.keep\\\"]\\n')\n"
            "os.unlink(victim)\nassert not list(records.glob('*.trashinfo'))\n"
            "policy.write_text('only_trash = [\\\"victim\\\"]\\n')\n"
            "victim.write_bytes(b'protected'); os.unlink(victim)\n"
            "assert len(list(records.glob('*.trashinfo')))==1\n"
            "policy.write_text('never_trash = [\\\"victim\\\"]\\n')\n"
            "victim.write_bytes(b'excluded'); os.unlink(victim)\n"
            "assert len(list(records.glob('*.trashinfo')))==1\n"
        )
        case("live-local-policy", "",
             command=lambda victim: ["/usr/bin/python3", "-c", live_policy, victim])
        # The advancing collision IDs remain unique after fork: children
        # inherit the counter but have a distinct PID. Every payload and
        # sidecar must survive; naming collisions never justify real unlink.
        collision_root = root / "collision-fork"
        collision_root.mkdir()
        collision_config = collision_root / "config/trashd"
        collision_config.mkdir(parents=True)
        (collision_config / "config.toml").write_text("")
        collision_env = dict(os.environ, LD_PRELOAD=library, HOME=str(collision_root),
                             XDG_CONFIG_HOME=str(collision_config.parent),
                             XDG_DATA_HOME=str(collision_root / "data"))
        collision_env.pop("TRASH_BYPASS", None)
        collision_env.pop("TRASHD_SECCOMP_ACTIVE", None)
        collision_script = (
            "import os,sys\nfrom pathlib import Path\n"
            "root=Path(sys.argv[1]); seed=root/'seed'; seed.mkdir()\n"
            "for i in range(3):\n"
            " p=seed/'victim'; p.write_bytes(('seed-'+str(i)).encode()); os.unlink(p)\n"
            "child=os.fork(); role='child' if child==0 else 'parent'\n"
            "directory=root/role; directory.mkdir()\n"
            "for i in range(20):\n"
            " p=directory/'victim'; p.write_bytes((role+'-'+str(i)).encode()); os.unlink(p)\n"
            "if child==0: os._exit(0)\n"
            "assert os.waitpid(child,0)[1]==0\n"
        )
        collision_result = subprocess.run(
            ["/usr/bin/python3", "-c", collision_script, str(collision_root)],
            env=collision_env, capture_output=True, timeout=10)
        assert collision_result.returncode == 0, collision_result.stderr
        collision_store = collision_root / "data/Trash"
        collision_files = list((collision_store / "files").iterdir())
        collision_records = list((collision_store / "info").glob("*.trashinfo"))
        expected = {f"seed-{i}".encode() for i in range(3)} | {
            f"{role}-{i}".encode() for role in ["parent", "child"] for i in range(20)}
        assert len(collision_files) == len(collision_records) == len(expected)
        assert {path.read_bytes() for path in collision_files} == expected
        assert {path.name for path in collision_files} == {
            path.name.removesuffix(".trashinfo") for path in collision_records}
        print("PASS: collision IDs preserve every parent and forked-child payload")
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

        # A PID captured once per operation must be refreshed after fork;
        # process-global PID caches would publish the parent's PID (#298).
        fixture, data, environment = focused_fixture("operation-pid")
        pid_code = (
            "import os,signal,sys\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGCHLD,signal.SIG_DFL)\n"
            "root=Path(sys.argv[1]); info=Path(os.environ['XDG_DATA_HOME'])/'Trash/info'\n"
            "def remove(name):\n"
            " victim=root/name; victim.write_bytes(b'pid check'); os.unlink(victim)\n"
            " record=next(info.glob(name+'*.trashinfo'))\n"
            " assert 'X-Trashd-PID='+str(os.getpid())+'\\n' in record.read_text()\n"
            "remove('parent-before')\n"
            "child=os.fork()\n"
            "if child==0:\n remove('child'); os._exit(0)\n"
            "assert os.waitpid(child,0)[1]==0\n"
            "remove('parent-after')\n"
        )
        result = subprocess.run(["/usr/bin/python3", "-c", pid_code, str(fixture)],
                                env=environment, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert len(list((data / "Trash/info").glob("*.trashinfo"))) == 3
        print("PASS: per-operation PID remains correct in parent and forked child")

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

        import errno
        from seccomp_regression import force_install_error
        renameat2 = {"x86_64": 316, "aarch64": 276}[os.uname().machine]
        unlink_nr = {"x86_64": 87, "aarch64": 35}[os.uname().machine]

        # Standalone preload must retain libc unlink's x86 syscall surface:
        # an application may allow unlink(87), but deny unlinkat(263). Force
        # the copy branch without a verified trashd notification filter.
        if os.uname().machine == "x86_64":
            def copy_with_unlinkat_denied():
                force_install_error(errno.EXDEV, renameat2)()
                force_install_error(errno.EACCES, 263)()
            code = (
                "import ctypes,errno,os,sys\n"
                "c=ctypes.CDLL(None,use_errno=True); c.syscall.restype=ctypes.c_long\n"
                "path=ctypes.c_char_p(os.fsencode(sys.argv[1]))\n"
                "assert c.syscall(316,-100,path,-100,path,1)==-1 and ctypes.get_errno()==errno.EXDEV\n"
                "assert c.syscall(263,-100,path,0)==-1 and ctypes.get_errno()==errno.EACCES\n"
                "ctypes.set_errno(errno.EDOM)\n"
                "assert c.unlink(path)==0, ctypes.get_errno()\n"
                "assert ctypes.get_errno()==errno.EDOM\n"
            )
            for is_link in [False, True]:
                fixture, data, environment = focused_fixture("unlink-only-copy-" + str(is_link))
                environment.pop("TRASHD_SECCOMP_ACTIVE", None)
                environment.pop("TRASHD_SECCOMP_COOKIE", None)
                victim = fixture / "victim"
                payload = b"complete recovery under unlink-only sandbox"
                if is_link:
                    target = fixture / "target"; target.write_bytes(payload)
                    victim.symlink_to(target)
                else:
                    victim.write_bytes(payload)
                result = subprocess.run(["/usr/bin/python3", "-c", code, str(victim)], env=environment,
                    capture_output=True, preexec_fn=copy_with_unlinkat_denied, timeout=10)
                assert result.returncode == 0 and not os.path.lexists(victim), result.stderr
                records = list((data / "Trash/info").glob("*.trashinfo"))
                assert len(records) == 1, records
                stored = data / "Trash/files" / records[0].stem
                assert stored.read_bytes() == payload and stored.is_symlink() == is_link
                if is_link:
                    assert os.readlink(stored) == str(target) and target.read_bytes() == payload
                restored = subprocess.run([cli, "restore", records[0].stem],
                    env=dict(environment, TRASH_BYPASS="1"), capture_output=True)
                assert restored.returncode == 0, restored.stderr
                assert victim.read_bytes() == payload and victim.is_symlink() == is_link
                if is_link:
                    assert os.readlink(victim) == str(target) and target.read_bytes() == payload
                assert not records[0].exists() and not os.path.lexists(stored)
            print("PASS: standalone x86 copied-source retirement preserves unlink-only sandbox profiles")

        # Exercise published-copy cleanup failure even without a usable
        # listener. Both filters affect only a sandbox child; errno denial
        # takes precedence over any inherited notification filter.
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

        # A supervisor declining a deferred deletion (a target it will not
        # lend its credentials to, or a listener gone) answers ENOSYS; the
        # preload then trashes in-process instead of leaving the kernel to
        # delete (#349). A plain filter stands in for the supervisor: it
        # proves the cookie and answers marked deletion calls.
        import ctypes
        from seccomp_regression import Instruction, Program, LIBC, SYSCALL_SECCOMP
        cookie = [0x01234567, 0x89abcdef, 0x0badf00d, 0x5eedcafe]
        mark = 0x7472_6173_6864_6d6b  # seccomp_identity::DEFER_MARK
        unlinkat_nr = {"x86_64": 263, "aarch64": 35}[os.uname().machine]
        getpid_nr = {"x86_64": 39, "aarch64": 172}[os.uname().machine]
        def supervisor_answering(error, proof_errno=4092, native_deletions=True):
            def install():
                allow, answer = 0x7FFF0000, 0x00050000 | error
                program = [Instruction(0x20, 0, 0, 0)]  # nr
                proof = [Instruction(0x20, 0, 0, 16 + 8 * i) for i in range(4)]
                # getpid(cookie...) -> versioned PROOF_ERRNO (4092)
                program += [Instruction(0x15, 0, 9, getpid_nr)]
                for i, word in enumerate(cookie):
                    program += [proof[i], Instruction(0x15, 0, 7 - 2 * i, word)]
                program += [Instruction(0x06, 0, 0, 0x00050000 | proof_errno)]
                # The fourth argument marks all native deletion families.
                deletion_nrs = [unlinkat_nr]
                if native_deletions and os.uname().machine == "x86_64": deletion_nrs += [87, 84]
                for nr in deletion_nrs:
                    program += [Instruction(0x20, 0, 0, 0), Instruction(0x15, 0, 5, nr),
                                Instruction(0x20, 0, 0, 40), Instruction(0x15, 0, 3, mark & 0xFFFFFFFF),
                                Instruction(0x20, 0, 0, 44), Instruction(0x15, 0, 1, mark >> 32),
                                Instruction(0x06, 0, 0, answer)]
                program += [Instruction(0x06, 0, 0, allow)]
                instructions = (Instruction * len(program))(*program)
                filt = Program(len(program), instructions)
                if LIBC.prctl(38, 1, 0, 0, 0) or LIBC.syscall(SYSCALL_SECCOMP, 1, 0, ctypes.byref(filt)):
                    raise RuntimeError("cannot install the stand-in supervisor filter")
            return install
        for error, trashed in [(errno.ENOSYS, True), (errno.EACCES, False)]:
            fixture, data, environment = focused_fixture(f"declined-{error}")
            environment["TRASHD_SECCOMP_ACTIVE"] = "1"
            environment["TRASHD_SECCOMP_COOKIE"] = "".join(f"{w:08x}" for w in cookie)
            for mode in ["unlink", "remove", "rmdir", "unlinkat", "unlinkat-dir"]:
                victim = fixture / f"victim-{mode}"
                if mode in ["rmdir", "unlinkat-dir"]: victim.mkdir()
                else: victim.write_bytes(b"recoverable")
                invocation = (f"c.unlinkat(-100,path,{512 if mode == 'unlinkat-dir' else 0})"
                              if mode.startswith("unlinkat") else f"c.{mode}(path)")
                code = ("import ctypes,os,sys\nc=ctypes.CDLL(None,use_errno=True)\n"
                        "path=ctypes.c_char_p(os.fsencode(sys.argv[1]))\n"
                        f"r={invocation}\n"
                        "print(r, ctypes.get_errno())")
                result = subprocess.run(["/usr/bin/python3", "-c", code, str(victim)], env=environment,
                    capture_output=True, text=True, preexec_fn=supervisor_answering(error), timeout=10)
                assert result.returncode == 0, result.stderr
                records = [r for r in (data / "Trash/info").glob("*.trashinfo") if r.stem.startswith(victim.name)]
                if trashed:
                    assert result.stdout.split()[0] == "0" and not os.path.lexists(victim), (mode, result.stdout)
                    assert len(records) == 1, (mode, records)
                else:
                    assert result.stdout.split() == ["-1", str(errno.EACCES)], (mode, result.stdout)
                    assert os.path.lexists(victim) and not records, mode
        print("PASS: a declined deferral is trashed in-process; a supervisor's error is returned")

        # A still-running older supervisor proves errno 4093 and recognizes
        # only marked unlinkat. New preload must reject that protocol, keeping
        # protection in-process instead of letting its native unlink/rmdir
        # deferrals run as permanent deletions through the old decline path.
        for mode in ["unlink", "rmdir", "remove"]:
            fixture, data, environment = focused_fixture("legacy-proof-" + mode)
            environment["TRASHD_SECCOMP_ACTIVE"] = "1"
            environment["TRASHD_SECCOMP_COOKIE"] = "".join(f"{w:08x}" for w in cookie)
            victim = fixture / "victim"
            if mode == "rmdir": victim.mkdir()
            else: victim.write_bytes(b"recoverable with an older supervisor")
            code = ("import ctypes,errno,os,sys\nc=ctypes.CDLL(None,use_errno=True)\n"
                    "ctypes.set_errno(errno.EDOM)\n"
                    f"assert c.{mode}(ctypes.c_char_p(os.fsencode(sys.argv[1])))==0, ctypes.get_errno()\n"
                    "assert ctypes.get_errno()==errno.EDOM\n")
            result = subprocess.run(["/usr/bin/python3", "-c", code, str(victim)], env=environment,
                capture_output=True, preexec_fn=supervisor_answering(errno.EACCES, 4093, False), timeout=10)
            assert result.returncode == 0 and not victim.exists(), (mode, result.stderr)
            records = list((data / "Trash/info").glob("*.trashinfo"))
            assert len(records) == 1, (mode, records)
            stored = data / "Trash/files" / records[0].stem
            assert stored.is_dir() if mode == "rmdir" else stored.read_bytes() == b"recoverable with an older supervisor"
        print("PASS: older supervisor proof keeps new preload protection in-process")

        # With active cookie proof, preserve the same native syscalls libc
        # needs. Both ERRNO and KILL take precedence over USER_NOTIF: even
        # attempting the alternative syscall can break the application.
        if os.uname().machine == "x86_64":
            for action in [0x00050000 | errno.EACCES, 0x80000000]:
                def deny_unlinkat():
                    supervisor_answering(errno.ENOSYS)()
                    program = (Instruction * 4)(
                        Instruction(0x20, 0, 0, 0), Instruction(0x15, 0, 1, unlinkat_nr),
                        Instruction(0x06, 0, 0, action), Instruction(0x06, 0, 0, 0x7FFF0000))
                    filt = Program(4, program)
                    if LIBC.syscall(SYSCALL_SECCOMP, 1, 0, ctypes.byref(filt)):
                        raise RuntimeError("cannot install the application's unlinkat denial")
                for mode, directory in [("unlink", False), ("rmdir", True),
                                        ("remove", False), ("remove", True)]:
                    fixture, data, environment = focused_fixture(f"active-native-{action}-{mode}-{directory}")
                    environment["TRASHD_SECCOMP_ACTIVE"] = "1"
                    environment["TRASHD_SECCOMP_COOKIE"] = "".join(f"{w:08x}" for w in cookie)
                    victim = fixture / "victim"
                    if directory: victim.mkdir()
                    else: victim.write_bytes(b"recoverable under original syscall policy")
                    code = ("import ctypes,errno,os,sys\nc=ctypes.CDLL(None,use_errno=True)\n"
                            f"call=c.{mode}; path=ctypes.c_char_p(os.fsencode(sys.argv[1]))\n"
                            "ctypes.set_errno(errno.EDOM)\n"
                            "assert call(path)==0, ctypes.get_errno()\n"
                            "assert ctypes.get_errno()==errno.EDOM\n"
                            "assert call(path)==-1 and ctypes.get_errno()==errno.ENOENT\n")
                    result = subprocess.run(["/usr/bin/python3", "-c", code, str(victim)],
                        env=environment, capture_output=True, preexec_fn=deny_unlinkat, timeout=10)
                    assert result.returncode == 0 and not victim.exists(), (mode, directory, result.stderr)
                    records = list((data / "Trash/info").glob("*.trashinfo"))
                    assert len(records) == 1, records
                    stored = data / "Trash/files" / records[0].stem
                    assert stored.is_dir() if directory else stored.read_bytes() == b"recoverable under original syscall policy"
            print("PASS: active supervision preserves x86 unlink/rmdir/remove with unlinkat denied or killed")

        # The preload runs inside every process, including those under
        # seccomp allowlists that kill syscalls newer than they know: it must
        # trash without openat2 (#357).
        def kill_on_openat2():
            program = (Instruction * 4)(
                Instruction(0x20, 0, 0, 0), Instruction(0x15, 0, 1, 437),
                Instruction(0x06, 0, 0, 0x80000000), Instruction(0x06, 0, 0, 0x7FFF0000))
            filt = Program(4, program)
            if LIBC.prctl(38, 1, 0, 0, 0) or LIBC.syscall(SYSCALL_SECCOMP, 1, 0, ctypes.byref(filt)):
                raise RuntimeError("cannot install the openat2 filter")
        fixture, data, environment = focused_fixture("allowlist-without-openat2")
        victim = fixture / "victim"; victim.write_bytes(b"recoverable")
        result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment,
            capture_output=True, preexec_fn=kill_on_openat2, timeout=10)
        assert result.returncode == 0 and not victim.exists(), (result.returncode, result.stderr)
        assert len(list((data / "Trash/info").glob("*.trashinfo"))) == 1
        print("PASS: trashing needs no syscall an older seccomp allowlist lacks (openat2)")

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

        # rmdir of a mount point fails busy, and nothing is prepared inside
        # the mounted filesystem first (#368).
        fixture, data, environment = focused_fixture("mount-root")
        mounted = fixture / "mounted"
        mounted.mkdir()
        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(mounted)], check=True)
        try:
            result = subprocess.run(["/usr/bin/rmdir", str(mounted)], env=environment, capture_output=True, text=True)
            assert result.returncode != 0 and "busy" in result.stderr, result.stderr
            assert not list(mounted.iterdir()), list(mounted.iterdir())
        finally:
            subprocess.run(["/usr/bin/umount", str(mounted)], check=True)
        print("PASS: rmdir of a mount point prepares no trash inside it")

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

        # A FreeDesktop tool that ignores trashd's lock can take files/<id>
        # while we claim that id. A fanotify permission event holds the
        # O_EXCL sidecar claim while the racer takes the name; unlink must
        # then trash under a fresh id, never fail with EEXIST (#225). The
        # record is written through the claiming descriptor (#305), so the
        # claim is the last open before the rename that can be held.
        import ctypes, select, struct, threading
        def race_for_name(info_dir, files_dir, name, stop, raced):
            libc = ctypes.CDLL(None, use_errno=True)
            fan = libc.fanotify_init(0x4 | 0x1, os.O_RDONLY)  # FAN_CLASS_CONTENT | FAN_CLOEXEC
            assert fan >= 0, os.strerror(ctypes.get_errno())
            # FAN_MARK_ADD of FAN_OPEN_PERM | FAN_EVENT_ON_CHILD on info/.
            assert libc.fanotify_mark(fan, 1, 0x10000 | 0x08000000, -100, bytes(info_dir)) == 0
            opens = 0
            try:
                while not stop.is_set():
                    if not select.select([fan], [], [], 0.05)[0]:
                        continue
                    buffer = os.read(fan, 4096)
                    offset = 0
                    while offset + 24 <= len(buffer):
                        length, _, _, _, _, fd, _ = struct.unpack_from("IBBHQii", buffer, offset)
                        offset += length
                        if os.readlink(f"/proc/self/fd/{fd}").endswith(f"/{name}.trashinfo"):
                            opens += 1
                            # Open 1 is the O_EXCL claim of the original name.
                            if opens == 1:
                                (files_dir / name).write_bytes(b"racer")
                                raced.set()
                        os.write(fan, struct.pack("iI", fd, 0x01))  # FAN_ALLOW
                        os.close(fd)
            finally:
                os.close(fan)
        fixture, data, environment = focused_fixture("claimed-name-race")
        for sub in ("files", "info"):
            (data / "Trash" / sub).mkdir(parents=True, mode=0o700)
        victim = fixture / "victim"
        victim.write_bytes(b"keep")
        stop, raced = threading.Event(), threading.Event()
        racer = threading.Thread(target=race_for_name, args=(data / "Trash/info", data / "Trash/files", "victim", stop, raced))
        racer.start()
        try:
            code = ("import os,sys\n"
                    "try: os.unlink(sys.argv[1])\n"
                    "except OSError as e: print(e.errno)\n"
                    "else: print('unlinked')")
            result = subprocess.run(["/usr/bin/python3", "-c", code, str(victim)], env=environment,
                                    capture_output=True, text=True, timeout=10)
        finally:
            stop.set(); racer.join()
        assert raced.is_set(), "the racer never saw the sidecar being claimed"
        assert result.stdout.strip() == "unlinked" and not victim.exists(), (result.stdout, result.stderr)
        assert (data / "Trash/files/victim").read_bytes() == b"racer"
        records = list((data / "Trash/info").glob("*.trashinfo"))
        assert len(records) == 1 and records[0].stem != "victim", records
        assert (data / "Trash/files" / records[0].stem).read_bytes() == b"keep"
        print("PASS: a name taken after the claim is retried under a fresh id")

        # A trusted symlinked ancestor (ostree's /home, a stowed ~/.local)
        # must not make the trash unusable (#222).
        fixture, _, environment = focused_fixture("symlinked-home")
        (fixture / "real-share").mkdir()
        (fixture / "share-link").symlink_to("real-share")
        environment["XDG_DATA_HOME"] = str(fixture / "share-link")
        victim = fixture / "victim"
        victim.write_bytes(b"recoverable")
        result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment, capture_output=True)
        assert result.returncode == 0 and not victim.exists(), result.stderr
        records = list((fixture / "real-share/Trash/info").glob("*.trashinfo"))
        assert len(records) == 1
        # Restore retires the sidecar while holding the root lock. Its
        # preload hook must recognize the physical trash path, too (#289).
        result = subprocess.run([cli, "restore", records[0].stem], env=environment,
                                capture_output=True, timeout=10)
        assert result.returncode == 0 and victim.read_bytes() == b"recoverable", result.stderr
        assert not records[0].exists()
        assert not list((fixture / "real-share/Trash/files").iterdir())
        print("PASS: trusted symlinked trash ancestors support preload-enabled restore")

        # A foreign symlink must not authenticate its target as our home
        # trash, even when the target itself is a private files/info tree.
        fixture, _, environment = focused_fixture("foreign-home-ancestor")
        target = fixture / "real-share"
        for sub in ["Trash", "Trash/files", "Trash/info"]:
            (target / sub).mkdir(parents=True, mode=0o700)
        link = fixture / "share-link"
        link.symlink_to("real-share")
        os.lchown(link, 65534, 65534)
        environment["XDG_DATA_HOME"] = str(link)
        victim = target / "Trash/files/foreign-ancestor-victim"
        victim.write_bytes(b"still protected")
        result = subprocess.run(["/usr/bin/unlink", str(victim)], env=environment,
                                capture_output=True, timeout=10)
        assert result.returncode == 0 and not victim.exists(), result.stderr
        records = list(Path("/root/.local/share/Trash/info").glob("foreign-ancestor-victim*.trashinfo"))
        assert len(records) == 1, "foreign home ancestor caused permanent deletion"
        stored = Path("/root/.local/share/Trash/files") / records[0].stem
        assert stored.read_bytes() == b"still protected"
        print("PASS: foreign symlinked home ancestors never bypass protection")

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
