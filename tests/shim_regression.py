#!/usr/bin/env python3
"""Exercise the built rm shim in a disposable sandbox: shim_regression.py PATH."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: sudo python3 tests/shim_regression.py path/to/trashd-rm")
    binary = Path(sys.argv[1]).resolve(strict=True)
    if os.environ.get("TRASHD_TEST_SANDBOX") != "1":
        runner = Path(__file__).resolve().with_name("sandbox.py")
        os.execv(sys.executable, [
            sys.executable, str(runner), "--binary", f"trashd-rm={binary}", "--",
            "/usr/bin/python3", "/tests/shim_regression.py", "/opt/trashd/bin/trashd-rm",
        ])
    from sandbox import require_sandbox
    require_sandbox()

    cases = [
        (["-rI"], True, 1),
        (["-r", "-I"], True, 3),
        (["--recursive", "--interactive=once"], True, 1),
        (["-frI"], True, 1),
        (["--force", "--recursive", "--interactive=once"], True, 1),
        (["-r", "--recursive", "-R", "-I"], True, 1),
        (["-fi"], False, 1),
        (["-f", "-i"], False, 1),
        (["--force", "--interactive"], False, 1),
        (["-ff", "--interactive=always"], False, 1),
        (["--interactive=once", "--interactive=always"], False, 1),
        (["-I"], False, 4),
    ]
    with tempfile.TemporaryDirectory(prefix="shim-regression-", dir="/work") as temporary:
        root = Path(temporary)
        env = dict(os.environ, HOME=str(root / "home"), XDG_DATA_HOME=str(root / "data"), XDG_CONFIG_HOME=str(root / "config"))
        for key in ("TRASH_BYPASS", "LD_PRELOAD", "TRASHD_SECCOMP_ACTIVE"):
            env.pop(key, None)

        def run(args):
            return subprocess.run([str(binary), *map(str, args)], input="n\n", text=True, capture_output=True, env=env, cwd=root, timeout=10)

        for i, (flags, directory, count) in enumerate(cases):
            operands = []
            for j in range(count):
                operand = root / f"operand-{i}-{j}"
                if directory:
                    operand.mkdir()
                    (operand / "keep").write_bytes(b"precious")
                else:
                    operand.write_bytes(b"precious")
                operands.append(operand)
            result = run([*flags, *operands])
            assert result.returncode == 0, (flags, result.stderr)
            # GNU rm uses a different prompt: require ours so a bypass cannot
            # accidentally turn this into a test of the system rm binary.
            assert "[y/N]" in result.stderr, (flags, "shim prompt absent", result.stderr)
            for operand in operands:
                assert (operand / "keep" if directory else operand).read_bytes() == b"precious", (flags, operand)
            print("PASS: declined", " ".join(flags), f"({count} operands)")

        for flags in [
            ["-ff"], ["-r", "--recursive"], ["-rRr"], ["-vv", "--verbose"],
            ["-dd", "--dir"], ["-iiII"], ["--force", "--force"],
            ["--one-file-system", "--one-file-system"],
            ["--preserve-root=all", "--preserve-root=all"],
            ["--no-preserve-root", "--no-preserve-root"],
        ]:
            result = run([*flags, "--version"])
            assert result.returncode == 0 and "trashd rm shim" in result.stdout, (flags, result.stdout, result.stderr)
        print("PASS: 10 repeated-option cases execute the shim")

        # GNU semantics (#117): ignore_missing_files is set by -f and never
        # cleared by interaction flags, so EVERY -f-led form exits 0 silently
        # for a missing operand; interaction only governs prompting of files
        # that exist.
        for flags, status in [
            (["-f", "-i"], 0), (["-i", "-f"], 0),
            (["-f", "--interactive=never"], 0),
            (["-f", "--interactive=always", "--interactive=never"], 0),
        ]:
            result = run([*flags, root / "not-present"])
            assert result.returncode == status, (flags, result.returncode, result.stderr)
        print("PASS: 4 missing-file force/interaction order cases")

        # A caller that ignores SIGCHLD (WSL's login hands one to every shell)
        # lets the kernel reap the real rm before the shim can wait for it.
        # The shim must still accept the genuine rm and report its status.
        def ignore_sigchld():
            import signal
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        def run_ignoring_sigchld(args):
            return subprocess.run([str(binary), *map(str, args)], text=True, capture_output=True, env=env, cwd=root, timeout=10, preexec_fn=ignore_sigchld)
        operand = root / "permanent-ignored-sigchld"
        operand.write_bytes(b"permanently removed")
        result = run_ignoring_sigchld(["--permanent", operand])
        assert result.returncode == 0 and not operand.exists(), result.stderr
        result = run_ignoring_sigchld(["--permanent", root / "not-present"])
        assert result.returncode == 1 and "trashd" not in result.stderr, result.stderr
        print("PASS: --permanent with ignored SIGCHLD reports the real rm's status")

        # Accepted custom long-option abbreviations must be stripped before
        # real rm, while identical operands after -- are kept (#272).
        for flag in ["--perm", "--no-t"]:
            operand = root / f"abbreviated-{flag[2:]}"
            operand.write_bytes(b"permanently removed")
            named_like_option = root / flag
            named_like_option.write_bytes(b"also permanently removed")
            result = run([flag, operand, "--", flag])
            assert result.returncode == 0, (flag, result.stderr)
            assert not operand.exists() and not named_like_option.exists(), flag
            assert not list((root / "data/Trash/info").glob(operand.name + "*.trashinfo")), flag
        print("PASS: abbreviated bypass flags preserve post-separator operands")

        for flag in ["--permanent", "--no-trash", "--perm", "--no-t"]:
            operand = root / f"env-bypassed-{flag[2:]}"
            operand.write_bytes(b"permanently removed")
            named_like_option = root / flag
            named_like_option.write_bytes(b"also permanently removed")
            result = subprocess.run([str(binary), flag, str(operand), "--", flag],
                                    env=dict(env, TRASH_BYPASS="1"), cwd=root,
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, (flag, result.stderr)
            assert not operand.exists() and not named_like_option.exists(), flag
        print("PASS: environment bypass accepts custom flags and preserves post-separator operands")

        # A stashed real-rm fixture records arguments that the shim parser
        # would reject. Environment bypass must still pass those through,
        # including ambiguous prefixes that are not custom options (#276).
        import shutil
        prefix = root / "passthrough-prefix"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "real").mkdir()
        fixture_shim = prefix / "bin/rm"
        shutil.copy2(binary, fixture_shim)
        fixture_rm = prefix / "real/rm"
        fixture_rm.write_text("#!/usr/bin/python3\nimport json,sys\n"
                              "print('rm fixture' if sys.argv[1:] == ['--version'] "
                              "else json.dumps(sys.argv[1:]))\n")
        fixture_rm.chmod(0o755)
        raw_name = os.fsdecode(b"raw-\xff")
        forwarded = ["--real-only-option", "--p", "--no", "--no-preserve-root",
                     "--", "--permanent", raw_name]
        result = subprocess.run([str(fixture_shim), "--perm", "--no-trash", *forwarded],
                                env=dict(env, TRASH_BYPASS="1"), cwd=root,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and json.loads(result.stdout) == forwarded, result
        print("PASS: environment bypass forwards real-rm-only options, ambiguous prefixes and raw names")

        for name, flags, directory in [
            ("repeated-force", ["-ff"], False),
            ("repeated-recursive", ["-r", "--recursive"], True),
            ("repeated-force-recursive", ["-rf", "-f"], True),
            ("recursive-short-alias", ["-rR"], True),
        ]:
            operand = root / name
            if directory:
                operand.mkdir()
                (operand / "keep").write_bytes(b"recoverable")
            else:
                operand.write_bytes(b"recoverable")
            result = run([*flags, operand])
            assert result.returncode == 0 and not operand.exists(), (flags, result.stderr)
            matches = list((root / "data/Trash/files").glob(name + "*"))
            assert len(matches) == 1, (flags, "permanent deletion or wrong trash destination", matches)
            stored = matches[0] / "keep" if directory else matches[0]
            assert stored.read_bytes() == b"recoverable"
        print("PASS: repeated force/recursive flags retain actual recoverable trash data")

        # -d permits empty directories in addition to ordinary files and
        # symlinks; it is not a directory-only operation (#268). Compare the
        # system rm for protected paths and never_trash fallback paths.
        link_target = root / "dir-flag-link-target"
        link_target.write_bytes(b"target survives")
        dir_target = root / "dir-flag-dir-target"
        dir_target.mkdir()
        (dir_target / "keep").write_bytes(b"target directory survives")
        for excluded in [False, True]:
            for kind in ["file", "file-link", "dir-link", "dangling", "empty-dir", "full-dir"]:
                suffix = ".tmp" if excluded else ""
                operands = [root / f"{tool}-dir-flag-{kind}{suffix}" for tool in ["system", "shim"]]
                for operand in operands:
                    if kind == "file":
                        operand.write_bytes(b"recoverable")
                    elif kind in ["empty-dir", "full-dir"]:
                        operand.mkdir()
                        if kind == "full-dir":
                            (operand / "keep").write_bytes(b"must remain")
                    else:
                        target = {"file-link": link_target, "dir-link": dir_target,
                                  "dangling": root / "missing-link-target"}[kind]
                        operand.symlink_to(target)
                system_rm = subprocess.run(["/usr/bin/rm", "-d", str(operands[0])],
                                           env=dict(env, TRASH_BYPASS="1"), capture_output=True)
                result = run(["-d", operands[1]])
                assert result.returncode == system_rm.returncode, (kind, excluded, result.stderr, system_rm.stderr)
                assert os.path.lexists(operands[1]) == os.path.lexists(operands[0]), (kind, excluded)
                if kind == "full-dir":
                    assert (operands[1] / "keep").read_bytes() == b"must remain"
                stored = list((root / "data/Trash/files").glob(operands[1].name + "*"))
                assert len(stored) == int(not excluded and kind != "full-dir"), (kind, excluded, stored)
                if stored:
                    if kind == "file":
                        assert stored[0].read_bytes() == b"recoverable"
                    elif kind == "empty-dir":
                        assert stored[0].is_dir() and not list(stored[0].iterdir())
                    else:
                        assert stored[0].is_symlink() and os.readlink(stored[0]) == str(target)
        assert link_target.read_bytes() == b"target survives"
        assert (dir_target / "keep").read_bytes() == b"target directory survives"
        print("PASS: -d matches system rm for files, links and directories, including excluded paths")

        # A trailing slash makes rm operate on a symlink's TARGET. Policy must
        # be evaluated on that target too: a link in never-trash /tmp used to
        # make the shim permanently delete the protected directory (#190).
        decoy = root / "decoy"
        decoy.mkdir()
        (decoy / "keep").write_bytes(b"recoverable")
        link = Path("/tmp/decoy-link")
        link.symlink_to(decoy)
        result = run(["-rf", f"{link}/"])
        assert result.returncode == 0 and not decoy.exists(), result.stderr
        matches = list((root / "data/Trash/files").glob("decoy*"))
        assert len(matches) == 1, ("target permanently deleted instead of trashed", matches)
        assert (matches[0] / "keep").read_bytes() == b"recoverable"
        link.unlink()
        print("PASS: trailing-slash symlink operands are trashed by their target's policy")

        # Raw terminal dots must be refused before normalization, even -f.
        for spelling in ["dot/.", "dot/./", "dot/..//"]:
            folder = root / "dot"
            folder.mkdir(exist_ok=True); (folder / "keep").write_bytes(b"precious")
            result = run(["-rf", spelling])
            assert result.returncode != 0 and (folder / "keep").read_bytes() == b"precious", (spelling, result.stderr)
        print("PASS: raw terminal-dot operands are refused")

        # Compare protected and excluded branches with genuine GNU partial
        # removal, on distinct tmpfs descendants of disposable operand trees.
        for excluded in [False, True]:
            base = Path("/tmp") if excluded else root
            operands = [base / ("boundary-" + ("gnu" if i else "shim")) for i in range(2)]
            try:
                for operand in operands:
                    operand.mkdir()
                    (operand / "foreign").mkdir()
                    (operand / "same").write_bytes(b"recoverable")
                    subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(operand / "foreign")], check=True)
                    (operand / "foreign/keep").write_bytes(b"foreign survives")
                ours = run(["-rf", "--one-file-system", operands[0]])
                gnu_env = dict(env, TRASH_BYPASS="1")
                oracle = subprocess.run(["/usr/bin/rm", "-rf", "--one-file-system", str(operands[1])], env=gnu_env, capture_output=True)
                assert ours.returncode == oracle.returncode != 0, (ours.stderr, oracle.stderr)
                for operand in operands:
                    assert not (operand / "same").exists()
                    assert (operand / "foreign/keep").read_bytes() == b"foreign survives"
                if not excluded:
                    records = list((root / "data/Trash/info").glob("*.trashinfo"))
                    assert any(str(operands[0] / "same") in record.read_text() for record in records)
            finally:
                for operand in operands:
                    if (operand / "foreign").is_mount():
                        subprocess.run(["/usr/bin/umount", str(operand / "foreign")], check=True)
            print("PASS: GNU filesystem boundary behavior", "excluded" if excluded else "protected")


if __name__ == "__main__":
    main()
