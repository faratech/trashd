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

        # The stash probe's verdict is remembered per user while the stash
        # keeps its identity: one probe, not one per passthrough.
        probes = root / "probes.log"
        def counting_fixture(version):
            fixture_rm.write_text("#!/usr/bin/python3\nimport json,sys\n"
                                  "if sys.argv[1:] == ['--version']:\n"
                                  f"    open({str(probes)!r}, 'a').write('probe\\n'); print({version!r})\n"
                                  "else: print(json.dumps(sys.argv[1:]))\n")
            fixture_rm.chmod(0o755)
        counting_fixture("rm fixture")
        cache_env = dict(env, TRASH_BYPASS="1", XDG_CACHE_HOME=str(root / "cache"))
        def passthrough():
            return subprocess.run([str(fixture_shim), "--", "x"], env=cache_env, cwd=root,
                                  capture_output=True, text=True, timeout=10)
        for _ in range(3):
            result = passthrough()
            assert result.returncode == 0 and json.loads(result.stdout) == ["--", "x"], result
        assert probes.read_text().count("probe") == 1, probes.read_text()
        assert (root / "cache/trashd/real-rm-probes").stat().st_mode & 0o777 == 0o600
        # A replaced stash is probed again; a shim copy is never trusted.
        counting_fixture("trashd rm shim (copy)")
        result = passthrough()
        assert "rm fixture" not in result.stdout and probes.read_text().count("probe") == 2, (result, probes.read_text())
        passthrough()
        assert probes.read_text().count("probe") == 2, probes.read_text()
        print("PASS: stash probe verdicts are reused until the stash changes")
        # Only a completed probe is remembered: a killed one (like one that
        # never started) says nothing about the binary (#339).
        killed = root / "probe-killed"
        fixture_rm.write_text("#!/usr/bin/python3\nimport json,os,sys\n"
                              "if sys.argv[1:] == ['--version']:\n"
                              f"    open({str(probes)!r}, 'a').write('probe\\n')\n"
                              f"    if os.path.exists({str(killed)!r}): os.kill(os.getpid(), 9)\n"
                              "    print('rm fixture')\n"
                              "else: print(json.dumps(sys.argv[1:]))\n")
        fixture_rm.chmod(0o755)
        killed.touch()
        count = probes.read_text().count("probe")
        passthrough()
        killed.unlink()
        result = passthrough()
        assert probes.read_text().count("probe") == count + 2, probes.read_text()
        assert json.loads(result.stdout) == ["--", "x"], result
        passthrough()
        assert probes.read_text().count("probe") == count + 2, probes.read_text()
        print("PASS: an interrupted stash probe is not remembered")
        # A symlinked cache base still caches, and a genuine rm that rejects
        # --version (busybox) is remembered as real (#352).
        real_cache = root / "real-cache"
        real_cache.mkdir()
        linked = root / "linked-cache"
        linked.symlink_to(real_cache)
        fixture_rm.write_text("#!/usr/bin/python3\nimport json,sys\n"
                              "if sys.argv[1:] == ['--version']:\n"
                              f"    open({str(probes)!r}, 'a').write('probe\\n'); sys.exit(1)\n"
                              "print(json.dumps(sys.argv[1:]))\n")
        fixture_rm.chmod(0o755)
        count = probes.read_text().count("probe")
        linked_env = dict(cache_env, XDG_CACHE_HOME=str(linked))
        for _ in range(2):
            result = subprocess.run([str(fixture_shim), "--", "x"], env=linked_env, cwd=root,
                                    capture_output=True, text=True, timeout=10)
            assert json.loads(result.stdout) == ["--", "x"], result
        assert probes.read_text().count("probe") == count + 1, probes.read_text()
        assert (real_cache / "trashd/real-rm-probes").read_text().startswith("real "), "verdict"
        print("PASS: symlinked caches and --version-rejecting rm binaries are remembered")

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

        # -f ignores operands through a non-directory (ENOTDIR), like rm.
        plain = root / "plain"
        plain.write_bytes(b"x")
        quiet = run(["-f", plain / "x"])
        oracle = subprocess.run(["/usr/bin/rm", "-f", str(plain / "x")], env=dict(env, TRASH_BYPASS="1"), capture_output=True)
        assert quiet.returncode == oracle.returncode == 0 and quiet.stderr == "", quiet.stderr
        assert run([plain / "x"]).returncode == 1 and plain.exists()
        print("PASS: -f ignores ENOTDIR operands")

        # -d on a directory the caller cannot list: only rmdir(2) knows it is
        # not empty; the shim used to trash it with its unseen contents.
        # The temporary root is 0700: nobody must reach its fixtures, or
        # both rm and the shim fail before ever seeing the directory.
        root.chmod(0o711)
        nobody = root / "nobody"
        nobody.mkdir()
        os.chown(nobody, 65534, 65534)
        unlistable = nobody / "unlistable"
        unlistable.mkdir()
        (unlistable / "secret").write_bytes(b"keep")
        os.chown(unlistable, 65534, 65534)
        unlistable.chmod(0o300)
        def as_nobody():
            os.setgroups([]); os.setgid(65534); os.setuid(65534)
        nobody_env = dict(env, HOME=str(nobody), XDG_DATA_HOME=str(nobody / "data"), XDG_CONFIG_HOME=str(nobody / "config"))
        ours = subprocess.run([str(binary), "-d", str(unlistable)], env=nobody_env, cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
        oracle = subprocess.run(["/usr/bin/rm", "-d", str(unlistable)], env=dict(nobody_env, TRASH_BYPASS="1"), cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
        unlistable.chmod(0o700)
        assert ours.returncode == oracle.returncode == 1, (ours.stderr, oracle.stderr)
        assert "not empty" in ours.stderr and "not empty" in oracle.stderr, (ours.stderr, oracle.stderr)
        assert (unlistable / "secret").read_bytes() == b"keep"
        assert not list((nobody / "data/Trash/info").glob("*.trashinfo")) if (nobody / "data/Trash/info").exists() else True
        print("PASS: -d on an unlistable non-empty directory refuses like rm")

        # -ri confirms every entry, as rm does, instead of one prompt for the tree.
        def interactive(answers, tree):
            return subprocess.run([str(binary), "-ri", str(tree)], input=answers, text=True, capture_output=True, env=env, cwd=root, timeout=10)
        tree = root / "interactive-tree"
        (tree / "sub").mkdir(parents=True)
        for name in ("a", "sub/b"):
            (tree / name).write_bytes(b"keep")
        declined = interactive("y\n" + "n\n" * 10, tree)
        assert declined.returncode == 0, declined.stderr
        assert declined.stderr.count("? [y/N]") >= 3, declined.stderr
        assert (tree / "a").read_bytes() == (tree / "sub/b").read_bytes() == b"keep"
        assert "/proc/self/fd" not in declined.stderr, declined.stderr
        assert f"descend into directory '{tree}'" in declined.stderr, declined.stderr
        # Declining one entry keeps it and its directory; the confirmed
        # subtree is one trash entry.
        info = root / "data/Trash/info"
        before = set(info.glob("*.trashinfo"))
        def drive(tree, decline, flags=("-ri",), before_answer=None, program=None):
            # Answer each prompt by its text: listing order is arbitrary.
            command = [program or str(binary), *flags, str(tree)]
            proc = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=root)
            transcript, prompt = b"", b""
            while True:
                byte = proc.stderr.read(1)
                if not byte:
                    break
                transcript += byte
                prompt += byte
                if prompt.endswith(b"? [y/N] ") or (program and prompt.endswith(b"? ")):
                    text = prompt.decode()
                    if before_answer:
                        before_answer(text)
                    answer = b"n\n" if decline and decline in text else b"y\n"
                    prompt = b""
                    proc.stdin.write(answer)
                    proc.stdin.flush()
            return proc.wait(timeout=10), transcript.decode()
        # Like rm, a declined entry still leaves its directory asked about,
        # and removing it then fails as not empty (#351).
        status, transcript = drive(tree, f"'{tree / 'a'}'")
        assert status == 1 and "Directory not empty" in transcript, transcript
        assert (tree / "a").read_bytes() == b"keep" and not (tree / "sub").exists(), transcript
        assert f"remove directory '{tree}'" in transcript, transcript
        added = [record.read_text() for record in set(info.glob("*.trashinfo")) - before]
        assert len(added) == 1 and f"Path={tree / 'sub'}\n" in added[0], added
        (tree / "sub").mkdir(); (tree / "sub/b").write_bytes(b"keep")
        # A fully confirmed tree is one entry that undo restores whole.
        before = set(info.glob("*.trashinfo"))
        accepted = interactive("y\n" * 10, tree)
        assert accepted.returncode == 0 and not tree.exists(), accepted.stderr
        added = [record.read_text() for record in set(info.glob("*.trashinfo")) - before]
        assert len(added) == 1 and f"Path={tree}\n" in added[0], added
        print("PASS: -ri prompts for each entry and trashes confirmed subtrees whole")

        # Answers are carried out only on what was confirmed: an entry that
        # appears before the last answer stays, never-trash or not (#351).
        for name in ["late-plan", "late-plan.tmp"]:
            tree = root / name
            (tree / "sub").mkdir(parents=True)
            (tree / "a").write_bytes(b"confirmed"); (tree / "sub/b").write_bytes(b"confirmed")
            def arrive(prompt, tree=tree):
                if f"remove directory '{tree}'" in prompt:
                    (tree / "late").write_bytes(b"never confirmed")
                    (tree / "sub/late").write_bytes(b"never confirmed")
            status, transcript = drive(tree, None, before_answer=arrive)
            assert status == 1 and "Directory not empty" in transcript, transcript
            assert (tree / "late").read_bytes() == (tree / "sub/late").read_bytes() == b"never confirmed", transcript
            assert not (tree / "a").exists() and not (tree / "sub/b").exists(), transcript
        print("PASS: -ri acts only on the entries it confirmed")

        # A confirmed directory mounted over during the prompts (a bind keeps
        # its identity) is emptied of what was confirmed and stays, busy; it
        # never travels into the trash (#362).
        tree = root / "mounted-over"
        (tree / "d").mkdir(parents=True)
        (tree / "d/x").write_bytes(b"x"); (tree / "f").write_bytes(b"x")
        def bind_over(prompt, tree=tree):
            if f"remove directory '{tree}'?" in prompt:
                subprocess.run(["/usr/bin/mount", "--bind", str(tree / "d"), str(tree / "d")], check=True)
        try:
            status, transcript = drive(tree, None, before_answer=bind_over)
            assert (tree / "d").is_dir() and not (tree / "d/x").exists(), transcript
            assert "busy" in transcript and status != 0, transcript
            # Like rm, its directories stay without another message (#363).
            assert "not empty" not in transcript, transcript
        finally:
            subprocess.run(["/usr/bin/umount", str(tree / "d")], check=False)
        print("PASS: -ri never moves a directory mounted over since it was confirmed")

        # Under -f, entries that vanish after confirmation are not errors.
        tree = root / "vanishing"
        tree.mkdir(); (tree / "a").write_bytes(b"x"); (tree / "b").write_bytes(b"x")
        def vanish(prompt, tree=tree):
            if f"remove directory '{tree}'" in prompt:
                os.unlink(tree / "a")
        status, transcript = drive(tree, None, flags=("-rf", "-i"), before_answer=vanish)
        assert status == 0 and "cannot remove" not in transcript and not tree.exists(), transcript
        print("PASS: -rfi ignores entries that vanish after confirmation")

        # The prompt sequence matches GNU rm where it is installed: a declined
        # file, a declined empty directory (#355) and every file kind's name.
        gnu = Path("/usr/bin/gnurm")
        if gnu.exists():
            def build_declined_file(tree):
                (tree / "sub").mkdir(parents=True)
                (tree / "a").write_bytes(b"x"); (tree / "sub/b").write_bytes(b"x")
                return "'" + str(tree / "a") + "'"
            def build_declined_empty(tree):
                (tree / "e").mkdir(parents=True); (tree / "s/e").mkdir(parents=True)
                (tree / "a").write_bytes(b"x")
                return "/e'"
            def build_kinds(tree):
                tree.mkdir()
                (tree / "empty").write_bytes(b""); (tree / "full").write_bytes(b"x")
                os.mkfifo(tree / "fifo"); (tree / "link").symlink_to("full")
                return "'" + str(tree) + "'?"
            for case, build in [("file", build_declined_file), ("empty", build_declined_empty), ("kinds", build_kinds)]:
                transcripts = []
                for program in [None, str(gnu)]:
                    tree = root / (f"gnu-{case}-" + ("gnu" if program else "shim"))
                    decline = build(tree)
                    status, transcript = drive(tree, decline, program=program)
                    prompts = [line.split(": ", 1)[1].replace(str(tree), "T").replace(" [y/N]", "")
                               for line in transcript.replace("? ", "?\n").splitlines() if line.endswith("?")]
                    left = sorted(str(p.relative_to(tree)) for p in tree.rglob("*")) if tree.exists() else None
                    transcripts.append((status, sorted(prompts), left))
                assert transcripts[0] == transcripts[1], (case, transcripts)
            # -I asks in GNU's words.
            questions = []
            for program in [str(binary), str(gnu)]:
                tree = root / ("gnu-once-" + ("gnu" if program == str(gnu) else "shim"))
                tree.mkdir(); (tree / "x").write_bytes(b"x")
                for flags in [["-rI", str(tree)], ["-I", *(str(tree / n) for n in "abcd")]]:
                    result = subprocess.run([program, *flags], input="n\n", text=True, capture_output=True, env=env, cwd=root, timeout=10)
                    questions.append(result.stderr.split(": ", 1)[1].replace(" [y/N]", "").replace(str(tree), "T").strip())
            assert questions[:2] == questions[2:], questions
            print("PASS: -ri and -I prompts and outcomes match GNU rm")

            # Other filesystems under --one-file-system (#357, #358): an empty
            # mount is offered for removal, one with entries for descent, a
            # file bind-mounted from another filesystem like any file; all
            # stay, and nothing around them is moved with them.
            source_fs = root / "bind-source-fs"
            source_fs.mkdir()
            subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(source_fs)], check=True)
            (source_fs / "source").write_bytes(b"bound")
            def mounted_tree(tree, parts):
                tree.mkdir(parents=True)
                (tree / "f").write_bytes(b"x"); (tree / "g").write_bytes(b"x")
                mounts = []
                for part in parts:
                    target = tree / part
                    if part == "bound":
                        target.write_bytes(b"")
                        subprocess.run(["/usr/bin/mount", "--bind", str(source_fs / "source"), str(target)], check=True)
                    elif part == "samefile":
                        # Bind mounts from the tree's own filesystem (#358).
                        source = tree.parent / (tree.name + "-same-source")
                        source.write_bytes(b"same")
                        target.write_bytes(b"")
                        subprocess.run(["/usr/bin/mount", "--bind", str(source), str(target)], check=True)
                    elif part == "sameempty":
                        source = tree.parent / (tree.name + "-same-empty")
                        source.mkdir()
                        target.mkdir()
                        subprocess.run(["/usr/bin/mount", "--bind", str(source), str(target)], check=True)
                    elif part == "samedir":
                        source = tree.parent / (tree.name + "-same-dir")
                        source.mkdir(); (source / "inside").write_bytes(b"x")
                        target.mkdir()
                        subprocess.run(["/usr/bin/mount", "--bind", str(source), str(target)], check=True)
                    else:
                        target.mkdir()
                        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(target)], check=True)
                        if part == "full":
                            (target / "inner").write_bytes(b"x")
                    mounts.append(target)
                return mounts
            try:
                for flags, parts in [
                    (("-ri", "--one-file-system"), ["empty", "full", "bound"]),
                    (("-ri", "--one-file-system"), ["empty"]),
                    (("-ri", "--one-file-system"), ["bound"]),
                    (("-r", "--one-file-system"), ["bound"]),
                    (("-r", "--one-file-system"), ["empty", "full"]),
                    (("-r", "--one-file-system"), ["samefile"]),
                    (("-ri", "--one-file-system"), ["samefile"]),
                    (("-r", "--one-file-system"), ["samedir"]),
                    (("-ri", "--one-file-system"), ["samedir"]),
                    (("-ri", "--one-file-system"), ["sameempty"]),
                    (("-ri",), ["sameempty"]),
                ]:
                    outcomes = []
                    for program in [None, str(gnu)]:
                        tree = root / ("gnu-mounts-" + "-".join(parts) + "-" + "".join(flags).replace("-", "") + ("-gnu" if program else "-shim"))
                        mounts = mounted_tree(tree, parts)
                        try:
                            if "-ri" in flags:
                                decline = "/sameempty'" if "sameempty" in parts else None
                                status, transcript = drive(tree, decline, flags=flags, program=program)
                            else:
                                result = subprocess.run([program or str(binary), *flags, str(tree)], text=True, capture_output=True, env=env, cwd=root, timeout=10)
                                status, transcript = result.returncode, result.stderr
                            prompts = [line.split(": ", 1)[1].replace(str(tree), "T").replace(" [y/N]", "")
                                       for line in transcript.replace("? ", "?\n").splitlines() if line.endswith("?")]
                            left = sorted(str(p.relative_to(tree)) for p in tree.rglob("*")) if tree.exists() else None
                            outcomes.append((sorted(prompts), left, "busy" in transcript or "different device" in transcript))
                        finally:
                            for mount in mounts:
                                subprocess.run(["/usr/bin/umount", str(mount)], check=False)
                    # A same-filesystem bind mount is a mount all the same: only
                    # -i empties one GNU's device check would cross (#368).
                    if "samedir" in parts and "-ri" not in flags:
                        outcomes[1] = (outcomes[1][0], sorted(outcomes[1][1] + ["samedir/inside"]), outcomes[1][2])
                    assert outcomes[0] == outcomes[1], (flags, parts, outcomes)
            finally:
                subprocess.run(["/usr/bin/umount", str(source_fs)], check=False)
            # A mounted directory never moves, but the size limit still refuses
            # it; only its own topdir trash inside it does not (#361).
            limit_config = root / "limit-config/trashd"
            limit_config.mkdir(parents=True)
            (limit_config / "config.toml").write_text("max_dir_size_mb = 1\n")
            limit_env = dict(env, XDG_CONFIG_HOME=str(root / "limit-config"))
            limited = root / "limited"
            (limited / "m").mkdir(parents=True)
            subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(limited / "m")], check=True)
            try:
                for i in range(3):
                    (limited / f"m/part{i}").mkdir()
                    (limited / f"m/part{i}/data").write_bytes(b"x" * 700 * 1024)
                result = subprocess.run([str(binary), "-r", "--one-file-system", str(limited / "m")],
                                        text=True, capture_output=True, env=limit_env, cwd=root, timeout=10)
                assert result.returncode != 0 and all((limited / f"m/part{i}/data").exists() for i in range(3)), result.stderr
                own_trash = limited / "m" / f".Trash-{os.geteuid()}"
                own_trash.mkdir(mode=0o700)
                for i in range(3):
                    (limited / f"m/part{i}/data").write_bytes(b"small")
                result = subprocess.run([str(binary), "-r", "--one-file-system", str(limited / "m")],
                                        text=True, capture_output=True, env=env, cwd=root, timeout=10)
                assert not any((limited / f"m/part{i}").exists() for i in range(3)), result.stderr
                assert len(list((own_trash / "info").glob("*.trashinfo"))) == 3, result.stderr
                # The mount and its trash stay; only the trash itself is refused.
                refused = [line for line in result.stderr.splitlines() if "refusing" in line]
                assert refused and all(own_trash.name in line for line in refused), result.stderr
            finally:
                subprocess.run(["/usr/bin/umount", str(limited / "m")], check=False)
            # A tree holding a mount moves whole or not at all: plain rm -r
            # refuses it and moves nothing. A mounted operand is emptied into
            # its own trash and stays busy, as GNU rm leaves it (#366, #368).
            plain_outcomes = []
            for program in [None, str(gnu)]:
                tree = root / ("plain-mounts-" + ("gnu" if program else "shim"))
                (tree / "sub").mkdir(parents=True)
                (tree / "f").write_bytes(b"x"); (tree / "sub/g").write_bytes(b"x")
                (tree / "f.lock").write_bytes(b"x")
                (tree / "m").mkdir(); (tree / "bound").write_bytes(b"")
                operand = root / ("plain-operand-" + ("gnu" if program else "shim"))
                operand.mkdir()
                bind_source = root / ("plain-bind-source-" + ("gnu" if program else "shim"))
                bind_source.write_bytes(b"source")
                mounts = [tree / "m", tree / "bound", operand]
                subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(tree / "m")], check=True)
                (tree / "m/inner").write_bytes(b"x")
                subprocess.run(["/usr/bin/mount", "--bind", str(bind_source), str(tree / "bound")], check=True)
                subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(operand)], check=True)
                (operand / "inside").write_bytes(b"x")
                try:
                    outcome = []
                    for target in [tree, operand]:
                        before = sorted(str(p.relative_to(target)) for p in target.rglob("*"))
                        result = subprocess.run([program or str(binary), "-r", str(target)], text=True,
                                                capture_output=True, env=env, cwd=root, timeout=10)
                        left = sorted(str(p.relative_to(target)) for p in target.rglob("*")
                                      if not any(part.startswith(".Trash") for part in p.relative_to(target).parts))
                        if program is None and target == tree:
                            assert result.returncode == 1 and left == before, (left, result.stderr)
                            assert "holds a mount point, 'm' inside it" in result.stderr or "holds a mount point, 'bound' inside it" in result.stderr, result.stderr
                            assert result.stderr.count("\n") == 1, result.stderr
                            continue
                        outcome.append((result.returncode, left, result.stderr.count("busy")))
                    plain_outcomes.append(outcome)
                finally:
                    for mount in mounts:
                        subprocess.run(["/usr/bin/umount", str(mount)], check=False)
            assert plain_outcomes[0] == plain_outcomes[1][1:], plain_outcomes
            # Inside a mounted operand, another mount stays as it is, and so
            # does a directory holding one; only the mount points are
            # reported (#368).
            nested = root / "nested-operand"
            nested.mkdir()
            subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(nested)], check=True)
            try:
                (nested / "a").write_bytes(b"x")
                (nested / "m").mkdir(); (nested / "sub/m2").mkdir(parents=True)
                (nested / "sub/b").write_bytes(b"x")
                subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(nested / "m")], check=True)
                subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(nested / "sub/m2")], check=True)
                (nested / "m/inner").write_bytes(b"x"); (nested / "sub/m2/inner").write_bytes(b"x")
                result = subprocess.run([str(binary), "-r", str(nested)], text=True,
                                        capture_output=True, env=env, cwd=root, timeout=10)
                left = sorted(str(p.relative_to(nested)) for p in nested.rglob("*")
                              if not any(part.startswith(".Trash") for part in p.relative_to(nested).parts))
                assert result.returncode == 1 and left == ["m", "m/inner", "sub", "sub/b", "sub/m2", "sub/m2/inner"], (left, result.stderr)
                reported = sorted(line.split("'")[1].replace(str(nested), "N") for line in result.stderr.splitlines())
                assert reported == ["N/m", "N/sub"], result.stderr
            finally:
                for mount in [nested / "sub/m2", nested / "m", nested]:
                    subprocess.run(["/usr/bin/umount", str(mount)], check=False)
            # Nothing on a read-only filesystem is copied into the trash only
            # to stay where it is (#368).
            readonly = root / "readonly-fs"
            readonly.mkdir()
            subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(readonly)], check=True)
            try:
                (readonly / "dir").mkdir(); (readonly / "dir/f").write_bytes(b"x"); (readonly / "file").write_bytes(b"x")
                subprocess.run(["/usr/bin/mount", "-o", "remount,ro", str(readonly)], check=True)
                home_files = root / "data/Trash/files"
                before = sorted(home_files.iterdir()) if home_files.exists() else []
                for args in [[str(readonly / "file")], ["-r", str(readonly / "dir")], ["-r", str(readonly)]]:
                    result = subprocess.run([str(binary), *args], text=True, capture_output=True, env=env, cwd=root, timeout=10)
                    # Like GNU, only what could not be removed is reported.
                    assert result.returncode == 1 and "Read-only file system" in result.stderr, (args, result.stderr)
                    assert "busy" not in result.stderr and "not empty" not in result.stderr, (args, result.stderr)
                    after = sorted(home_files.iterdir()) if home_files.exists() else []
                    assert after == before, (args, after)
                assert (readonly / "dir/f").exists() and (readonly / "file").exists()
            finally:
                subprocess.run(["/usr/bin/umount", str(readonly)], check=False)
            # Mount points rm cannot remove either are reported as GNU rm
            # reports them, and nothing is prepared inside them: a
            # bind-mounted file (on home's filesystem and on another), an
            # empty mount under -d (asked about first under -i), and a mount
            # inside an excluded tree, around which the rest still goes. Its
            # contents stay, where GNU rm empties it (#368).
            exclude_config = root / "exclude-config/trashd"
            exclude_config.mkdir(parents=True)
            (exclude_config / "config.toml").write_text(f'never_trash = ["{root}/excluded-*"]\n')
            exclude_env = dict(env, XDG_CONFIG_HOME=str(root / "exclude-config"))
            busy_outcomes = []
            for program in [None, str(gnu)]:
                suffix = "gnu" if program else "shim"
                source = root / f"busy-source-{suffix}"; source.write_bytes(b"source")
                bound = root / f"busy-bound-{suffix}"; bound.write_bytes(b"")
                other = root / f"busy-other-{suffix}"; other.mkdir()
                empty = root / f"busy-empty-{suffix}"; empty.mkdir()
                excluded = root / f"excluded-{suffix}"
                for part in ["a", "m", "z"]:
                    (excluded / part).mkdir(parents=True)
                (excluded / "a/f").write_bytes(b"x"); (excluded / "z/f").write_bytes(b"x")
                mounts = [bound, other / "bound", other, empty, excluded / "m"]
                subprocess.run(["/usr/bin/mount", "--bind", str(source), str(bound)], check=True)
                subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(other)], check=True)
                (other / "bound").write_bytes(b"")
                subprocess.run(["/usr/bin/mount", "--bind", str(source), str(other / "bound")], check=True)
                subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(empty)], check=True)
                subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(excluded / "m")], check=True)
                (excluded / "m/inner").write_bytes(b"x")
                try:
                    outcome = []
                    for args, answer in [([str(bound)], None), ([str(other / "bound")], None), (["-d", str(empty)], None),
                                         (["-di", str(empty)], "n\n"), (["-di", str(empty)], "y\n"), (["-r", str(excluded)], None)]:
                        result = subprocess.run([program or str(binary), *args], text=True, capture_output=True,
                                                input=answer, env=exclude_env, cwd=root, timeout=10)
                        # A prompt and the message after it share a line.
                        lines = [line.rsplit("? ", 1)[-1].removeprefix("[y/N] ") for line in result.stderr.splitlines()]
                        messages = [line.split(": ", 1)[1].replace(str(root), "R").replace(suffix, "X")
                                    for line in lines if ": " in line]
                        prompted = "?" in result.stderr
                        outcome.append((result.returncode, prompted, messages))
                    left = sorted(str(p.relative_to(root)).replace(suffix, "X") for p in [*empty.rglob("*"), *excluded.rglob("*")])
                    if program is None:
                        assert "excluded-X/m/inner" in left, left
                        left.remove("excluded-X/m/inner")
                    outcome.append(left)
                    busy_outcomes.append(outcome)
                finally:
                    for mount in mounts:
                        subprocess.run(["/usr/bin/umount", str(mount)], check=False)
            assert busy_outcomes[0] == busy_outcomes[1], busy_outcomes
            print("PASS: rm -r moves no mount, reaches into none it was not given, copies nothing it cannot remove")
            # overlayfs with layers on other filesystems reports a file's
            # device from its layer: only directories compare devices (#358).
            layers = root / "overlay-layers"
            for name in ["lower", "upper", "merged"]:
                (layers / name).mkdir(parents=True)
            subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(layers / "lower")], check=True)
            subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", str(layers / "upper")], check=True)
            (layers / "lower/T").mkdir(); (layers / "lower/T/a").write_bytes(b"lower")
            (layers / "upper/data").mkdir(); (layers / "upper/work").mkdir()
            overlay = subprocess.run(["/usr/bin/mount", "-t", "overlay", "none", "-o",
                f"lowerdir={layers}/lower,upperdir={layers}/upper/data,workdir={layers}/upper/work,xino=off",
                str(layers / "merged")], capture_output=True)
            try:
                if overlay.returncode == 0:
                    result = subprocess.run([str(binary), "-r", "--one-file-system", str(layers / "merged/T")],
                                            text=True, capture_output=True, env=env, cwd=root, timeout=10)
                    assert result.returncode == 0 and not (layers / "merged/T").exists(), result.stderr
            finally:
                for name in ["merged", "upper", "lower"]:
                    subprocess.run(["/usr/bin/umount", str(layers / name)], check=False)
            print("PASS: -ri --one-file-system asks about other filesystems as GNU rm does")

        # Like GNU, an answer counts as yes when it starts with y or Y.
        for answer, kept in [(" y\n", True), ("yeah\n", False), ("Y\n", False), ("no\n", True)]:
            victim = root / "answer"; victim.write_bytes(b"x")
            subprocess.run([str(binary), "-i", str(victim)], input=answer, text=True, capture_output=True, env=env, cwd=root, timeout=10)
            assert victim.exists() == kept, (answer, kept)
            if victim.exists(): victim.unlink()
        print("PASS: prompt answers follow GNU's yes rule")

        # -di confirms an unlistable empty directory before rmdir(2).
        empty = nobody / "unlistable-empty"
        empty.mkdir()
        os.chown(empty, 65534, 65534)
        empty.chmod(0o300)
        declined = subprocess.run([str(binary), "-di", str(empty)], input="n\n", env=nobody_env, cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
        assert declined.returncode == 0 and empty.is_dir() and "? [y/N]" in declined.stderr, declined.stderr
        confirmed = subprocess.run([str(binary), "-di", str(empty)], input="y\n", env=nobody_env, cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
        assert confirmed.returncode == 0 and not empty.exists(), confirmed.stderr
        print("PASS: -di confirms an unlistable empty directory")

        # Unprivileged, real rm -r of an excluded tree needs no read access
        # to its parent, and removes an empty directory it cannot list, as rm
        # does. A tree it could not retire after a cross-device copy (an
        # unwritable directory inside) is not copied at all (#370).
        excl_parent = nobody / "excl-parent"
        (excl_parent / "tree/a").mkdir(parents=True)
        (excl_parent / "tree/a/f").write_bytes(b"x")
        (excl_parent / "tree/sealed").mkdir()
        for path in [excl_parent, excl_parent / "tree", excl_parent / "tree/a", excl_parent / "tree/a/f", excl_parent / "tree/sealed"]:
            os.chown(path, 65534, 65534)
        (excl_parent / "tree/sealed").chmod(0o000)
        excl_parent.chmod(0o300)
        (nobody / "excl-config/trashd").mkdir(parents=True)
        (nobody / "excl-config/trashd/config.toml").write_text(f'never_trash = ["{excl_parent}/*"]\n')
        excl_env = dict(nobody_env, XDG_CONFIG_HOME=str(nobody / "excl-config"))
        removed = subprocess.run([str(binary), "-r", str(excl_parent / "tree")], env=excl_env, cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
        excl_parent.chmod(0o700)
        assert removed.returncode == 0 and not (excl_parent / "tree").exists(), removed.stderr
        xdev = nobody / "xdev"
        xdev.mkdir()
        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "mode=755", "none", str(xdev)], check=True)
        try:
            (xdev / "w/own/ro").mkdir(parents=True)
            (xdev / "w/own/ro/f").write_bytes(b"keep")
            for path in [xdev / "w", xdev / "w/own", xdev / "w/own/ro", xdev / "w/own/ro/f"]:
                os.chown(path, 65534, 65534)
            (xdev / "w/own/ro").chmod(0o555)
            refused = subprocess.run([str(binary), "-r", str(xdev / "w/own")], env=nobody_env, cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
            copies = list((nobody / "data/Trash/files").iterdir()) if (nobody / "data/Trash/files").exists() else []
            assert refused.returncode == 1 and "Permission denied" in refused.stderr, refused.stderr
            assert "--permanent" not in refused.stderr, refused.stderr
            assert not copies and (xdev / "w/own/ro/f").read_bytes() == b"keep", (copies, refused.stderr)
            # An empty read-only directory needs nothing of itself: such a
            # tree is trashed (#370).
            (xdev / "w/own2/leaf").mkdir(parents=True)
            (xdev / "w/own2/f").write_bytes(b"x")
            for path in [xdev / "w/own2", xdev / "w/own2/leaf", xdev / "w/own2/f"]:
                os.chown(path, 65534, 65534)
            (xdev / "w/own2/leaf").chmod(0o555)
            trashed = subprocess.run([str(binary), "-r", str(xdev / "w/own2")], env=nobody_env, cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
            assert trashed.returncode == 0 and not (xdev / "w/own2").exists(), trashed.stderr
            assert (nobody / "data/Trash/files/own2/leaf").is_dir(), trashed.stderr
            # A directory the user cannot list cannot be copied either: that
            # is the trash failing, which --permanent gets past, not a
            # removal rm would refuse (#371).
            (xdev / "w/own3/hidden").mkdir(parents=True)
            for path in [xdev / "w/own3", xdev / "w/own3/hidden"]:
                os.chown(path, 65534, 65534)
            (xdev / "w/own3/hidden").chmod(0o300)
            failed = subprocess.run([str(binary), "-r", str(xdev / "w/own3")], env=nobody_env, cwd=nobody, capture_output=True, text=True, timeout=10, preexec_fn=as_nobody)
            assert failed.returncode == 1 and "--permanent" in failed.stderr, failed.stderr
            assert (xdev / "w/own3/hidden").is_dir() and not (nobody / "data/Trash/files/own3").exists(), failed.stderr
        finally:
            subprocess.run(["/usr/bin/umount", str(xdev)], check=False)
        print("PASS: unprivileged real rm -r and cross-device trashing leave nothing half done")

        # A container can deny statx even on a current kernel. The inode-flag
        # fallback must still refuse every immutable/append-only victim before
        # a cross-device copy, including empty directories.
        import array
        import ctypes
        import fcntl
        import platform

        def deny_statx():
            class Instruction(ctypes.Structure):
                _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                            ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
            class Program(ctypes.Structure):
                _fields_ = [("length", ctypes.c_ushort),
                            ("filter", ctypes.POINTER(Instruction))]
            syscall = {"aarch64": 291, "x86_64": 332}[platform.machine()]
            instructions = (Instruction * 4)(
                Instruction(0x20, 0, 0, 0),
                Instruction(0x15, 0, 1, syscall),
                Instruction(0x06, 0, 0, 0x50001),  # SECCOMP_RET_ERRNO | EPERM
                Instruction(0x06, 0, 0, 0x7fff0000),
            )
            program = Program(4, instructions)
            libc = ctypes.CDLL(None, use_errno=True)
            assert libc.prctl(38, 1, 0, 0, 0) == 0  # PR_SET_NO_NEW_PRIVS
            assert libc.prctl(22, 2, ctypes.byref(program), 0, 0) == 0

        pinned_xdev = root / "pinned-xdev"
        pinned_xdev.mkdir()
        # An untrusted topdir forces the authenticated home-trash fallback.
        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "mode=777",
                        "none", str(pinned_xdev)], check=True)
        try:
            home_files = root / "data/Trash/files"
            before = sorted(home_files.iterdir()) if home_files.exists() else []
            checked = 0
            for label, flag, directory in [("immutable-file", 0x10, False),
                                            ("immutable-dir", 0x10, True),
                                            ("append-file", 0x20, False),
                                            ("append-dir", 0x20, True)]:
                tree = pinned_xdev / label
                (tree / "sub").mkdir(parents=True)
                victim = tree / "sub/pinned"
                if directory:
                    victim.mkdir()
                else:
                    victim.write_bytes(b"keep")
                descriptor = os.open(victim, os.O_RDONLY | os.O_NONBLOCK)
                flags = array.array("I", [0])
                try:
                    try:
                        fcntl.ioctl(descriptor, 0x80086601, flags)
                        original = flags[0]
                        fcntl.ioctl(descriptor, 0x40086602, array.array("I", [original | flag]))
                    except OSError:
                        continue  # filesystem/capabilities do not support this flag
                    try:
                        for preexec in [None, deny_statx]:
                            result = subprocess.run([str(binary), "-r", str(tree)], env=env,
                                cwd=root, capture_output=True, text=True, timeout=10,
                                preexec_fn=preexec)
                            assert result.returncode == 1 and "Operation not permitted" in result.stderr, (label, result.stderr)
                            assert "--permanent" not in result.stderr, (label, result.stderr)
                            after = sorted(home_files.iterdir()) if home_files.exists() else []
                            assert after == before and victim.exists(), (label, after, result.stderr)
                            if not directory:
                                assert victim.read_bytes() == b"keep", label
                        checked += 1
                    finally:
                        fcntl.ioctl(descriptor, 0x40086602, array.array("I", [original]))
                finally:
                    os.close(descriptor)
            # Unsupported ioctl/filesystem flags must still allow ordinary
            # cross-device trashing when statx is denied.
            clean = pinned_xdev / "clean-fallback"
            clean.mkdir()
            (clean / "file").write_bytes(b"recover me")
            (clean / "link").symlink_to("missing")
            result = subprocess.run([str(binary), "-r", str(clean)], env=env, cwd=root,
                capture_output=True, text=True, timeout=10, preexec_fn=deny_statx)
            assert result.returncode == 0 and not clean.exists(), result.stderr
            assert (home_files / "clean-fallback/file").read_bytes() == b"recover me"
            assert os.readlink(home_files / "clean-fallback/link") == "missing"
            print(f"PASS: blocked statx retains cross-device inode-flag refusals ({checked} flag cases)")
        finally:
            subprocess.run(["/usr/bin/umount", str(pinned_xdev)], check=True)

        # A bypassed caller passes through before the store is opened, so a
        # broken trash cannot turn its rm into a failure.
        make = root / "make"
        make.write_bytes(Path("/bin/sh").read_bytes())
        make.chmod(0o755)
        victim = root / "make-victim.o"
        victim.write_bytes(b"x")
        broken = dict(env, XDG_DATA_HOME=str(plain))
        bypassed = subprocess.run([str(make), "-c", f"{binary} -f {victim}"], env=broken, cwd=root, capture_output=True, text=True, timeout=10)
        assert bypassed.returncode == 0 and not victim.exists(), bypassed.stderr
        print("PASS: bypassed callers pass through without opening the store")

        # One desktop notification per invocation, not one per operand.
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        log = root / "notify.log"
        (fake_bin / "notify-send").write_text(f"#!/bin/sh\necho \"$*\" >> {log}\n")
        (fake_bin / "notify-send").chmod(0o755)
        files = [root / f"notify-{i}" for i in range(3)]
        for f in files:
            f.write_bytes(b"x")
        gui = dict(env, DISPLAY=":0", PATH=f"{fake_bin}:{env.get('PATH', '/usr/bin:/bin')}")
        result = subprocess.run([str(binary), *map(str, files)], env=gui, cwd=root, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        import time
        for _ in range(50):
            if log.exists():
                break
            time.sleep(0.1)
        lines = log.read_text().splitlines()
        assert len(lines) == 1 and "and 2 more items" in lines[0], lines
        print("PASS: one desktop notification per invocation")


if __name__ == "__main__":
    main()
