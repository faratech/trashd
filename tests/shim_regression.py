#!/usr/bin/env python3
"""Exercise the built rm shim in a disposable sandbox: shim_regression.py PATH."""

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


if __name__ == "__main__":
    main()
