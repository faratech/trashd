#!/usr/bin/env python3
r"""Compare syscall counts in disposable fixtures; requires root and strace.

Examples (build the workspace first):
  sudo python3 tests/syscall_bench.py --build-dir target/release
  sudo python3 tests/syscall_bench.py --build-dir target/release --entries 6000 \
    --baseline-cli /path/to/previous/bin/trash \
    --baseline-preload /path/to/previous/lib/libtrashd_preload.so > comparison.json

All fixture operations run through tests/sandbox.py. Baseline artifacts occupy
the sandbox's trashd and trashd-exec slots as benchmark-only aliases; neither
the daemon nor the seccomp supervisor is exercised. Counts include process
startup and fixture operations performed by the traced process. They depend
on the fixture, host and build/linker options, and are not latency gates.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from urllib.parse import unquote


SUMMARY_PREFIX = "TRASHD_SYSCALL_BENCH_JSON="
SENTINEL_PASS = "PASS: external mounted trash sentinel unchanged"
OPERATIONS = 100
PAYLOAD = b"recoverable benchmark data\n"
SCAN_PAYLOAD = b"s" * 64
SCAN_DATE = "2026-10-20T12:00:00"
SCAN_CASES = ("status", "ls_json", "info_exact")
PRELOAD_WORKER = """import os, sys
root, suffix = sys.argv[1:]
for i in range(50):
    path = root + '/file-' + str(i) + suffix
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b'recoverable benchmark data\\n')
    os.close(fd)
    os.unlink(path)
    path = root + '/dir-' + str(i) + suffix
    os.mkdir(path)
    os.rmdir(path)
"""


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def output_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def parse_strace(path):
    """Read calls/errors from strace -c, including calls reported with no errors."""
    calls, errors, reported_total = {}, {}, None
    for line in path.read_text().splitlines():
        fields = line.split()
        if not fields or fields[0] in ("%", "------") or set(line.strip()) == {"-"}:
            continue
        if len(fields) < 5:
            raise RuntimeError(f"Unrecognized strace summary line: {line}")
        try:
            float(fields[0])
            float(fields[1])
            int(fields[2])
            count = int(fields[3])
            failed = int(fields[4]) if len(fields) == 6 else 0
        except ValueError as error:
            raise RuntimeError(f"Unrecognized strace summary line: {line}") from error
        name = fields[-1]
        if name == "total":
            reported_total = count
        else:
            if not re.fullmatch(r"[a-zA-Z0-9_]+", name) or len(fields) not in (5, 6):
                raise RuntimeError(f"Unrecognized strace summary line: {line}")
            calls[name] = count
            if failed:
                errors[name] = failed
    total = sum(calls.values())
    if not calls or total != reported_total:
        raise RuntimeError(f"Incomplete strace summary: {path}")
    return {"total_syscalls": total, "syscalls": calls, "syscall_errors": errors}


def profile(command, env, trace, preload=None, bypass="1"):
    # -E changes only the tracee's loader environment. The tracer and fixture
    # controller retain bypass, so their cleanup never becomes measured work.
    invocation = ["/usr/bin/strace", "-qq", "-f", "-c", "-o", str(trace),
                  "-E", f"TRASH_BYPASS={bypass}"]
    if preload:
        invocation += ["-E", f"LD_PRELOAD={preload}"]
    result = subprocess.run([*invocation, "--", *map(str, command)], env=env,
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f"Benchmark command failed ({result.returncode}): {command}\n{result.stderr}")
    return parse_strace(trace), result.stdout


def fixture_environment(root):
    root.mkdir(mode=0o700)
    (root / "data").mkdir(mode=0o700)
    (root / "config/trashd").mkdir(parents=True, mode=0o700)
    (root / "config/trashd/config.toml").write_text(
        'never_trash = ["*.tmp"]\nmax_file_size_mb = 0\nmax_dir_size_mb = 0\n')
    env = dict(os.environ, HOME=str(root), XDG_DATA_HOME=str(root / "data"),
               XDG_CONFIG_HOME=str(root / "config"), TRASH_BYPASS="1",
               TZ="UTC", NO_COLOR="1")
    for key in ("LD_PRELOAD", "TRASHD_SECCOMP_ACTIVE", "TRASHD_SECCOMP_COOKIE"):
        env.pop(key, None)
    return env


def scan_fixture(root, entries):
    trash = root / "data/Trash"
    for name in ("files", "info"):
        (trash / name).mkdir(parents=True, mode=0o700)
    trash.chmod(0o700)
    for i in range(entries):
        name = f"scan-{i:06d}"
        (trash / "files" / name).write_bytes(SCAN_PAYLOAD)
        (trash / "info" / (name + ".trashinfo")).write_text(scan_sidecar(name))
    return trash


def scan_sidecar(name):
    return (f"[Trash Info]\nPath=/original/{name}\nDeletionDate={SCAN_DATE}\n"
            f"X-Trashd-Size={len(SCAN_PAYLOAD)}\nX-Trashd-PID=1\n"
            "X-Trashd-Command=syscall-bench\n")


def verify_scan(trash, entries):
    expected = {f"scan-{i:06d}" for i in range(entries)}
    assert {path.name for path in (trash / "files").iterdir()} == expected
    assert {path.name for path in (trash / "info").iterdir()} == {
        name + ".trashinfo" for name in expected}
    for name in expected:
        assert (trash / "files" / name).read_bytes() == SCAN_PAYLOAD
        assert (trash / "info" / (name + ".trashinfo")).read_text() == scan_sidecar(name)


def run_scan(label, cli, case, root, entries):
    env = fixture_environment(root)
    trash = scan_fixture(root, entries)
    target = f"scan-{entries // 2:06d}"
    args = {"status": ["status"], "ls_json": ["ls", "--json"],
            "info_exact": ["info", target]}[case]
    counts, output = profile([cli, *args], env, root / "strace.txt")
    verify_scan(trash, entries)
    if case == "status":
        assert re.search(rf"^\s*Items:\s+{entries}\s*$", output, re.MULTILINE), output
        normalized = output.replace(str(root), "{fixture}")
    elif case == "info_exact":
        assert re.search(rf"^\s*ID:\s+{target}\s*$", output, re.MULTILINE), output
        assert re.search(rf"^\s*Original path:\s+/original/{target}\s*$", output, re.MULTILINE), output
        assert re.search(r"^\s*Type:\s+file\s*$", output, re.MULTILINE), output
        assert re.search(r"^\s*Size:\s+64 B \(64 bytes\)\s*$", output, re.MULTILINE), output
        normalized = output.replace(str(root), "{fixture}")
    else:
        records = json.loads(output)
        assert len(records) == entries
        expected = {f"scan-{i:06d}" for i in range(entries)}
        assert {record["id"] for record in records} == expected
        normalized = []
        for record in sorted(records, key=lambda value: value["id"]):
            name = record["id"]
            assert record["original_path"] == f"/original/{name}"
            assert record["size"] == len(SCAN_PAYLOAD)
            assert record["deletion_date"] == SCAN_DATE
            assert record["command"] == "syscall-bench"
            assert record["trashed_path"] == str(trash / "files" / name)
            assert record["trash_dir"] == str(trash)
            normalized.append({key: value.replace(str(root), "{fixture}")
                               if isinstance(value, str) else value
                               for key, value in record.items()})
    return {"label": label, "case": case, **counts,
            "behavior": {"entries": entries, "data_bytes": entries * len(SCAN_PAYLOAD),
                         "fixture_unchanged": True,
                         "output_sha256": output_digest(normalized)}}


def verify_preload(root, mode):
    suffix = ".tmp" if mode == "excluded" else ""
    expected = {str(root / f"{kind}-{i}{suffix}"): kind
                for i in range(50) for kind in ("file", "dir")}
    assert all(not Path(path).exists() for path in expected)
    trash = root / "data/Trash"
    sidecars = list((trash / "info").glob("*.trashinfo"))
    files = list((trash / "files").glob("*"))
    wanted = OPERATIONS if mode == "protected" else 0
    assert len(sidecars) == len(files) == wanted, (mode, len(sidecars), len(files))
    observed = set()
    for sidecar in sidecars:
        fields = dict(line.split("=", 1) for line in sidecar.read_text().splitlines() if "=" in line)
        original = unquote(fields["Path"])
        assert original in expected and original not in observed, original
        observed.add(original)
        data = trash / "files" / sidecar.name.removesuffix(".trashinfo")
        if expected[original] == "file":
            assert data.is_file() and data.read_bytes() == PAYLOAD, data
        else:
            assert data.is_dir() and not list(data.iterdir()), data
    if wanted:
        assert observed == set(expected)
    return {"operations": OPERATIONS, "source_operands_removed": True,
            "trash_entries": wanted, "recoverable_files": wanted // 2,
            "recoverable_empty_directories": wanted // 2,
            "payloads_verified": True}


def run_preload(label, preload, mode, root):
    env = fixture_environment(root)
    suffix = ".tmp" if mode == "excluded" else ""
    counts, _ = profile(["/usr/bin/python3", "-c", PRELOAD_WORKER, root, suffix],
                        env, root / "strace.txt", preload=preload,
                        bypass="1" if mode == "bypass" else "0")
    return {"label": label, "case": f"preload_{mode}", **counts,
            "behavior": verify_preload(root, mode)}


def run_contained(args):
    from sandbox import require_sandbox
    require_sandbox()
    os.environ["TRASH_BYPASS"] = "1"
    os.environ.pop("LD_PRELOAD", None)
    cli = {"candidate": Path("/opt/trashd/bin/trash")}
    preload = {"candidate": Path("/opt/trashd/lib/libtrashd_preload.so")}
    if args.baseline_cli:
        cli["baseline"] = Path(args.baseline_cli)
    if args.baseline_preload:
        preload["baseline"] = Path(args.baseline_preload)
    artifacts = {}
    for kind, versions in (("cli", cli), ("preload", preload)):
        for label, path in versions.items():
            artifacts.setdefault(label, {})[kind] = {
                "sandbox_path": str(path), "sha256": digest(path)}
    profiles = []
    with tempfile.TemporaryDirectory(prefix="syscall-bench-", dir="/work") as temporary:
        root = Path(temporary)
        for label in ("baseline", "candidate"):
            if label in cli:
                for case in SCAN_CASES:
                    profiles.append(run_scan(label, cli[label], case,
                                             root / f"{label}-{case}", args.entries))
            if label in preload:
                for mode in ("protected", "excluded", "bypass"):
                    profiles.append(run_preload(label, preload[label], mode,
                                                root / f"{label}-{mode}"))
    indexed = {(item["label"], item["case"]): item for item in profiles}
    comparisons = []
    for case in (*SCAN_CASES, "preload_protected", "preload_excluded", "preload_bypass"):
        before, after = indexed.get(("baseline", case)), indexed[("candidate", case)]
        if before:
            assert before["behavior"] == after["behavior"], f"Behavior differs for {case}"
            old, new = before["total_syscalls"], after["total_syscalls"]
            comparison = {"case": case, "behavior_parity": True,
                          "baseline_syscalls": old, "candidate_syscalls": new,
                          "reduction_percent": round((old - new) * 100 / old, 2)}
            if case in ("preload_protected", "preload_excluded"):
                comparison["baseline_minus_bypass"] = old - indexed[("baseline", "preload_bypass")]["total_syscalls"]
                comparison["candidate_minus_bypass"] = new - indexed[("candidate", "preload_bypass")]["total_syscalls"]
            comparisons.append(comparison)
    return {"schema_version": 1, "startup_included": True, "timing_gates": False,
            "sandbox_containment_verified": True,
            "host": {"machine": platform.machine(), "kernel": platform.release(),
                     "python": platform.python_version()},
            "workload": {"scan_entries": args.entries, "scan_payload_bytes": len(SCAN_PAYLOAD),
                         "scan_deletion_date": SCAN_DATE, "timezone": "UTC",
                         "exact_lookup_id": f"scan-{args.entries // 2:06d}",
                         "preload_operations": OPERATIONS,
                         "preload_description": "50 file create/write/unlink and 50 empty mkdir/rmdir operations in one Python process per mode",
                         "fresh_fixture_per_profile": True},
            "notes": ["Syscall totals include per-command loader/runtime startup and traced file creation/writes; filesystem caches are not flushed.",
                      "Bypass controls expose loader/build differences between libraries.",
                      "Results are fixture-specific and do not predict live runtime."],
            "artifacts": artifacts, "profiles": profiles, "comparisons": comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", default="target/release")
    parser.add_argument("--baseline-cli", type=Path)
    parser.add_argument("--baseline-preload", type=Path)
    parser.add_argument("--entries", type=int, default=6000)
    args = parser.parse_args()
    if args.entries < 1:
        parser.error("--entries must be positive")
    if os.environ.get("TRASHD_TEST_SANDBOX") == "1":
        print(SUMMARY_PREFIX + json.dumps(run_contained(args)), flush=True)
        return 0
    if os.geteuid() != 0:
        parser.error("the disposable test sandbox needs mount privileges; rerun with sudo")
    if not Path("/usr/bin/strace").is_file():
        parser.error("/usr/bin/strace is required")
    build = Path(args.build_dir).resolve(strict=True)
    sources = {"candidate": {"cli": build / "trash", "preload": build / "libtrashd_preload.so"}}
    for path in sources["candidate"].values():
        if not path.is_file():
            parser.error(f"missing artifact: {path}; build the workspace first")
    runner = Path(__file__).resolve().with_name("sandbox.py")
    command = [sys.executable, str(runner), "--build-dir", str(build)]
    inner = ["/usr/bin/python3", "/tests/syscall_bench.py", "--entries", str(args.entries)]
    for kind, path, alias in (("cli", args.baseline_cli, "trashd"),
                              ("preload", args.baseline_preload, "trashd-exec")):
        if path:
            source = path.resolve(strict=True)
            if not source.is_file():
                parser.error(f"baseline artifact must be a regular file: {source}")
            sources.setdefault("baseline", {})[kind] = source
            command += ["--binary", f"{alias}={source}"]
            inner += [f"--baseline-{kind}", f"/opt/trashd/bin/{alias}"]
    os.environ["TRASH_BYPASS"] = "1"
    os.environ.pop("LD_PRELOAD", None)
    result = subprocess.run([*command, "--", *inner], capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        return result.returncode
    lines = result.stdout.splitlines()
    summaries = [line[len(SUMMARY_PREFIX):] for line in lines if line.startswith(SUMMARY_PREFIX)]
    if len(summaries) != 1 or not lines or lines[-1] != SENTINEL_PASS:
        raise RuntimeError(f"Sandbox did not confirm benchmark completion and external sentinels: {result.stdout}")
    summary = json.loads(summaries[0])
    summary["external_mounted_trash_sentinels_unchanged"] = True
    for label, artifacts in sources.items():
        for kind, path in artifacts.items():
            summary["artifacts"][label][kind]["source"] = str(path)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
