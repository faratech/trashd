#!/usr/bin/env python3
r"""Compare syscall counts in disposable fixtures; requires root and strace.

Examples (build the workspace first):
  sudo python3 tests/syscall_bench.py --build-dir target/release
  sudo python3 tests/syscall_bench.py --build-dir target/release --entries 6000 \
    --baseline-cli /path/to/previous/bin/trash \
    --baseline-shim /path/to/previous/bin/trashd-rm \
    --baseline-preload /path/to/previous/lib/libtrashd_preload.so > comparison.json

All fixture operations run through tests/sandbox.py. Baseline artifacts have
dedicated benchmark-only slots; neither the daemon nor the seccomp supervisor
is exercised. Counts include process startup and fixture operations performed
by the traced process. They depend on the fixture, host and build/linker
options, and are not latency gates.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
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
SCAN_STAMP = int(datetime.fromisoformat(SCAN_DATE).replace(tzinfo=timezone.utc).timestamp()) * 10**9
SCAN_CASES = ("status", "ls_json", "info_exact", "find_one", "find_none",
              "ls_date_none", "du_top", "restore_all_none", "restore_all_fullpath_glob",
              "info_ambiguous", "restore_ambiguous", "purge_ambiguous",
              "purge_file", "purge_directory", "compress_age_none")
SHIM_CASES = ("shim_file_warm", "shim_cross_device")
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


def profile_result(command, env, trace, preload=None, bypass="1", expected_status=0,
                   preexec_fn=None):
    # -E changes only the tracee's loader environment. The tracer and fixture
    # controller retain bypass, so their cleanup never becomes measured work.
    invocation = ["/usr/bin/strace", "-qq", "-f", "-c", "-o", str(trace),
                  "-E", f"TRASH_BYPASS={bypass}"]
    if preload:
        invocation += ["-E", f"LD_PRELOAD={preload}"]
    result = subprocess.run([*invocation, "--", *map(str, command)], env=env,
                            capture_output=True, text=True, timeout=180,
                            preexec_fn=preexec_fn)
    if result.returncode != expected_status:
        raise RuntimeError(f"Benchmark command failed ({result.returncode}): {command}\n{result.stderr}")
    return parse_strace(trace), result


def profile(command, env, trace, preload=None, bypass="1"):
    counts, result = profile_result(command, env, trace, preload, bypass)
    return counts, result.stdout


def fixture_environment(root):
    root.mkdir(mode=0o700)
    (root / "data").mkdir(mode=0o700)
    (root / "config/trashd").mkdir(parents=True, mode=0o700)
    (root / "config/trashd/config.toml").write_text(
        'never_trash = ["*.tmp"]\nbypass_processes = []\n'
        'max_file_size_mb = 0\nmax_dir_size_mb = 0\n'
        '[retention]\nmax_age_days = 0\nmax_size_gb = 0\ndisk_pressure_percent = 0\n')
    env = dict(os.environ, HOME=str(root), XDG_DATA_HOME=str(root / "data"),
               XDG_CONFIG_HOME=str(root / "config"), TRASH_BYPASS="1",
               TZ="UTC", NO_COLOR="1")
    for key in ("LD_PRELOAD", "TRASHD_SECCOMP_ACTIVE", "TRASHD_SECCOMP_COOKIE",
                "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"):
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
        sidecar = trash / "info" / (name + ".trashinfo")
        sidecar.write_text(scan_sidecar(name))
        os.utime(sidecar, ns=(SCAN_STAMP + i, SCAN_STAMP + i))
    return trash


def scan_sidecar(name, original=None, stamp=None, size=None):
    if original is None:
        original = f"/original/{name}"
    if stamp is None:
        stamp = SCAN_STAMP + int(name.removeprefix("scan-"))
    if size is None:
        size = len(SCAN_PAYLOAD)
    return (f"[Trash Info]\nPath={original}\nDeletionDate={SCAN_DATE}\n"
            f"X-Trashd-Size={size}\nX-Trashd-DeletedNs={stamp}\nX-Trashd-PID=1\n"
            "X-Trashd-Command=syscall-bench\n")


def verify_scan(trash, entries, extra=None):
    extra = extra or {}
    expected = {f"scan-{i:06d}" for i in range(entries)}
    assert {path.name for path in (trash / "files").iterdir()} == expected | extra.keys()
    assert {path.name for path in (trash / "info").iterdir()} == {
        name + ".trashinfo" for name in expected | extra.keys()}
    for name in expected:
        assert (trash / "files" / name).read_bytes() == SCAN_PAYLOAD
        assert (trash / "info" / (name + ".trashinfo")).read_text() == scan_sidecar(name)
    for name, info in extra.items():
        data = trash / "files" / name
        if info["directory"]:
            assert data.is_dir() and not list(data.iterdir())
        else:
            assert data.is_file() and data.read_bytes() == SCAN_PAYLOAD
        assert (trash / "info" / (name + ".trashinfo")).read_text() == info["sidecar"]


def add_scan_entry(trash, name, original, stamp, directory=False):
    data = trash / "files" / name
    data.mkdir() if directory else data.write_bytes(SCAN_PAYLOAD)
    text = scan_sidecar(name, original, stamp, 0 if directory else len(SCAN_PAYLOAD))
    sidecar = trash / "info" / (name + ".trashinfo")
    sidecar.write_text(text)
    os.utime(sidecar, ns=(stamp, stamp))
    return {"directory": directory, "sidecar": text}


def normalize_output(value, root):
    return value.replace(str(root), "{fixture}")


def run_scan(label, cli, case, root, entries):
    env = fixture_environment(root)
    trash = scan_fixture(root, entries)
    target = f"scan-{entries // 2:06d}"
    extra = {}
    restored = []
    args = {"status": ["status"], "ls_json": ["ls", "--json"],
            "info_exact": ["info", target],
            "find_one": ["find", f"/original/{target}"],
            "find_none": ["find", "benchmark-never-present*"],
            "ls_date_none": ["ls", "--json", "--after", "2100-01-01"],
            "du_top": ["du", "--top", "5"],
            "restore_all_none": ["restore", "benchmark-never-present*", "--all"],
            "restore_all_fullpath_glob": ["restore", str(root / "restored/*/target.dat"), "--all"],
            "info_ambiguous": ["info", "ambiguous.dat"],
            "restore_ambiguous": ["restore", "ambiguous.dat"],
            "purge_ambiguous": ["purge", "ambiguous.dat"],
            "purge_file": ["purge", "victim"],
            "purge_directory": ["purge", "victim"],
            # Always younger than the threshold, independent of the run date.
            "compress_age_none": ["compress", "--older", "4294967295d"]}[case]
    if case.endswith("_ambiguous") or case == "restore_all_fullpath_glob":
        for i, branch in enumerate(("a", "b")):
            name = f"selected-{branch}"
            original = (root / f"restored/{branch}/target.dat" if case == "restore_all_fullpath_glob"
                        else Path(f"/original/{branch}/ambiguous.dat"))
            extra[name] = add_scan_entry(trash, name, original, SCAN_STAMP + entries + i)
            restored.append(original)
    elif case in ("purge_file", "purge_directory"):
        directory = case == "purge_directory"
        extra["victim"] = add_scan_entry(trash, "victim", "/original/victim",
                                          SCAN_STAMP + entries, directory)
        if directory:
            mtime = (trash / "info/victim.trashinfo").stat().st_mtime_ns // 10**9
            (trash / "directorysizes").write_text(f"0 {mtime} victim\n")
    expected_status = 1 if case.endswith("_ambiguous") or case == "restore_all_none" else 0
    counts, result = profile_result([cli, *args], env, root / "strace.txt",
                                     expected_status=expected_status)
    output = result.stdout
    destructive = case in ("restore_all_fullpath_glob", "purge_file", "purge_directory")
    verify_scan(trash, entries, None if destructive else extra)
    normalized = normalize_output(output, root)
    if case == "status":
        assert re.search(rf"^\s*Items:\s+{entries}\s*$", output, re.MULTILINE), output
    elif case == "info_exact":
        assert re.search(rf"^\s*ID:\s+{target}\s*$", output, re.MULTILINE), output
        assert re.search(rf"^\s*Original path:\s+/original/{target}\s*$", output, re.MULTILINE), output
        assert re.search(r"^\s*Type:\s+file\s*$", output, re.MULTILINE), output
        assert re.search(r"^\s*Size:\s+64 B \(64 bytes\)\s*$", output, re.MULTILINE), output
    elif case == "ls_json":
        records = json.loads(output)
        assert len(records) == entries
        expected = [f"scan-{i:06d}" for i in range(entries - 1, -1, -1)]
        assert [record["id"] for record in records] == expected
        normalized = []
        for record in records:
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
    elif case == "find_one":
        assert f"/original/{target}" in output and "\n1 matches" in output, output
        assert len(re.findall(r"/original/scan-\d+", output)) == 1, output
    elif case == "find_none":
        assert "No matches for 'benchmark-never-present*'." in output, output
    elif case == "ls_date_none":
        assert json.loads(output) == [], output
    elif case == "du_top":
        shown = re.findall(r"/original/(scan-\d+)\s+(scan-\d+)", output)
        expected = [f"scan-{i:06d}" for i in range(entries - 1, max(-1, entries - 6), -1)]
        assert shown == [(name, name) for name in expected], output
    elif case == "restore_all_none":
        assert "no matches" in result.stderr.lower(), result.stderr
    elif case == "compress_age_none":
        assert output.strip() == "Nothing to compress.", output
    elif case == "restore_all_fullpath_glob":
        assert "2 restored, 0 failed" in output, output
        assert all(path.read_bytes() == SCAN_PAYLOAD for path in restored)
    elif case.endswith("_ambiguous"):
        assert "ambiguous" in result.stderr.lower(), result.stderr
        assert all(name in result.stderr for name in extra), result.stderr
        assert not (root / "restored").exists()
    elif case in ("purge_file", "purge_directory"):
        assert "Purged:" in output and "victim" in output, output
        if case == "purge_directory":
            assert not (trash / "directorysizes").read_text().strip()
    return {"label": label, "case": case, **counts,
            "behavior": {"entries": entries, "data_bytes": entries * len(SCAN_PAYLOAD),
                         "fixture_unchanged": not destructive,
                         "unrelated_payloads_verified": True,
                         "restored_payloads": 2 if case == "restore_all_fullpath_glob" else 0,
                         "exit_status": result.returncode,
                         "stderr_sha256": output_digest(normalize_output(result.stderr, root)),
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
    counts, result = profile_result(["/usr/bin/python3", "-c", PRELOAD_WORKER, root, suffix],
                                    env, root / "strace.txt", preload=preload,
                                    bypass="1" if mode == "bypass" else "0")
    behavior = verify_preload(root, mode)
    behavior.update(exit_status=result.returncode,
                    output_sha256=output_digest(normalize_output(result.stdout, root)),
                    stderr_sha256=output_digest(normalize_output(result.stderr, root)))
    return {"label": label, "case": f"preload_{mode}", **counts,
            "behavior": behavior}


def run_cross_device(label, shim, entries):
    # A root-owned 0755 filesystem root cannot host nobody's topdir trash,
    # so this exercises the real home-trash copy path, not a same-device
    # rename into .Trash-65534. All mounts remain inside the outer sandbox.
    with tempfile.TemporaryDirectory(prefix="syscall-bench-xdev-", dir="/home/nobody") as temporary:
        base = Path(temporary)
        os.chown(base, 65534, 65534)
        root = base / "fixture"
        env = fixture_environment(root)
        for path in (root, *root.rglob("*")):
            os.chown(path, 65534, 65534)
        mountpoint = root / "xdev"
        mountpoint.mkdir()
        subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "mode=755", "none", str(mountpoint)],
                       check=True, capture_output=True, text=True)
        try:
            source = mountpoint / "w/tree"
            source.mkdir(parents=True)
            for i in range(entries):
                path = source / f"copy-{i:06d}"
                path.write_bytes(SCAN_PAYLOAD)
                os.chown(path, 65534, 65534)
            for path in (mountpoint / "w", source):
                os.chown(path, 65534, 65534)
            assert source.stat().st_dev != (root / "data").stat().st_dev

            def as_nobody():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)

            counts, result = profile_result([shim, "-r", source], env, root / "strace.txt",
                                             bypass="0", preexec_fn=as_nobody)
            assert not source.exists(), result.stderr
            assert not (mountpoint / ".Trash-65534").exists()
            trash = root / "data/Trash"
            assert {path.name for path in (trash / "files").iterdir()} == {"tree"}
            assert {path.name for path in (trash / "info").iterdir()} == {"tree.trashinfo"}
            copy = trash / "files/tree"
            expected = {f"copy-{i:06d}" for i in range(entries)}
            assert {path.name for path in copy.iterdir()} == expected
            assert all((copy / name).read_bytes() == SCAN_PAYLOAD for name in expected)
            info = dict(line.split("=", 1) for line in (trash / "info/tree.trashinfo").read_text().splitlines()
                        if "=" in line)
            assert unquote(info["Path"]) == str(source)
            return {"label": label, "case": "shim_cross_device", **counts,
                    "behavior": {"entries": entries, "data_bytes": entries * len(SCAN_PAYLOAD),
                                 "source_operands_removed": True, "trash_entries": 1,
                                 "recoverable_files": entries, "payloads_verified": True,
                                 "copy_between_devices": True, "effective_uid": 65534,
                                 "exit_status": result.returncode,
                                 "output_sha256": output_digest(normalize_output(result.stdout, root)),
                                 "stderr_sha256": output_digest(normalize_output(result.stderr, root))}}
        finally:
            subprocess.run(["/usr/bin/umount", str(mountpoint)], check=True,
                           capture_output=True, text=True)


def run_warm_shim(label, shim, root):
    env = fixture_environment(root)
    warmup = root / "warmup"
    source = root / "file"
    warmup.write_bytes(PAYLOAD)
    # Initialize the authenticated store and retention marker before the
    # measured single-file invocation, matching the established warm path.
    warmed = subprocess.run([shim, str(warmup)], env=dict(env, TRASH_BYPASS="0"),
                            capture_output=True, text=True, timeout=30)
    assert warmed.returncode == 0, warmed.stderr
    source.write_bytes(PAYLOAD)
    counts, result = profile_result([shim, source], env, root / "strace.txt", bypass="0")
    trash = root / "data/Trash"
    assert not warmup.exists() and not source.exists()
    assert {path.name for path in (trash / "files").iterdir()} == {"warmup", "file"}
    assert {path.name for path in (trash / "info").iterdir()} == {"warmup.trashinfo", "file.trashinfo"}
    for name in ("warmup", "file"):
        assert (trash / "files" / name).read_bytes() == PAYLOAD
        fields = dict(line.split("=", 1) for line in (trash / "info" / (name + ".trashinfo")).read_text().splitlines()
                      if "=" in line)
        assert unquote(fields["Path"]) == str(root / name)
        assert fields["X-Trashd-Size"] == str(len(PAYLOAD))
    assert not (trash / "directorysizes").exists()
    return {"label": label, "case": "shim_file_warm", **counts,
            "behavior": {"operations": 1, "untraced_warmup_operations": 1,
                         "source_operands_removed": True, "trash_entries": 2,
                         "recoverable_files": 2, "payloads_verified": True,
                         "directorysizes_absent": True, "exit_status": result.returncode,
                         "output_sha256": output_digest(normalize_output(result.stdout, root)),
                         "stderr_sha256": output_digest(normalize_output(result.stderr, root))}}


def run_contained(args):
    from sandbox import require_sandbox
    require_sandbox()
    os.environ["TRASH_BYPASS"] = "1"
    os.environ.pop("LD_PRELOAD", None)
    cli = {"candidate": Path("/opt/trashd/bin/trash")}
    shim = {"candidate": Path("/opt/trashd/bin/trashd-rm")}
    preload = {"candidate": Path("/opt/trashd/lib/libtrashd_preload.so")}
    if args.baseline_cli:
        cli["baseline"] = Path(args.baseline_cli)
    if args.baseline_shim:
        shim["baseline"] = Path(args.baseline_shim)
    if args.baseline_preload:
        preload["baseline"] = Path(args.baseline_preload)
    artifacts = {}
    for kind, versions in (("cli", cli), ("shim", shim), ("preload", preload)):
        for label, path in versions.items():
            artifacts.setdefault(label, {})[kind] = {
                "sandbox_path": str(path), "sha256": digest(path)}
    profiles = []
    with tempfile.TemporaryDirectory(prefix="syscall-bench-", dir="/work") as temporary:
        root = Path(temporary)
        for label in ("baseline", "candidate"):
            if label in cli:
                for case in SCAN_CASES:
                    fixture = root / f"{label}-{case}"
                    profiles.append(run_scan(label, cli[label], case, fixture, args.entries))
                    shutil.rmtree(fixture)
            if label in preload:
                for mode in ("protected", "excluded", "bypass"):
                    fixture = root / f"{label}-{mode}"
                    profiles.append(run_preload(label, preload[label], mode, fixture))
                    shutil.rmtree(fixture)
            if label in shim:
                fixture = root / f"{label}-shim-file-warm"
                profiles.append(run_warm_shim(label, shim[label], fixture))
                shutil.rmtree(fixture)
                profiles.append(run_cross_device(label, shim[label], args.entries))
    indexed = {(item["label"], item["case"]): item for item in profiles}
    comparisons = []
    for case in (*SCAN_CASES, *SHIM_CASES,
                 "preload_protected", "preload_excluded", "preload_bypass"):
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
                         "scan_deletion_stamp_base_ns": SCAN_STAMP,
                         "exact_lookup_id": f"scan-{args.entries // 2:06d}",
                         "preload_operations": OPERATIONS,
                         "preload_description": "50 file create/write/unlink and 50 empty mkdir/rmdir operations in one Python process per mode",
                         "cross_device_description": "uid 65534 recursively trashes one flat tree from root-owned 0755 tmpfs into home trash",
                         "warm_shim_description": "one file trash after one untraced file trash initializes the store and retention marker",
                         "fresh_fixture_per_profile": True},
            "notes": ["Syscall totals include per-command loader/runtime startup and traced file creation/writes; filesystem caches are not flushed.",
                      "Bypass controls expose loader/build differences between libraries.",
                      "Results are fixture-specific and do not predict live runtime."],
            "artifacts": artifacts, "profiles": profiles, "comparisons": comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", default="target/release")
    parser.add_argument("--baseline-cli", type=Path)
    parser.add_argument("--baseline-shim", type=Path)
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
    sources = {"candidate": {"cli": build / "trash", "shim": build / "trashd-rm",
                             "preload": build / "libtrashd_preload.so"}}
    for path in sources["candidate"].values():
        if not path.is_file():
            parser.error(f"missing artifact: {path}; build the workspace first")
    runner = Path(__file__).resolve().with_name("sandbox.py")
    command = [sys.executable, str(runner), "--build-dir", str(build)]
    inner = ["/usr/bin/python3", "/tests/syscall_bench.py", "--entries", str(args.entries)]
    for kind, path, alias, destination in (
            ("cli", args.baseline_cli, "bench-baseline-cli", "/opt/trashd/bin/bench-baseline-cli"),
            ("shim", args.baseline_shim, "bench-baseline-shim", "/opt/trashd/bin/bench-baseline-shim"),
            ("preload", args.baseline_preload, "bench-baseline-preload.so", "/opt/trashd/lib/bench-baseline-preload.so")):
        if path:
            source = path.resolve(strict=True)
            if not source.is_file():
                parser.error(f"baseline artifact must be a regular file: {source}")
            sources.setdefault("baseline", {})[kind] = source
            command += ["--binary", f"{alias}={source}"]
            inner += [f"--baseline-{kind}", destination]
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
