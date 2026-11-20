#!/usr/bin/env python3
"""daemon-7: does `rm -rf TREE && umount` fail with EBUSY because trashd runs?

trashd holds no descriptor between lookups (#197), but every directory
handle it decodes opens the handle's mount for a few microseconds, and an
unmount that lands inside one of those windows fails with EBUSY. Whether
that happens in practice cannot be read from the code, so this measures it.

Each trial mounts an ext4 filesystem, fills a directory tree, removes it with
the real rm and unmounts at once. Trials run in alternating blocks with the
daemon ("daemon") and without it ("control"): the control arm shows how often
an immediate unmount is busy for reasons that have nothing to do with trashd.
The daemon runs as its unit does, in a mount namespace of its own that
receives the mount by propagation, and in a chroot that shows it nothing but
this one filesystem, so it marks no filesystem of the host.

The unmount only meets an open mount when the daemon is behind the removal
or off the CPU as rm ends, which an idle host seldom arranges. Two modes
arrange it, and neither depends on the host's load:

  --stall-ms 20    stops the daemon during the removal, so the unmount races
                   its whole backlog
  --freeze-ms 100  stops it at a random moment of the removal and unmounts
                   while it is stopped: the EBUSY rate is the share of its
                   running time for which a preemption leaves the mount open

--hogs adds load instead, and --dirs/--files shape the tree. Many small
directories are the worst case: each is decoded once while it still exists.

Opt-in: it is an experiment, not a pass/fail suite, and no CI job runs it.
Needs root, e2fsprogs and a free loop device:

  sudo env TRASH_BYPASS=1 python3 tests/sandbox.py --build-dir target/release \\
      --loop-device 256 -- /usr/bin/python3 /tests/daemon_umount_race.py

With --max-excess it is a check. `--stall-ms 20 --trials 30 --max-excess 3`
separates a daemon that decodes the directories a removal has removed (EBUSY
in 50 of 130 such trials) from one that does not (1 of 130).

Exit status: 0 when the trials ran (whatever they showed, unless
--max-excess is given), 1 on a harness failure, 77 when it cannot run here.
"""

import argparse
import ctypes
import errno
import json
import math
import os
from pathlib import Path
import random
import shutil
import signal
import statistics
import subprocess
import sys
import time

sys.path.insert(0, "/tests")
from sandbox import LOOP_NODE, require_sandbox

MS_REC, MS_SLAVE, MS_SHARED = 0x4000, 1 << 19, 1 << 20
CLONE_NEWNS = 0x00020000
JAIL = Path("/jail")
MOUNT = JAIL / "mnt/t"  # "/mnt/t" to the daemon
TREE = MOUNT / "tree"
LOG = Path("/work/daemon-umount-race.log")
DAEMON = Path("/opt/trashd/bin/trashd")
DELETE = b"[trashd] DELETE "
SKIP = 77

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]


def skip(reason):
    print(f"SKIP: daemon-7 experiment: {reason}", flush=True)
    sys.exit(SKIP)


def sys_mount(source, target, fstype, flags=0, data=None):
    encode = lambda value: None if value is None else os.fsencode(value)
    if libc.mount(encode(source), encode(target), encode(fstype), flags, encode(data)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"mount {target}: {os.strerror(error)}")


def try_umount(target=MOUNT):
    """umount(2) without any flag; returns 0 or the errno."""
    return 0 if libc.umount2(os.fsencode(target), 0) == 0 else ctypes.get_errno()


def umount_when_free(target=MOUNT, limit=10.0):
    """Retry a busy unmount; returns how long it stayed busy, in seconds:
    until the last attempt that failed."""
    start = last_busy = time.monotonic()
    while True:
        error = try_umount(target)
        if error == 0:
            return last_busy - start
        last_busy = time.monotonic()
        if error != errno.EBUSY or last_busy - start > limit:
            raise OSError(error, f"umount {target}: {os.strerror(error)}")
        time.sleep(0.0001)


def real_rm(requested):
    """A real rm: never the built shim, which the sandbox PATH puts first."""
    for candidate in (requested, "/usr/bin/gnurm", "/usr/bin/rm", "/bin/rm"):
        if candidate and os.access(candidate, os.X_OK):
            version = subprocess.run([candidate, "--version"], capture_output=True, text=True).stdout
            if "trashd" in version:
                raise SystemExit(f"{candidate} is a trashd shim; pass --rm")
            return candidate, version.splitlines()[0] if version else "?"
    raise SystemExit("no rm found")


def build_jail():
    """A root for the daemon holding its binary, its libraries, /proc and
    the mount point: the only filesystem it can see, and so mark, is ours."""
    JAIL.mkdir()
    sys_mount("trashd-jail", JAIL, "tmpfs", 0, "mode=755")
    # Shared, so a mount below it propagates to the daemon's namespace.
    sys_mount(None, JAIL, None, MS_SHARED)
    for name in ("bin", "lib", "proc", "mnt/t"):
        (JAIL / name).mkdir(parents=True)
    shutil.copy(DAEMON, JAIL / "bin/trashd")
    listing = subprocess.run(["/usr/bin/ldd", str(DAEMON)], capture_output=True, text=True, check=True).stdout
    for line in listing.splitlines():
        fields = line.split()
        if "=>" in fields and len(fields) >= 3 and fields[2].startswith("/"):
            shutil.copy(fields[2], JAIL / "lib" / Path(fields[2]).name)
        elif fields and fields[0].startswith("/"):  # the ELF interpreter
            target = JAIL / fields[0].lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(fields[0], target)
    sys_mount("proc", JAIL / "proc", "proc")


def in_namespace(namespace):
    """preexec_fn: a mount namespace as a systemd unit with ProtectSystem=
    gets one (mounts propagate into it, none out of it), or the caller's."""

    def enter():
        if namespace == "slave":
            if libc.unshare(CLONE_NEWNS) != 0 or libc.mount(None, b"/", None, MS_REC | MS_SLAVE, None) != 0:
                os._exit(125)

    return enter


class Daemon:
    """trashd --foreground in the jail, logging to LOG."""

    THROTTLE = (
        "import os, sys, time\n"
        "delay = float(sys.argv[1]) / 1e6\n"
        "out = os.open(sys.argv[2], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)\n"
        "while True:\n"
        "    chunk = os.read(0, 1 << 16)\n"
        "    if not chunk:\n"
        "        break\n"
        "    os.write(out, chunk)\n"
        "    time.sleep(delay * chunk.count(b'\\n'))\n"
    )

    def __init__(self, namespace, sink_us_per_line):
        start = log_size()
        enter_namespace = in_namespace(namespace)

        def enter():
            enter_namespace()
            os.chroot(JAIL)
            os.chdir("/")

        environment = {"HOME": "/", "PATH": "/bin", "LD_LIBRARY_PATH": "/lib"}
        self.reader = None
        if sink_us_per_line:
            # A consumer that takes time per line, as journald does: the
            # daemon blocks on a full pipe and falls behind the removal.
            self.process = subprocess.Popen(
                ["/bin/trashd", "--foreground"], preexec_fn=enter, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            self.reader = subprocess.Popen(
                [sys.executable, "-c", self.THROTTLE, str(sink_us_per_line), str(LOG)],
                stdin=self.process.stderr, stdout=subprocess.DEVNULL,
            )
            self.process.stderr.close()
        else:
            with open(LOG, "ab") as log:
                self.process = subprocess.Popen(
                    ["/bin/trashd", "--foreground"], preexec_fn=enter, env=environment,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
                )
        deadline = time.monotonic() + 10
        while b"trashd: monitoring " not in log_since(start):
            status = self.process.poll()
            if status is not None:
                self.stop()
                tail = log_since(start).decode(errors="replace").strip().splitlines()[-2:]
                if status == 78:
                    skip(f"fanotify is unavailable here: {tail}")
                raise RuntimeError(f"daemon exited {status}: {tail}")
            if time.monotonic() > deadline:
                self.stop()
                raise RuntimeError("daemon did not start")
            time.sleep(0.005)

    def stop(self):
        if self.process.poll() is None:
            # A daemon left stopped by a failed --stall-ms trial would never
            # see the termination.
            self.process.send_signal(signal.SIGCONT)
            self.process.terminate()
        self.process.wait()
        if self.reader:
            self.reader.wait()


def log_size():
    try:
        return LOG.stat().st_size
    except FileNotFoundError:
        return 0


def log_since(offset, end=None):
    try:
        with open(LOG, "rb") as log:
            log.seek(offset)
            return log.read() if end is None else log.read(max(0, end - offset))
    except FileNotFoundError:
        return b""


def probe(index, watched):
    """Delete a file on the fresh mount. With the daemon, repeat until it
    logs one: its mark died with the last unmount, and it re-marks when it
    sees the mount table change."""
    start = log_size()
    deadline = time.monotonic() + 10
    attempt = 0
    while True:
        name = f"probe-{index}-{attempt}"
        attempt += 1
        (MOUNT / name).touch()
        os.unlink(MOUNT / name)
        if not watched:
            return
        wanted = f'path="/mnt/t/{name}"'.encode()
        for _ in range(40):
            if wanted in log_since(start):
                return
            time.sleep(0.001)
        if time.monotonic() > deadline:
            raise RuntimeError("the daemon never reported a deletion on the new mount")


def build_tree(dirs, files):
    os.mkdir(TREE)
    for d in range(dirs):
        path = f"{TREE}/d{d:05}"
        os.mkdir(path)
        for f in range(files):
            os.close(os.open(f"{path}/f{f}", os.O_CREAT | os.O_WRONLY, 0o644))


def settle(mark, expected, watched):
    """Wait until the daemon has logged the whole removal (or stopped
    logging): nothing of this trial may still be queued for the next."""
    if not watched:
        return 0
    deadline = time.monotonic() + 30
    seen, quiet_since = -1, time.monotonic()
    while True:
        now = log_since(mark).count(DELETE)
        if now >= expected:
            return now
        if now != seen:
            seen, quiet_since = now, time.monotonic()
        elif time.monotonic() - quiet_since > 1.0 or time.monotonic() > deadline:
            return now
        time.sleep(0.01)


def trial(index, daemon, args, rm):
    watched = daemon is not None
    sys_mount(LOOP_NODE, MOUNT, "ext4")
    probe(index, watched)
    build_tree(args.dirs, args.files)
    expected = args.dirs * (args.files + 1) + 1
    mark = log_size()
    delay = None
    if args.umount == "shell":
        # The reported command line, as a shell runs it.
        result = subprocess.run(
            ["/bin/sh", "-c", f"{rm} -rf {TREE} && exec /usr/bin/umount {MOUNT}"],
            capture_output=True, text=True, env={},
        )
        at_umount = None
        busy = result.returncode != 0
        if busy and "busy" not in result.stderr:
            raise RuntimeError(f"rm && umount failed otherwise: {result.stderr.strip()}")
        gap = None
    else:
        # The tightest case: umount(2) right after rm is reaped.
        stalled = watched and args.stall_ms is not None
        if stalled:
            os.kill(daemon.process.pid, signal.SIGSTOP)
        pid = os.posix_spawn(rm, [rm, "-rf", str(TREE)], {})
        if args.freeze_ms is not None:
            # Somewhere within the removal, where a preemption would fall.
            delay = random.uniform(0, args.freeze_ms) / 1e3
            time.sleep(delay)
            if watched:
                os.kill(daemon.process.pid, signal.SIGSTOP)
                _, stopped = os.waitpid(daemon.process.pid, os.WUNTRACED)
                if not os.WIFSTOPPED(stopped):
                    raise RuntimeError("the daemon exited instead of stopping")
        _, status = os.waitpid(pid, 0)
        if stalled:
            os.kill(daemon.process.pid, signal.SIGCONT)
        if args.stall_ms is not None:
            # Somewhere within the time the daemon takes for its backlog.
            delay = random.uniform(0, args.stall_ms) / 1e3
            time.sleep(delay)
        at_umount = log_size()
        reaped = time.perf_counter()
        error = try_umount()
        gap = time.perf_counter() - reaped
        if watched and args.freeze_ms is not None:
            os.kill(daemon.process.pid, signal.SIGCONT)
        if status != 0:
            raise RuntimeError(f"rm exited with status {status}")
        if error not in (0, errno.EBUSY):
            raise OSError(error, f"umount: {os.strerror(error)}")
        busy = error == errno.EBUSY
    busy_for = umount_when_free() if busy else 0.0
    logged = settle(mark, expected, watched)
    # Removal records the daemon had not yet written when the unmount was
    # attempted: it was still decoding handles. (Unknown for a shell's.)
    behind = None
    if watched and at_umount is not None:
        behind = max(0, logged - log_since(mark, at_umount).count(DELETE))
    text = log_since(mark)
    overflow = b"fanotify queue overflow" in text
    # Records that name no directory: the daemon could not resolve theirs.
    unnamed = text.count(DELETE) - text.count(b' path="/mnt/t/tree') if watched else None
    return {
        "trial": index,
        "arm": "daemon" if watched else "control",
        "busy": busy,
        "busy_ms": round(busy_for * 1e3, 3),
        "umount_us": None if gap is None else round(gap * 1e6),
        "delay_ms": None if delay is None else round(delay * 1e3, 3),
        "behind": behind,
        "logged": logged if watched else None,
        "unnamed": unnamed,
        "expected": expected,
        "overflow": overflow,
    }


def positive_controls(namespace):
    """The measurement must see a pin when there is one."""
    sys_mount(LOOP_NODE, MOUNT, "ext4")
    held = os.open(MOUNT, os.O_RDONLY | os.O_DIRECTORY)
    error = try_umount()
    os.close(held)
    if error != errno.EBUSY:
        raise RuntimeError(f"an open descriptor did not make umount busy (errno {error})")
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import os, sys\n"
         f"os.open({str(MOUNT)!r}, os.O_RDONLY | os.O_DIRECTORY)\n"
         "print('held', flush=True)\nsys.stdin.read()\n"],
        preexec_fn=in_namespace(namespace), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    if holder.stdout.readline().strip() != b"held":
        raise RuntimeError("the holder in the daemon's kind of namespace did not start")
    error = try_umount()
    holder.stdin.close()
    holder.wait()
    if error != errno.EBUSY:
        raise RuntimeError(
            f"a descriptor held in a {namespace} mount namespace did not make umount busy (errno {error})"
        )
    umount_when_free()
    print(f"PASS: positive controls: an open descriptor (here, and in a {namespace} namespace) makes umount EBUSY")


def fisher_one_sided(busy_daemon, n_daemon, busy_control, n_control):
    """P(at least this many of the busy trials fall in the daemon arm) if the
    daemon made no difference."""
    total_busy = busy_daemon + busy_control
    total = n_daemon + n_control
    if total_busy == 0 or n_daemon == 0 or n_control == 0:
        return 1.0
    denominator = math.comb(total, total_busy)
    upper = min(total_busy, n_daemon)
    return sum(
        math.comb(n_daemon, k) * math.comb(n_control, total_busy - k)
        for k in range(busy_daemon, upper + 1)
        if total_busy - k <= n_control
    ) / denominator


def summarize(results):
    summary = {}
    for arm in ("control", "daemon"):
        rows = [row for row in results if row["arm"] == arm]
        busy = [row for row in rows if row["busy"]]
        entry = {
            "trials": len(rows),
            "ebusy": len(busy),
            "max_busy_ms": max((row["busy_ms"] for row in busy), default=0.0),
        }
        gaps = [row["umount_us"] for row in rows if row["umount_us"] is not None]
        if gaps:
            entry["median_umount_us"] = statistics.median(gaps)
        if arm == "daemon" and rows:
            behind = [row["behind"] for row in rows if row["behind"] is not None]
            if behind:
                entry.update(
                    # Trials in which the unmount raced the daemon at all.
                    trials_daemon_still_decoding=sum(1 for value in behind if value > 0),
                    median_records_behind=statistics.median(behind),
                    max_records_behind=max(behind),
                    ebusy_while_still_decoding=sum(1 for row in busy if row["behind"]),
                )
            entry.update(
                median_logged=statistics.median(row["logged"] for row in rows),
                expected_records=rows[0]["expected"],
                trials_with_queue_overflow=sum(1 for row in rows if row["overflow"]),
                trials_without_any_record=sum(1 for row in rows if row["logged"] == 0),
                trials_with_unnamed_records=sum(1 for row in rows if row["unnamed"]),
                max_unnamed_records=max(row["unnamed"] for row in rows),
            )
        summary[arm] = entry
    summary["p_one_sided"] = round(
        fisher_one_sided(
            summary["daemon"]["ebusy"], summary["daemon"]["trials"],
            summary["control"]["ebusy"], summary["control"]["trials"],
        ),
        6,
    )
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trials", type=int, default=50, help="per arm (default 50)")
    parser.add_argument("--block", type=int, default=10, help="trials per arm before switching arms")
    parser.add_argument("--dirs", type=int, default=5000, help="directories in the removed tree")
    parser.add_argument("--files", type=int, default=2, help="files in each directory")
    parser.add_argument("--umount", choices=("syscall", "shell"), default="syscall",
                        help="umount(2) right after rm is reaped, or `sh -c 'rm -rf T && umount M'`")
    parser.add_argument("--namespace", choices=("slave", "shared"), default="slave",
                        help="the daemon's mount namespace: its own, as under systemd, or the caller's")
    parser.add_argument("--sink-us-per-line", type=float, default=0,
                        help="read the daemon's log through a pipe at this cost per line (0: a file)")
    parser.add_argument("--cpu", type=int, help="pin the daemon, rm and the unmount to this one CPU")
    parser.add_argument("--hogs", type=int, default=0,
                        help="busy processes to run beside the trials: on a loaded host the daemon lags behind "
                             "the removal, and is preempted while it has the mount open")
    parser.add_argument("--stall-ms", type=float,
                        help="stop the daemon while the tree is removed and continue it when rm is reaped; unmount "
                             "after a random delay of up to this long (in both arms): the unmount then always "
                             "races a daemon that is behind, as one on a busy host or with a slow journal is")
    parser.add_argument("--rm", help="the rm to run (default: GNU rm)")
    parser.add_argument("--freeze-ms", type=float,
                        help="stop the daemon at a random moment within this long after rm starts, and unmount "
                             "while it is stopped: EBUSY then means it was stopped with the mount open, so the "
                             "rate is the share of its running time for which a preemption has that effect")
    parser.add_argument("--max-excess", type=int,
                        help="exit 1 when the daemon arm has more than this many EBUSY over the control arm")
    parser.add_argument("--json", action="store_true", help="print every trial as a JSON line")
    args = parser.parse_args()
    if (args.stall_ms is not None or args.freeze_ms is not None) and args.umount == "shell":
        parser.error("--stall-ms and --freeze-ms need --umount syscall")
    if args.stall_ms is not None and args.freeze_ms is not None:
        parser.error("--stall-ms and --freeze-ms exclude each other")

    require_sandbox()
    if not LOOP_NODE.is_block_device():
        skip("no loop device; run tests/sandbox.py with --loop-device 256")
    if not DAEMON.is_file():
        skip("no built trashd in the sandbox")
    mkfs = shutil.which("mkfs.ext4", path="/usr/sbin:/sbin:/usr/bin:/bin")
    if not mkfs:
        skip("mkfs.ext4 (e2fsprogs) is not installed")
    rm, rm_version = real_rm(args.rm)
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})

    # No lazy initialization: its kernel thread would write to the
    # filesystem during the first trials only.
    subprocess.run(
        [mkfs, "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0", str(LOOP_NODE)],
        check=True, stdout=subprocess.DEVNULL,
    )
    build_jail()
    positive_controls(args.namespace)
    print(
        f"daemon-7: {args.trials} trials per arm in blocks of {args.block}; tree of {args.dirs} directories x "
        f"{args.files} files; {rm} ({rm_version}); umount by {args.umount}; daemon namespace {args.namespace}; "
        f"log sink {'file' if not args.sink_us_per_line else f'pipe at {args.sink_us_per_line} us/line'}; "
        f"{'' if args.stall_ms is None else f'daemon stalled during rm, unmount within {args.stall_ms} ms; '}"
        f"{'' if args.freeze_ms is None else f'daemon stopped within {args.freeze_ms} ms of rm starting; '}"
        f"{args.hogs} busy processes; "
        f"cpus {sorted(os.sched_getaffinity(0)) if args.cpu is not None else 'all'}; kernel {os.uname().release}",
        flush=True,
    )

    results = []
    index = 0
    blocks = math.ceil(args.trials / args.block)
    hogs = [subprocess.Popen([sys.executable, "-c", "while True: pass"]) for _ in range(args.hogs)]
    try:
        for block in range(blocks):
            count = min(args.block, args.trials - block * args.block)
            # Alternate which arm goes first, so drift in host load averages out.
            for watched in ((False, True) if block % 2 == 0 else (True, False)):
                daemon = Daemon(args.namespace, args.sink_us_per_line) if watched else None
                try:
                    for _ in range(count):
                        row = trial(index, daemon, args, rm)
                        index += 1
                        results.append(row)
                        if args.json:
                            print(json.dumps(row), flush=True)
                finally:
                    if daemon:
                        daemon.stop()
    finally:
        for hog in hogs:
            hog.kill()
            hog.wait()

    summary = summarize(results)
    print("SUMMARY " + json.dumps(summary), flush=True)
    control, daemon = summary["control"], summary["daemon"]
    print(
        f"RESULT: EBUSY on the immediate unmount: {daemon['ebusy']}/{daemon['trials']} with trashd, "
        f"{control['ebusy']}/{control['trials']} without (one-sided p = {summary['p_one_sided']}); "
        f"the daemon was still decoding in {daemon.get('trials_daemon_still_decoding', 'an unknown number')} "
        "of its trials",
        flush=True,
    )
    if args.max_excess is not None and daemon["ebusy"] - control["ebusy"] > args.max_excess:
        print(f"FAIL: more than {args.max_excess} EBUSY over the control arm", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
