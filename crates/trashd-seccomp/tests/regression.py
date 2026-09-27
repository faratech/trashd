#!/usr/bin/env python3
"""Disposable seccomp integration, invoked through tests/sandbox.py.

No installation or existing-trash operations. REQUIRE_SECCOMP=1 makes an
unavailable listener a failure, for CI on a clean Linux kernel. The fallback
and signal cases always run, even on hosts with an existing notification filter.
"""

import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote_to_bytes


sys.path.insert(0, "/tests")
from sandbox import require_sandbox

BIN = Path("/opt/trashd/bin/trashd-exec")
PRELOAD = Path("/opt/trashd/lib/libtrashd_preload.so")
LIBC = ctypes.CDLL(None, use_errno=True)
SYSCALL_SECCOMP = {"x86_64": 317, "aarch64": 277}[os.uname().machine]
SYSCALL_READV = {"x86_64": 310, "aarch64": 270}[os.uname().machine]


class Instruction(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("instructions", ctypes.POINTER(Instruction))]


def force_install_error(error, syscall=SYSCALL_SECCOMP):
    """A real inherited kernel filter that rejects only one syscall."""
    def install():
        instructions = (Instruction * 4)(
            Instruction(0x20, 0, 0, 0),
            Instruction(0x15, 0, 1, syscall),
            Instruction(0x06, 0, 0, 0x00050000 | error),
            Instruction(0x06, 0, 0, 0x7FFF0000),
        )
        program = Program(len(instructions), instructions)
        if LIBC.prctl(38, 1, 0, 0, 0) or LIBC.syscall(SYSCALL_SECCOMP, 1, 0, ctypes.byref(program)):
            raise RuntimeError("cannot install failure-injection filter")
    return install


def wait_until(predicate, description, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError(f"timed out: {description}")


def line(process):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise AssertionError("wrapped command stopped responding")
    result = process.stdout.readline().strip()
    assert result, f"wrapped command exited unexpectedly ({process.poll()})"
    return json.loads(result)


def children(pid):
    try:
        return [int(p) for p in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]
    except FileNotFoundError:
        return []


def recovery_records(data, original):
    records = []
    for info in (data / "Trash/info").glob("*.trashinfo"):
        contents = info.read_bytes()
        for entry in contents.splitlines():
            if entry.startswith(b"Path=") and unquote_to_bytes(entry[5:]) == os.fsencode(original):
                records.append(contents)
                break
    return records


TARGET = r'''
import json, os, subprocess, sys, time
print(json.dumps([os.getpid(), os.environ.get("TRASHD_SECCOMP_ACTIVE")]), flush=True)
for row in sys.stdin:
    mode, path = json.loads(row)
    if mode == "child":
        subprocess.run([sys.executable, "-c", "import os,sys; os.unlink(sys.argv[1])", path], check=True)
    elif mode == "dirfd":
        fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
        try: os.unlink(os.path.basename(path), dir_fd=fd)
        finally: os.close(fd)
    elif mode == "exit":
        break
    elif mode == "orphan":
        parent = os.getpid()
        child = os.fork()
        if child:
            os._exit(37)
        while os.getppid() == parent:
            time.sleep(0.01)
        print(json.dumps(["adopted", os.getpid()]), flush=True)
        while not os.path.exists(path + ".go"):
            time.sleep(0.01)
        os.unlink(path)
        print(json.dumps("ok"), flush=True)
        os._exit(0)
    else:
        os.unlink(path)
    print(json.dumps("ok"), flush=True)
'''


def launch(env, log, error=None, syscall=SYSCALL_SECCOMP):
    return subprocess.Popen(
        [str(BIN), sys.executable, "-u", "-c", TARGET],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=log, text=True, start_new_session=True,
        preexec_fn=force_install_error(error, syscall) if error is not None else None,
    )


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def delete(process, work, data, mode, name, fifo=False):
    path = work / name
    if fifo:
        os.mkfifo(path)
    else:
        path.write_bytes(b"recoverable\n")
    process.stdin.write(json.dumps([mode, str(path)]) + "\n")
    process.stdin.flush()
    assert line(process) == "ok"
    assert not path.exists(), path
    assert recovery_records(data, path), f"permanent deletion: {path}"


def run():
    require_sandbox()
    assert BIN.is_file() and PRELOAD.is_file(), "build seccomp + preload before creating sandbox"
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    assert os.geteuid() != 0, "Yama regression must run without root privileges"
    # HOME (rather than /tmp) avoids the product's default never-trash list.
    with tempfile.TemporaryDirectory(prefix=".trashd-seccomp-test-", dir=Path.home()) as location:
        fixture = Path(location)
        home, data, work = fixture / "home", fixture / "data", fixture / "work"
        work.mkdir()
        data.mkdir()  # ensure preload can compare the home trash device
        config = home / ".config/trashd"
        config.mkdir(parents=True)
        (config / "config.toml").write_text(
            "only_trash = []\nmax_file_size_mb = 0\nsha256_max_size_mb = 1\n"
            "[retention]\nmax_age_days = 0\nmax_size_gb = 0\ndisk_pressure_percent = 0\n"
        )
        env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(data),
                   XDG_CONFIG_HOME=str(home / ".config"), TRASH_BYPASS="0",
                   LD_PRELOAD=str(PRELOAD), TRASHD_SECCOMP_ACTIVE="1")
        # Force both documented startup failure classes and confirm actual
        # preload recovery, even when an inherited ACTIVE marker was present.
        for error in [errno.EBUSY, errno.EPERM]:
            log_path = fixture / f"fallback-{error}.log"
            with log_path.open("w") as log:
                process = launch(env, log, error)
                try:
                    _, active = line(process)
                    assert active is None
                    delete(process, work, data, "unlink", f"fallback-{error}.txt")
                    process.stdin.write(json.dumps(["exit", ""]) + "\n")
                    process.stdin.flush()
                    assert process.wait(timeout=5) == 0
                finally:
                    stop(process)
            assert "seccomp filter install failed" in log_path.read_text()
        print("PASS: EBUSY/EPERM clear ACTIVE and retain preload recovery", flush=True)

        # On a clean kernel this installs a listener successfully, then fails
        # the parent's startup access probe. It must kill that waiting child
        # and exec a fresh unfiltered fallback, keeping preload functional.
        with (fixture / "access-failure.log").open("w") as log:
            process = launch(env, log, errno.EPERM, SYSCALL_READV)
            try:
                _, active = line(process)
                assert active is None
                delete(process, work, data, "unlink", "access-fallback.txt")
                process.stdin.write(json.dumps(["exit", ""]) + "\n")
                process.stdin.flush()
                assert process.wait(timeout=5) == 0
            finally:
                stop(process)
        if os.environ.get("REQUIRE_SECCOMP") == "1":
            assert "cannot inspect protected child" in (fixture / "access-failure.log").read_text()

        # Direct-to-wrapper signals must work on the guaranteed fallback path.
        for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
            with (fixture / f"signal-{sig}.log").open("w") as log:
                process = launch(env, log, errno.EBUSY)
                try:
                    target, _ = line(process)
                    os.kill(process.pid, sig)
                    assert process.wait(timeout=5) == 128 + sig
                    assert not Path(f"/proc/{target}").exists()
                finally:
                    stop(process)
        print("PASS: HUP/INT/TERM forwarded on startup fallback", flush=True)

        # With preload disabled, only a working notification supervisor can
        # recover these deletes; descendants exercise the Yama fork boundary.
        protected_env = dict(env)
        protected_env.pop("LD_PRELOAD", None)
        protected_env.pop("TRASHD_SECCOMP_ACTIVE", None)
        log_path = fixture / "protected.log"
        with log_path.open("w") as log:
            process = launch(protected_env, log)
            try:
                target, active = line(process)
                if active != "1":
                    if os.environ.get("REQUIRE_SECCOMP") == "1":
                        raise AssertionError("listener unavailable:\n" + log_path.read_text())
                    print("SKIP: protected integration (listener unavailable); set REQUIRE_SECCOMP=1 in CI")
                    return
                for mode in ["unlink", "child", "dirfd"]:
                    delete(process, work, data, mode, f"before-{mode}.txt")
                delete(process, work, data, "unlink", "pipe", fifo=True)
                watchdog = wait_until(lambda: next((p for p in children(process.pid) if p != target), None), "watchdog")
                supervisor = wait_until(lambda: children(watchdog), "supervisor")[0]
                os.kill(supervisor, signal.SIGKILL)
                wait_until(lambda: [p for p in children(watchdog) if p != supervisor], "replacement supervisor")
                for mode in ["unlink", "child", "dirfd"]:
                    delete(process, work, data, mode, f"after-{mode}.txt")
                os.kill(process.pid, signal.SIGTERM)
                assert process.wait(timeout=5) == 128 + signal.SIGTERM
                assert not Path(f"/proc/{target}").exists()
            finally:
                stop(process)
        print("PASS: protected deletes, forked children, dirfds, FIFO, restart, signals", flush=True)

        for sig in [signal.SIGHUP, signal.SIGINT]:
            with (fixture / f"protected-signal-{sig}.log").open("w") as log:
                process = launch(protected_env, log)
                try:
                    target, active = line(process)
                    assert active == "1", "protected signal case lost listener"
                    os.kill(process.pid, sig)
                    assert process.wait(timeout=5) == 128 + sig
                    assert not Path(f"/proc/{target}").exists()
                finally:
                    stop(process)
        print("PASS: HUP/INT forwarded with active seccomp protection", flush=True)

        # Successful startup must suppress the loaded fallback library. The
        # only recovery record must belong to seccomp, with the original path.
        preloaded_env = dict(protected_env, LD_PRELOAD=str(PRELOAD))
        with (fixture / "protected-with-preload.log").open("w") as log:
            process = launch(preloaded_env, log)
            try:
                _, active = line(process)
                assert active == "1"
                before = set((data / "Trash/info").glob("*.trashinfo"))
                delete(process, work, data, "unlink", "single-interception.txt")
                after = set((data / "Trash/info").glob("*.trashinfo"))
                records = recovery_records(data, work / "single-interception.txt")
                assert len(after - before) == len(records) == 1, "duplicate interception"
                assert b"X-Trashd-Command=seccomp" in records[0].splitlines()
                process.stdin.write(json.dumps(["exit", ""]) + "\n")
                process.stdin.flush()
                assert process.wait(timeout=5) == 0
            finally:
                stop(process)
        print("PASS: active seccomp with preload creates exactly one seccomp record", flush=True)

        for cancel in [False, True]:
            with (fixture / f"orphan-{cancel}.log").open("w") as log:
                process = launch(protected_env, log)
                try:
                    original, active = line(process)
                    assert active == "1"
                    path = work / f"orphan-{cancel}.txt"
                    path.write_bytes(b"orphan must remain recoverable\n")
                    process.stdin.write(json.dumps(["orphan", str(path)]) + "\n")
                    process.stdin.flush()
                    event, orphan = line(process)
                    assert event == "adopted"
                    wait_until(lambda: not Path(f"/proc/{original}").exists(), "original command reaped")
                    assert process.poll() is None, "wrapper exited with protected descendant alive"
                    if cancel:
                        os.kill(process.pid, signal.SIGTERM)
                    else:
                        Path(str(path) + ".go").touch()
                        assert line(process) == "ok"
                        assert recovery_records(data, path), "orphan deletion was not recovered"
                    assert process.wait(timeout=5) == 37, "original exit status must be preserved"
                    assert not Path(f"/proc/{orphan}").exists(), "adopted child not reaped"
                finally:
                    stop(process)
        print("PASS: orphan descendants retain protection and signal forwarding until reaped", flush=True)


if __name__ == "__main__":
    run()
