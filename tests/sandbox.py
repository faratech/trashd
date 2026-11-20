#!/usr/bin/env python3
"""Run destructive regression commands in a disposable mount/PID namespace.

Usage: sudo python3 tests/sandbox.py --build-dir target/debug -- COMMAND [ARG ...]
Built artifacts are available under /opt/trashd/bin (preload under /opt/trashd/lib),
and regression scripts under /tests. No installed trashd configuration is loaded.
"""

import argparse
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time


MARKER = Path("/.trashd-test-sandbox")
# With --loop-device, a block device no host filesystem uses: suites that need
# a filesystem the daemon marks (it never marks tmpfs) mkfs and mount it.
LOOP_NODE = Path("/dev/trashd-test-loop")
ARTIFACTS = {
    "trash": "bin/trash",
    "trashd-rm": "bin/trashd-rm",
    "trashd-exec": "bin/trashd-exec",
    "libtrashd_preload.so": "lib/libtrashd_preload.so",
    "trashd": "bin/trashd",
    # Optional benchmark-only artifacts; keep real daemon/supervisor slots
    # available when comparing all interception layers in one sandbox.
    "bench-baseline-cli": "bin/bench-baseline-cli",
    "bench-baseline-shim": "bin/bench-baseline-shim",
    "bench-baseline-preload.so": "lib/bench-baseline-preload.so",
}


def require_sandbox():
    """Fail before any fixture operation unless the runner contains this process."""
    token = os.environ.get("TRASHD_TEST_SANDBOX_TOKEN")
    try:
        valid = (
            os.environ.get("TRASHD_TEST_SANDBOX") == "1"
            and token
            and MARKER.read_text() == token
            and os.path.samestat(os.stat("/"), os.stat("/proc/1/root"))
            and any(
                line.split()[4] == "/" and " - tmpfs trashd-test-root " in line
                for line in Path("/proc/self/mountinfo").read_text().splitlines()
            )
        )
    except (OSError, IndexError):
        valid = False
    if not valid:
        raise SystemExit("Refusing destructive tests outside tests/sandbox.py containment")


def mount(*args):
    subprocess.run(["/usr/bin/mount", *map(str, args)], check=True)


def unmount_tree(target):
    # Tasks that exit after their task_work has run drop their last file and
    # mount references from a kernel workqueue (delayed fput/mntput), so the
    # tree can stay busy briefly after the namespace's init is reaped. Retry
    # for a bounded time; a tree that stays busy still fails closed.
    for _ in range(40):
        if subprocess.run(["/usr/bin/umount", "-R", str(target)], stderr=subprocess.DEVNULL).returncode == 0:
            return
        time.sleep(0.25)
    subprocess.run(["/usr/bin/umount", "-R", str(target)], check=True)


def attach_loop(image):
    """Bind `image` to a free loop device; return (descriptor, device path).

    LO_FLAGS_AUTOCLEAR has the kernel detach the device when its last user
    closes it. The returned descriptor is that user while a suite runs, so
    even a runner that is killed leaves no attached device behind.
    """
    LOOP_CTL_GET_FREE, LOOP_CONFIGURE, LO_FLAGS_AUTOCLEAR = 0x4C82, 0x4C0A, 4
    backing = os.open(image, os.O_RDWR | os.O_CLOEXEC)
    try:
        control = os.open("/dev/loop-control", os.O_RDWR | os.O_CLOEXEC)
    except OSError:
        os.close(backing)
        raise
    try:
        for _ in range(16):
            path = f"/dev/loop{fcntl.ioctl(control, LOOP_CTL_GET_FREE)}"
            device = os.open(path, os.O_RDWR | os.O_CLOEXEC)
            # struct loop_config { u32 fd; u32 block_size; struct loop_info64
            # info; u64 reserved[8]; }, with info.lo_flags at byte 52.
            config = bytearray(8 + 232 + 64)
            struct.pack_into("=I", config, 0, backing)
            struct.pack_into("=I", config, 8 + 52, LO_FLAGS_AUTOCLEAR)
            try:
                fcntl.ioctl(device, LOOP_CONFIGURE, bytes(config))
                return device, path
            except OSError as error:
                os.close(device)
                if error.errno != errno.EBUSY:  # EBUSY: another process took it first
                    raise
        raise OSError(errno.EBUSY, "no free loop device")
    finally:
        os.close(control)
        os.close(backing)


def release_loop(device, path):
    """Close the runner's descriptor and require the device to be detached."""
    LOOP_GET_STATUS64 = 0x4C05
    os.close(device)
    for _ in range(40):
        with open(path, "rb") as probe:
            try:
                fcntl.ioctl(probe, LOOP_GET_STATUS64, bytes(232))
            except OSError as error:
                if error.errno == errno.ENXIO:  # no backing file: detached
                    return
                raise
        time.sleep(0.25)
    raise RuntimeError(f"loop device {path} is still attached")


def enter(root, command):
    # Internal entry point invoked as PID 1 by unshare. A marker alone does
    # not authorize execution: require_sandbox also checks the root mount and
    # PID namespace after chroot and proc mounting.
    token = os.environ.get("TRASHD_TEST_SANDBOX_TOKEN")
    if not token or (root / MARKER.name).read_text() != token:
        raise SystemExit("Invalid sandbox entry marker")
    os.chroot(root)
    os.chdir("/work")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(b"proc", b"/proc", b"proc", 2 | 4 | 8, None) != 0:
        raise OSError(ctypes.get_errno(), "mount sandbox /proc")
    env = {
        "PATH": "/opt/trashd/bin:/usr/bin:/bin",
        "HOME": "/home/test",
        "XDG_DATA_HOME": "/home/test/.local/share",
        "XDG_CONFIG_HOME": "/home/test/.config",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "TRASH_BYPASS": "0",
        "TRASHD_TEST_SANDBOX": "1",
        "TRASHD_TEST_SANDBOX_TOKEN": token,
    }
    for name in ("REQUIRE_SECCOMP", "TRASHD_TEST_NETWORK"):
        if name in os.environ:
            env[name] = os.environ[name]
    os.environ.clear()
    os.environ.update(env)
    require_sandbox()
    os.execvpe(command[0], command, env)


def run(args, command):
    if os.geteuid() != 0:
        raise SystemExit("The test sandbox needs mount privileges; rerun with sudo")
    repo = Path(__file__).resolve().parents[1]
    build = Path(args.build_dir).resolve() if args.build_dir else repo / "target/debug"
    artifacts = {name: build / name for name in ARTIFACTS if (build / name).is_file()}
    for override in args.binary:
        name, separator, path = override.partition("=")
        if not separator or name not in ARTIFACTS:
            raise SystemExit(f"Expected --binary NAME=PATH; supported names: {', '.join(ARTIFACTS)}")
        artifacts[name] = Path(path).resolve(strict=True)
    if not artifacts:
        raise SystemExit(f"No built artifacts in {build}; run cargo build first")

    # Disable any already-loaded host preload before temporary-file cleanup.
    # Removing LD_PRELOAD affects child loaders; TRASH_BYPASS also handles an
    # installed /etc/ld.so.preload library already present in this process.
    os.environ["TRASH_BYPASS"] = "1"
    os.environ.pop("LD_PRELOAD", None)
    os.environ.pop("TRASHD_SECCOMP_ACTIVE", None)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.unshare(0x00020000) != 0:  # CLONE_NEWNS
        raise SystemExit(f"Mount namespace unavailable: {os.strerror(ctypes.get_errno())}; no tests ran")
    mount("--make-rprivate", "/")

    # A terminated runner (a timeout, a closed terminal) cleans up as an
    # interrupted one does, instead of leaving its sandbox running.
    def terminated(number, _frame):
        raise SystemExit(128 + number)

    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, terminated)

    scratch = Path(tempfile.mkdtemp(prefix="trashd-sandbox-"))
    # The UID 65534 sentinel must be traversable before chroot, so its
    # protection is demonstrated by containment rather than host permissions.
    scratch.chmod(0o755)
    root = scratch / "root"
    external = scratch / "external"
    root.mkdir()
    external.mkdir()
    loop = None
    try:
        mount("-t", "tmpfs", "-o", "mode=755", "trashd-test-root", root)
        mount("-t", "tmpfs", "-o", "mode=755", "trashd-test-external", external)
        # Model a pre-existing mounted trash outside the sandbox. A real
        # `trash empty` runs inside; neither discovery nor deletion may
        # reach this old entry, even though the mount namespace contains it.
        sidecar = b"[Trash Info]\nPath=/external-sentinel\nDeletionDate=2000-01-01T00:00:00\n"
        sentinels = []
        for uid in (0, 65534):
            sentinel = external / f".Trash-{uid}"
            (sentinel / "files").mkdir(parents=True, mode=0o700)
            sentinel.chmod(0o700)
            (sentinel / "info").mkdir(mode=0o700)
            (sentinel / "files/KEEP").write_bytes(b"external trash must survive\n")
            (sentinel / "info/KEEP.trashinfo").write_bytes(sidecar)
            for entry in (sentinel, *sentinel.rglob("*")):
                os.chown(entry, uid, uid)
            sentinels.append(sentinel)

        for name in ("usr", "etc", "dev", "proc", "tmp", "work", "home/test", "home/nobody", "opt/trashd/bin", "opt/trashd/lib"):
            (root / name).mkdir(parents=True, exist_ok=True)
        # Non-recursive read-only binds expose runtimes, never writable
        # host data. Separate host submounts are not imported.
        for name in ("usr", "bin", "sbin", "lib", "lib64"):
            source = Path("/") / name
            if source.is_symlink():
                (root / name).symlink_to(os.readlink(source))
            elif source.is_dir():
                (root / name).mkdir(exist_ok=True)
                mount("--bind", source, root / name)
                mount("-o", "remount,bind,ro", root / name)
        # Hide installed trashd binaries/stashes as well as global config.
        if (root / "usr/local").is_dir():
            mount("-t", "tmpfs", "-o", "mode=755", "trashd-test-local", root / "usr/local")
        for name in ("null", "zero", "full", "random", "urandom"):
            (root / "dev" / name).touch()
            mount("--bind", Path("/dev") / name, root / "dev" / name)
        if args.loop_device:
            image = scratch / "loop.img"
            with open(image, "wb") as backing:
                backing.truncate(args.loop_device << 20)
            loop = attach_loop(image)
            # The device keeps the image open; unnamed, it is freed with the
            # device even when this runner is killed.
            image.unlink()
            (root / LOOP_NODE.relative_to("/")).touch()
            mount("--bind", loop[1], root / LOOP_NODE.relative_to("/"))
        (root / "dev/fd").symlink_to("/proc/self/fd")
        for name, fd in (("stdin", 0), ("stdout", 1), ("stderr", 2)):
            (root / "dev" / name).symlink_to(f"/proc/self/fd/{fd}")
        (root / "tmp").chmod(0o1777)
        (root / "work").chmod(0o1777)
        # The suite runs as uid 0 with HOME=/home/test: keep the home
        # root-owned. A foreign-owned ancestor is correctly refused by the
        # store ("can be replaced by another user") and used to abort the
        # whole suite on its first call (#126).
        os.chown(root / "home/test", 0, 0)
        os.chown(root / "home/nobody", 65534, 65534)
        (root / "home/nobody").chmod(0o700)
        (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/home/nobody:/bin/sh\n")
        (root / "etc/group").write_text("root:x:0:\nnogroup:x:65534:\n")
        for name in ("resolv.conf", "localtime"):
            if (Path("/etc") / name).is_file():
                shutil.copyfile(Path("/etc") / name, root / "etc" / name)
        # Debian-style /usr/bin tools (awk, editor, ...) are alternatives
        # symlinks through /etc/alternatives; expose those links read-only.
        if Path("/etc/alternatives").is_dir():
            (root / "etc/alternatives").mkdir(parents=True)
            mount("--bind", "/etc/alternatives", root / "etc/alternatives")
            mount("-o", "remount,bind,ro", root / "etc/alternatives")
        if Path("/etc/ssl/certs").is_dir():
            (root / "etc/ssl/certs").mkdir(parents=True)
            mount("--bind", "/etc/ssl/certs", root / "etc/ssl/certs")
            mount("-o", "remount,bind,ro", root / "etc/ssl/certs")

        shutil.copytree(repo / "tests", root / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        for source, target in (
            ("crates/trashd-preload/tests/policy.py", "preload_policy.py"),
            ("crates/trashd-seccomp/tests/regression.py", "seccomp_regression.py"),
        ):
            if (repo / source).is_file():
                shutil.copyfile(repo / source, root / "tests" / target)
        # Installer sources for tests/install_regression.sh; the sandbox's /etc
        # and /usr/local are tmpfs, so installing there never reaches the host.
        (root / "src").mkdir()
        shutil.copyfile(repo / "install.sh", root / "src/install.sh")
        (root / "src/install.sh").chmod(0o755)
        shutil.copyfile(repo / "Makefile", root / "src/Makefile")
        for name in ("install", "config"):
            shutil.copytree(repo / name, root / "src" / name)
        for name, source in artifacts.items():
            shutil.copyfile(source, root / "opt/trashd" / ARTIFACTS[name])
            (root / "opt/trashd" / ARTIFACTS[name]).chmod(0o755)
        if "trashd-rm" in artifacts:
            (root / "opt/trashd/bin/rm").symlink_to("trashd-rm")

        token = secrets.token_hex(24)
        (root / MARKER.name).write_text(token)
        os.environ["TRASHD_TEST_SANDBOX_TOKEN"] = token
        # PR_SET_PDEATHSIG: a runner that is killed outright takes the
        # sandbox with it (unshare, then --kill-child, then the PID
        # namespace), and with it the mounts and the loop device.
        result = subprocess.run([
            "/usr/bin/unshare", "--pid", "--fork", "--kill-child",
            "/usr/bin/python3", str(Path(__file__).resolve()),
            "--enter", str(root), "--", *command,
        ], preexec_fn=lambda: libc.prctl(1, signal.SIGKILL))
        for sentinel in sentinels:
            if (sentinel / "files/KEEP").read_bytes() != b"external trash must survive\n" or (sentinel / "info/KEEP.trashinfo").read_bytes() != sidecar:
                raise RuntimeError(f"external mounted trash sentinel was changed: {sentinel.name}")
        print("PASS: external mounted trash sentinel unchanged", flush=True)
        return result.returncode
    finally:
        # Never recurse into mounted host runtimes during cleanup. A
        # failed unmount deliberately leaves scratch behind and errors.
        for target in (root, external):
            if os.path.ismount(target):
                unmount_tree(target)
        # After the unmount: a filesystem the suite left mounted on the
        # device went with the tree, so nothing else holds it.
        if loop:
            release_loop(*loop)
        shutil.rmtree(scratch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir")
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument(
        "--loop-device", type=int, metavar="MIB",
        help=f"expose an empty loop device of this size as {LOOP_NODE}",
    )
    parser.add_argument("--enter", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command after -- is required")
    if args.enter:
        enter(args.enter, command)
    return run(args, command)


if __name__ == "__main__":
    sys.exit(main())
