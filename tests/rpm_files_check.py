#!/usr/bin/env python3
"""Compare the RPM spec's %files with what `make install` stages.

rpmbuild fails on files that are installed but unpackaged, and on packaged
files that were never installed (#141, #159, #213). This reproduces that check
without rpmbuild: stage `make install` with RPM's paths into a temporary
DESTDIR (never touching the host) and compare both sets.

Usage: python3 tests/rpm_files_check.py   (after `cargo build --release`)
"""
import pathlib
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
MACROS = {
    "_bindir": "/usr/bin",
    "_prefix": "/usr",
    "_sysconfdir": "/etc",
    "_unitdir": "/usr/lib/systemd/system",
    "_userunitdir": "/usr/lib/systemd/user",
    "_mandir": "/usr/share/man",
    "_datadir": "/usr/share",
}


def claimed_files(spec):
    section = spec.split("\n%files\n", 1)[1].split("\n\n%", 1)[0]
    files, prefixes = set(), set()
    for line in section.splitlines():
        line = line.strip()
        if not line or line.startswith(("%license", "%doc", "%dir ")):
            continue
        line = re.sub(r"^%config\(noreplace\)\s+", "", line)
        path = re.sub(r"%\{(\w+)\}", lambda m: MACROS[m.group(1)], line)
        if path.endswith("*"):  # e.g. compressed man pages
            prefixes.add(path.rstrip("*"))
        else:
            files.add(path)
    return files, prefixes


def main():
    spec = (REPO / "packaging/trashd.spec").read_text()
    files, prefixes = claimed_files(spec)
    with tempfile.TemporaryDirectory() as stage:
        subprocess.run(
            ["make", "-s", "-C", str(REPO), "install", f"DESTDIR={stage}",
             "PREFIX=/usr", f"UNITDIR={MACROS['_unitdir']}",
             f"USERUNITDIR={MACROS['_userunitdir']}"],
            check=True, stdout=subprocess.DEVNULL,
        )
        root = pathlib.Path(stage)
        staged = {"/" + str(p.relative_to(root)) for p in root.rglob("*")
                  if p.is_file() or p.is_symlink()}
    unpackaged = sorted(p for p in staged
                        if p not in files and not any(p.startswith(x) for x in prefixes))
    missing = sorted(p for p in files if p not in staged)
    missing += sorted(x + "*" for x in prefixes if not any(p.startswith(x) for p in staged))
    for path in unpackaged:
        print(f"installed but unpackaged: {path}")
    for path in missing:
        print(f"packaged but not installed: {path}")
    if unpackaged or missing:
        return 1
    print(f"ok: {len(staged)} staged files match %files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
