#!/usr/bin/env python3
"""Lint the distribution package scriptlets and the release workflow.

- Arch: pacman runs scriptlets only from the file the PKGBUILD names with
  install= (makepkg packages it as .INSTALL); functions written into the
  PKGBUILD itself never run, so Layer 2 was never registered (install-3).
- Both packages drop their /etc/ld.so.preload entry before the library is
  erased: RPM in %preun on erase ($1 == 0), Arch in pre_remove. %postun and
  post_remove run after the files are gone (install-6).
- Registration is idempotent across upgrades and leaves the list mode 0644
  (install-2). The scriptlets run here against a temporary root, with every
  absolute path they touch redirected into it.
- Workflow jobs that run third-party build code (cargo, pip, make) hold no
  write permission and do not persist the token in .git/config (install-7).

Usage: python3 tests/packaging_lint.py
"""
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
PACKAGING = REPO / "packaging"
ARCH_SCRIPTLETS = ("pre_install", "post_install", "pre_upgrade", "post_upgrade",
                   "pre_remove", "post_remove")
ERRORS = []


def check(ok, message):
    if not ok:
        ERRORS.append(message)
    return ok


def shell_function(text, name):
    match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}", text, re.M | re.S)
    return match.group(1) if match else None


def run_sh(script, *args):
    # TRASH_BYPASS: on a host with the preload registered, nothing here may
    # be redirected into a trash directory.
    env = {"PATH": "/usr/bin:/bin", "TRASH_BYPASS": "1", "LC_ALL": "C"}
    result = subprocess.run(["/bin/sh", "-c", script, "sh", *args], env=env,
                            capture_output=True, text=True)
    check(result.returncode == 0,
          f"scriptlet {args} exited {result.returncode}: {result.stderr.strip()}")


class FakeRoot:
    """A temporary root holding ld.so.preload and the packaged library."""

    def __init__(self, base, libdir):
        self.preload = pathlib.Path(base) / "etc/ld.so.preload"
        self.preload.parent.mkdir(parents=True)
        self.lib = pathlib.Path(base) / libdir.lstrip("/") / "libtrashd_preload.so"
        self.lib.parent.mkdir(parents=True)
        self.lib.write_bytes(b"")

    def write(self, text, mode=0o644):
        self.preload.write_text(text)
        self.preload.chmod(mode)

    def read(self):
        return self.preload.read_text() if self.preload.exists() else None

    def mode(self):
        return stat.S_IMODE(self.preload.stat().st_mode)


def exercise(what, root, register, deregister, keep_on_upgrade=None):
    """Register, re-register, then deregister against a FakeRoot."""
    entry = str(root.lib)
    root.write("/other/libaudit.so\n", mode=0o600)
    register()
    check(root.read() == f"/other/libaudit.so\n{entry}\n",
          f"{what}: registration wrote {root.read()!r}")
    check(root.mode() == 0o644, f"{what}: registration left the list mode {root.mode():o}")
    register()
    check(root.read() == f"/other/libaudit.so\n{entry}\n",
          f"{what}: registration is not idempotent: {root.read()!r}")
    if keep_on_upgrade:
        keep_on_upgrade()
        check(root.read() == f"/other/libaudit.so\n{entry}\n",
              f"{what}: an upgrade deregistered the library: {root.read()!r}")
    root.write(f"/other/a.so:{entry} # note\n{entry}\n")
    deregister()
    check(root.read() == "/other/a.so # note\n",
          f"{what}: deregistration wrote {root.read()!r}")
    root.write(f"{entry}\n")
    deregister()
    check(root.read() is None, f"{what}: an empty list was left behind: {root.read()!r}")


def lint_arch():
    pkgbuild = (PACKAGING / "PKGBUILD").read_text()
    for name in ARCH_SCRIPTLETS:
        check(not re.search(rf"^{name}\(\)", pkgbuild, re.M),
              f"PKGBUILD defines {name}() itself; pacman never runs it")
    match = re.search(r"""^install=['"]?([^'"\s]+)['"]?\s*$""", pkgbuild, re.M)
    if not check(match, "PKGBUILD has no install=, so pacman runs no scriptlet"):
        return
    install = PACKAGING / match.group(1)
    if not check(install.is_file(), f"PKGBUILD install={match.group(1)} does not exist"):
        return
    text = install.read_text()
    for name in ("post_install", "post_upgrade", "pre_remove"):
        check(shell_function(text, name) is not None, f"{install.name} defines no {name}()")
    post_remove = shell_function(text, "post_remove") or ""
    check("ld.so.preload" not in post_remove,
          f"{install.name}: post_remove runs after the library is deleted")
    check("ld.so.preload" in (shell_function(text, "pre_remove") or ""),
          f"{install.name}: pre_remove does not deregister the library")

    with tempfile.TemporaryDirectory() as base:
        root = FakeRoot(base, "/usr/lib/trashd")
        script = (text.replace("/etc/ld.so.preload", str(root.preload))
                  .replace("/usr/lib/trashd/", str(root.lib.parent) + "/"))
        exercise(install.name, root,
                 lambda: run_sh(script + '\npost_install "$1"\n', "1.0-1"),
                 lambda: run_sh(script + '\npre_remove "$1"\n', "1.0-1"),
                 lambda: run_sh(script + '\npost_upgrade "$1" "$2"\n', "1.1-1", "1.0-1"))


def spec_sections(spec):
    sections, name = {}, None
    for line in spec.splitlines():
        header = re.match(r"^%(\w+)\s*$", line)
        if header and header.group(1) in ("post", "preun", "postun", "pre", "files",
                                          "changelog", "install", "build", "prep",
                                          "description"):
            name = header.group(1)
            sections[name] = []
        elif name:
            sections[name].append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def lint_rpm():
    spec = (PACKAGING / "trashd.spec").read_text()
    sections = spec_sections(spec)
    preun, postun = sections.get("preun", ""), sections.get("postun", "")
    check("ld.so.preload" not in postun,
          "trashd.spec: %postun rewrites ld.so.preload after the library is erased")
    check("ld.so.preload" in preun and re.search(r'"\$1" -eq 0', preun),
          "trashd.spec: %preun does not deregister the library on erase ($1 == 0)")

    with tempfile.TemporaryDirectory() as base:
        root = FakeRoot(base, "/usr/lib/trashd")
        prefix = str(root.lib.parents[2])

        def scriptlet(name):
            body = "\n".join(line for line in sections.get(name, "").splitlines()
                             if not line.startswith("%"))
            return body.replace("%{_prefix}", prefix).replace("/etc/ld.so.preload", str(root.preload))

        exercise("trashd.spec", root,
                 lambda: run_sh(scriptlet("post"), "1"),
                 lambda: run_sh(scriptlet("preun"), "0"),
                 lambda: run_sh(scriptlet("preun"), "1"))


def lint_workflows():
    try:
        import yaml
    except ImportError:
        print("skip: PyYAML is not installed; workflow permissions not checked")
        return
    build = re.compile(r"(^|[\s;&|(/])(cargo|pip3?|make|rustup)\s", re.M)
    for path in sorted((REPO / ".github/workflows").glob("*.yml")):
        doc = yaml.safe_load(path.read_text())
        top = doc.get("permissions")
        for name, job in (doc.get("jobs") or {}).items():
            steps = job.get("steps") or []
            runs = "\n".join(str(step.get("run", "")) for step in steps)
            uses = [str(step.get("uses", "")) for step in steps]
            if not (build.search(runs) or any(u.startswith("Swatinem/rust-cache") for u in uses)):
                continue
            where = f"{path.name}: job {name}"
            perms = job.get("permissions", top)
            check(isinstance(perms, dict) and "write" not in perms.values(),
                  f"{where} runs build code with write permissions: {perms!r}")
            for step in steps:
                if str(step.get("uses", "")).startswith("actions/checkout"):
                    check((step.get("with") or {}).get("persist-credentials") is False,
                          f"{where} persists the checkout token in .git/config")


def main():
    lint_arch()
    lint_rpm()
    lint_workflows()
    for error in ERRORS:
        print(f"FAIL: {error}")
    if ERRORS:
        return 1
    print("ok: package scriptlets and workflow permissions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
