#!/usr/bin/env bash
# Installer checks against locally built artifacts, inside tests/sandbox.py.
# Usage: sudo ./tests/install_regression.sh [target/debug|target/release]
#
# The sandbox's /etc and /usr/local are tmpfs, so ld.so.preload, profile.d and
# PREFIX writes made by install.sh never reach the host.
set -euo pipefail

if [[ "${TRASHD_TEST_SANDBOX:-}" != "1" ]]; then
    REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    exec env TRASH_BYPASS=1 python3 "$REPO/tests/sandbox.py" \
        --build-dir "${1:-$REPO/target/debug}" -- /bin/bash /tests/install_regression.sh
fi
python3 -c 'import sys; sys.path.insert(0, "/tests"); from sandbox import require_sandbox; require_sandbox()'
[[ -x /src/install.sh ]] || { echo "Missing installer sources in the sandbox" >&2; exit 1; }
for artifact in trash trashd-rm trashd-exec trashd; do
    [[ -x "/opt/trashd/bin/$artifact" ]] || { echo "Missing built artifact: $artifact" >&2; exit 1; }
done

WORK=$(mktemp -d /work/install.XXXXXX)
# The sandbox PATH puts the built shim first; a real system's installer runs
# with the genuine rm, so do the same here.
INSTALL_PATH=/usr/bin:/bin

# Stage a release-tarball layout (as .github/workflows/release.yml packages it).
stage() {
    local dir="$1"
    mkdir -p "$dir/bin" "$dir/lib" "$dir/config" "$dir/install"
    cp /opt/trashd/bin/trash /opt/trashd/bin/trashd-rm /opt/trashd/bin/trashd-exec \
        /opt/trashd/bin/trashd "$dir/bin/"
    cp /opt/trashd/lib/libtrashd_preload.so "$dir/lib/"
    cp /src/install.sh "$dir/"
    cp -r /src/install/. "$dir/install/"
    cp /src/config/trashd.toml "$dir/config/"
    # trash-future stands in for a subcommand newer than any fixed list.
    mkdir -p "$dir/share/man/man1"
    for page in trash trash-ls trash-future; do
        printf '.TH %s 1\n' "$page" > "$dir/share/man/man1/$page.1"
    done
}

fail() { echo "FAIL: $1" >&2; exit 1; }

# -----------------------------------------------------------------------
# #191: an artifact this system's loader cannot run is refused before any
# change. Registering it in /etc/ld.so.preload would break every program.
# -----------------------------------------------------------------------
stage "$WORK/broken"
printf 'not an ELF object\n' > "$WORK/broken/lib/libtrashd_preload.so"
if env PATH="$INSTALL_PATH" "$WORK/broken/install.sh" > "$WORK/broken.log" 2>&1; then
    fail "installer accepted a non-loadable preload library"
fi
grep -q "cannot be loaded" "$WORK/broken.log" || fail "no loader diagnostic: $(cat "$WORK/broken.log")"
if grep -qs libtrashd_preload.so /etc/ld.so.preload; then
    fail "/etc/ld.so.preload was modified"
fi
[[ ! -e /usr/local/bin/trash ]] || fail "binaries were installed before the load check"
echo "PASS: non-loadable preload is refused before any system change"

stage "$WORK/good"
mkdir -p /etc/profile.d  # absent in the sandbox; install.sh only writes the hook if it exists
env PATH="$INSTALL_PATH" "$WORK/good/install.sh" > "$WORK/good.log" 2>&1 \
    || fail "installer failed: $(cat "$WORK/good.log")"
grep -qx /usr/local/lib/trashd/libtrashd_preload.so /etc/ld.so.preload \
    || fail "preload not registered"
[[ -x /usr/local/bin/trash ]] || fail "CLI not installed"
echo "PASS: loadable build installs and registers the preload"

# -----------------------------------------------------------------------
# #200: the profile hook re-execs the RUNNING shell. An empty or stale SHELL
# (docker exec, env -i, toolbox) used to end every root login, and a
# different valid SHELL silently replaced the user's shell.
# -----------------------------------------------------------------------
[[ -f /etc/profile.d/trashd.sh ]] || fail "profile hook not installed"
for shell_value in "" /bin/false; do
    out=$(printf 'echo LOGIN_OK\nexit\n' | env -i PATH=/usr/bin:/bin HOME=/root \
        SHELL="$shell_value" /bin/bash -i -c '. /etc/profile.d/trashd.sh' 2>/dev/null) || true
    [[ "$out" == *LOGIN_OK* ]] || fail "root login with SHELL='$shell_value' did not reach a shell"
done
echo "PASS: root login hook survives an empty or stale SHELL"

# -----------------------------------------------------------------------
# #216: where systemctl exists but systemd is not running (WSL without
# systemd, containers), the installer used to abort halfway under set -e.
# -----------------------------------------------------------------------
mkdir -p /etc/systemd/system "$WORK/fakebin"
printf '#!/bin/sh\necho "System has not been booted with systemd" >&2\nexit 1\n' \
    > "$WORK/fakebin/systemctl"
chmod +x "$WORK/fakebin/systemctl"
env PATH="$WORK/fakebin:$INSTALL_PATH" "$WORK/good/install.sh" > "$WORK/nosystemd.log" 2>&1 \
    || fail "installer aborted without a running systemd: $(tail -3 "$WORK/nosystemd.log")"
grep -q "installed successfully" "$WORK/nosystemd.log" || fail "installer did not finish"
echo "PASS: installer completes where systemd is not running"

# -----------------------------------------------------------------------
# #227: the cleanup timer was never installed, and its service prompted on
# /dev/null and did nothing. Trash is per-user, so both ship as user units,
# rendered for the install prefix and left disabled.
# -----------------------------------------------------------------------
check_cleanup_units() {
    local prefix="$1" unit=/etc/systemd/user/trashd-cleanup.service
    [[ -f "$unit" && -f /etc/systemd/user/trashd-cleanup.timer ]] || fail "cleanup units not installed"
    grep -qx "ExecStart=$prefix/bin/trash empty --older 30d -y" "$unit" \
        || fail "cleanup service does not run unattended from $prefix: $(grep ExecStart "$unit")"
    [[ ! -e /etc/systemd/user/timers.target.wants/trashd-cleanup.timer ]] || fail "cleanup timer enabled by default"
}
check_cleanup_units /usr/local
echo "PASS: cleanup units install disabled and run without a prompt"

# -----------------------------------------------------------------------
# #215: uninstall removed per-user configs as root through paths users
# control; a planted ~/.config symlink made root delete another user's files.
# -----------------------------------------------------------------------
# #229: ld.so.preload is a list separated by whitespace or colons. Uninstall
# deleted whole lines, dropping other libraries listed beside ours, and its
# trash-*.1 glob removed trash-cli's man pages.
LIBC=$(ldd /bin/true | awk '/libc\.so/ {print $3}')
[[ -f "$LIBC" ]] || fail "cannot locate libc for the co-located preload entry"
printf '%s /usr/local/lib/trashd/libtrashd_preload.so\n' "$LIBC" > /etc/ld.so.preload
MAN1=/usr/local/share/man/man1
[[ -f $MAN1/trash-future.1 ]] || fail "staged man pages not installed"
echo "trash-cli" > $MAN1/trash-put.1
mkdir -p /home/admin/trashd /home/test/.config/trashd /home/mallory
echo keep > /home/admin/trashd/sentinel
ln -s /home/admin /home/mallory/.config
chown -h 1001:1001 /home/mallory /home/mallory/.config
env PATH="$INSTALL_PATH" "$WORK/good/install.sh" --uninstall > "$WORK/uninstall.log" 2>&1 \
    || fail "uninstall failed: $(tail -3 "$WORK/uninstall.log")"
[[ -f /home/admin/trashd/sentinel ]] || fail "uninstall deleted through a planted symlink"
[[ ! -e /home/test/.config/trashd ]] || fail "uninstall left a real per-user config"
echo "PASS: uninstall never follows user-planted symlinks"
[[ "$(cat /etc/ld.so.preload 2>/dev/null)" == "$LIBC" ]] \
    || fail "co-located preload entry lost: '$(cat /etc/ld.so.preload 2>/dev/null)'"
[[ -f $MAN1/trash-put.1 ]] || fail "uninstall removed trash-cli's man page"
for page in trash.1 trash-ls.1 trash-future.1; do
    [[ ! -e $MAN1/$page ]] || fail "uninstall left $page"
done
echo "PASS: uninstall removes only trashd's preload entries and man pages"

# #229: make install compiled as root, and make uninstall left the unit
# running. Here there is no build tree, so make install must refuse.
if out=$(cd /src && env PATH="$INSTALL_PATH" make install 2>&1); then
    fail "make install succeeded without built artifacts"
fi
[[ "$out" == *"make build"* && "$out" != *"cargo build"* ]] \
    || fail "make install did not refuse cleanly: $out"
mkdir -p /run/systemd/system
printf '#!/bin/sh\necho "$*" >> %s\n' "$WORK/systemctl.log" > "$WORK/fakebin/systemctl"
printf '%s:/usr/local/lib/trashd/libtrashd_preload.so\n' "$LIBC" > /etc/ld.so.preload
(cd /src && env PATH="$WORK/fakebin:$INSTALL_PATH" make uninstall > "$WORK/make-un.log" 2>&1) \
    || fail "make uninstall failed: $(tail -3 "$WORK/make-un.log")"
rmdir /run/systemd/system
grep -qx "disable --now trashd" "$WORK/systemctl.log" || fail "make uninstall left the unit running"
[[ "$(cat /etc/ld.so.preload 2>/dev/null)" == "$LIBC" ]] \
    || fail "make uninstall dropped a co-located preload entry"
echo "PASS: make install never builds; make uninstall stops the unit"

env PATH="$INSTALL_PATH" PREFIX=/work/custom "$WORK/good/install.sh" > "$WORK/custom.log" 2>&1 \
    || fail "custom prefix install failed: $(tail -3 "$WORK/custom.log")"
check_cleanup_units /work/custom
env PATH="$INSTALL_PATH" PREFIX=/work/custom "$WORK/good/install.sh" --uninstall > "$WORK/custom-un.log" 2>&1 \
    || fail "custom prefix uninstall failed: $(tail -3 "$WORK/custom-un.log")"
[[ ! -e /etc/systemd/user/trashd-cleanup.service && ! -e /etc/systemd/user/trashd-cleanup.timer ]] \
    || fail "uninstall left the cleanup units"
echo "PASS: cleanup units follow PREFIX and are removed on uninstall"

echo "install regression: all checks passed"
