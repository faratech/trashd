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
    # Shell completions, as the release tarball ships them.
    mkdir -p "$dir/share/completions"
    printf '# trash bash completion\n' > "$dir/share/completions/trash.bash"
    printf '#compdef trash\n' > "$dir/share/completions/_trash"
    printf 'complete -c trash\n' > "$dir/share/completions/trash.fish"
}

fail() { echo "FAIL: $1" >&2; exit 1; }

# True when /bin/true, run through the given command prefix, loads trashd's
# preload with no loader complaint. An unreadable /etc/ld.so.preload is
# skipped silently, so the absence of errors alone proves nothing.
preload_loads() {
    local err dbg
    if ! err=$("$@" /bin/true 2>&1 >/dev/null) || [[ -n "$err" ]]; then
        echo "loader output: $err" >&2
        return 1
    fi
    dbg=$("$@" env LD_DEBUG=libs /bin/true 2>&1 >/dev/null) || return 1
    [[ "$dbg" == *"calling init: /usr/local/lib/trashd/"*libtrashd_preload.so* ]]
}
AS_NOBODY=(setpriv --reuid=65534 --regid=65534 --clear-groups --)

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

# -----------------------------------------------------------------------
# install-8: the source build staged under a hardcoded /tmp, which CIS
# hardening mounts noexec; cargo runs build scripts from there. TMPDIR is
# honored, a noexec stage is diagnosed before any change, and as root only
# a TMPDIR that nobody but root can modify is used.
# -----------------------------------------------------------------------
mkdir -p "$WORK/srcmode" "$WORK/noexec-tmp" "$WORK/user-tmp"
cp /src/install.sh "$WORK/srcmode/"
mount -t tmpfs -o noexec,mode=1777 trashd-noexec "$WORK/noexec-tmp"
if env PATH="$INSTALL_PATH" TMPDIR="$WORK/noexec-tmp" "$WORK/srcmode/install.sh" \
    > "$WORK/noexec.log" 2>&1; then
    fail "install-8: source install proceeded on a noexec TMPDIR"
fi
grep -q "noexec" "$WORK/noexec.log" || fail "install-8: no noexec diagnostic: $(cat "$WORK/noexec.log")"
[[ -z "$(ls -A "$WORK/noexec-tmp")" ]] || fail "install-8: build stage left in TMPDIR"
umount "$WORK/noexec-tmp"
chown 65534:65534 "$WORK/user-tmp"
if env PATH="$INSTALL_PATH" TMPDIR="$WORK/user-tmp" "$WORK/srcmode/install.sh" \
    > "$WORK/usertmp.log" 2>&1; then
    fail "install-8: source install as root proceeded in a user-owned TMPDIR"
fi
grep -q "TMPDIR" "$WORK/usertmp.log" || fail "install-8: no TMPDIR diagnostic: $(cat "$WORK/usertmp.log")"
[[ -z "$(ls -A "$WORK/user-tmp")" ]] || fail "install-8: root staged a build in a user-owned TMPDIR"
[[ ! -e /etc/ld.so.preload && ! -e /usr/local/bin ]] || fail "install-8: a refused source install changed the system"
echo "PASS: source builds stage under TMPDIR and refuse noexec or user-owned stages"

stage "$WORK/good"
mkdir -p /etc/profile.d  # absent in the sandbox; install.sh only writes the hook if it exists
# install-2: sudo keeps a hardened caller umask (027/077). The preload list,
# the trashd tree and /etc/trashd must still come out readable by everyone.
[[ ! -e /etc/ld.so.preload && ! -e /usr/local/lib && ! -e /etc/trashd ]] \
    || fail "test precondition: the first install must create the preload list and directories"
(umask 077; env PATH="$INSTALL_PATH" "$WORK/good/install.sh") > "$WORK/good.log" 2>&1 \
    || fail "installer failed: $(cat "$WORK/good.log")"
grep -qx /usr/local/lib/trashd/libtrashd_preload.so /etc/ld.so.preload \
    || fail "preload not registered"
[[ -x /usr/local/bin/trash ]] || fail "CLI not installed"
echo "PASS: loadable build installs and registers the preload"
for path_mode in /etc/ld.so.preload:644 /usr/local/lib:755 /usr/local/lib/trashd:755 \
    /usr/local/lib/trashd/bin:755 /usr/local/lib/trashd/real:755 /etc/trashd:755 \
    /etc/trashd/config.toml:644 /etc/profile.d/trashd.sh:644; do
    mode=$(stat -c %a "${path_mode%:*}") || fail "install-2: ${path_mode%:*} missing"
    [[ "$mode" == "${path_mode##*:}" ]] || fail "install-2: ${path_mode%:*} has mode $mode under umask 077"
done
preload_loads "${AS_NOBODY[@]}" || fail "install-2: Layer 2 does not load for other users"
nobody_rm=$("${AS_NOBODY[@]}" env -i PATH=/usr/bin:/bin /bin/sh -c '. /etc/profile.d/trashd.sh; command -v rm')
[[ "$nobody_rm" == /usr/local/lib/trashd/bin/rm ]] \
    || fail "install-2: the profile hook does not put the shim first for other users: $nobody_rm"
echo "PASS: a umask 077 install stays readable and active for other users"

# -----------------------------------------------------------------------
# #427: bash completions were silently skipped when /etc/bash_completion.d
# did not exist. The PREFIX-relative fallback must always land.
# -----------------------------------------------------------------------
[[ ! -d /etc/bash_completion.d ]] || fail "test precondition: sandbox must lack /etc/bash_completion.d"
[[ -f /usr/local/share/bash-completion/completions/trash ]] \
    || fail "bash completions missing without /etc/bash_completion.d"
echo "PASS: bash completions install without /etc/bash_completion.d"

# -----------------------------------------------------------------------
# #423: the profile hook template must stay parseable when some other
# tooling renders it for a prefix containing spaces (the installer itself
# refuses such prefixes; #422).
# -----------------------------------------------------------------------
sed 's|/usr/local/lib/trashd/bin|/opt/my dir/lib/trashd/bin|g; s|/usr/local/bin/trashd-exec|/opt/my dir/bin/trashd-exec|g' \
    /src/install/profile.d/trashd.sh > "$WORK/hook-space.sh"
hook_err=$(env -i PATH=/usr/bin:/bin TRASHD_SECCOMP_AUTO=0 \
    /bin/sh -c ". '$WORK/hook-space.sh'" 2>&1 >/dev/null) || true
[[ "$hook_err" != *"unexpected operator"* && "$hook_err" != *"too many arguments"* ]] \
    || fail "profile hook breaks on a space prefix: $hook_err"
echo "PASS: profile hook template survives a space prefix"

# -----------------------------------------------------------------------
# #200: the profile hook re-execs the RUNNING shell. An empty or stale SHELL
# (docker exec, env -i, toolbox) used to end every root login, and a
# different valid SHELL silently replaced the user's shell.
# -----------------------------------------------------------------------
[[ -f /etc/profile.d/trashd.sh ]] || fail "profile hook not installed"
# Homes whose startup files source the hook the way /etc/profile (login
# shells) and Fedora's /etc/bashrc (every interactive bash) do.
HOOK_HOME="$WORK/hook-home"
mkdir -p "$HOOK_HOME"
printf '. /etc/profile.d/trashd.sh\n' > "$HOOK_HOME/.bash_profile"
printf '. /etc/profile.d/trashd.sh\n' > "$HOOK_HOME/.bashrc"
printf '. /etc/profile.d/trashd.sh\n' > "$HOOK_HOME/.profile"
SHOW_WRAP='echo "LOGIN_OK ATTEMPTED=${TRASHD_SECCOMP_ATTEMPTED:-unset}"'
for shell_value in "" /bin/false; do
    out=$(printf '%s\nexit\n' "$SHOW_WRAP" | env -i PATH=/usr/bin:/bin HOME="$HOOK_HOME" \
        SHELL="$shell_value" /bin/bash -il 2>/dev/null) || true
    [[ "$out" == *"LOGIN_OK ATTEMPTED=1"* ]] \
        || fail "root login with SHELL='$shell_value' did not reach a wrapped shell: $out"
done
echo "PASS: root login hook survives an empty or stale SHELL"

# -----------------------------------------------------------------------
# install-5: the hook re-executed every interactive root shell as
# `$shell -l`, discarding a -c command string: `bash -lic cmd` skipped cmd
# and exited 0, or ran its stdin as root commands. Only login shells
# without a command string are wrapped; Fedora's /etc/bashrc also sources
# profile.d for non-login interactive shells, which must stay as they are.
# -----------------------------------------------------------------------
out=$(printf 'echo STDIN_RAN\n' | env -i PATH=/usr/bin:/bin HOME="$HOOK_HOME" \
    /bin/bash -i -l -c 'echo CMD_RAN' 2>/dev/null) || true
[[ "$out" == *CMD_RAN* && "$out" != *STDIN_RAN* ]] \
    || fail "install-5: bash -lic ran stdin instead of its command: '$out'"
rc=0
env -i PATH=/usr/bin:/bin HOME="$HOOK_HOME" /bin/bash -lic 'exit 7' </dev/null >/dev/null 2>&1 || rc=$?
[[ "$rc" -eq 7 ]] || fail "install-5: bash -lic 'exit 7' exited $rc"
out=$(printf '%s\n' "$SHOW_WRAP" | env -i PATH=/usr/bin:/bin HOME="$HOOK_HOME" \
    /bin/bash -i 2>/dev/null) || true
[[ "$out" == *"ATTEMPTED=unset"* ]] || fail "install-5: a non-login interactive bash was wrapped: '$out'"
if command -v dash >/dev/null; then
    # dash leaves -c out of $-, so only a real login shell (argv[0] "-dash") is wrapped.
    out=$(printf 'echo STDIN_RAN\n' | env -i PATH=/usr/bin:/bin HOME="$HOOK_HOME" \
        dash -i -l -c 'echo CMD_RAN' 2>/dev/null) || true
    [[ "$out" == *CMD_RAN* && "$out" != *STDIN_RAN* ]] \
        || fail "install-5: dash -lic ran stdin instead of its command: '$out'"
    out=$(printf '%s\nexit\n' "$SHOW_WRAP" | env -i PATH=/usr/bin:/bin HOME="$HOOK_HOME" \
        /bin/bash -c 'exec -a -dash "$0" -i' "$(command -v dash)" 2>/dev/null) || true
    [[ "$out" == *"LOGIN_OK ATTEMPTED=1"* ]] || fail "install-5: a dash login shell was not wrapped: '$out'"
fi
echo "PASS: the hook wraps login shells only and never discards a -c command"

# -----------------------------------------------------------------------
# install-12: a busybox login shell's exe is the multi-call binary, and
# `busybox -l` is "applet not found" (exit 127): the re-exec ended every root
# login. A stand-in multi-call shell records the wrapper's argv.
# -----------------------------------------------------------------------
BB="$WORK/bb"
mkdir -p "$BB/home"
cp "$(readlink -f /bin/sh)" "$BB/busybox"
printf '#!/bin/sh\n[ "$1" = --version ] && exit 0\nprintf "%%s\\n" "$@" > %s/argv\n' "$BB" > "$BB/trashd-exec"
chmod +x "$BB/trashd-exec"
sed "s|/usr/local/bin/trashd-exec|$BB/trashd-exec|g" /etc/profile.d/trashd.sh > "$BB/hook.sh"
printf '. %s/hook.sh\n' "$BB" > "$BB/home/.profile"
printf 'exit\n' | env -i PATH=/usr/bin:/bin HOME="$BB/home" \
    /bin/bash -c 'exec -a -sh "$0" -i' "$BB/busybox" >/dev/null 2>&1 || true
[[ "$(cat "$BB/argv" 2>/dev/null)" == "$(printf '%s\n' --preserve-privileges -- "$BB/busybox" sh -l)" ]] \
    || fail "install-12: busybox login re-exec argv: $(tr '\n' ' ' < "$BB/argv" 2>/dev/null)"
if command -v busybox >/dev/null; then
    out=$(printf '%s\nexit\n' "$SHOW_WRAP" | env -i PATH=/usr/bin:/bin HOME="$HOOK_HOME" \
        /bin/bash -c 'exec -a -sh "$0" -i' "$(command -v busybox)" 2>/dev/null) || true
    [[ "$out" == *"LOGIN_OK ATTEMPTED=1"* ]] || fail "install-12: busybox root login did not survive: '$out'"
fi
echo "PASS: a busybox login shell is re-executed through its sh applet"

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
# #407: a chroot or offline image build has /etc/systemd but no running
# systemd. The unit file must still be installed so Layer 3 can start
# after boot; only enable/start needs a running systemd.
# -----------------------------------------------------------------------
[[ -f /etc/systemd/system/trashd.service ]] || fail "daemon unit not installed without a running systemd"
grep -qx "ExecStart=/usr/local/lib/trashd/trashd" /etc/systemd/system/trashd.service \
    || fail "daemon unit not templated for the prefix: $(grep ExecStart /etc/systemd/system/trashd.service)"
# #426: the unit must be wanted by multi-user.target, the enablement link
# both uninstallers remove.
grep -qx "WantedBy=multi-user.target" /etc/systemd/system/trashd.service \
    || fail "unit is not wanted by multi-user.target: $(grep WantedBy /etc/systemd/system/trashd.service)"
[[ ! -e /etc/systemd/system/multi-user.target.wants/trashd.service ]] \
    || fail "unit was enabled without a running systemd"
echo "PASS: daemon unit installs (disabled) without a running systemd"
# daemon-4: a kernel or container that cannot run fanotify makes the daemon
# exit 78, and Restart=always must not relaunch it every 5 s forever.
grep -qx "RestartPreventExitStatus=78" /etc/systemd/system/trashd.service \
    || fail "daemon-4: unit restarts the daemon after an unsupported-kernel exit"
# daemon-1: journald's default per-unit limit (10000 lines / 30 s) dropped
# most DELETE lines of one large rm -rf; the unit raises it, but keeps a limit.
grep -qx "LogRateLimitIntervalSec=30s" /etc/systemd/system/trashd.service \
    && burst=$(sed -n 's/^LogRateLimitBurst=//p' /etc/systemd/system/trashd.service) \
    && [[ "$burst" =~ ^[0-9]+$ ]] && (( burst > 10000 )) \
    || fail "daemon-1: unit keeps journald's default rate limit or disables it"
echo "PASS: daemon unit stops on unsupported kernels and keeps a raised journald limit"

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
# #422: a PREFIX with whitespace or a colon would be written into
# /etc/ld.so.preload and the profile hook as an unparseable entry, and
# every reinstall appended another broken line. Refuse before creating
# anything.
# -----------------------------------------------------------------------
LIBC=$(ldd /bin/true | awk '/libc\.so/ {print $3}')
[[ -f "$LIBC" ]] || fail "cannot locate libc for the co-located preload entry"
# install-9: awk -v unescapes backslashes, so the registered-check never
# matched a prefix containing one and uninstall left its entry behind.
for bad_prefix in '/work/sp ace' '/work/co:lon' '/work/back\slash'; do
    if env PATH="$INSTALL_PATH" PREFIX="$bad_prefix" "$WORK/good/install.sh" \
        > "$WORK/badprefix.log" 2>&1; then
        fail "installer accepted PREFIX='$bad_prefix'"
    fi
    grep -q "unsafe for /etc/ld.so.preload" "$WORK/badprefix.log" \
        || fail "no diagnostic for PREFIX='$bad_prefix': $(cat "$WORK/badprefix.log")"
    [[ ! -e "$bad_prefix" ]] || fail "PREFIX='$bad_prefix' created directories before refusing"
done
echo "PASS: installer refuses prefixes unsafe for ld.so.preload"

# Where this host's native loader puts $LIB (glibc 2.33+ reports it), so
# fixtures match a real install instead of a guessed multiarch path. The
# i686 library pairs only with an x86_64 host's i386 loader.
LDSO64=$(ldd /bin/true | awk '/ld-linux/ {print $1}')
ldso_lib_dir() { "$1" --list-diagnostics 2>/dev/null | awk -F'"' '$1 == "dl_dst_lib=" { print $2 }'; }
DST64=$(ldso_lib_dir "$LDSO64")
[[ -n "$DST64" ]] || fail "test precondition: $LDSO64 does not report dl_dst_lib"
DST32=""
if [[ "$(uname -m)" == x86_64 && -x /lib/ld-linux.so.2 ]]; then
    DST32=$(ldso_lib_dir /lib/ld-linux.so.2)
fi

# -----------------------------------------------------------------------
# install-1: with the optional i686 preload, both installers laid out
# lib64/ and lib/ and registered $LIB, which ld.so expands to lib/<triplet>
# on Debian/Ubuntu and lib/lib32 on Arch: every process printed a preload
# error (or loaded the wrong ELF class) and Layer 2 was off. The $LIB form
# is used only where both loaders report their expansion; otherwise the
# 64-bit library is registered alone.
# -----------------------------------------------------------------------
stage "$WORK/abi"
cp /opt/trashd/lib/libtrashd_preload.so "$WORK/abi/lib/libtrashd_preload32.so"
env PATH="$INSTALL_PATH" "$WORK/abi/install.sh" > "$WORK/abi.log" 2>&1 \
    || fail "install-1: install with a 32-bit preload failed: $(tail -3 "$WORK/abi.log")"
preload_loads || fail "install-1: the registered preload does not load cleanly"
LIBC32=""
[[ -z "$DST32" ]] || LIBC32="$(dirname "$(readlink -f /lib/ld-linux.so.2)")/libc.so.6"
if [[ -n "$DST32" && "$DST32" != "$DST64" && ! -x "$LIBC32" ]]; then
    grep -qx '/usr/local/lib/trashd/$LIB/libtrashd_preload.so' /etc/ld.so.preload \
        || fail "install-1: \$LIB entry not registered although both loaders report it"
    [[ -f "/usr/local/lib/trashd/$DST64/libtrashd_preload.so" && -f "/usr/local/lib/trashd/$DST32/libtrashd_preload.so" ]] \
        || fail "install-1: per-ABI copies not where ld.so resolves \$LIB"
else
    # The 32-bit stand-in is a 64-bit copy: where the i386 libc can be run,
    # the post-registration check must reject the $LIB entry and fall back.
    if [[ -n "$DST32" && "$DST32" != "$DST64" ]]; then
        grep -q "did not load cleanly" "$WORK/abi.log" \
            || fail "install-1: a \$LIB entry that fails for 32-bit programs was kept"
    fi
    grep -qx /usr/local/lib/trashd/libtrashd_preload.so /etc/ld.so.preload \
        || fail "install-1: flat entry not registered where \$LIB cannot be resolved for both ABIs"
    ! grep -q 'LIB/libtrashd_preload' /etc/ld.so.preload || fail "install-1: unresolvable \$LIB entry registered"
    for d in lib lib64 lib32; do
        [[ ! -e "/usr/local/lib/trashd/$d" ]] || fail "install-1: unused per-ABI tree $d installed"
    done
fi
echo "PASS: a 32-bit preload never leaves an unresolvable registration"

# -----------------------------------------------------------------------
# #406: registration is form-specific. A prior $LIB install (with the
# i686 library) followed by a flat-only install must replace the entry
# and drop the stale per-ABI copies; the old either-form check froze the
# first form in place forever. The stale 64-bit copy is a valid ELF library
# where this host's ld.so resolves $LIB, as a real per-ABI install leaves
# it: a registered entry that cannot be resolved makes every process print
# an ld.so error, which the installer's load probes treat as fatal.
# install-10: the per-ABI trees were deleted while the $LIB entry still
# named them; a PATH-first rm records any removal that happens too early.
# -----------------------------------------------------------------------
mkdir -p "/usr/local/lib/trashd/$DST64" "$WORK/rmcheck"
cp /opt/trashd/lib/libtrashd_preload.so "/usr/local/lib/trashd/$DST64/libtrashd_preload.so"
cat > "$WORK/rmcheck/rm" <<EOF
#!/bin/sh
for arg in "\$@"; do
    case "\$arg" in
        /usr/local/lib/trashd/lib|/usr/local/lib/trashd/lib64|/usr/local/lib/trashd/lib32)
            if grep -q 'LIB/libtrashd_preload' /etc/ld.so.preload; then
                echo "\$arg" >> "$WORK/rmcheck/early"
            fi ;;
    esac
done
exec /usr/bin/rm "\$@"
EOF
chmod +x "$WORK/rmcheck/rm"
printf '%s /usr/local/lib/trashd/$LIB/libtrashd_preload.so\n# other lib\n/usr/local/lib/trashd/$LIB/libtrashd_preload.so\n' "$LIBC" \
    > /etc/ld.so.preload
env PATH="$WORK/rmcheck:$INSTALL_PATH" "$WORK/good/install.sh" > "$WORK/transition.log" 2>&1 \
    || fail "flat install after a \$LIB install failed: $(tail -3 "$WORK/transition.log")"
grep -qx /usr/local/lib/trashd/libtrashd_preload.so /etc/ld.so.preload \
    || fail "flat entry not registered after the \$LIB -> flat transition"
! grep -q 'LIB/libtrashd_preload' /etc/ld.so.preload \
    || fail "\$LIB entry survived the transition"
grep -qx "$LIBC" /etc/ld.so.preload || fail "co-located preload entry lost in the transition"
grep -qx "# other lib" /etc/ld.so.preload || fail "comment line lost in the transition"
for d in lib lib64 lib32; do
    [[ ! -e "/usr/local/lib/trashd/$d" ]] || fail "stale per-ABI tree $d left behind"
done
[[ ! -e "$WORK/rmcheck/early" ]] \
    || fail "install-10: per-ABI trees removed while the \$LIB entry still named them: $(cat "$WORK/rmcheck/early")"
preload_loads || fail "the flat registration does not load cleanly after the transition"
echo "PASS: reinstall without the i686 library replaces the registration form"

# -----------------------------------------------------------------------
# #215: uninstall removed per-user configs as root through paths users
# control; a planted ~/.config symlink made root delete another user's files.
# -----------------------------------------------------------------------
# #229: ld.so.preload is a list separated by whitespace or colons. Uninstall
# deleted whole lines, dropping other libraries listed beside ours, and its
# trash-*.1 glob removed trash-cli's man pages.
printf '%s /usr/local/lib/trashd/libtrashd_preload.so\n' "$LIBC" > /etc/ld.so.preload
MAN1=/usr/local/share/man/man1
[[ -f $MAN1/trash-future.1 ]] || fail "staged man pages not installed"
echo "trash-cli" > $MAN1/trash-put.1
mkdir -p /home/admin/trashd /home/test/.config/trashd /home/mallory
echo keep > /home/admin/trashd/sentinel
ln -s /home/admin /home/mallory/.config
chown -h 1001:1001 /home/mallory /home/mallory/.config
# #420: a user who enabled the cleanup timer as instructed keeps an
# enablement symlink; uninstall must remove ours (symlinks only) and leave
# everything else in the user's systemd directories alone.
mkdir -p /home/test/.config/systemd/user/timers.target.wants \
    /home/test/.config/systemd/user/default.target.wants
ln -s /etc/systemd/user/trashd-cleanup.timer \
    /home/test/.config/systemd/user/timers.target.wants/trashd-cleanup.timer
ln -s /etc/systemd/user/other.timer \
    /home/test/.config/systemd/user/timers.target.wants/other.timer
printf 'not a symlink' > /home/test/.config/systemd/user/default.target.wants/trashd-cleanup.timer
# #421: a home recorded in passwd outside /home must be swept (config now,
# trash by the --purge run at the end).
mkdir -p /srv/home/joe/.config/trashd /srv/home/joe/.local/share/Trash/files
echo config > /srv/home/joe/.config/trashd/config.toml
echo trash > /srv/home/joe/.local/share/Trash/files/keep-me
chown -R 1500:1500 /srv/home/joe
grep -qs '^joe:' /etc/passwd || echo 'joe:x:1500:1500::/srv/home/joe:/bin/sh' >> /etc/passwd
env PATH="$INSTALL_PATH" "$WORK/good/install.sh" --uninstall > "$WORK/uninstall.log" 2>&1 \
    || fail "uninstall failed: $(tail -3 "$WORK/uninstall.log")"
[[ -f /home/admin/trashd/sentinel ]] || fail "uninstall deleted through a planted symlink"
[[ ! -e /home/test/.config/trashd ]] || fail "uninstall left a real per-user config"
echo "PASS: uninstall never follows user-planted symlinks"
[[ ! -L /home/test/.config/systemd/user/timers.target.wants/trashd-cleanup.timer ]] \
    || fail "#420: user cleanup timer enablement link left behind"
[[ -L /home/test/.config/systemd/user/timers.target.wants/other.timer ]] \
    || fail "#420: removed an enablement link this project does not ship"
[[ -f /home/test/.config/systemd/user/default.target.wants/trashd-cleanup.timer ]] \
    || fail "#420: removed a regular file, not an enablement symlink"
[[ ! -e /srv/home/joe/.config/trashd ]] \
    || fail "#421: config left in a passwd home outside /home"
echo "PASS: uninstall removes user enablement links and passwd homes outside /home"
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
# install-9: the Makefile's prefix check missed backslashes as well.
if out=$(cd /src && env PATH="$INSTALL_PATH" make install 'PREFIX=/work/back\slash' 2>&1); then
    fail "install-9: make install accepted a backslash PREFIX"
fi
[[ "$out" == *"unsafe for /etc/ld.so.preload"* ]] \
    || fail "install-9: make install did not refuse a backslash PREFIX: $out"
# #424: the recipes expanded PREFIX and DESTDIR unquoted, so a space split
# every install and uninstall path. They are quoted now, and a prefix with
# whitespace is refused before anything is touched, as install.sh does.
for prefix in '/work/with space' $'/work/with\ttab'; do
    if out=$(cd /src && env PATH="$INSTALL_PATH" make install "PREFIX=$prefix" 2>&1); then
        fail "#424: make install accepted PREFIX='$prefix'"
    fi
    [[ "$out" == *"unsafe for /etc/ld.so.preload"* ]] \
        || fail "#424: make install did not refuse PREFIX='$prefix': $out"
done
[[ ! -e "/work/with space" ]] || fail "#424: a refused make install created its prefix"
if out=$(cd /src && env PATH="$INSTALL_PATH" make install 'DESTDIR=/work/stage dir' 2>&1); then
    fail "#424: make install accepted a DESTDIR with a space"
fi
echo "PASS: make install refuses a PREFIX or DESTDIR with whitespace"

# Stand-ins for a `make build` tree. /usr is read-only here, so the units
# are staged elsewhere.
mkdir -p /src/target/release /src/target/man /src/target/completions
cp /opt/trashd/bin/trash /opt/trashd/bin/trashd-rm /opt/trashd/bin/trashd-exec \
    /opt/trashd/bin/trashd /src/target/release/
printf '.TH trash 1\n' > /src/target/man/trash.1
printf '# trash bash completion\n' > /src/target/completions/trash.bash
printf '#compdef trash\n' > /src/target/completions/_trash
printf 'complete -c trash\n' > /src/target/completions/trash.fish
MAKE_DIRS=(UNITDIR=/work/units USERUNITDIR=/work/user-units)

# -----------------------------------------------------------------------
# install-4: make install registered whatever `make` produced with no loader
# probe (install.sh's #191 guard): a preload built against a newer glibc
# than the host's is fatal to every dynamically linked program.
# -----------------------------------------------------------------------
printf 'not an ELF object\n' > /src/target/release/libtrashd_preload.so
cp /etc/ld.so.preload "$WORK/preload.before"
if out=$(cd /src && env PATH="$INSTALL_PATH" make install "${MAKE_DIRS[@]}" 2>&1); then
    fail "install-4: make install accepted a non-loadable preload library"
fi
[[ "$out" == *"cannot be loaded"* ]] || fail "install-4: no loader diagnostic: $out"
cmp -s /etc/ld.so.preload "$WORK/preload.before" || fail "install-4: /etc/ld.so.preload was modified"
[[ ! -e /usr/local/lib/trashd && ! -e /usr/local/bin/trash ]] \
    || fail "install-4: files were installed before the load check"
echo "PASS: make install refuses a non-loadable preload before any change"

# install-2 for make install: every recipe line inherits the caller's umask,
# and an existing preload list left unreadable is repaired on registration.
cp /opt/trashd/lib/libtrashd_preload.so /src/target/release/
chmod 0600 /etc/ld.so.preload
(cd /src && umask 077 && env PATH="$INSTALL_PATH" make install "${MAKE_DIRS[@]}") > "$WORK/make-in.log" 2>&1 \
    || fail "make install failed: $(tail -3 "$WORK/make-in.log")"
grep -qx /usr/local/lib/trashd/libtrashd_preload.so /etc/ld.so.preload \
    || fail "make install did not register the preload"
for path_mode in /etc/ld.so.preload:644 /usr/local/lib/trashd:755 /usr/local/lib/trashd/bin:755 \
    /etc/trashd:755 /etc/trashd/config.toml:644 /etc/profile.d/trashd.sh:644; do
    mode=$(stat -c %a "${path_mode%:*}") || fail "install-2: ${path_mode%:*} missing after make install"
    [[ "$mode" == "${path_mode##*:}" ]] || fail "install-2: make install left ${path_mode%:*} at mode $mode"
done
preload_loads "${AS_NOBODY[@]}" || fail "install-2: Layer 2 does not load for other users after make install"
echo "PASS: a umask 077 make install stays readable and active for other users"

# -----------------------------------------------------------------------
# install-11: the Makefile chained awk, chmod and mv with ';', so an awk
# that failed partway (ENOSPC) still replaced /etc/ld.so.preload, dropping
# other libraries' entries, and uninstall went on to delete the library.
# -----------------------------------------------------------------------
mkdir -p "$WORK/failawk"
cat > "$WORK/failawk/awk" <<'EOF'
#!/bin/sh
for arg in "$@"; do
    if [ "$arg" = /etc/ld.so.preload ]; then
        head -c 8 /etc/ld.so.preload
        exit 1
    fi
done
exec /usr/bin/awk "$@"
EOF
chmod +x "$WORK/failawk/awk"
printf '%s /usr/local/lib/trashd/libtrashd_preload.so\n# keep\n' "$LIBC" > /etc/ld.so.preload
cp /etc/ld.so.preload "$WORK/preload.before"
if (cd /src && env PATH="$WORK/failawk:$INSTALL_PATH" make uninstall "${MAKE_DIRS[@]}") > "$WORK/make-awk.log" 2>&1; then
    fail "install-11: make uninstall succeeded although rewriting /etc/ld.so.preload failed"
fi
cmp -s /etc/ld.so.preload "$WORK/preload.before" \
    || fail "install-11: a failed rewrite replaced /etc/ld.so.preload: '$(cat /etc/ld.so.preload)'"
[[ ! -e /etc/ld.so.preload.trashd-new ]] || fail "install-11: partial rewrite left behind"
[[ -f /usr/local/lib/trashd/libtrashd_preload.so ]] \
    || fail "install-11: the library was deleted while still registered"
echo "PASS: a failed ld.so.preload rewrite leaves the list and the library in place"

mkdir -p /run/systemd/system
printf '#!/bin/sh\necho "$*" >> %s\n' "$WORK/systemctl.log" > "$WORK/fakebin/systemctl"
printf '%s:/usr/local/lib/trashd/libtrashd_preload.so\n' "$LIBC" > /etc/ld.so.preload
# #426: a dangling enablement link from a unit older than the
# multi-user.target [Install] (systemctl could not disable it) must go too.
mkdir -p /etc/systemd/system/default.target.wants
ln -s /usr/lib/systemd/system/trashd.service /etc/systemd/system/default.target.wants/trashd.service
(cd /src && env PATH="$WORK/fakebin:$INSTALL_PATH" make uninstall "${MAKE_DIRS[@]}" > "$WORK/make-un.log" 2>&1) \
    || fail "make uninstall failed: $(tail -3 "$WORK/make-un.log")"
rmdir /run/systemd/system
grep -qx "disable --now trashd" "$WORK/systemctl.log" || fail "make uninstall left the unit running"
[[ "$(cat /etc/ld.so.preload 2>/dev/null)" == "$LIBC" ]] \
    || fail "make uninstall dropped a co-located preload entry"
[[ ! -e /etc/systemd/system/default.target.wants/trashd.service ]] \
    || fail "#426: make uninstall left the legacy default.target.wants link"
echo "PASS: make install never builds; make uninstall stops the unit"

env PATH="$INSTALL_PATH" PREFIX=/work/custom "$WORK/good/install.sh" > "$WORK/custom.log" 2>&1 \
    || fail "custom prefix install failed: $(tail -3 "$WORK/custom.log")"
check_cleanup_units /work/custom
[[ -f /work/custom/share/bash-completion/completions/trash ]] \
    || fail "#427: custom prefix bash completions not installed"
env PATH="$INSTALL_PATH" PREFIX=/work/custom "$WORK/good/install.sh" --uninstall > "$WORK/custom-un.log" 2>&1 \
    || fail "custom prefix uninstall failed: $(tail -3 "$WORK/custom-un.log")"
[[ ! -e /etc/systemd/user/trashd-cleanup.service && ! -e /etc/systemd/user/trashd-cleanup.timer ]] \
    || fail "uninstall left the cleanup units"
[[ ! -e /work/custom/share/bash-completion/completions/trash ]] \
    || fail "#427: custom prefix bash completions left on uninstall"
echo "PASS: cleanup units follow PREFIX and are removed on uninstall"

# -----------------------------------------------------------------------
# daemon-3 follow-up: a started daemon audits the filesystems it can mark,
# which excludes btrfs subvolume mounts, tmpfs, overlay and FUSE; the
# installer reported it as "monitoring deletions" without qualification.
# -----------------------------------------------------------------------
mkdir -p /run/systemd/system
env PATH="$WORK/fakebin:$INSTALL_PATH" PREFIX=/work/custom "$WORK/good/install.sh" > "$WORK/active.log" 2>&1 \
    || fail "install with a running systemd failed: $(tail -3 "$WORK/active.log")"
env PATH="$WORK/fakebin:$INSTALL_PATH" PREFIX=/work/custom "$WORK/good/install.sh" --uninstall > "$WORK/active-un.log" 2>&1 \
    || fail "uninstall with a running systemd failed: $(tail -3 "$WORK/active-un.log")"
rmdir /run/systemd/system
running=$(grep "trashd is running" "$WORK/active.log") \
    || fail "no status line for a started daemon: $(tail -20 "$WORK/active.log")"
[[ "$running" != *"(monitoring deletions)"* ]] \
    || fail "installer claims the daemon monitors every deletion: $running"
[[ "$running" == *"filesystems it can mark"* && "$running" == *"journalctl -u trashd"* ]] \
    || fail "daemon status line does not say what is audited: $running"
echo "PASS: the installer reports what a started daemon audits"

# -----------------------------------------------------------------------
# #421: --purge must also reach trash in passwd homes outside /home.
# -----------------------------------------------------------------------
env PATH="$INSTALL_PATH" "$WORK/good/install.sh" --uninstall --purge > "$WORK/purge.log" 2>&1 \
    || fail "purge uninstall failed: $(tail -3 "$WORK/purge.log")"
[[ ! -e /srv/home/joe/.local/share/Trash ]] \
    || fail "#421: --purge left trash in a passwd home outside /home"
echo "PASS: --purge reaches passwd homes outside /home"

echo "install regression: all checks passed"
