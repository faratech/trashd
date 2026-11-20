#!/bin/sh
# trashd — activate all trash interception layers
# Installed to /etc/profile.d/trashd.sh

# Layer 1: PATH shim — shadow rm with trash-aware version
# Every path stays quoted: installers template other prefixes in place of the
# /usr/local literals, and an unquoted expansion turned a prefix containing
# whitespace into "unexpected operator" errors that silently disabled Layers
# 1 and 4 (#423).
if [ -d "/usr/local/lib/trashd/bin" ]; then
    export PATH="/usr/local/lib/trashd/bin:$PATH"
fi

# Layer 4: capable root login shells attempt privilege-preserving seccomp.
# Nonroot shells use preload/shim automatically; explicit trashd-exec remains
# available with its documented NoNewPrivs restriction. Re-exec for kernel-level
# syscall trapping. This is the most robust layer: catches statically-linked
# binaries, programs that bypass LD_PRELOAD, and anything else.
# The LD_PRELOAD layer (Layer 2) defers to seccomp when this is active,
# so there's no double interception.
if [ "${TRASHD_SECCOMP_AUTO:-1}" != "0" ] && [ "$(id -u)" = "0" ] && [ -z "${TRASHD_SECCOMP_ACTIVE:-}" ] && [ -z "${TRASHD_SECCOMP_ATTEMPTED:-}" ] && [ -x "/usr/local/bin/trashd-exec" ]; then
    # Only wrap interactive login shells (not scripts, not subshells). The
    # re-exec below starts a fresh `$shell -l`, which discarded a -c command
    # string: `bash -lic cmd` skipped cmd and exited 0, or ran its stdin as
    # root commands. Fedora's /etc/bashrc also sources this file for every
    # non-login interactive bash, which the re-exec turned into a login
    # shell (install-5). bash reports both; dash and ash leave -c out of $-,
    # so for them only a shell started as a login shell (argv[0] "-sh") counts.
    _trashd_login=""
    case "$-" in
        *c*) ;;
        *i*)
            if [ -n "${BASH_VERSION:-}" ]; then
                shopt -q login_shell 2>/dev/null && _trashd_login=1
            else
                case "$0" in -*) _trashd_login=1 ;; esac
            fi
            ;;
    esac
    if [ -n "$_trashd_login" ]; then
        # Re-exec the shell that is running this script, not $SHELL: an
        # unset or stale SHELL (docker exec, env -i, toolbox) made the exec
        # fail and ended every root login, and a different SHELL silently
        # replaced the user's shell (#200). Only exec once both the shell
        # and the wrapper are known to start; otherwise stay unwrapped.
        _trashd_shell="$(readlink /proc/$$/exe 2>/dev/null)"
        # A multi-call busybox takes argv[1] as the applet name: `busybox -l`
        # failed with "applet not found" and ended the login (install-12).
        _trashd_applet=""
        case "${_trashd_shell##*/}" in busybox*) _trashd_applet=sh ;; esac
        if [ -n "$_trashd_shell" ] && [ -x "$_trashd_shell" ] \
            && "/usr/local/bin/trashd-exec" --version >/dev/null 2>&1; then
            # Prevent login-shell recursion if listener installation fails.
            # Only trashd-exec sets ACTIVE, after protection is established.
            export TRASHD_SECCOMP_ATTEMPTED=1
            exec "/usr/local/bin/trashd-exec" --preserve-privileges -- "$_trashd_shell" ${_trashd_applet:+"$_trashd_applet"} -l
        fi
        unset _trashd_shell _trashd_applet
    fi
    unset _trashd_login
fi
