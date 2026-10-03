#!/bin/sh
# trashd — activate all trash interception layers
# Installed to /etc/profile.d/trashd.sh

# Layer 1: PATH shim — shadow rm with trash-aware version
if [ -d /usr/local/lib/trashd/bin ]; then
    export PATH="/usr/local/lib/trashd/bin:$PATH"
fi

# Layer 4: capable root login shells attempt privilege-preserving seccomp.
# Nonroot shells use preload/shim automatically; explicit trashd-exec remains
# available with its documented NoNewPrivs restriction. Re-exec for kernel-level
# syscall trapping. This is the most robust layer: catches statically-linked
# binaries, programs that bypass LD_PRELOAD, and anything else.
# The LD_PRELOAD layer (Layer 2) defers to seccomp when this is active,
# so there's no double interception.
if [ "${TRASHD_SECCOMP_AUTO:-1}" != "0" ] && [ "$(id -u)" = "0" ] && [ -z "${TRASHD_SECCOMP_ACTIVE:-}" ] && [ -z "${TRASHD_SECCOMP_ATTEMPTED:-}" ] && [ -x /usr/local/bin/trashd-exec ]; then
    # Only wrap interactive login shells (not scripts, not subshells)
    case "$-" in
        *i*)
            # Re-exec the shell that is running this script, not $SHELL: an
            # unset or stale SHELL (docker exec, env -i, toolbox) made the exec
            # fail and ended every root login, and a different SHELL silently
            # replaced the user's shell (#200). Only exec once both the shell
            # and the wrapper are known to start; otherwise stay unwrapped.
            _trashd_shell="$(readlink /proc/$$/exe 2>/dev/null)"
            if [ -n "$_trashd_shell" ] && [ -x "$_trashd_shell" ] \
                && /usr/local/bin/trashd-exec --version >/dev/null 2>&1; then
                # Prevent login-shell recursion if listener installation fails.
                # Only trashd-exec sets ACTIVE, after protection is established.
                export TRASHD_SECCOMP_ATTEMPTED=1
                exec /usr/local/bin/trashd-exec --preserve-privileges -- "$_trashd_shell" -l
            fi
            unset _trashd_shell
            ;;
    esac
fi
