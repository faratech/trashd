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
            # Prevent login-shell recursion if listener installation fails.
            # Only trashd-exec sets ACTIVE, after protection is established.
            export TRASHD_SECCOMP_ATTEMPTED=1
            exec /usr/local/bin/trashd-exec --preserve-privileges -- "$SHELL" -l
            ;;
    esac
fi
