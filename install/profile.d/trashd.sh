#!/bin/sh
# trashd — activate all trash interception layers
# Installed to /etc/profile.d/trashd.sh

# Layer 1: PATH shim — shadow rm with trash-aware version
if [ -d /usr/local/lib/trashd/bin ]; then
    export PATH="/usr/local/lib/trashd/bin:$PATH"
fi

# Layer 4: seccomp — re-exec shell under trashd-exec for kernel-level
# syscall trapping. This is the most robust layer: catches statically-linked
# binaries, programs that bypass LD_PRELOAD, and anything else.
# The LD_PRELOAD layer (Layer 2) defers to seccomp when this is active,
# so there's no double interception.
if [ -z "${TRASHD_SECCOMP_ACTIVE:-}" ] && [ -x /usr/local/bin/trashd-exec ]; then
    # Only wrap interactive login shells (not scripts, not subshells)
    case "$-" in
        *i*)
            export TRASHD_SECCOMP_ACTIVE=1
            exec /usr/local/bin/trashd-exec "$SHELL" -l
            ;;
    esac
fi
