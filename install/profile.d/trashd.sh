#!/bin/sh
# trashd — activate all trash interception layers
# Installed to /etc/profile.d/trashd.sh

# Layer 1: PATH shim — shadow rm with trash-aware version
if [ -d /usr/local/lib/trashd/bin ]; then
    export PATH="/usr/local/lib/trashd/bin:$PATH"
fi

# Layer 4: seccomp — re-exec shell under trashd-exec for kernel-level
# syscall trapping. Covers statically-linked binaries and anything that
# bypasses LD_PRELOAD. Guard prevents infinite re-exec.
# Skip if LD_PRELOAD is already providing system-wide coverage (they
# conflict — seccomp filter install fails when preload hooks are active).
if [ -z "${TRASHD_SECCOMP_ACTIVE:-}" ] && [ -x /usr/local/bin/trashd-exec ]; then
    _trashd_preload_active=0
    [ -f /etc/ld.so.preload ] && grep -qs "libtrashd_preload.so" /etc/ld.so.preload && _trashd_preload_active=1
    if [ "$_trashd_preload_active" = "0" ]; then
        # Only wrap interactive login shells (not scripts, not subshells)
        case "$-" in
            *i*)
                export TRASHD_SECCOMP_ACTIVE=1
                exec /usr/local/bin/trashd-exec "$SHELL" -l
                ;;
        esac
    fi
    unset _trashd_preload_active
fi
