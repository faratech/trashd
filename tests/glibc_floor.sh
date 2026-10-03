#!/usr/bin/env bash
# Fail when a built artifact needs a newer glibc symbol version than the floor.
# Usage: tests/glibc_floor.sh 2.28 path/to/libtrashd_preload.so path/to/trashd-exec ...
#
# The preload is registered in /etc/ld.so.preload: a symbol version the host
# glibc lacks is fatal to the loader, so EVERY dynamically linked program
# would stop starting (#191). Releases are built against an old glibc
# (cargo zigbuild --target <triple>.2.28) and checked here.
set -euo pipefail

floor="${1:?usage: glibc_floor.sh <max-version> <artifact>...}"
shift
[ "$#" -gt 0 ] || { echo "glibc_floor.sh: no artifacts given" >&2; exit 2; }

status=0
for artifact in "$@"; do
    needed="$(objdump -T "$artifact" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1)"
    if [ -z "$needed" ]; then
        echo "ok      $artifact (no versioned glibc symbols)"
    elif [ "$(printf '%s\n%s\n' "$needed" "$floor" | sort -V | tail -1)" != "$floor" ]; then
        echo "FAIL    $artifact needs GLIBC_$needed (floor GLIBC_$floor):" >&2
        objdump -T "$artifact" | grep -E "GLIBC_${needed//./\\.}([^0-9.]|$)" | awk '{print "          " $NF}' >&2
        status=1
    else
        echo "ok      $artifact needs GLIBC_$needed (floor GLIBC_$floor)"
    fi
done
exit "$status"
