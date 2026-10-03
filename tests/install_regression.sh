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
env PATH="$INSTALL_PATH" "$WORK/good/install.sh" > "$WORK/good.log" 2>&1 \
    || fail "installer failed: $(cat "$WORK/good.log")"
grep -qx /usr/local/lib/trashd/libtrashd_preload.so /etc/ld.so.preload \
    || fail "preload not registered"
[[ -x /usr/local/bin/trash ]] || fail "CLI not installed"
echo "PASS: loadable build installs and registers the preload"

echo "install regression: all checks passed"
