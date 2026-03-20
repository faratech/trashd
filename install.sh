#!/usr/bin/env bash
set -euo pipefail

# Bypass trashd interception during install — we don't want the LD_PRELOAD
# layer trashing old binaries when install overwrites them.
export TRASH_BYPASS=1

PREFIX="${PREFIX:-/usr/local}"
SHIM_DIR="${PREFIX}/lib/trashd/bin"
REAL_DIR="${PREFIX}/lib/trashd/real"
LIB_DIR="${PREFIX}/lib/trashd"
BIN_DIR="${PREFIX}/bin"

# -----------------------------------------------------------------------
# Uninstall
# -----------------------------------------------------------------------
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "uninstall" ]; then
    echo "==> Uninstalling trashd..."

    # Restore real rm if we stashed it
    if [ -f "${REAL_DIR}/rm" ]; then
        echo "    Stashed real rm found at ${REAL_DIR}/rm (leaving in place)"
    fi

    # Remove binaries
    for bin in trash trashd-exec trashd-daemon; do
        if [ -f "${BIN_DIR}/${bin}" ]; then
            rm -f "${BIN_DIR}/${bin}"
            echo "    Removed ${BIN_DIR}/${bin}"
        fi
    done

    # Remove shim directory (rm shim, unlink symlink)
    if [ -d "${SHIM_DIR}" ]; then
        rm -rf "${SHIM_DIR}"
        echo "    Removed ${SHIM_DIR}"
    fi

    # Remove LD_PRELOAD library
    if [ -f "${LIB_DIR}/libtrashd_preload.so" ]; then
        rm -f "${LIB_DIR}/libtrashd_preload.so"
        echo "    Removed ${LIB_DIR}/libtrashd_preload.so"
    fi

    # Remove from /etc/ld.so.preload if present
    if [ -f /etc/ld.so.preload ]; then
        if grep -q "libtrashd_preload.so" /etc/ld.so.preload 2>/dev/null; then
            sed -i '\|libtrashd_preload.so|d' /etc/ld.so.preload
            echo "    Removed from /etc/ld.so.preload"
        fi
    fi

    # Remove stashed real rm and lib dir if empty
    rm -f "${REAL_DIR}/rm" 2>/dev/null
    rmdir "${REAL_DIR}" 2>/dev/null || true
    rmdir "${LIB_DIR}" 2>/dev/null || true

    # Remove PATH hook
    if [ -f /etc/profile.d/trashd.sh ]; then
        rm -f /etc/profile.d/trashd.sh
        echo "    Removed /etc/profile.d/trashd.sh"
    fi

    # Remove systemd service if installed
    if [ -f /etc/systemd/system/trashd-daemon.service ]; then
        systemctl stop trashd-daemon 2>/dev/null || true
        systemctl disable trashd-daemon 2>/dev/null || true
        rm -f /etc/systemd/system/trashd-daemon.service
        systemctl daemon-reload 2>/dev/null || true
        echo "    Removed trashd-daemon.service"
    fi

    # Remove global config
    if [ -f /etc/trashd/config.toml ]; then
        rm -f /etc/trashd/config.toml
        rmdir /etc/trashd 2>/dev/null || true
        echo "    Removed /etc/trashd/config.toml"
    fi

    # Remove per-user configs for all users
    for home_dir in /home/* /root; do
        config_dir="${home_dir}/.config/trashd"
        if [ -d "${config_dir}" ]; then
            rm -rf "${config_dir}"
            echo "    Removed ${config_dir}"
        fi
    done

    echo ""
    echo "==> trashd uninstalled."
    echo "    Trash contents preserved at ~/.local/share/Trash/"
    echo "    Start a new shell to clear PATH changes."
    exit 0
fi

# -----------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------
echo "==> Updating Rust toolchain and dependencies..."
rustup update stable 2>/dev/null || true
cargo update --manifest-path="$(dirname "$0")/Cargo.toml" 2>/dev/null || true

echo "==> Building trashd..."
cargo build --release --manifest-path="$(dirname "$0")/Cargo.toml"

TARGET_DIR="$(dirname "$0")/target/release"

echo "==> Installing binaries..."
install -Dm755 "${TARGET_DIR}/trash"       "${BIN_DIR}/trash"
install -Dm755 "${TARGET_DIR}/trashd-exec" "${BIN_DIR}/trashd-exec"
install -Dm755 "${TARGET_DIR}/trashd-daemon" "${LIB_DIR}/trashd-daemon"

echo "==> Setting up shim directory..."
mkdir -p "${SHIM_DIR}" "${REAL_DIR}"

# Stash the real rm binary
REAL_RM="$(which rm 2>/dev/null || echo /usr/bin/rm)"
if [ -x "${REAL_RM}" ] && [ ! -f "${REAL_DIR}/rm" ]; then
    cp "${REAL_RM}" "${REAL_DIR}/rm"
    echo "    Saved real rm -> ${REAL_DIR}/rm"
fi

# Install rm shim
install -Dm755 "${TARGET_DIR}/trashd-rm" "${SHIM_DIR}/rm"

# Create convenience symlinks for common destructive commands
# that just invoke the rm shim
for cmd in unlink; do
    ln -sf rm "${SHIM_DIR}/${cmd}"
done

echo "==> Installing LD_PRELOAD library (Layer 2)..."
install -Dm755 "${TARGET_DIR}/libtrashd_preload.so" "${LIB_DIR}/libtrashd_preload.so"
echo "    Installed ${LIB_DIR}/libtrashd_preload.so"
# Enable system-wide: catches unlink/rmdir from any dynamically-linked program
if ! grep -qs "libtrashd_preload.so" /etc/ld.so.preload 2>/dev/null; then
    echo "${LIB_DIR}/libtrashd_preload.so" >> /etc/ld.so.preload
    echo "    Enabled system-wide via /etc/ld.so.preload"
else
    echo "    Already in /etc/ld.so.preload"
fi

echo "==> Installing PATH + seccomp hook (Layers 1 & 4)..."
if [ -d /etc/profile.d ]; then
    install -Dm644 "$(dirname "$0")/install/profile.d/trashd.sh" /etc/profile.d/trashd.sh
    echo "    Installed /etc/profile.d/trashd.sh"
    echo "    Layer 1: PATH shim shadows rm"
    echo "    Layer 4: Interactive shells run under seccomp protection"
fi

echo "==> Installing fanotify daemon (Layer 3)..."
if [ -d /etc/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    install -Dm644 "$(dirname "$0")/install/systemd/trashd-daemon.service" \
        /etc/systemd/system/trashd-daemon.service
    systemctl daemon-reload
    systemctl enable trashd-daemon 2>/dev/null || true
    systemctl start trashd-daemon 2>/dev/null || true
    if systemctl is-active --quiet trashd-daemon 2>/dev/null; then
        echo "    trashd-daemon is running (monitoring deletions)"
    else
        echo "    trashd-daemon installed but could not start (needs CAP_SYS_ADMIN)"
        echo "    Start manually: sudo systemctl start trashd-daemon"
    fi
else
    echo "    systemd not available, skipping daemon install"
    echo "    Run manually: sudo trashd-daemon --foreground"
fi

echo "==> Installing global config..."
GLOBAL_CONFIG_DIR="/etc/trashd"
if [ ! -f "${GLOBAL_CONFIG_DIR}/config.toml" ]; then
    install -Dm644 "$(dirname "$0")/config/trashd.toml" "${GLOBAL_CONFIG_DIR}/config.toml"
    echo "    Installed ${GLOBAL_CONFIG_DIR}/config.toml"
else
    echo "    Global config already exists, skipping"
fi
echo "    Per-user overrides: ~/.config/trashd/config.toml"

echo ""
echo "==> trashd installed successfully! All layers active."
echo ""
echo "    Start a new shell or run: source /etc/profile.d/trashd.sh"
echo ""
echo "    Active layers:"
echo "      Layer 1 — PATH shim:    rm -> trash (via PATH)"
echo "      Layer 2 — LD_PRELOAD:   unlink()/rmdir() -> trash (system-wide)"
echo "      Layer 3 — fanotify:     deletion audit/logging (systemd service)"
echo "      Layer 4 — seccomp:      syscall trapping (interactive shells)"
echo ""
echo "    Bypass trash when needed:"
echo "      rm --permanent file     # real delete through shim"
echo "      TRASH_BYPASS=1 rm file  # real delete via env var"
echo ""
echo "    CLI:"
echo "      trash ls             # list trashed files"
echo "      trash undo           # restore last deletion"
echo "      trash restore file   # restore specific file"
echo "      trash empty          # permanently empty trash"
echo "      trash status         # show per-partition stats"
