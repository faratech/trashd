#!/usr/bin/env bash
set -euo pipefail

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

    echo ""
    echo "==> trashd uninstalled."
    echo "    User config preserved at ~/.config/trashd/"
    echo "    Trash contents preserved at ~/.local/share/Trash/"
    echo "    Start a new shell to clear PATH changes."
    exit 0
fi

# -----------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------
echo "==> Building trashd..."
cargo build --release --manifest-path="$(dirname "$0")/Cargo.toml"

TARGET_DIR="$(dirname "$0")/target/release"

echo "==> Installing binaries..."
install -Dm755 "${TARGET_DIR}/trash"    "${BIN_DIR}/trash"

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

echo "==> Installing LD_PRELOAD library..."
install -Dm755 "${TARGET_DIR}/libtrashd_preload.so" "${LIB_DIR}/libtrashd_preload.so"
echo "    Installed ${LIB_DIR}/libtrashd_preload.so"
echo "    To enable system-wide: echo '${LIB_DIR}/libtrashd_preload.so' >> /etc/ld.so.preload"
echo "    To enable per-session: export LD_PRELOAD=${LIB_DIR}/libtrashd_preload.so"

echo "==> Installing PATH hook..."
if [ -d /etc/profile.d ]; then
    install -Dm644 "$(dirname "$0")/install/profile.d/trashd.sh" /etc/profile.d/trashd.sh
    echo "    Installed /etc/profile.d/trashd.sh"
fi

echo "==> Installing default config..."
CONFIG_DIR="${HOME}/.config/trashd"
if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
    mkdir -p "${CONFIG_DIR}"
    cp "$(dirname "$0")/config/trashd.toml" "${CONFIG_DIR}/config.toml"
    echo "    Installed ${CONFIG_DIR}/config.toml"
else
    echo "    Config already exists, skipping"
fi

echo ""
echo "==> trashd installed successfully!"
echo ""
echo "    Start a new shell or run: source /etc/profile.d/trashd.sh"
echo ""
echo "    Layer 1 (PATH shims):"
echo "      rm file.txt          # moves to trash (intercepted by shim)"
echo "      rm --permanent file  # real delete (bypasses trash)"
echo "      TRASH_BYPASS=1 rm f  # real delete via env var"
echo ""
echo "    Layer 2 (LD_PRELOAD — catches unlink/rmdir from any program):"
echo "      LD_PRELOAD=${LIB_DIR}/libtrashd_preload.so <command>"
echo "      TRASHD_PRELOAD_LOG=1 to see interceptions"
echo ""
echo "    CLI:"
echo "      trash ls             # list trashed files (all partitions)"
echo "      trash undo           # restore last deletion"
echo "      trash restore file   # restore specific file"
echo "      trash empty          # permanently empty trash"
echo "      trash status         # show per-partition trash stats"
