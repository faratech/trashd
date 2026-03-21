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
    for bin in trash trashd-exec; do
        if [ -f "${BIN_DIR}/${bin}" ]; then
            rm -f "${BIN_DIR}/${bin}"
            echo "    Removed ${BIN_DIR}/${bin}"
        fi
    done
    # Daemon lives in LIB_DIR (current) or BIN_DIR (old versions)
    for loc in "${LIB_DIR}/trashd" "${LIB_DIR}/trashd-daemon" "${BIN_DIR}/trashd-daemon"; do
        if [ -f "$loc" ]; then
            rm -f "$loc"
            echo "    Removed $loc"
        fi
    done

    # Remove shim directory (rm shim, unlink symlink)
    if [ -d "${SHIM_DIR}" ]; then
        rm -rf "${SHIM_DIR}"
        echo "    Removed ${SHIM_DIR}"
    fi

    # Remove from /etc/ld.so.preload FIRST (before deleting the .so,
    # otherwise every process gets an error about missing preload library)
    if [ -f /etc/ld.so.preload ]; then
        if grep -q "libtrashd_preload.so" /etc/ld.so.preload 2>/dev/null; then
            sed -i '\|libtrashd_preload.so|d' /etc/ld.so.preload
            echo "    Removed from /etc/ld.so.preload"
        fi
    fi

    # Now safe to remove the library itself
    if [ -f "${LIB_DIR}/libtrashd_preload.so" ]; then
        rm -f "${LIB_DIR}/libtrashd_preload.so"
        echo "    Removed ${LIB_DIR}/libtrashd_preload.so"
    fi

    # Remove stashed real rm and lib dir if empty
    rm -f "${REAL_DIR}/rm" 2>/dev/null
    rmdir "${REAL_DIR}" 2>/dev/null || true
    rmdir "${LIB_DIR}" 2>/dev/null || true

    # Remove man pages
    for f in trash trash-ls trash-find trash-info trash-restore trash-undo \
             trash-purge trash-empty trash-status trash-log trash-fsck; do
        rm -f "${PREFIX}/share/man/man1/${f}.1" 2>/dev/null
    done
    echo "    Removed man pages"

    # Remove shell completions
    rm -f /etc/bash_completion.d/trash 2>/dev/null
    rm -f "${PREFIX}/share/zsh/site-functions/_trash" 2>/dev/null
    rm -f /usr/share/fish/vendor_completions.d/trash.fish 2>/dev/null
    echo "    Removed shell completions"

    # Remove PATH hook
    if [ -f /etc/profile.d/trashd.sh ]; then
        rm -f /etc/profile.d/trashd.sh
        echo "    Removed /etc/profile.d/trashd.sh"
    fi

    # Remove systemd service (check both old and new names)
    for svc in trashd trashd-daemon; do
        if [ -f "/etc/systemd/system/${svc}.service" ]; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc}.service"
            echo "    Removed ${svc}.service"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true

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

    # Remove ALL FreeDesktop.org Trash spec v1.0 trash directories
    echo "==> Removing all trash directories..."

    # Home trash for all users
    for home_dir in /home/* /root; do
        trash_dir="${home_dir}/.local/share/Trash"
        if [ -d "${trash_dir}" ]; then
            rm -rf "${trash_dir}"
            echo "    Removed ${trash_dir}"
        fi
    done

    # Per-mountpoint trash directories (.Trash-$UID and .Trash/$UID)
    # Scan all mount points for trash dirs
    while IFS= read -r mpoint; do
        # .Trash-* (per-user topdir trash)
        for d in "${mpoint}"/.Trash-*; do
            if [ -d "$d" ]; then
                rm -rf "$d"
                echo "    Removed $d"
            fi
        done
        # .Trash/ (shared topdir trash)
        if [ -d "${mpoint}/.Trash" ]; then
            rm -rf "${mpoint}/.Trash"
            echo "    Removed ${mpoint}/.Trash"
        fi
    done < <(awk '{print $2}' /proc/mounts 2>/dev/null | sort -u)

    echo ""
    echo "==> trashd fully uninstalled. All trash directories removed."
    echo "    Start a new shell to clear PATH changes."
    exit 0
fi

# -----------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------

# Detect pre-built binaries (tarball install) vs source install
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/bin/trash" ]; then
    # Tarball install — binaries already built
    TARGET_DIR="${SCRIPT_DIR}/bin"
    PRELOAD_DIR="${SCRIPT_DIR}/lib"
    MAN_SRC="${SCRIPT_DIR}/share/man/man1"
    COMP_DIR="${SCRIPT_DIR}/share/completions"
    echo "==> Installing from pre-built release..."
else
    # Source install — build from cargo
    echo "==> Updating Rust toolchain and dependencies..."
    rustup update stable 2>/dev/null || true
    cargo update --manifest-path="${SCRIPT_DIR}/Cargo.toml" 2>/dev/null || true

    echo "==> Building trashd..."
    cargo build --release --manifest-path="${SCRIPT_DIR}/Cargo.toml"

    TARGET_DIR="${SCRIPT_DIR}/target/release"
    PRELOAD_DIR="${TARGET_DIR}"
    MAN_SRC="${SCRIPT_DIR}/target/man"
    COMP_DIR="${SCRIPT_DIR}/target/completions"
fi

echo "==> Installing binaries..."
install -Dm755 "${TARGET_DIR}/trash"       "${BIN_DIR}/trash"
install -Dm755 "${TARGET_DIR}/trashd-exec" "${BIN_DIR}/trashd-exec"
install -Dm755 "${TARGET_DIR}/trashd" "${LIB_DIR}/trashd"

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

MAN_DIR="${PREFIX}/share/man/man1"
# MAN_SRC and COMP_DIR already set above (tarball or source paths)

echo "==> Installing man pages..."
if [ -d "${MAN_SRC}" ]; then
    mkdir -p "${MAN_DIR}"
    for f in "${MAN_SRC}"/*.1; do
        install -Dm644 "$f" "${MAN_DIR}/$(basename "$f")"
    done
    echo "    Installed man pages to ${MAN_DIR}"
else
    echo "    No man pages found (skipping)"
fi

echo "==> Installing shell completions..."
if [ -d "${COMP_DIR}" ]; then
    # Bash
    if [ -d /etc/bash_completion.d ]; then
        install -Dm644 "${COMP_DIR}/trash.bash" /etc/bash_completion.d/trash
        echo "    Installed bash completions"
    fi
    # Zsh
    ZSH_COMP_DIR="${PREFIX}/share/zsh/site-functions"
    mkdir -p "${ZSH_COMP_DIR}"
    install -Dm644 "${COMP_DIR}/_trash" "${ZSH_COMP_DIR}/_trash"
    echo "    Installed zsh completions"
    # Fish
    if [ -d /usr/share/fish/vendor_completions.d ]; then
        install -Dm644 "${COMP_DIR}/trash.fish" /usr/share/fish/vendor_completions.d/trash.fish
        echo "    Installed fish completions"
    fi
else
    echo "    No completions found (skipping)"
fi

echo "==> Installing LD_PRELOAD library (Layer 2)..."
install -Dm755 "${PRELOAD_DIR}/libtrashd_preload.so" "${LIB_DIR}/libtrashd_preload.so"
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
    # Migrate from old trashd-daemon.service name
    if [ -f /etc/systemd/system/trashd-daemon.service ]; then
        systemctl stop trashd-daemon 2>/dev/null || true
        systemctl disable trashd-daemon 2>/dev/null || true
        rm -f /etc/systemd/system/trashd-daemon.service
        echo "    Migrated from trashd-daemon.service -> trashd.service"
    fi
    # Remove old daemon binary name (was in BIN_DIR or LIB_DIR depending on version)
    rm -f "${LIB_DIR}/trashd-daemon" "${BIN_DIR}/trashd-daemon" 2>/dev/null
    install -Dm644 "$(dirname "$0")/install/systemd/trashd.service" \
        /etc/systemd/system/trashd.service
    systemctl daemon-reload
    systemctl enable trashd 2>/dev/null || true
    systemctl restart trashd 2>/dev/null || true
    if systemctl is-active --quiet trashd 2>/dev/null; then
        echo "    trashd is running (monitoring deletions)"
    else
        echo "    trashd installed but could not start (needs CAP_SYS_ADMIN)"
        echo "    Start manually: sudo systemctl start trashd"
    fi
else
    echo "    systemd not available, skipping daemon install"
    echo "    Run manually: sudo trashd --foreground"
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
