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
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "uninstall" ] || [ "${1:-}" = "--purge" ]; then
    echo "==> Uninstalling trashd..."

    # By default we remove all trashd software but PRESERVE trash contents
    # (the whole point of the tool is to not lose data). Pass --purge to also
    # delete every trash directory.
    PURGE=0
    for arg in "$@"; do
        [ "$arg" = "--purge" ] && PURGE=1
    done

    # CRITICAL: the trashd `rm` shim shadows the real `rm` in PATH, and step 4
    # below deletes it. After that, any PATH/hash lookup of `rm` resolves to the
    # now-deleted shim and every later `rm` fails with "No such file or
    # directory". Two defenses (TRASH_BYPASS=1, set at top, also stops the shim
    # from trashing what we delete):
    #   (a) resolve an absolute real `rm` once and use "$RM" for every removal;
    #   (b) scrub the shim dir from PATH (duplicate-safe) and clear the hash.
    RM=rm
    for _cand in /usr/bin/rm /bin/rm /usr/local/bin/rm; do
        if [ -x "$_cand" ] && [ "$_cand" != "${SHIM_DIR}/rm" ]; then
            RM="$_cand"
            break
        fi
    done
    # Rebuild PATH without SHIM_DIR. A simple ":${SHIM_DIR}:" -> ":" substitution
    # mishandles ADJACENT duplicates (they share a colon), so split and filter.
    set -f
    _new_path=""
    _old_ifs="$IFS"
    IFS=':'
    for _d in $PATH; do
        [ -z "$_d" ] && continue
        [ "$_d" = "${SHIM_DIR}" ] && continue
        _new_path="${_new_path:+$_new_path:}$_d"
    done
    IFS="$_old_ifs"
    set +f
    PATH="$_new_path"
    export PATH
    hash -r 2>/dev/null || true

    # 1. Remove the LD_PRELOAD entry FIRST — before deleting the .so — otherwise
    #    every dynamically-linked process errors about the missing library.
    if [ -f /etc/ld.so.preload ]; then
        if grep -q "libtrashd_preload.so" /etc/ld.so.preload 2>/dev/null; then
            sed -i '\|libtrashd_preload.so|d' /etc/ld.so.preload
            echo "    Removed from /etc/ld.so.preload"
        fi
        # Drop the file entirely if nothing else is left in it.
        [ -s /etc/ld.so.preload ] || "$RM" -f /etc/ld.so.preload
    fi

    # 2. Stop the fanotify daemon: the systemd unit (old + new names) AND any
    #    lingering process (covers manual / non-systemd starts).
    if command -v systemctl >/dev/null 2>&1; then
        for svc in trashd trashd-daemon; do
            if [ -f "/etc/systemd/system/${svc}.service" ]; then
                systemctl stop "$svc" 2>/dev/null || true
                systemctl disable "$svc" 2>/dev/null || true
                "$RM" -f "/etc/systemd/system/${svc}.service"
                echo "    Removed ${svc}.service"
            fi
        done
        systemctl daemon-reload 2>/dev/null || true
    fi
    if pkill -x trashd 2>/dev/null; then
        echo "    Stopped running trashd daemon"
    fi

    # 3. Remove CLI binaries (current + legacy locations/names).
    "$RM" -f "${BIN_DIR}/trash" "${BIN_DIR}/trashd-exec" "${BIN_DIR}/trashd-daemon"
    echo "    Removed binaries from ${BIN_DIR}"

    # 4. Remove the entire trashd lib tree in one shot: the rm shim (bin/), the
    #    stashed real rm (real/), the preload .so, and the daemon binary.
    if [ -d "${LIB_DIR}" ]; then
        "$RM" -rf "${LIB_DIR}"
        echo "    Removed ${LIB_DIR}"
    fi

    # 5. Remove ALL trashd man pages: trash.1 plus every trash-<subcommand>.1
    #    (globbed, so new subcommands are covered without editing this list).
    MAN_DIR="${PREFIX}/share/man/man1"
    "$RM" -f "${MAN_DIR}/trash.1" "${MAN_DIR}"/trash-*.1
    echo "    Removed man pages"

    # 6. Remove shell completions (bash, zsh, fish).
    "$RM" -f /etc/bash_completion.d/trash \
          "${PREFIX}/share/zsh/site-functions/_trash" \
          /usr/share/fish/vendor_completions.d/trash.fish
    echo "    Removed shell completions"

    # 7. Remove the PATH + seccomp hook.
    "$RM" -f /etc/profile.d/trashd.sh
    echo "    Removed /etc/profile.d/trashd.sh"

    # 8. Remove global config.
    if [ -d /etc/trashd ]; then
        "$RM" -rf /etc/trashd
        echo "    Removed /etc/trashd"
    fi

    # 9. Remove per-user configs for all users (and root).
    for home_dir in /home/* /root; do
        if [ -d "${home_dir}/.config/trashd" ]; then
            "$RM" -rf "${home_dir}/.config/trashd"
            echo "    Removed ${home_dir}/.config/trashd"
        fi
    done

    # 10. Optionally remove every FreeDesktop.org Trash spec v1.0 trash
    #     directory (home + per-mountpoint). This DESTROYS trashed files, so it
    #     only runs with --purge.
    if [ "${PURGE}" -eq 1 ]; then
        echo "==> Removing all trash directories (--purge)..."
        for home_dir in /home/* /root; do
            if [ -d "${home_dir}/.local/share/Trash" ]; then
                "$RM" -rf "${home_dir}/.local/share/Trash"
                echo "    Removed ${home_dir}/.local/share/Trash"
            fi
        done
        while IFS= read -r mpoint; do
            for d in "${mpoint}"/.Trash-*; do
                [ -d "$d" ] && { "$RM" -rf "$d"; echo "    Removed $d"; }
            done
            [ -d "${mpoint}/.Trash" ] && { "$RM" -rf "${mpoint}/.Trash"; echo "    Removed ${mpoint}/.Trash"; }
        done < <(awk '{print $2}' /proc/mounts 2>/dev/null | sort -u)
    fi

    echo ""
    if [ "${PURGE}" -eq 1 ]; then
        echo "==> trashd fully uninstalled. All trash directories removed."
    else
        echo "==> trashd uninstalled. Trash contents were preserved."
        echo "    Re-run with --purge to also delete all trash directories."
    fi
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
