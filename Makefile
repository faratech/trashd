PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/trashd
MANDIR ?= $(PREFIX)/share/man/man1
UNITDIR ?= /usr/lib/systemd/system
USERUNITDIR ?= /usr/lib/systemd/user
DESTDIR ?=

COMPLETIONS_BASH ?= $(PREFIX)/share/bash-completion/completions
COMPLETIONS_ZSH ?= $(PREFIX)/share/zsh/site-functions
COMPLETIONS_FISH ?= $(PREFIX)/share/fish/vendor_completions.d

# The full man page set: the top-level page plus one per CLI subcommand,
# exactly what crates/trashd-cli/build.rs generates into target/man.
# Uninstall iterates this list instead of globbing target/man/*.1: after
# `make clean` (or with a downgraded tree) the glob only sees the pages
# still there and left the rest installed (#425).
MAN_PAGES = trash.1 trash-compress.1 trash-config.1 trash-du.1 trash-empty.1 \
	trash-find.1 trash-fsck.1 trash-info.1 trash-log.1 trash-ls.1 \
	trash-purge.1 trash-restore.1 trash-self-update.1 trash-status.1 \
	trash-undo.1

.PHONY: all build install uninstall clean test update

all: build

# Opt-in dependency refresh — NOT part of build/install: releases and installs
# must build against the committed Cargo.lock (same discipline as install.sh
# --locked and the CI workflows).
update:
	@echo "==> Updating Rust toolchain..."
	rustup update stable 2>/dev/null || true
	@echo "==> Updating dependencies..."
	cargo update

build:
	cargo build --release
	@# Optional i686 preload (#229): only where the target is installed; a
	@# failure here loses only the 32-bit library, never the build.
	@if [ "$$(uname -m)" = "x86_64" ] && [ -d "$$(rustc --print sysroot 2>/dev/null)/lib/rustlib/i686-unknown-linux-gnu" ]; then \
		cargo build --release -p trashd-preload --target i686-unknown-linux-gnu \
			|| echo "warning: i686 preload build failed; continuing without it" >&2; \
	fi

test:
	TRASH_BYPASS=1 cargo test --workspace

clean:
	cargo clean

# install never builds: under sudo, cargo's build scripts and proc macros
# would run as root (#229). Run `make` first as your own user.
install:
	@# /etc/ld.so.preload holds whitespace/colon-separated tokens, and a
	@# PREFIX or DESTDIR containing either would be written into it broken —
	@# and word-split all over these recipes. Refuse before touching
	@# anything, the way install.sh does (#422).
	@if printf '%s' "$(PREFIX)$(DESTDIR)$(BINDIR)$(LIBDIR)$(MANDIR)" | grep -qE '[[:space:]:]'; then \
		echo "error: PREFIX/DESTDIR contains whitespace or ':' — unsafe for /etc/ld.so.preload" >&2; \
		exit 1; \
	fi
	@for artifact in trash trashd-rm trashd-exec trashd libtrashd_preload.so; do \
		if [ ! -f target/release/$$artifact ]; then \
			echo "error: target/release/$$artifact is missing; run 'make build' first (without sudo)" >&2; \
			exit 1; \
		fi; \
	done
	install -Dm755 target/release/trash "$(DESTDIR)$(BINDIR)/trash"
	install -Dm755 target/release/trashd-rm "$(DESTDIR)$(LIBDIR)/bin/rm"
	install -Dm755 target/release/trashd-exec "$(DESTDIR)$(BINDIR)/trashd-exec"
	# The daemon lives in LIBDIR (install.sh's layout) with a BIN symlink: the
	# systemd unit's ExecStart points at LIBDIR, and a BINDIR-only install made
	# `systemctl start trashd` fail with status=203/EXEC (#160).
	install -Dm755 target/release/trashd "$(DESTDIR)$(LIBDIR)/trashd"
	ln -sf "$(LIBDIR)/trashd" "$(DESTDIR)$(BINDIR)/trashd"
	install -Dm755 target/release/libtrashd_preload.so "$(DESTDIR)$(LIBDIR)/libtrashd_preload.so"
	@# Per-ABI layout for the $LIB registration below, when the optional
	@# i686 preload was built (#229).
	@if [ -f target/i686-unknown-linux-gnu/release/libtrashd_preload.so ]; then \
		install -Dm755 target/release/libtrashd_preload.so "$(DESTDIR)$(LIBDIR)/lib64/libtrashd_preload.so"; \
		install -Dm755 target/i686-unknown-linux-gnu/release/libtrashd_preload.so "$(DESTDIR)$(LIBDIR)/lib/libtrashd_preload.so"; \
		echo "==> Installed 32-bit preload (registered via \$$LIB)"; \
	else \
		rm -rf "$(DESTDIR)$(LIBDIR)/lib" "$(DESTDIR)$(LIBDIR)/lib64"; \
	fi
	# Shipped defaults only: never reset an admin's policy on a re-run
	# (install.sh and %config(noreplace) already behave this way) (#161).
	if [ -n "$(DESTDIR)" ] || [ ! -f /etc/trashd/config.toml ]; then \
		install -Dm644 config/trashd.toml "$(DESTDIR)/etc/trashd/config.toml"; \
	fi
	# Template the runtime prefix into the profile script — the shipped file
	# hardcodes /usr/local, which would leave Layers 1/4 inactive for custom
	# PREFIX installs (#101, #124). DESTDIR is staging-only, so the script
	# embeds the un-prefixed runtime paths. index/substr splicing keeps
	# metacharacters in the prefix byte-exact.
	mkdir -p "$(DESTDIR)/etc/profile.d"
	awk -v shim="$(LIBDIR)/bin" -v bin="$(BINDIR)/trashd-exec" '{ s = $$0; out = ""; while ((i = index(s, "/usr/local/lib/trashd/bin")) > 0) { out = out substr(s, 1, i-1) shim; s = substr(s, i + length("/usr/local/lib/trashd/bin")) } s = out s; out = ""; while ((i = index(s, "/usr/local/bin/trashd-exec")) > 0) { out = out substr(s, 1, i-1) bin; s = substr(s, i + length("/usr/local/bin/trashd-exec")) } print out s }' \
		install/profile.d/trashd.sh > "$(DESTDIR)/etc/profile.d/trashd.sh"
	chmod 0644 "$(DESTDIR)/etc/profile.d/trashd.sh"
	# Same templating for the unit's ExecStart, staged to UNITDIR so the RPM
	# spec's %{_unitdir} %files entry matches what this Makefile actually
	# writes (#159, #160).
	mkdir -p "$(DESTDIR)$(UNITDIR)"
	awk -v daemon="$(LIBDIR)/trashd" '{ s = $$0; out = ""; while ((i = index(s, "/usr/local/lib/trashd/trashd")) > 0) { out = out substr(s, 1, i-1) daemon; s = substr(s, i + length("/usr/local/lib/trashd/trashd")) } print out s }' \
		install/systemd/trashd.service > "$(DESTDIR)$(UNITDIR)/trashd.service"
	chmod 0644 "$(DESTDIR)$(UNITDIR)/trashd.service"
	# The cleanup timer is a per-user unit, shipped disabled (#227).
	mkdir -p "$(DESTDIR)$(USERUNITDIR)"
	awk -v trash="$(BINDIR)/trash" '{ s = $$0; out = ""; while ((i = index(s, "/usr/local/bin/trash")) > 0) { out = out substr(s, 1, i-1) trash; s = substr(s, i + length("/usr/local/bin/trash")) } print out s }' \
		install/systemd/trashd-cleanup.service > "$(DESTDIR)$(USERUNITDIR)/trashd-cleanup.service"
	chmod 0644 "$(DESTDIR)$(USERUNITDIR)/trashd-cleanup.service"
	install -Dm644 install/systemd/trashd-cleanup.timer "$(DESTDIR)$(USERUNITDIR)/trashd-cleanup.timer"
	# Native installs only (DESTDIR staging must never touch the host):
	# register Layer 2 system-wide, matching install.sh (#160). Registration
	# is form-specific (#406): a prior install without the i686 library
	# registered the flat path, one with it registered the $$LIB path — the
	# old either-form check froze whichever came first, so a transition now
	# replaces the other form before appending.
	if [ -z "$(DESTDIR)" ]; then \
		entry="$(LIBDIR)/libtrashd_preload.so"; \
		if [ -f target/i686-unknown-linux-gnu/release/libtrashd_preload.so ]; then \
			entry="$(LIBDIR)/\$$LIB/libtrashd_preload.so"; \
		fi; \
		if ! awk -v lib="$$entry" '{ line = $$0; if ((h = index(line, "#")) > 0) line = substr(line, 1, h - 1); n = split(line, e, /[ \t:]+/); for (i = 1; i <= n; i++) if (e[i] == lib) found = 1 } END { exit !found }' /etc/ld.so.preload 2>/dev/null; then \
			if [ -f /etc/ld.so.preload ] && grep -qsF "$(LIBDIR)/" /etc/ld.so.preload; then \
				awk -v lib="$(LIBDIR)/libtrashd_preload.so" -v libalt="$(LIBDIR)/\$$LIB/libtrashd_preload.so" '{ line = $$0; comment = ""; if ((h = index(line, "#")) > 0) { comment = substr(line, h); line = substr(line, 1, h - 1) } if (index(line, lib) == 0 && index(line, libalt) == 0) { print $$0; next } n = split(line, entry, /[ \t:]+/); out = ""; for (i = 1; i <= n; i++) if (entry[i] != "" && entry[i] != lib && entry[i] != libalt) out = out (out == "" ? "" : " ") entry[i]; if (comment != "") out = out (out == "" ? "" : " ") comment; if (out != "") print out }' \
					/etc/ld.so.preload > /etc/ld.so.preload.trashd-new; \
				chmod 0644 /etc/ld.so.preload.trashd-new; \
				mv -f /etc/ld.so.preload.trashd-new /etc/ld.so.preload; \
			fi; \
			mkdir -p /etc; \
			if [ -s /etc/ld.so.preload ] && [ "$$(tail -c1 /etc/ld.so.preload | wc -l)" -eq 0 ]; then \
				printf '\n' >> /etc/ld.so.preload; \
			fi; \
			echo "$$entry" >> /etc/ld.so.preload; \
			echo "==> Enabled LD_PRELOAD layer via /etc/ld.so.preload"; \
		fi; \
	fi
	# Man pages: the full generated set, not only trash.1 (#260)
	@for page in target/man/*.1; do \
		[ -e "$$page" ] || { echo "error: no man pages in target/man; run 'make build' first" >&2; exit 1; }; \
		install -Dm644 "$$page" "$(DESTDIR)$(MANDIR)/$$(basename "$$page")"; \
	done
	# Shell completions
	install -Dm644 target/completions/trash.bash "$(DESTDIR)$(COMPLETIONS_BASH)/trash"
	install -Dm644 target/completions/_trash "$(DESTDIR)$(COMPLETIONS_ZSH)/_trash"
	install -Dm644 target/completions/trash.fish "$(DESTDIR)$(COMPLETIONS_FISH)/trash.fish"

uninstall:
	# Stop the daemon before its binary goes away (#229).
	if [ -z "$(DESTDIR)" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then \
		systemctl disable --now trashd 2>/dev/null || true; \
	fi
	rm -f "$(DESTDIR)$(BINDIR)/trash"
	rm -f "$(DESTDIR)$(BINDIR)/trashd-exec"
	rm -f "$(DESTDIR)$(BINDIR)/trashd"
	# Remove the LD_PRELOAD registration BEFORE deleting the .so (mirror of
	# the install step and install.sh's uninstall step 1): a dangling entry
	# makes every dynamic process print an ld.so error forever (#166).
	if [ -z "$(DESTDIR)" ] && grep -qsF "$(LIBDIR)/" /etc/ld.so.preload 2>/dev/null; then \
		awk -v lib="$(LIBDIR)/libtrashd_preload.so" -v libalt="$(LIBDIR)/\$$LIB/libtrashd_preload.so" '{ line = $$0; comment = ""; if ((h = index(line, "#")) > 0) { comment = substr(line, h); line = substr(line, 1, h - 1) } if (index(line, lib) == 0 && index(line, libalt) == 0) { print $$0; next } n = split(line, entry, /[ \t:]+/); out = ""; for (i = 1; i <= n; i++) if (entry[i] != "" && entry[i] != lib && entry[i] != libalt) out = out (out == "" ? "" : " ") entry[i]; if (comment != "") out = out (out == "" ? "" : " ") comment; if (out != "") print out }' \
			/etc/ld.so.preload > /etc/ld.so.preload.trashd-new; \
		chmod 0644 /etc/ld.so.preload.trashd-new; \
		mv -f /etc/ld.so.preload.trashd-new /etc/ld.so.preload; \
		[ -s /etc/ld.so.preload ] || rm -f /etc/ld.so.preload; \
		echo "==> Removed LD_PRELOAD layer from /etc/ld.so.preload"; \
	fi
	rm -rf "$(DESTDIR)$(LIBDIR)"
	rm -f "$(DESTDIR)/etc/profile.d/trashd.sh"
	rm -f "$(DESTDIR)$(UNITDIR)/trashd.service"
	rm -f "$(DESTDIR)/etc/systemd/system/trashd.service"
	rm -f "$(DESTDIR)$(USERUNITDIR)/trashd-cleanup.service" "$(DESTDIR)$(USERUNITDIR)/trashd-cleanup.timer"
	rm -f "$(DESTDIR)/etc/systemd/user/trashd-cleanup.service" "$(DESTDIR)/etc/systemd/user/trashd-cleanup.timer"
	# Enablement symlinks: multi-user.target is the unit's [Install] target;
	# default.target.wants links are left over from units older than the
	# multi-user change (#426).
	rm -f "$(DESTDIR)/etc/systemd/system/multi-user.target.wants/trashd.service"
	rm -f "$(DESTDIR)$(UNITDIR)/multi-user.target.wants/trashd.service"
	rm -f "$(DESTDIR)/etc/systemd/system/default.target.wants/trashd.service"
	rm -f "$(DESTDIR)$(UNITDIR)/default.target.wants/trashd.service"
	rm -f "$(DESTDIR)/etc/systemd/user/timers.target.wants/trashd-cleanup.timer" "$(DESTDIR)$(USERUNITDIR)/timers.target.wants/trashd-cleanup.timer"
	if [ -z "$(DESTDIR)" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then \
		systemctl daemon-reload 2>/dev/null || true; \
	fi
	@# Man pages: the full known set (MAN_PAGES), not the glob of what
	@# target/man still holds — `make clean` or a downgraded tree used to
	@# leave pages installed (#425). Pages newer than this list are added
	@# back when target/man still exists, so a newer tree is cleaned too.
	@pages="$(MAN_PAGES)"; \
	for page in target/man/*.1; do \
		[ -e "$$page" ] && pages="$$pages $$(basename "$$page")"; \
	done; \
	for page in $$pages; do \
		rm -f "$(DESTDIR)$(MANDIR)/$$page"; \
	done
	rm -f "$(DESTDIR)$(COMPLETIONS_BASH)/trash"
	rm -f "$(DESTDIR)$(COMPLETIONS_ZSH)/_trash"
	rm -f "$(DESTDIR)$(COMPLETIONS_FISH)/trash.fish"
