PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/trashd
MANDIR ?= $(PREFIX)/share/man/man1
DESTDIR ?=

COMPLETIONS_BASH ?= $(PREFIX)/share/bash-completion/completions
COMPLETIONS_ZSH ?= $(PREFIX)/share/zsh/site-functions
COMPLETIONS_FISH ?= $(PREFIX)/share/fish/vendor_completions.d

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

test:
	TRASH_BYPASS=1 cargo test --workspace

clean:
	cargo clean

install: build
	install -Dm755 target/release/trash $(DESTDIR)$(BINDIR)/trash
	install -Dm755 target/release/trashd-rm $(DESTDIR)$(LIBDIR)/bin/rm
	install -Dm755 target/release/trashd-exec $(DESTDIR)$(BINDIR)/trashd-exec
	install -Dm755 target/release/trashd $(DESTDIR)$(BINDIR)/trashd
	install -Dm755 target/release/libtrashd_preload.so $(DESTDIR)$(LIBDIR)/libtrashd_preload.so
	install -Dm644 config/trashd.toml $(DESTDIR)/etc/trashd/config.toml
	# Template the runtime prefix into the profile script — the shipped file
	# hardcodes /usr/local, which would leave Layers 1/4 inactive for custom
	# PREFIX installs (#101, #124). DESTDIR is staging-only, so the script
	# embeds the un-prefixed runtime paths. index/substr splicing keeps
	# metacharacters in the prefix byte-exact.
	mkdir -p $(DESTDIR)/etc/profile.d
	awk -v shim="$(LIBDIR)/bin" -v bin="$(BINDIR)/trashd-exec" '{ s = $$0; out = ""; while ((i = index(s, "/usr/local/lib/trashd/bin")) > 0) { out = out substr(s, 1, i-1) shim; s = substr(s, i + length("/usr/local/lib/trashd/bin")) } s = out s; out = ""; while ((i = index(s, "/usr/local/bin/trashd-exec")) > 0) { out = out substr(s, 1, i-1) bin; s = substr(s, i + length("/usr/local/bin/trashd-exec")) } print out s }' \
		install/profile.d/trashd.sh > $(DESTDIR)/etc/profile.d/trashd.sh
	chmod 0644 $(DESTDIR)/etc/profile.d/trashd.sh
	install -Dm644 install/systemd/trashd.service $(DESTDIR)/etc/systemd/system/trashd.service
	# Man page
	install -Dm644 target/man/trash.1 $(DESTDIR)$(MANDIR)/trash.1
	# Shell completions
	install -Dm644 target/completions/trash.bash $(DESTDIR)$(COMPLETIONS_BASH)/trash
	install -Dm644 target/completions/_trash $(DESTDIR)$(COMPLETIONS_ZSH)/_trash
	install -Dm644 target/completions/trash.fish $(DESTDIR)$(COMPLETIONS_FISH)/trash.fish

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/trash
	rm -f $(DESTDIR)$(BINDIR)/trashd-exec
	rm -f $(DESTDIR)$(BINDIR)/trashd
	rm -rf $(DESTDIR)$(LIBDIR)
	rm -f $(DESTDIR)/etc/profile.d/trashd.sh
	rm -f $(DESTDIR)/etc/systemd/system/trashd.service
	rm -f $(DESTDIR)$(MANDIR)/trash.1
	rm -f $(DESTDIR)$(COMPLETIONS_BASH)/trash
	rm -f $(DESTDIR)$(COMPLETIONS_ZSH)/_trash
	rm -f $(DESTDIR)$(COMPLETIONS_FISH)/trash.fish
