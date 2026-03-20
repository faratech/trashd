PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/trashd
MANDIR ?= $(PREFIX)/share/man/man1
DESTDIR ?=

COMPLETIONS_BASH ?= $(PREFIX)/share/bash-completion/completions
COMPLETIONS_ZSH ?= $(PREFIX)/share/zsh/site-functions
COMPLETIONS_FISH ?= $(PREFIX)/share/fish/vendor_completions.d

.PHONY: all build install uninstall clean test

all: build

build:
	cargo build --release

test:
	cargo test --workspace

clean:
	cargo clean

install: build
	install -Dm755 target/release/trash $(DESTDIR)$(BINDIR)/trash
	install -Dm755 target/release/trashd-rm $(DESTDIR)$(LIBDIR)/bin/rm
	install -Dm755 target/release/trashd-exec $(DESTDIR)$(BINDIR)/trashd-exec
	install -Dm755 target/release/trashd-daemon $(DESTDIR)$(BINDIR)/trashd-daemon
	install -Dm755 target/release/libtrashd_preload.so $(DESTDIR)$(LIBDIR)/libtrashd_preload.so
	install -Dm644 config/trashd.toml $(DESTDIR)/etc/trashd/config.toml
	install -Dm644 install/profile.d/trashd.sh $(DESTDIR)/etc/profile.d/trashd.sh
	install -Dm644 install/systemd/trashd-daemon.service $(DESTDIR)/etc/systemd/system/trashd-daemon.service
	# Man page
	install -Dm644 target/man/trash.1 $(DESTDIR)$(MANDIR)/trash.1
	# Shell completions
	install -Dm644 target/completions/trash.bash $(DESTDIR)$(COMPLETIONS_BASH)/trash
	install -Dm644 target/completions/_trash $(DESTDIR)$(COMPLETIONS_ZSH)/_trash
	install -Dm644 target/completions/trash.fish $(DESTDIR)$(COMPLETIONS_FISH)/trash.fish

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/trash
	rm -f $(DESTDIR)$(BINDIR)/trashd-exec
	rm -f $(DESTDIR)$(BINDIR)/trashd-daemon
	rm -rf $(DESTDIR)$(LIBDIR)
	rm -f $(DESTDIR)/etc/profile.d/trashd.sh
	rm -f $(DESTDIR)/etc/systemd/system/trashd-daemon.service
	rm -f $(DESTDIR)$(MANDIR)/trash.1
	rm -f $(DESTDIR)$(COMPLETIONS_BASH)/trash
	rm -f $(DESTDIR)$(COMPLETIONS_ZSH)/_trash
	rm -f $(DESTDIR)$(COMPLETIONS_FISH)/trash.fish
