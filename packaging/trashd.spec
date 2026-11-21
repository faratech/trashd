Name:           trashd
Version:        0.1.15
Release:        1%{?dist}
Summary:        A Linux recycle bin that works in scripts, cron, and at the desktop
License:        MIT
URL:            https://github.com/faratech/trashd
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

# The workspace's rust-version; %{_unitdir} and the %systemd_* scriptlets
# come from systemd-rpm-macros (#213).
BuildRequires:  rust >= 1.99.1
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros

%description
trashd intercepts destructive delete commands (rm, unlink, rmdir) and moves
files to a FreeDesktop.org-compliant trash directory instead of permanently
deleting them. Works transparently in shell scripts, cron jobs, and at the
desktop via PATH shims, LD_PRELOAD hooks, seccomp supervision, and fanotify
monitoring.

%prep
%autosetup

%build
cargo build --release

%install
# %make_install alone does not pass PREFIX, so the Makefile's /usr/local
# default would stage everything under /usr/local while %files claims
# %{_prefix} (/usr) — failing the build.
%make_install PREFIX=%{_prefix}

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/trash
%{_bindir}/trashd-exec
%{_bindir}/trashd
%dir %{_prefix}/lib/trashd
%dir %{_prefix}/lib/trashd/bin
%{_prefix}/lib/trashd/bin/rm
%{_prefix}/lib/trashd/trashd
%{_prefix}/lib/trashd/libtrashd_preload.so
%config(noreplace) %{_sysconfdir}/trashd/config.toml
%{_sysconfdir}/profile.d/trashd.sh
%{_unitdir}/trashd.service
%{_userunitdir}/trashd-cleanup.service
%{_userunitdir}/trashd-cleanup.timer
%{_mandir}/man1/trash.1*
%{_mandir}/man1/trash-compress.1*
%{_mandir}/man1/trash-config.1*
%{_mandir}/man1/trash-du.1*
%{_mandir}/man1/trash-empty.1*
%{_mandir}/man1/trash-find.1*
%{_mandir}/man1/trash-fsck.1*
%{_mandir}/man1/trash-info.1*
%{_mandir}/man1/trash-log.1*
%{_mandir}/man1/trash-ls.1*
%{_mandir}/man1/trash-purge.1*
%{_mandir}/man1/trash-restore.1*
%{_mandir}/man1/trash-self-update.1*
%{_mandir}/man1/trash-status.1*
%{_mandir}/man1/trash-undo.1*
%{_datadir}/bash-completion/completions/trash
%{_datadir}/zsh/site-functions/_trash
%{_datadir}/fish/vendor_completions.d/trash.fish

# Layer 2 registration is owned by the package scriptlets: the Makefile
# deliberately skips /etc/ld.so.preload when DESTDIR is set (#408). Mirror
# install.sh exactly — a whole-token match on the flat entry (a single-arch
# RPM build has no i686 library and thus no $LIB form), and on removal drop
# only our entry, keeping other libraries that share a line (#229, #261).
# The list is left mode 0644: ld.so silently skips one other users cannot
# read (install-2). Deregistration runs in %preun on erase ($1 == 0), before
# the payload is removed: in %postun the library was already gone, so every
# process started meanwhile printed an ld.so error (install-6, #166).
# NOTE: lines inside these scriptlets must not start with '#' — rpm strips
# them as spec comments before the scriptlet runs.
%post
%systemd_post trashd.service
trashd_entry=%{_prefix}/lib/trashd/libtrashd_preload.so
if [ -f "%{_prefix}/lib/trashd/libtrashd_preload.so" ] \
    && ! awk -v lib="$trashd_entry" '{ line = $0; if ((h = index(line, "#")) > 0) line = substr(line, 1, h - 1); n = split(line, e, /[ \t:]+/); for (i = 1; i <= n; i++) if (e[i] == lib) found = 1 } END { exit !found }' /etc/ld.so.preload 2>/dev/null; then
    if [ -s /etc/ld.so.preload ] && [ "$(tail -c1 /etc/ld.so.preload | wc -l)" -eq 0 ]; then
        printf '\n' >> /etc/ld.so.preload || :
    fi
    printf '%s\n' "$trashd_entry" >> /etc/ld.so.preload || :
    chmod 0644 /etc/ld.so.preload || :
fi

%preun
%systemd_preun trashd.service
if [ "$1" -eq 0 ] && [ -f /etc/ld.so.preload ] \
    && grep -qsF %{_prefix}/lib/trashd/ /etc/ld.so.preload; then
    awk -v lib=%{_prefix}/lib/trashd/libtrashd_preload.so '{ line = $0; comment = ""; if ((h = index(line, "#")) > 0) { comment = substr(line, h); line = substr(line, 1, h - 1) } if (index(line, lib) == 0) { print $0; next } n = split(line, entry, /[ \t:]+/); out = ""; for (i = 1; i <= n; i++) if (entry[i] != "" && entry[i] != lib) out = out (out == "" ? "" : " ") entry[i]; if (comment != "") out = out (out == "" ? "" : " ") comment; if (out != "") print out }' \
        /etc/ld.so.preload > /etc/ld.so.preload.trashd-rpmnew \
        && chmod 0644 /etc/ld.so.preload.trashd-rpmnew \
        && mv -f /etc/ld.so.preload.trashd-rpmnew /etc/ld.so.preload \
        || { rm -f /etc/ld.so.preload.trashd-rpmnew; echo "warning: could not remove %{_prefix}/lib/trashd/libtrashd_preload.so from /etc/ld.so.preload" >&2; }
    [ -s /etc/ld.so.preload ] || rm -f /etc/ld.so.preload
fi

%postun
%systemd_postun_with_restart trashd.service

%changelog
* Thu Mar 20 2026 Faratech <dev@faratech.com> - 0.1.0-1
- Initial release
