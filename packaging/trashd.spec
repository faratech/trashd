Name:           trashd
Version:        0.1.0
Release:        1%{?dist}
Summary:        A Linux recycle bin that works in scripts, cron, and at the desktop
License:        MIT
URL:            https://github.com/faratech/trashd
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.75
BuildRequires:  cargo
BuildRequires:  gcc

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
%make_install PREFIX=%{_prefix}

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/trash
%{_bindir}/trashd-exec
%{_bindir}/trashd-daemon
%dir %{_prefix}/lib/trashd
%{_prefix}/lib/trashd/bin/rm
%{_prefix}/lib/trashd/libtrashd_preload.so
%config(noreplace) %{_sysconfdir}/trashd/config.toml
%{_sysconfdir}/profile.d/trashd.sh
%{_unitdir}/trashd-daemon.service
%{_mandir}/man1/trash.1*
%{_datadir}/bash-completion/completions/trash
%{_datadir}/zsh/site-functions/_trash
%{_datadir}/fish/vendor_completions.d/trash.fish

%post
%systemd_post trashd-daemon.service

%preun
%systemd_preun trashd-daemon.service

%postun
%systemd_postun_with_restart trashd-daemon.service

%changelog
* Thu Mar 20 2026 Faratech <dev@faratech.com> - 0.1.0-1
- Initial release
