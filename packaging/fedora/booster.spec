%global _hardened_build 1

# The FIDO2 plugin is a Go plugin (.so) loaded by booster's init, not a system
# shared library: keep it out of the automatic Provides/Requires scan.
%global __provides_exclude_from ^%{_prefix}/lib/booster/.*\\.so$
%global __requires_exclude_from ^%{_prefix}/lib/booster/.*\\.so$

Name:           booster
Version:        0.13
Release:        1%{?dist}
Summary:        Fast and secure initramfs generator

License:        MIT
URL:            https://github.com/anatol/booster
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.gz

BuildRequires:  golang >= 1.26
BuildRequires:  gcc
BuildRequires:  git-core
BuildRequires:  libfido2-devel
BuildRequires:  rubygem-ronn-ng
BuildRequires:  systemd-rpm-macros

Requires:       bash
# The kernel-install plugin drives image generation on kernel updates.
Requires:       systemd >= 254

Recommends:     busybox
Recommends:     systemd-ukify
Suggests:       binutils
Suggests:       yubikey-personalization

%description
Booster is a fast and secure initramfs generator. It builds early boot images
that unlock encrypted volumes and mount the root filesystem, with support for
LUKS, LVM, mdraid, ZFS, TPM2, FIDO2 and network-bound disk encryption.

Booster integrates with systemd's kernel-install: set initrd_generator=booster
in /etc/kernel/install.conf and images are regenerated on kernel updates.

%prep
%autosetup -n %{name}-%{version}
# Dependencies are vendored so the build needs no network access.
tar -xzf %{SOURCE1}

%build
export GOFLAGS="-mod=vendor -trimpath"

pushd generator
CGO_CPPFLAGS="%{optflags}" CGO_LDFLAGS="%{build_ldflags}" \
    go build -buildmode=pie \
        -ldflags "-linkmode external -extldflags \"%{build_ldflags}\""
popd

# init loads plugins through Go's plugin package, which requires cgo.
pushd init
CGO_ENABLED=1 go build
for plugin_dir in fido2plugin clevisplugin; do
    if [ -d "$plugin_dir" ]; then
        pushd "$plugin_dir"
        CGO_ENABLED=1 CGO_CPPFLAGS="%{optflags}" CGO_LDFLAGS="%{build_ldflags}" \
            go build -buildmode=plugin -o "../${plugin_dir}.so" .
        popd
    fi
done
popd

ronn docs/manpage.md

%install
install -Dpm 0755 generator/generator %{buildroot}%{_bindir}/%{name}
install -Dpm 0755 init/init %{buildroot}%{_prefix}/lib/%{name}/init
for p in init/*.so; do
    [ -f "$p" ] && install -Dpm 0755 "$p" "%{buildroot}%{_prefix}/lib/%{name}/$(basename "$p")"
done

# The kernel-install plugin. Named 60- so it runs after 50-depmod.install and
# before 60-ukify.install, which collects the initrd from the staging area.
install -Dpm 0755 packaging/common/60-%{name}.install \
    %{buildroot}%{_prefix}/lib/kernel/install.d/60-%{name}.install

install -Dpm 0644 docs/manpage.1 %{buildroot}%{_mandir}/man1/%{name}.1
install -Dpm 0644 contrib/completion/bash \
    %{buildroot}%{_datadir}/bash-completion/completions/%{name}

# Empty default config; booster applies its built-in defaults when unset.
install -Dpm 0644 /dev/null %{buildroot}%{_sysconfdir}/%{name}.yaml

%files
%license LICENSE
%doc README.md CHANGES.md
%{_bindir}/%{name}
%dir %{_prefix}/lib/%{name}
%{_prefix}/lib/%{name}/init
%{_prefix}/lib/%{name}/*.so
%{_prefix}/lib/kernel/install.d/60-%{name}.install
%{_mandir}/man1/%{name}.1*
%{_datadir}/bash-completion/completions/%{name}
%config(noreplace) %{_sysconfdir}/%{name}.yaml

%changelog
* Fri Aug 07 2026 pilotstew <pilotstew@gmail.com> - 0.13-1
- Initial Fedora packaging
