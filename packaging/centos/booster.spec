Name: booster
Version: 0.9
Release: 1%{?dist}
Summary: Fast and secure initramfs generator
License: MIT
URL: https://github.com/anatol/booster
BuildRequires: git
BuildRequires: go
BuildRequires: unzip
BuildRequires: yum-plugin-post-transaction-actions
BuildRequires: yum-plugin-pre-transaction-actions
Requires: bash
Requires: golang 1.17 > =
Source0: %{name}-%{version}.zip
Source1: %{name}-%{version}-vendor.zip

%description
RPM build for booster package

%prep
%setup

%build

go version

# Install go from tar zip
%{__mkdir_p} $RPM_BUILD_ROOT/usr || :
%{__mkdir_p} $RPM_BUILD_ROOT/usr/local || :

# create vendor file
unzip -n %{SOURCE1}

# TEST_DISABLE_KVM=1
# create directory to host action and script files
%{__mkdir_p} $RPM_BUILD_ROOT/usr/share/yum-plugins/post-actions || :          # try and make directory or do nothing
%{__mkdir_p} $RPM_BUILD_ROOT/usr/share/yum-plugins/post-actions/scripts/ || : # try and make directory or do nothing
%{__mkdir_p} $RPM_BUILD_ROOT/usr/share/yum-plugins/pre-actions || :           # try and make directory or do nothing
%{__mkdir_p} $RPM_BUILD_ROOT/usr/share/yum-plugins/pre-actions/scripts/ || :  # try and make directory or do nothing

go env -w GO111MODULE=on
cd generator
CGO_CPPFLAGS="${CPPFLAGS}" CGO_CFLAGS="${CFLAGS}" CGO_CXXFLAGS="${CXXFLAGS}" CGO_LDFLAGS="${LDFLAGS}" \
  go build -trimpath \
  -buildmode=pie \
  -mod=vendor \
  -ldflags "-linkmode external -extldflags \"${LDFLAGS}\""

cd ../init

CGO_ENABLED=0 go build -trimpath -mod=vendor

%undefine _missing_build_ids_terminate_build # don't fail on missing build ids

%install

%{__mkdir_p} "$RPM_BUILD_ROOT/etc/"

touch $RPM_BUILD_ROOT/etc/booster.yaml

%{__install} -Dp -m755 generator/generator "%{buildroot}/usr/bin/booster"
%{__install} -Dp -m755 init/init "$RPM_BUILD_ROOT/usr/lib/booster/init"

%{__mkdir_p} "$RPM_BUILD_ROOT/usr/share/yum-plugins/post-actions/scripts/" || : # create scripts directory in post actions
%{__install} -Dp -m755 packaging/centos/booster-install "$RPM_BUILD_ROOT/usr/share/yum-plugins/post-actions/scripts/booster-install"
%{__install} -Dp -m755 packaging/centos/booster-remove "$RPM_BUILD_ROOT/usr/share/yum-plugins/post-actions/scripts/booster-remove"
%{__install} -Dp -m755 packaging/centos/booster-install-pre.action "$RPM_BUILD_ROOT/etc/yum/pre-actions/booster-pre.action"
%{__install} -Dp -m755 packaging/centos/booster-install-post.action "$RPM_BUILD_ROOT/etc/yum/post-actions/booster-post.action"

%files
/etc/booster.yaml
/usr/bin/booster
/usr/lib/booster/init
/usr/share/yum-plugins/post-actions/scripts/booster-install
/usr/share/yum-plugins/post-actions/scripts/booster-remove
/etc/yum/post-actions/booster-post.action
/etc/yum/pre-actions/booster-pre.action

%changelog
* Mon Aug 1 2022 Stefan Vercillo < stvercillo@twitter.com > version 0.9:
- Initial Booster packaging for Centos
