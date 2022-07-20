Name:           booster
Version:        0.9
Release:        %{?dist}
Summary:        Fast and secure initramfs generator
License:        MIT
URL:            https://github.com/anatol/booster
BuildRequires:  git
BuildRequires:  go
BuildRequires:  yum-plugin-post-transaction-actions
BuildRequires:  yum-plugin-pre-transaction-actions
# BuildRequires:  ruby-ronn-ng
Requires:       bash
#Source0:       git+https://github.com/anatol/booster
Source0:        %{name}-%{version}.zip 


%description
RPM build for booster package


%prep
%setup

%build

# TEST_DISABLE_KVM=1 
# create directory to host action and script files
sudo mkdir /usr/share/yum-plugins/post-actions || : # try and make directory or do nothing
sudo mkdir /usr/share/yum-plugins/post-actions/scripts/ || : # try and make directory or do nothing
sudo mkdir /usr/share/yum-plugins/pre-actions || : # try and make directory or do nothing
sudo mkdir /usr/share/yum-plugins/pre-actions/scripts/ || : # try and make directory or do nothing

go env -w GO111MODULE=on;
cd generator
CGO_CPPFLAGS="${CPPFLAGS}" CGO_CFLAGS="${CFLAGS}" CGO_CXXFLAGS="${CXXFLAGS}" CGO_LDFLAGS="${LDFLAGS}" \
    go build -trimpath \
      -buildmode=pie \
      -mod=readonly \
      -modcacherw \
      -ldflags "-linkmode external -extldflags \"${LDFLAGS}\""

cd ../init
CGO_ENABLED=0 go build -trimpath -mod=readonly -modcacherw
#ronn docs/manpage.md

%undefine _missing_build_ids_terminate_build # don't fail on missing build ids 

%install
ls;
mkdir "%{buildroot}/etc/";
touch "%{buildroot}/etc/booster.yaml";
install -Dp -m755 generator/generator "%{buildroot}/usr/bin/booster";
install -Dp -m755 init/init "%{buildroot}/usr/lib/booster/init";

mkdir "%{buildroot}/usr/share/yum-plugins/post-actions/scripts/" || :  # create scripts directory in post actions
install -Dp -m755 packaging/centos/booster-install "%{buildroot}/usr/share/yum-plugins/post-actions/scripts/booster-install";
install -Dp -m755 packaging/centos/booster-install-post.action "%{buildroot}/usr/share/yum-plugins/post-actions/scripts/booster-install-post.action";


mkdir "%{buildroot}/usr/share/dnf-plugins/post-actions/scripts/" || :  # create scripts directory in post actions
install -Dp -m755 packaging/centos/booster-install "%{buildroot}/usr/share/dnf-plugins/post-actions/scripts/booster-install";
install -Dp -m755 packaging/centos/booster-install-post.action "%{buildroot}/usr/share/dnf-plugins/post-actions/scripts/booster-install-post.action";


%files
/etc/booster.yaml
/usr/bin/booster
/usr/lib/booster/init
/usr/share/yum-plugins/post-actions/scripts/booster-install
/usr/share/yum-plugins/post-actions/scripts/booster-install-post.action
/usr/share/dnf-plugins/post-actions/scripts/booster-install
/usr/share/dnf-plugins/post-actions/scripts/booster-install-post.action


%changelog
* Sun Jun 12 2022  <> - 0.3.r2.g1350d7a
- Initial version
- Notes:
-   change zip file:
