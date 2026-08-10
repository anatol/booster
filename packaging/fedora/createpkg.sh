#!/bin/bash
# Build the booster RPM from a source checkout.
#
# Produces the two archives booster.spec expects — the sources and the vendored
# Go dependencies — then runs rpmbuild. Vendoring here keeps the rpmbuild step
# offline, which is what Fedora's build system requires.
set -euo pipefail

specdir=$(cd "$(dirname "$0")" && pwd)
srcdir=$(cd "$specdir/../.." && pwd)
topdir=$(rpm --eval '%{_topdir}')

# Both archive names derive from the spec's own Version, so they cannot drift
# apart from what %prep looks for.
version=$(sed -n 's/^Version:[[:space:]]*//p' "$specdir/booster.spec")
if [[ -z $version ]]; then
    echo "could not read Version from $specdir/booster.spec" >&2
    exit 1
fi

mkdir -p "$topdir"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git -C "$srcdir" archive --format=tar --prefix="booster-$version/" HEAD |
    gzip >"$topdir/SOURCES/booster-$version.tar.gz"

git -C "$srcdir" archive --format=tar --prefix=src/ HEAD | tar -x -C "$work"
(cd "$work/src" && go mod vendor)
tar -czf "$topdir/SOURCES/booster-$version-vendor.tar.gz" -C "$work/src" vendor

rpmbuild -ba "$specdir/booster.spec"
