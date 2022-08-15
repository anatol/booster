curr=$(pwd)

if [[ $curr != */booster/* ]]; then
  echo "This  must be run from within the 'booster' repository"
  exit 0
fi

projectDir=${curr%booster*}booster
version=$(cat $projectDir/packaging/centos/version)

cd $projectDir
rm -rf vendor
go mod vendor

zip -r booster-vendor-$version.zip vendor
mv booster-vendor-$version.zip ~/rpmbuild/SOURCES/

rm -rf vendor

cd ../

cp -r booster booster-0.9

zip -r booster-0.9.zip booster-0.9 -x *.git/*
rm -rf booster-0.9

mv -f booster-0.9.zip ~/rpmbuild/SOURCES/booster-0.9.zip

rpmbuild -ba $projectDir/packaging/centos/booster.spec
