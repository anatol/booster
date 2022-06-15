

cd /home/snvercil

# print(os.getcwd())

cp -r booster booster-0.9

zip -r booster-0.9.zip booster-0.9
rm -rf booster-0.9


mv -f /home/snvercil/booster-0.9.zip /home/snvercil/rpmbuild/SOURCES/booster-0.9.zip
cd /home/snvercil/booster/packaging/centos

rpmbuild -ba /home/snvercil/booster/packaging/centos/booster.spec


# yum remove -y  booster
# yum install -y /home/snvercil/rpmbuild/RPMS/x86_64/booster-0.9.el7.x86_64.rpm
