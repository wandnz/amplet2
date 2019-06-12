#!/bin/bash

set -x -e -o pipefail

# libtool apparently doesn't set rpaths for standard directories since version
# 1.5.2 (released in 2004), why are they still being included? It seems to do
# the right thing on Debian but still has the old behaviour on CentOS.
export QA_RPATHS=$[ 0x0001 ]

. /etc/os-release
CODENAME=${ID}_${VERSION_ID}
TAGNAME=`echo ${CI_COMMIT_REF_NAME} | cut -d '-' -f 1`

# add the repository that has our dependencies
cat << EOF > /etc/yum.repos.d/bintray-wand-amp-rpm.repo
#bintray-wand-amp-rpm - packages by wand from Bintray
[bintray-wand-amp-rpm]
name=bintray-wand-amp-rpm
baseurl=https://dl.bintray.com/wand/amp-rpm/${ID}/\$releasever/\$basearch/
gpgkey=https://bintray.com/user/downloadSubjectPublicKey?username=wand
gpgcheck=0
repo_gpgcheck=1
enabled=1
EOF

# set up an RPM build environment
yum install -y rpm-build rpmdevtools make gcc epel-release
rpmdev-setuptree
yum-builddep -y rpm/${CI_PROJECT_NAME}.spec

# create a tarball to build the RPM from
./bootstrap.sh
./configure
make dist

# copy it into position
cp ${CI_PROJECT_NAME}-*.tar.gz ~/rpmbuild/SOURCES/${TAGNAME}.tar.gz
cp rpm/*.patch ~/rpmbuild/SOURCES/ || true
cp rpm/${CI_PROJECT_NAME}.spec ~/rpmbuild/SPECS/

# build the RPM
cd ~/rpmbuild/
rpmbuild -bb --define "debug_package %{nil}" SPECS/${CI_PROJECT_NAME}.spec

# move the built RPM into position
mkdir -p ${CI_PROJECT_DIR}/built-packages/${CODENAME}/ || true
mv ~/rpmbuild/RPMS/*/*.rpm ${CI_PROJECT_DIR}/built-packages/${CODENAME}/
