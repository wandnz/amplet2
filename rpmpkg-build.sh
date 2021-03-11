#!/bin/bash

set -x -e -o pipefail

# libtool apparently doesn't set rpaths for standard directories since version
# 1.5.2 (released in 2004), why are they still being included? It seems to do
# the right thing on Debian but still has the old behaviour on CentOS.
export QA_RPATHS=$[ 0x0001 ]

VERSION=`grep -m 1 Version rpm/amplet2.spec | awk '{print $2}'`

# create a tarball to build the RPM from
./bootstrap.sh
./configure
make dist

# copy it into position
cp amplet2-*.tar.gz ~/rpmbuild/SOURCES/${VERSION}.tar.gz
cp rpm/*.patch ~/rpmbuild/SOURCES/ || true
cp rpm/amplet2.spec ~/rpmbuild/SPECS/

# build the RPM
cd ~/rpmbuild/
rpmbuild -bb --define "debug_package %{nil}" SPECS/amplet2.spec
