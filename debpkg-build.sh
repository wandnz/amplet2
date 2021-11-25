#!/bin/bash

set -x -e -o pipefail

export CODENAME=`lsb_release -c -s`
export ARCH=`dpkg-architecture -qDEB_HOST_ARCH`

# check if chromium/youtube packages should be built
{
    wget -nv https://wand.net.nz/~brendonj/amp/youtube/chromium-libs_$CODENAME-$ARCH.tar.gz &&
    tar xzvf chromium-libs_$CODENAME-$ARCH.tar.gz &&
    echo "deb http://apt.llvm.org/${CODENAME}/ llvm-toolchain-${CODENAME}-12 main" > /etc/apt/sources.list.d/llvm-toolchain.list &&
    wget -O- https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - &&
    apt-get update &&
    export YOUTUBE="pkg.amplet2.build-youtube" || true;
}

# check if sip packages should be built
{
    apt-cache show libpjproject-dev > /dev/null 2>&1 &&
    export SIP="pkg.amplet2.build-sip" || true;
}

export DEB_BUILD_PROFILES="$CODENAME $YOUTUBE $SIP"

mk-build-deps -i -r -t 'apt-get -f -y --force-yes'
dpkg-buildpackage -b -us -uc -rfakeroot -jauto
