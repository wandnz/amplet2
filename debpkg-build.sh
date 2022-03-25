#!/bin/bash

set -x -e -o pipefail

export CODENAME=`lsb_release -c -s`
export ARCH=`dpkg-architecture -qDEB_HOST_ARCH`

# check if chromium/youtube packages should be built, based on minimum
# versions of libwebsockets and libjannson
{
    lws=`apt-cache show --no-all-versions libwebsockets-dev | grep Version | awk '{print $2}'` &&
    jsn=`apt-cache show --no-all-versions libjansson-dev | grep Version | awk '{print $2}'` &&
    if dpkg --compare-versions "$lws" gt "2.0.0" &&
            dpkg --compare-versions "$jsn" ge "2.10"; then
        export YOUTUBE="pkg.amplet2.build-youtube"
    fi || true;
}

# check if sip packages should be built
{
    apt-cache show libpjproject-dev > /dev/null 2>&1 &&
    export SIP="pkg.amplet2.build-sip" || true;
}

export DEB_BUILD_PROFILES="$CODENAME $YOUTUBE $SIP"

mk-build-deps -i -r -t 'apt-get -f -y --force-yes'
dpkg-buildpackage -b -us -uc -rfakeroot -jauto
