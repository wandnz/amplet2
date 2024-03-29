#!/bin/bash

set -x -e -o pipefail

# TODO check an upgrade from the previous version as well as a fresh install
# TODO is the null virt-server the most appropriate one to use here?

export CODENAME=`lsb_release -c -s`
ARCH=`dpkg --print-architecture`

case "$CODENAME" in
    xenial)
        apt-get -t xenial-backports install -y autopkgtest
        ;;

    *)
        apt-get install -y autopkgtest
        ;;
esac

# autopkgtest will run tests based on entries in debian/tests/control
autopkgtest packages/${DIRNAME}/amplet2-client_*${ARCH}.deb -- null
