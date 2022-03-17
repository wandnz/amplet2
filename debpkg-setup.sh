#!/bin/bash

set -x -e -o pipefail

echo 'APT::Install-Recommends "0";' > /etc/apt/apt.conf.d/10no-recommends
echo 'APT::Install-Suggests "0";' > /etc/apt/apt.conf.d/10no-suggests

apt-get update
apt-get -y upgrade
apt-get install -y ca-certificates devscripts dpkg-dev equivs lsb-release \
                   wget gnupg apt-transport-https

export CODENAME=`lsb_release -c -s`

# add AMP repositories if backported dependencies are needed
if [ "$CODENAME" = "bionic" ]; then
    # bionic has debhelper 11.1 which breaks using rename to move debug
    # packages across filesystems
    apt-get install -y dwz/bionic-backports debhelper/bionic-backports
fi
