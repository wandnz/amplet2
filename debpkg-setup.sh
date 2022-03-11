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
if [ "$CODENAME" = "jessie" ]; then
    echo "deb https://dl.cloudsmith.io/public/wand/amp/deb/debian jessie main" > /etc/apt/sources.list.d/amplet2.list
    wget -O- https://dl.cloudsmith.io/public/wand/amp/gpg.81EB1488CDD7837D.key | apt-key add -
    apt-get update
    apt-get -y upgrade
elif [ "$CODENAME" = "bionic" ]; then
    # bionic has debhelper 11.1 which breaks using rename to move debug
    # packages across filesystems
    apt-get install -y dwz/bionic-backports debhelper/bionic-backports
fi
