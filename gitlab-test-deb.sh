#!/bin/bash

set -x -e -o pipefail

# TODO check an upgrade from the previous version as well as a fresh install
# TODO is the null virt-server the most appropriate one to use here?

# autopkgtest will run tests based on entries in debian/tests/control
apt-get install -y autopkgtest
autopkgtest built-packages/$CODENAME/amplet2-client_*deb -- null
