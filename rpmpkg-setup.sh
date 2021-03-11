#!/bin/bash

set -x -e -o pipefail

yum update -y

# set up an RPM build environment
yum install -y rpm-build rpmdevtools make gcc epel-release
rpmdev-setuptree
yum-builddep -y rpm/amplet2.spec
