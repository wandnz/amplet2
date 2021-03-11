#!/bin/bash

set -x -e -o pipefail

VERSION=`grep -m 1 ProductVersion w32/amplet2-client.wxs | awk -F \" '{print $2}'`

if [ -x bootstrap.sh ]; then
    ./bootstrap.sh;
fi

./configure --host x86_64-w64-mingw32 --disable-python --disable-tcpping --disable-udpstream --disable-throughput --disable-external --disable-fastping --disable-traceroute --disable-syslog CFLAGS=-I`pwd`/mingw64/include/ LDFLAGS=-L`pwd`/mingw64/lib/ --prefix=`pwd`/install
make
make install

wixl -v -o amplet2-client_${VERSION}.msi w32/amplet2-client.wxs
