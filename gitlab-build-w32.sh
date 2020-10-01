#!/bin/bash

apt-get update
apt-get -y upgrade
apt-get install -y apt-transport-https automake autotools-dev ca-certificates flex libtool make mingw-w64 protobuf-compiler protobuf-c-compiler python wget wixl xz-utils zstd

VERSION=`grep -m 1 ProductVersion w32/amplet2-client.wxs | awk -F \" '{print $2}'`
REPO="https://repo.msys2.org/mingw/x86_64/"
DEPS="
    mingw-w64-x86_64-protobuf-c-1.3.3-1-any.pkg.tar.xz
    mingw-w64-x86_64-rabbitmq-c-0.10.0-1-any.pkg.tar.xz
    mingw-w64-x86_64-libyaml-0.2.5-1-any.pkg.tar.zst
    mingw-w64-x86_64-curl-7.71.0-1-any.pkg.tar.zst
    mingw-w64-x86_64-unbound-1.10.0-1-any.pkg.tar.xz
    mingw-w64-x86_64-openssl-1.1.1.g-1-any.pkg.tar.xz
    mingw-w64-x86_64-confuse-3.2.2-1-any.pkg.tar.xz
    mingw-w64-x86_64-libevent-2.1.11-2-any.pkg.tar.xz
    mingw-w64-x86_64-gettext-0.19.8.1-9-any.pkg.tar.zst
    mingw-w64-x86_64-libiconv-1.16-1-any.pkg.tar.xz
    mingw-w64-x86_64-zlib-1.2.11-7-any.pkg.tar.xz
    mingw-w64-x86_64-brotli-1.0.7-4-any.pkg.tar.xz
    mingw-w64-x86_64-libidn2-2.3.0-1-any.pkg.tar.xz
    mingw-w64-x86_64-libunistring-0.9.10-2-any.pkg.tar.zst
    mingw-w64-x86_64-nghttp2-1.41.0-1-any.pkg.tar.zst
    mingw-w64-x86_64-libpsl-0.21.0-2-any.pkg.tar.xz
    mingw-w64-x86_64-libssh2-1.9.0-2-any.pkg.tar.zst
    "

for i in $DEPS; do
    wget ${REPO}${i}
    tar xvf ${i}
done

if [ -x bootstrap.sh ]; then
    ./bootstrap.sh;
fi

./configure --host x86_64-w64-mingw32 --disable-tcpping --disable-udpstream --disable-throughput --disable-external --disable-fastping --disable-traceroute --disable-syslog CFLAGS=-I`pwd`/mingw64/include/ LDFLAGS=-L`pwd`/mingw64/lib/ --prefix=`pwd`/install
make
make install

# https://wiki.gnome.org/msitools/HowTo/CreateLibraryWxi
#find install/bin/ | grep exe | wixl-heat -p install/ > test-binaries.wxi
#find install/bin/ | grep dll | wixl-heat -p install/ > libamp-dll.wxi
#find install/lib/amplet2/tests/ | grep dll | wixl-heat -p install/ > test-dlls.wxi

mkdir -p built-packages/w32/ || true &&
wixl -v -o built-packages/w32/amplet2-client_${VERSION}.msi w32/amplet2-client.wxs
