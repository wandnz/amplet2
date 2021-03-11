#!/bin/bash

set -x -e -o pipefail

apt-get update
apt-get -y upgrade
apt-get install -y apt-transport-https automake autotools-dev ca-certificates flex libtool make mingw-w64 protobuf-compiler protobuf-c-compiler wget wixl xz-utils zstd

# files originally from https://repo.msys2.org/mingw/x86_64/ but they only
# keep the newest version which breaks our builds, so we mirror them
REPO="https://wand.net.nz/~brendonj/amp/mingw/"
DEPS="
    mingw-w64-x86_64-protobuf-c-1.3.3-1-any.pkg.tar.xz
    mingw-w64-x86_64-rabbitmq-c-0.10.0-1-any.pkg.tar.xz
    mingw-w64-x86_64-libyaml-0.2.5-1-any.pkg.tar.zst
    mingw-w64-x86_64-curl-7.71.0-1-any.pkg.tar.zst
    mingw-w64-x86_64-unbound-1.10.0-1-any.pkg.tar.xz
    mingw-w64-x86_64-openssl-1.1.1.g-1-any.pkg.tar.xz
    mingw-w64-x86_64-confuse-3.3-1-any.pkg.tar.zst
    mingw-w64-x86_64-libevent-2.1.12-1-any.pkg.tar.zst
    mingw-w64-x86_64-gettext-0.19.8.1-9-any.pkg.tar.zst
    mingw-w64-x86_64-libiconv-1.16-2-any.pkg.tar.zst
    mingw-w64-x86_64-zlib-1.2.11-9-any.pkg.tar.zst
    mingw-w64-x86_64-brotli-1.0.9-2-any.pkg.tar.zst
    mingw-w64-x86_64-libidn2-2.3.0-1-any.pkg.tar.xz
    mingw-w64-x86_64-libunistring-0.9.10-2-any.pkg.tar.zst
    mingw-w64-x86_64-nghttp2-1.41.0-1-any.pkg.tar.zst
    mingw-w64-x86_64-libpsl-0.21.1-2-any.pkg.tar.zst
    mingw-w64-x86_64-libssh2-1.9.0-2-any.pkg.tar.zst
    "

for i in $DEPS; do
    wget ${REPO}${i}
    tar xvf ${i}
done
