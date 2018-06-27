#!/bin/bash
set -eux

git clone -b ${OPENSSL_BRANCH} https://github.com/openssl/openssl.git

cd openssl
./config shared --prefix=${PREFIX} --openssldir=${PREFIX}
make all install_sw
