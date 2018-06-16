#!/bin/bash
set -eux

git clone -b ${OPENSSL_BRANCH} https://github.com/openssl/openssl.git

cd openssl
./config shared --prefix=${PREFIX} --openssldir=${PREFIX}
make all install_sw

cat <<EOF >> ${PREFIX}/openssl.cnf
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
gost = gost_section

[gost_section]
default_algorithms = ALL
engine_id = gost
CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet
EOF
