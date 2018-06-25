#!/bin/bash
set -eux

cmake -DOPENSSL_ROOT_DIR=${PREFIX} -DOPENSSL_LIBRARIES=${PREFIX}/lib
make

cp ./bin/gost.so ${PREFIX}/lib/engines-1.1

export LD_LIBRARY_PATH=${PREFIX}/lib

${PREFIX}/bin/openssl ciphers |grep GOST
