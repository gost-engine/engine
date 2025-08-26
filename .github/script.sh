#!/bin/bash -efux

PREFIX=$HOME/opt
PATH=$PREFIX/bin:$PATH

mkdir build
cd build
cmake -DTLS13_PATCHED_OPENSSL=$PATCH_OPENSSL -DOPENSSL_ROOT_DIR=$PREFIX -DOPENSSL_ENGINES_DIR=$PREFIX/engines ${ASAN-} ..
make
make test CTEST_OUTPUT_ON_FAILURE=1
if [ -z "${ASAN-}" ]; then
    make tcl_tests_engine
    make tcl_tests_provider
fi
