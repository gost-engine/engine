#!/bin/bash -efux

# Download cpanm and make it executable as a standalone script
curl -L https://cpanmin.us -o cpanm
chmod 0755 cpanm

sudo ./cpanm --notest Test2::V0 > build.log 2>&1 \
    || (cat build.log && exit 1)

if [ "${APT_INSTALL-}" ]; then
    sudo apt-get install -y $APT_INSTALL
fi

git clone --depth 1 -b $OPENSSL_BRANCH https://github.com/openssl/openssl.git
if [ "${PATCH_OPENSSL}" == "1" ]; then
    git apply patches/openssl-tls1.3.patch
    git apply patches/openssl-asn1_item_verify_ctx.patch
    git apply patches/openssl-x509_sig_info_init.patch
    git apply patches/openssl-aes_cfb128_vaes_x64.patch
fi

# pkcs12 RFC 9337/9548 libcrypto fallbacks (see patches/pkcs12/README.md).
# 3.6 needs the tls1.3 patch above as a prerequisite, so it stays gated
# on PATCH_OPENSSL=1. 4.0 has no prereqs and is applied unconditionally
# (the engine API is gone from apps/pkcs12.c on 4.0, so provider-mode
# pkcs12 export hard-requires these fallbacks).
case "$OPENSSL_BRANCH" in
    openssl-3.6.0)
        if [ "${PATCH_OPENSSL}" == "1" ]; then
            git apply patches/pkcs12/openssl-pkcs12-provider-pbe-3.6.patch
        fi
        ;;
    openssl-4.0.0)
        git apply patches/pkcs12/openssl-pkcs12-provider-pbe-4.0.patch
        ;;
esac
cd openssl
git describe --always --long

PREFIX=$HOME/opt

${SETARCH-} ./config shared -d --prefix=$PREFIX --libdir=lib --openssldir=$PREFIX ${USE_RPATH:+-Wl,-rpath=$PREFIX/lib}
${SETARCH-} make -s -j$(nproc) build_libs
${SETARCH-} make -s -j$(nproc) build_programs
make -s install_sw
