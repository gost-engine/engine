#!/bin/bash -efux

curl -L https://cpanmin.us | sudo perl - --sudo App::cpanminus
sudo cpanm --notest Test2::V0 > build.log 2>&1 || (cat build.log && exit 1)

if [ "${APT_INSTALL-}" ]; then
    sudo apt-get install -y $APT_INSTALL
fi

git clone --depth 1 -b $OPENSSL_BRANCH https://github.com/openssl/openssl.git
cd openssl
patch -p0 < ../patches/openssl_111m.diff
patch -p0 < ../patches/openssl_111m_obj.diff
patch -p0 < ../patches/openssl_111m_tls13.diff
git describe --always --long

PREFIX=$HOME/opt

${SETARCH-} ./config shared -d --prefix=$PREFIX --openssldir=$PREFIX -Wl,-rpath=$PREFIX/lib
${SETARCH-} make -s -j$(nproc) build_libs
${SETARCH-} make -s -j$(nproc) build_programs
make -s install_sw
