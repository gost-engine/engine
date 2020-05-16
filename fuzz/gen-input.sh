#!/bin/bash -efu
# SPDX-License-Identifier: Apache-2.0
#
# Generate different input coprpora for fuzzing
#
# Copyright (C) 2020 Vitaly Chikunov <vt@altlinux.org>

mkdir -p input/{cert,pkey,cms,pem}
cd input

log() {
  echo + "$*"
  eval "$@"
}

CA=test-ca.conf
if [ ! -e $CA ]; then
cat > $CA <<- EOF
	[ req ]
	distinguished_name = req_distinguished_name
	prompt = no
	string_mask = utf8only
	x509_extensions = v3_ca

	[ req_distinguished_name ]
	O = TEST-CA
	CN = TEST certificate signing key
	emailAddress = ca@test

	[ v3_ca ]
	basicConstraints=CA:TRUE
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid:always,issuer
EOF
fi

head -c 2000 /dev/urandom > test.dat

for m in \
  gost2001:0 \
  gost2001:A \
  gost2001:B \
  gost2001:C \
  gost2001:XA \
  gost2001:XB \
  gost2012_256:0 \
  gost2012_256:A \
  gost2012_256:B \
  gost2012_256:C \
  gost2012_256:XA \
  gost2012_256:XB \
  gost2012_256:TCA \
  gost2012_256:TCB \
  gost2012_256:TCC \
  gost2012_256:TCD \
  gost2012_512:A \
  gost2012_512:B \
  gost2012_512:C; do
    IFS=':' read -r algo param <<< "$m"
    log openssl req -nodes -x509 -utf8 -days 999 -batch \
      -config $CA \
      -newkey $algo \
      -pkeyopt paramset:$param \
      -out    pem/$algo-$param.crt \
      -keyout pem/$algo-$param.key
    # convert from PEM to DER
    log openssl x509 -in pem/$algo-$param.crt -out cert/$algo-$param.crt -outform DER
    log openssl pkey -in pem/$algo-$param.key -out pkey/$algo-$param.key -outform DER

    log openssl cms -sign -in test.dat -text -out cms/sign_$algo-$param.cmsg -outform DER -signer pem/$algo-$param.crt -inkey pem/$algo-$param.key
    log openssl cms -sign -in test.dat -text -out cms/sign_$algo-$param.msg -outform DER -signer pem/$algo-$param.crt -inkey pem/$algo-$param.key -nocerts
    log openssl cms -sign -binary -in test.dat -out cms/sign_$algo-$param.dsig -outform DER -signer pem/$algo-$param.crt -inkey pem/$algo-$param.key
done



