#!/bin/sh
# Phase 16d cross-mode parity check.
#
# Runs test_pkcs12_rfc9337 twice — once under engine.cnf, once under
# provider.cnf — capturing structural fingerprints to two temp files
# (per the RFC9337_FINGERPRINT_OUT side-channel). Identical files =>
# engine and provider produce structurally equivalent PFXes for every
# (cipher, macalg) case in the matrix.
#
# Args (positional, set by ctest registration in cmake/tests.cmake):
#   $1  path to the test_pkcs12_rfc9337 binary
#   $2  path to test/engine.cnf
#   $3  path to test/provider.cnf

set -eu

if [ $# -ne 3 ]; then
    echo "usage: $0 <test_binary> <engine.cnf> <provider.cnf>" >&2
    exit 2
fi

BIN=$1
ENGINE_CNF=$2
PROVIDER_CNF=$3
BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$BIN")" && pwd)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ENGINE_FP="$TMP/engine.fp"
PROVIDER_FP="$TMP/provider.fp"

OPENSSL_ENGINES="$BIN_DIR" \
OPENSSL_CONF="$ENGINE_CNF" \
RFC9337_FINGERPRINT_OUT="$ENGINE_FP" \
"$BIN" >/dev/null

env -u OPENSSL_ENGINES \
OPENSSL_MODULES="$BIN_DIR" \
OPENSSL_CONF="$PROVIDER_CNF" \
RFC9337_FINGERPRINT_OUT="$PROVIDER_FP" \
"$BIN" >/dev/null

if ! diff -u "$ENGINE_FP" "$PROVIDER_FP"; then
    echo "FAIL: engine and provider PFX fingerprints diverge" >&2
    exit 1
fi

# Sanity: non-empty outputs (4 cases × 14 lines + 4 blank = 60 lines).
ENGINE_LINES=$(wc -l < "$ENGINE_FP")
if [ "$ENGINE_LINES" -lt 50 ]; then
    echo "FAIL: engine fingerprint truncated ($ENGINE_LINES lines)" >&2
    exit 1
fi

echo "OK: engine + provider PFX fingerprints match across $ENGINE_LINES lines"
