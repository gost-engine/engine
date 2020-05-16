/* SPDX-License-Identifier: Apache-2.0
 *
 * Part of gost-engine fuzzing
 *
 * Copyright (C) 2020 Vitaly Chikunov <vt@altlinux.org>
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

#define T(e) ({ \
    if (!(e)) {\
        ERR_print_errors_fp(stderr);\
        OpenSSLDie(__FILE__, __LINE__, #e);\
    } \
})

ENGINE *eng;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	/* Initialize engine. */
	OPENSSL_add_all_algorithms_conf();
	CRYPTO_free_ex_index(0, -1);
	ERR_load_crypto_strings();
	T(eng = ENGINE_by_id("gost"));
	T(ENGINE_init(eng));
	T(ENGINE_set_default(eng, ENGINE_METHOD_ALL));
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t size)
{
	const uint8_t *b = buf;

	EVP_PKEY *x = d2i_AutoPrivateKey(NULL, &b, size);

	if (x) {
		BIO *bio = BIO_new(BIO_s_null());
		EVP_PKEY_print_private(bio, x, 0, NULL);
		BIO_free(bio);
		EVP_PKEY_free(x);
	}

	return 0;
}
