/* SPDX-License-Identifier: Apache-2.0
 *
 * Part of gost-engine fuzzing
 *
 * Copyright (C) 2020 Vitaly Chikunov <vt@altlinux.org>
 *
 * Based on honggfuzz/examples/openssl/x509.c
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
	X509 *x = d2i_X509(NULL, &b, size);

	if (x) {
		BIO *o = BIO_new_fp(stdout, BIO_NOCLOSE);
		X509_print_ex(o, x, XN_FLAG_RFC2253, X509_FLAG_COMPAT);

		unsigned char *der = NULL;
		i2d_X509(x, &der);
		OPENSSL_free(der);
		X509_free(x);
		BIO_free(o);
	} else {
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
	}

	return 0;
}
