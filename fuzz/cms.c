/* SPDX-License-Identifier: Apache-2.0
 *
 * Part of gost-engine fuzzing
 *
 * Copyright (C) 2020 Vitaly Chikunov <vt@altlinux.org>
 *
 * Based on openssl/fuzz/cms.c
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <openssl/engine.h>
#include <openssl/cms.h>
#include <openssl/err.h>

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

	CMS_ContentInfo *cms;
	BIO *mem;

	if (size == 0)
		return 0;
	mem = BIO_new(BIO_s_mem());
	T(BIO_write(mem, buf, size) == size);
	cms = d2i_CMS_bio(mem, NULL);
	if (cms) {
		BIO *out = BIO_new(BIO_s_null());
		i2d_CMS_bio(out, cms);
		BIO_free(out);
		CMS_ContentInfo_free(cms);
	}
	BIO_free(mem);
	ERR_clear_error();
	return 0;
}
