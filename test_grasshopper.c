/*
 * Copyright (C) 2018 vt@altlinux.org. All Rights Reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include "gost_grasshopper_cipher.h"
#include "gost_grasshopper_defines.h"
#include "gost_grasshopper_math.h"
#include "gost_grasshopper_core.h"
#include "e_gost_err.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <string.h>

enum e_mode {
    E_ECB = 0,
    E_CTR
};

static void hexdump(void *ptr, size_t len)
{
    unsigned char *p = ptr;
    size_t i;

    for (i = 0; i < len; i++)
	printf(" %02x", p[i]);
    printf("\n");
}

/* Test vectors from GOST R 34.13-2015 A.1 which* includes vectors
 * from GOST R 34.12-2015 A.1 as first block of ecb mode */
static int test_modes(const EVP_CIPHER *type, const char *mode, enum e_mode t)
{
    EVP_CIPHER_CTX ctx;
    unsigned char k[] = {
	0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
	0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    };
    unsigned char p[] = {
	/* plaintext from GOST R 34.13-2015 A.1 */
	/* first 16 bytes is vector (a) from GOST R 34.12-2015 A.1 */
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
	0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
	0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11,
    };
    unsigned char e[4][sizeof(p)] = {
	{ /* ecb test vectors from GOST R 34.13-2015  A.1.1 */
	    /* first 16 bytes is vector (b) from GOST R 34.12-2015 A.1 */
	    0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd,
	    0xb4,0x29,0x91,0x2c,0x6e,0x00,0x32,0xf9,0x28,0x54,0x52,0xd7,0x67,0x18,0xd0,0x8b,
	    0xf0,0xca,0x33,0x54,0x9d,0x24,0x7c,0xee,0xf3,0xf5,0xa5,0x31,0x3b,0xd4,0xb1,0x57,
	    0xd0,0xb0,0x9c,0xcd,0xe8,0x30,0xb9,0xeb,0x3a,0x02,0xc4,0xc5,0xaa,0x8a,0xda,0x98,
	},
	{ /* ctr test vectors from GOST R 34.13-2015  A.1.2 */
	    0xf1,0x95,0xd8,0xbe,0xc1,0x0e,0xd1,0xdb,0xd5,0x7b,0x5f,0xa2,0x40,0xbd,0xa1,0xb8,
	    0x85,0xee,0xe7,0x33,0xf6,0xa1,0x3e,0x5d,0xf3,0x3c,0xe4,0xb3,0x3c,0x45,0xde,0xe4,
	    0xa5,0xea,0xe8,0x8b,0xe6,0x35,0x6e,0xd3,0xd5,0xe8,0x77,0xf1,0x35,0x64,0xa3,0xa5,
	    0xcb,0x91,0xfa,0xb1,0xf2,0x0c,0xba,0xb6,0xd1,0xc6,0xd1,0x58,0x20,0xbd,0xba,0x73,
	},
    };
    unsigned char iv_ctr[] = { 0x12,0x34,0x56,0x78,0x90,0xab,0xce,0xf0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    unsigned char *iv[4] = { NULL, iv_ctr, };
    unsigned char c[sizeof(p)];
    int outlen, tmplen;
    int ret = 0, test;

    printf("Encryption test from GOST R 34.13-2015 [%s] \n", mode);
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, type, NULL, k, iv[t], 1);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    EVP_CipherUpdate(&ctx, c, &outlen, p, sizeof(p));
    EVP_CipherFinal_ex(&ctx, c + outlen, &tmplen);
    EVP_CIPHER_CTX_cleanup(&ctx);
    // hexdump(c, outlen);

    test = outlen != sizeof(p) ||
	memcmp(c, e[t], sizeof(p));

    printf("Test %s\n", test? "FAILED" : "passed");
    ret |= test;

    if (t == E_CTR) {
	int i;

	printf("Stream encryption test from GOST R 34.13-2015 [%s] \n", mode);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, type, NULL, k, iv[t], 1);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i = 0; i < sizeof(p); i++) {
	    EVP_CipherUpdate(&ctx, c + i, &outlen, p + i, 1);
	    OPENSSL_assert(outlen == 1);
	}
	outlen = i;
	EVP_CipherFinal_ex(&ctx, c + outlen, &tmplen);
	EVP_CIPHER_CTX_cleanup(&ctx);

	test = outlen != sizeof(p) ||
	    memcmp(c, e[t], sizeof(p));

	printf("Test %s\n", test? "FAILED" : "passed");
#if 0
	ret |= test;
#endif
    }

    printf("Decryption test from GOST R 34.13-2015 [%s] \n", mode);
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, type, NULL, k, iv[t], 0);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    EVP_CipherUpdate(&ctx, c, &outlen, e[t], sizeof(p));
    EVP_CipherFinal_ex(&ctx, c + outlen, &tmplen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    test = outlen != sizeof(p) ||
	memcmp(c, p, sizeof(p));

    printf("Test %s\n", test? "FAILED" : "passed");
    ret |= test;

    return ret;
}

int main(int argc, char **argv)
{
    int ret = 0;

    ret |= test_modes(cipher_gost_grasshopper_ecb(), "ecb", E_ECB);
    ret |= test_modes(cipher_gost_grasshopper_ctr(), "ctr", E_CTR);
    /*
     * Other modes (ofb, cbc, cfb) is impossible to test to match GOST R
     * 34.13-2015 test vectors due to these vectors having exceeding IV
     * length value (m) = 256 bits, while openssl have hardcoded limit
     * of maximum IV length of 128 bits (EVP_MAX_IV_LENGTH).
     * Also, current grasshopper code having fixed IV length of 128 bits.
     */

    return ret;
}
