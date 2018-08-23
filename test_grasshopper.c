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
#include "gost_lcl.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <string.h>

#define T(e) if (!(e)) {\
	ERR_print_errors_fp(stderr);\
	OpenSSLDie(__FILE__, __LINE__, #e);\
    }

#define cRED	"\033[1;31m"
#define cDRED	"\033[0;31m"
#define cGREEN	"\033[1;32m"
#define cDGREEN	"\033[0;32m"
#define cNORM	"\033[m"
#define TEST_ASSERT(e) {if ((test = (e))) \
		 printf(cRED "Test FAILED\n" cNORM); \
	     else \
		 printf(cGREEN "Test passed\n" cNORM);}

/* Test key from both GOST R 34.12-2015 and GOST R 34.13-2015. */
static const unsigned char K[] = {
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
};

/* Plaintext from GOST R 34.13-2015 A.1.
 * First 16 bytes is vector (a) from GOST R 34.12-2015 A.1. */
static const unsigned char P[] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11,
};
static const unsigned char E_ecb[] = {
    /* ECB test vectors from GOST R 34.13-2015  A.1.1 */
    /* first 16 bytes is vector (b) from GOST R 34.12-2015 A.1 */
    0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd,
    0xb4,0x29,0x91,0x2c,0x6e,0x00,0x32,0xf9,0x28,0x54,0x52,0xd7,0x67,0x18,0xd0,0x8b,
    0xf0,0xca,0x33,0x54,0x9d,0x24,0x7c,0xee,0xf3,0xf5,0xa5,0x31,0x3b,0xd4,0xb1,0x57,
    0xd0,0xb0,0x9c,0xcd,0xe8,0x30,0xb9,0xeb,0x3a,0x02,0xc4,0xc5,0xaa,0x8a,0xda,0x98,
};
static const unsigned char E_ctr[] = {
    /* CTR test vectors from GOST R 34.13-2015  A.1.2 */
    0xf1,0x95,0xd8,0xbe,0xc1,0x0e,0xd1,0xdb,0xd5,0x7b,0x5f,0xa2,0x40,0xbd,0xa1,0xb8,
    0x85,0xee,0xe7,0x33,0xf6,0xa1,0x3e,0x5d,0xf3,0x3c,0xe4,0xb3,0x3c,0x45,0xde,0xe4,
    0xa5,0xea,0xe8,0x8b,0xe6,0x35,0x6e,0xd3,0xd5,0xe8,0x77,0xf1,0x35,0x64,0xa3,0xa5,
    0xcb,0x91,0xfa,0xb1,0xf2,0x0c,0xba,0xb6,0xd1,0xc6,0xd1,0x58,0x20,0xbd,0xba,0x73,
};
/*
 * Other modes (ofb, cbc, cfb) is impossible to test to match GOST R
 * 34.13-2015 test vectors exactly, due to these vectors having exceeding
 * IV length value (m) = 256 bits, while openssl have hard-coded limit
 * of maximum IV length of 128 bits (EVP_MAX_IV_LENGTH).
 * Also, current grasshopper code having fixed IV length of 128 bits.
 *
 * Thus, new test vectors are generated with truncated 128-bit IV using
 * canonical GOST implementation from TC26.
 */
static const unsigned char E_ofb[] = {
    /* OFB test vector generated from canonical implementation */
    0x81,0x80,0x0a,0x59,0xb1,0x84,0x2b,0x24,0xff,0x1f,0x79,0x5e,0x89,0x7a,0xbd,0x95,
    0x77,0x91,0x46,0xdb,0x2d,0x93,0xa9,0x4e,0xd9,0x3c,0xf6,0x8b,0x32,0x39,0x7f,0x19,
    0xe9,0x3c,0x9e,0x57,0x44,0x1d,0x87,0x05,0x45,0xf2,0x40,0x36,0xa5,0x8c,0xee,0xa3,
    0xcf,0x3f,0x00,0x61,0xd5,0x64,0x23,0x54,0x5b,0x96,0x0d,0x86,0x4c,0xc8,0x68,0xda,
};
static const unsigned char E_cbc[] = {
    /* CBC test vector generated from canonical implementation */
    0x68,0x99,0x72,0xd4,0xa0,0x85,0xfa,0x4d,0x90,0xe5,0x2e,0x3d,0x6d,0x7d,0xcc,0x27,
    0xab,0xf1,0x70,0xb2,0xb2,0x26,0xc3,0x01,0x0c,0xcf,0xa1,0x36,0xd6,0x59,0xcd,0xaa,
    0xca,0x71,0x92,0x72,0xab,0x1d,0x43,0x8e,0x15,0x50,0x7d,0x52,0x1e,0xcd,0x55,0x22,
    0xe0,0x11,0x08,0xff,0x8d,0x9d,0x3a,0x6d,0x8c,0xa2,0xa5,0x33,0xfa,0x61,0x4e,0x71,
};
static const unsigned char E_cfb[] = {
    /* CFB test vector generated from canonical implementation */
    0x81,0x80,0x0a,0x59,0xb1,0x84,0x2b,0x24,0xff,0x1f,0x79,0x5e,0x89,0x7a,0xbd,0x95,
    0x68,0xc1,0xb9,0x9c,0x4d,0xf5,0x9c,0xc7,0x95,0x1e,0x37,0x39,0xb5,0xb3,0xcd,0xbf,
    0x07,0x3f,0x4d,0xd2,0xd6,0xde,0xb3,0xcf,0xb0,0x26,0x54,0x5f,0x7a,0xf1,0xd8,0xe8,
    0xe1,0xc8,0x52,0xe9,0xa8,0x56,0x71,0x62,0xdb,0xb5,0xda,0x7f,0x66,0xde,0xa9,0x26,
};

static const unsigned char iv_ctr[]	= { 0x12,0x34,0x56,0x78,0x90,0xab,0xce,0xf0, 0,0,0,0,0,0,0,0 };
/* truncated to 128-bits IV */
static const unsigned char iv_128bit[]	= { 0x12,0x34,0x56,0x78,0x90,0xab,0xce,0xf0,
					    0xa1,0xb2,0xc3,0xd4,0xe5,0xf0,0x01,0x12 };
struct testcase {
    const char *name;
    const EVP_CIPHER *(*type)(void);
    int stream;
    const unsigned char *plaintext;
    const unsigned char *expected;
    size_t size;
    const unsigned char *iv;
    size_t iv_size;
    int acpkm;
};
static struct testcase testcases[] = {
    { "ecb", cipher_gost_grasshopper_ecb, 0, P,  E_ecb,  sizeof(P),  NULL,       0, 0 },
    { "ctr", cipher_gost_grasshopper_ctr, 1, P,  E_ctr,  sizeof(P),  iv_ctr,     sizeof(iv_ctr), 0 },
    { "ofb", cipher_gost_grasshopper_ofb, 1, P,  E_ofb,  sizeof(P),  iv_128bit,  sizeof(iv_128bit), 0 },
    { "cbc", cipher_gost_grasshopper_cbc, 0, P,  E_cbc,  sizeof(P),  iv_128bit,  sizeof(iv_128bit), 0 },
    { "cfb", cipher_gost_grasshopper_cfb, 0, P,  E_cfb,  sizeof(P),  iv_128bit,  sizeof(iv_128bit), 0 },
    NULL
};

static void hexdump(const void *ptr, size_t len)
{
    const unsigned char *p = ptr;
    size_t i, j;

    for (i = 0; i < len; i += j) {
	for (j = 0; j < 16 && i + j < len; j++)
	    printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n");
}

static int test_block(const EVP_CIPHER *type, const char *name,
    const unsigned char *pt, const unsigned char *exp, size_t size,
    const unsigned char *iv, size_t iv_size, int acpkm)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char c[size];
    int outlen, tmplen;
    int ret = 0, test;

    OPENSSL_assert(ctx);
    printf("Encryption test from GOST R 34.13-2015 [%s] \n", name);
    /* test with single big chunk */
    EVP_CIPHER_CTX_init(ctx);
    T(EVP_CipherInit_ex(ctx, type, NULL, K, iv, 1));
    T(EVP_CIPHER_CTX_set_padding(ctx, 0));
    memset(c, 0, sizeof(c));
    if (acpkm)
	T(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_KEY_MESH, 256 / 8, NULL));
    T(EVP_CipherUpdate(ctx, c, &outlen, pt, size));
    T(EVP_CipherFinal_ex(ctx, c + outlen, &tmplen));
    EVP_CIPHER_CTX_cleanup(ctx);
    printf("  c[%d] = ", outlen);
    hexdump(c, outlen);

    TEST_ASSERT(outlen != size || memcmp(c, exp, size));
    ret |= test;

    /* test with small chunks of block size */
    printf("Chunked encryption test from GOST R 34.13-2015 [%s] \n", name);
    int blocks = size / GRASSHOPPER_BLOCK_SIZE;
    int z;
    EVP_CIPHER_CTX_init(ctx);
    T(EVP_CipherInit_ex(ctx, type, NULL, K, iv, 1));
    T(EVP_CIPHER_CTX_set_padding(ctx, 0));
    memset(c, 0, sizeof(c));
    if (acpkm)
	T(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_KEY_MESH, 256 / 8, NULL));
    for (z = 0; z < blocks; z++) {
	int offset = z * GRASSHOPPER_BLOCK_SIZE;
	int sz = GRASSHOPPER_BLOCK_SIZE;

	T(EVP_CipherUpdate(ctx, c + offset, &outlen, pt + offset, sz));
    }
    outlen = z * GRASSHOPPER_BLOCK_SIZE;
    T(EVP_CipherFinal_ex(ctx, c + outlen, &tmplen));
    EVP_CIPHER_CTX_cleanup(ctx);
    printf("  c[%d] = ", outlen);
    hexdump(c, outlen);

    TEST_ASSERT(outlen != size || memcmp(c, exp, size));
    ret |= test;

    /* test with single big chunk */
    printf("Decryption test from GOST R 34.13-2015 [%s] \n", name);
    EVP_CIPHER_CTX_init(ctx);
    T(EVP_CipherInit_ex(ctx, type, NULL, K, iv, 0));
    T(EVP_CIPHER_CTX_set_padding(ctx, 0));
    memset(c, 0, sizeof(c));
    if (acpkm)
	T(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_KEY_MESH, 256 / 8, NULL));
    T(EVP_CipherUpdate(ctx, c, &outlen, exp, size));
    T(EVP_CipherFinal_ex(ctx, c + outlen, &tmplen));
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    printf("  d[%d] = ", outlen);
    hexdump(c, outlen);

    TEST_ASSERT(outlen != size || memcmp(c, pt, size));
    ret |= test;

    return ret;
}

static int test_stream(const EVP_CIPHER *type, const char *name,
    const unsigned char *pt, const unsigned char *exp, size_t size,
    const unsigned char *iv, size_t iv_size, int acpkm)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ret = 0, test;
    int z;

    OPENSSL_assert(ctx);
    /* Cycle through all lengths from 1 upto maximum size */
    printf("Stream encryption test from GOST R 34.13-2015 [%s] \n", name);
    for (z = 1; z <= size; z++) {
	unsigned char c[size];
	int outlen, tmplen;
	int sz = 0;
	int i;

	EVP_CIPHER_CTX_init(ctx);
	EVP_CipherInit_ex(ctx, type, NULL, K, iv, 1);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	memset(c, 0xff, sizeof(c));
	if (acpkm)
	    T(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_KEY_MESH, 256 / 8, NULL));
	for (i = 0; i < size; i += z) {
	    if (i + z > size)
		sz = size - i;
	    else
		sz = z;
	    EVP_CipherUpdate(ctx, c + i, &outlen, pt + i, sz);
	    OPENSSL_assert(outlen == sz);
	}
	outlen = i - z + sz;
	EVP_CipherFinal_ex(ctx, c + outlen, &tmplen);
	EVP_CIPHER_CTX_cleanup(ctx);

	test = outlen != size || memcmp(c, exp, size);
	printf("%c", test ? 'E' : '+');
	ret |= test;
    }
    printf("\n");
    TEST_ASSERT(ret);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int main(int argc, char **argv)
{
    int ret = 0;
    const struct testcase *t;

    for (t = testcases; t->name; t++) {
	ret |= test_block(t->type(), t->name,
	    t->plaintext, t->expected, t->size,
	    t->iv, t->iv_size, t->acpkm);
	if (t->stream)
	    ret |= test_stream(t->type(), t->name,
		t->plaintext, t->expected, t->size,
		t->iv, t->iv_size, t->acpkm);
    }

    if (ret)
	printf(cDRED "= Some tests FAILED!\n" cNORM);
    else
	printf(cDGREEN "= All tests passed!\n" cNORM);
    return ret;
}
