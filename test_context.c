/*
 * Copyright (C) 2018 vt@altlinux.org. All Rights Reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include <openssl/engine.h>
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
#define cBLUE	"\033[1;34m"
#define cDBLUE	"\033[0;34m"
#define cNORM	"\033[m"
#define TEST_ASSERT(e) {if ((test = (e))) \
		 printf(cRED "  Test FAILED\n" cNORM); \
	     else \
		 printf(cGREEN "  Test passed\n" cNORM);}

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

#define TEST_SIZE 256
#define STEP_SIZE 16

static int test_contexts(int nid, const int enc, int acpkm)
{
    EVP_CIPHER_CTX *ctx, *save;
    unsigned char pt[TEST_SIZE] = {1};
    unsigned char b[TEST_SIZE]; /* base output */
    unsigned char c[TEST_SIZE]; /* cloned output */
    unsigned char K[32] = {1};
    unsigned char iv[16] = {1};
    int outlen, tmplen;
    int ret = 0, test = 0;

    const EVP_CIPHER *type = EVP_get_cipherbynid(nid);
    const char *name = EVP_CIPHER_name(type);

    printf(cBLUE "%s test for %s (nid %d)\n" cNORM,
	enc ? "Encryption" : "Decryption", name, nid);

    /* produce base encryption */
    ctx = EVP_CIPHER_CTX_new();
    T(ctx);
    T(EVP_CipherInit_ex(ctx, type, NULL, K, iv, enc));
    if (acpkm)
	T(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_KEY_MESH, acpkm, NULL));
    T(EVP_CIPHER_CTX_set_padding(ctx, 0));
    T(EVP_CipherUpdate(ctx, b, &outlen, pt, sizeof(b)));
    T(EVP_CipherFinal_ex(ctx, b + outlen, &tmplen));

    /* and now tests */
    EVP_CIPHER_CTX_reset(ctx);
    EVP_CIPHER_CTX_reset(ctx); /* double call is intentional */
    T(EVP_CipherInit_ex(ctx, type, NULL, K, iv, enc));
    T(EVP_CIPHER_CTX_set_padding(ctx, 0));
    if (acpkm)
	T(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_KEY_MESH, acpkm, NULL));
    save = ctx;

    printf(" cloned contexts: ");
    int i;
    memset(c, 0, sizeof(c));
    for (i = 0; i < TEST_SIZE / STEP_SIZE; i++) {
	EVP_CIPHER_CTX *copy = EVP_CIPHER_CTX_new();
	T(copy);
	T(EVP_CIPHER_CTX_copy(copy, ctx));
	if (save != ctx) /* else original context */
	    EVP_CIPHER_CTX_free(ctx);
	ctx = copy;

	T(EVP_CipherUpdate(ctx, c + STEP_SIZE * i, &outlen,
	       	pt + STEP_SIZE * i, STEP_SIZE));
    }

    outlen = i * STEP_SIZE;
    T(EVP_CipherFinal_ex(ctx, c + outlen, &tmplen));
    TEST_ASSERT(outlen != TEST_SIZE || memcmp(c, b, TEST_SIZE));
    EVP_CIPHER_CTX_free(ctx);
    if (test) {
	printf("  b[%d] = ", outlen);
	hexdump(b, outlen);
	printf("  c[%d] = ", outlen);
	hexdump(c, outlen);
    }
    ret |= test;

    /* resume original context */
    printf("    base context: ");
    memset(c, 0, sizeof(c));
    T(EVP_CipherUpdate(save, c, &outlen, pt, sizeof(c)));
    T(EVP_CipherFinal_ex(save, c + outlen, &tmplen));
    TEST_ASSERT(outlen != TEST_SIZE || memcmp(c, b, TEST_SIZE));
    EVP_CIPHER_CTX_cleanup(save); /* multiple calls are intentional */
    EVP_CIPHER_CTX_cleanup(save);
    EVP_CIPHER_CTX_free(save);
    if (test) {
	printf("  b[%d] = ", outlen);
	hexdump(b, outlen);
	printf("  c[%d] = ", outlen);
	hexdump(c, outlen);
    }
    ret |= test;

    return ret;
}

static struct testcase {
    int nid;
    int acpkm;
} testcases[] = {
    { NID_id_Gost28147_89, },
    { NID_gost89_cnt, },
    { NID_gost89_cnt_12, },
    { NID_gost89_cbc, },
    { NID_grasshopper_ecb, },
    { NID_grasshopper_cbc, },
    { NID_grasshopper_cfb, },
    { NID_grasshopper_ofb, },
    { NID_grasshopper_ctr, },
    { NID_magma_cbc, },
    { NID_magma_ctr, },
    { NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm, 256 / 8 },
    { 0 },
};

int main(int argc, char **argv)
{
    int ret = 0;

    setenv("OPENSSL_ENGINES", ENGINE_DIR, 0);
    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    ENGINE *eng;
    T(eng = ENGINE_by_id("gost"));
    T(ENGINE_init(eng));
    T(ENGINE_set_default(eng, ENGINE_METHOD_ALL));

    const struct testcase *t;
    for (t = testcases; t->nid; t++) {
	ret |= test_contexts(t->nid, 1, t->acpkm);
	ret |= test_contexts(t->nid, 0, t->acpkm);
    }

    ENGINE_finish(eng);
    ENGINE_free(eng);

    if (ret)
	printf(cDRED "= Some tests FAILED!\n" cNORM);
    else
	printf(cDGREEN "= All tests passed!\n" cNORM);
    return ret;
}
