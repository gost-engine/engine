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
#include "test.h"
#include "ansi_terminal.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <string.h>


#define TEST_SIZE 256
#define STEP_SIZE 16

static int test_contexts(const EVP_CIPHER *type, const int enc, const char *msg,
    int acpkm)
{
    EVP_CIPHER_CTX *ctx, *save;
    unsigned char pt[TEST_SIZE] = {1};
    unsigned char b[TEST_SIZE];
    unsigned char c[TEST_SIZE];
    unsigned char K[32] = {1};
    unsigned char iv[16] = {1};
    int outlen, tmplen;
    int ret = 0, test = 0;

    printf(cBLUE "%s test for %s\n" cNORM, enc ? "Encryption" : "Decryption", msg);

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
    printf(" cloned contexts\n");
    EVP_CIPHER_CTX_reset(ctx);
    EVP_CIPHER_CTX_reset(ctx); /* double call is intentional */
    T(EVP_CipherInit_ex(ctx, type, NULL, K, iv, enc));
    T(EVP_CIPHER_CTX_set_padding(ctx, 0));
    if (acpkm)
    T(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_KEY_MESH, acpkm, NULL));

    save = ctx;
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

    outlen = i * GRASSHOPPER_BLOCK_SIZE;
    T(EVP_CipherFinal_ex(ctx, c + outlen, &tmplen));
    TEST_ASSERT(outlen != TEST_SIZE || memcmp(c, b, TEST_SIZE) );
    EVP_CIPHER_CTX_free(ctx);
    if (test) {
        printf("  b[%d] = ", outlen);
        hexdump_inline(b, outlen);
        printf("  c[%d] = ", outlen);
        hexdump_inline(c, outlen);
    }
    ret |= test;

    /* resume original context */
    printf(" base context\n");
    memset(c, 0, sizeof(c));
    T(EVP_CipherUpdate(save, c, &outlen, pt, sizeof(c)));
    T(EVP_CipherFinal_ex(save, c + outlen, &tmplen));
    TEST_ASSERT(outlen != TEST_SIZE || memcmp(c, b, TEST_SIZE));
    EVP_CIPHER_CTX_cleanup(save); /* multiple calls are intentional */
    EVP_CIPHER_CTX_cleanup(save);
    EVP_CIPHER_CTX_free(save);
    if (test) {
        printf("  b[%d] = ", outlen);
        hexdump_inline(b, outlen);
        printf("  c[%d] = ", outlen);
        hexdump_inline(c, outlen);
    }
    ret |= test;
    
    return ret;
}


int main(int argc, char **argv)
{
    int ret = 0;
    setupConsole();
    ret |= test_contexts(cipher_gost_grasshopper_ecb(), 1, "grasshopper ecb", 0);
    ret |= test_contexts(cipher_gost_grasshopper_ecb(), 0, "grasshopper ecb", 0);
    ret |= test_contexts(cipher_gost_grasshopper_cbc(), 1, "grasshopper cbc", 0);
    ret |= test_contexts(cipher_gost_grasshopper_cbc(), 0, "grasshopper cbc", 0);
    ret |= test_contexts(cipher_gost_grasshopper_ctr(), 1, "grasshopper ctr", 0);
    ret |= test_contexts(cipher_gost_grasshopper_ctr(), 0, "grasshopper ctr", 0);
    ret |= test_contexts(cipher_gost_grasshopper_ofb(), 1, "grasshopper ofb", 0);
    ret |= test_contexts(cipher_gost_grasshopper_ofb(), 0, "grasshopper ofb", 0);
    ret |= test_contexts(cipher_gost_grasshopper_ctracpkm(), 1, "grasshopper ctracpkm", 256 / 8);
    ret |= test_contexts(cipher_gost_grasshopper_ctracpkm(), 0, "grasshopper ctracpkm", 256 / 8);

    if (ret)
        printf(cDRED "= Some tests FAILED!\n" cNORM);
    else
        printf(cDGREEN "= All tests passed!\n" cNORM);
    restoreConsole();
    return ret;
}
