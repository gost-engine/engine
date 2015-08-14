/**********************************************************************
 *                          gost_md2012.c                             *
 *             Copyright (c) 2013 Cryptocom LTD.                      *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *          GOST R 34.11-2012 interface to OpenSSL engine.            *
 *                                                                    *
 * Author: Alexey Degtyarev <alexey@renatasystems.org>                *
 *                                                                    *
 **********************************************************************/

#include <openssl/evp.h>
#include "gosthash2012.h"

static int gost_digest_init512(EVP_MD_CTX *ctx);
static int gost_digest_init256(EVP_MD_CTX *ctx);
static int gost_digest_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int gost_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int gost_digest_cleanup(EVP_MD_CTX *ctx);

EVP_MD digest_gost2012_512 = {
    NID_id_GostR3411_2012_512,
    NID_undef,
    64,                         /* digest size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    gost_digest_init512,
    gost_digest_update,
    gost_digest_final,
    gost_digest_copy,
    gost_digest_cleanup,
    NULL,
    NULL,
    {NID_undef, NID_undef, 0, 0, 0},
    64,                         /* block size */
    sizeof(gost2012_hash_ctx),
    NULL
};

EVP_MD digest_gost2012_256 = {
    NID_id_GostR3411_2012_256,
    NID_undef,
    32,                         /* digest size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
    gost_digest_init256,
    gost_digest_update,
    gost_digest_final,
    gost_digest_copy,
    gost_digest_cleanup,
    NULL,
    NULL,
    {NID_undef, NID_undef, 0, 0, 0},
    64,                         /* block size */
    sizeof(gost2012_hash_ctx),
    NULL
};

static int gost_digest_init512(EVP_MD_CTX *ctx)
{
    init_gost2012_hash_ctx((gost2012_hash_ctx *) ctx->md_data, 512);
    return 1;
}

static int gost_digest_init256(EVP_MD_CTX *ctx)
{
    init_gost2012_hash_ctx((gost2012_hash_ctx *) ctx->md_data, 256);
    return 1;
}

static int gost_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    gost2012_hash_block((gost2012_hash_ctx *) ctx->md_data, data, count);
    return 1;
}

static int gost_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    gost2012_finish_hash((gost2012_hash_ctx *) ctx->md_data, md);
    return 1;
}

static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    if (to->md_data && from->md_data)
        memcpy(to->md_data, from->md_data, sizeof(from->md_data));

    return 1;
}

static int gost_digest_cleanup(EVP_MD_CTX *ctx)
{
    if (ctx->md_data)
        memset(ctx->md_data, 0x00, sizeof(gost2012_hash_ctx));

    return 1;
}
