/**********************************************************************
 *                          gost_md2012.c                             *
 *             Copyright (c) 2013 Cryptocom LTD.                      *
 *             Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>   *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *          GOST R 34.11-2012 interface to OpenSSL engine.            *
 *                                                                    *
 * Author: Alexey Degtyarev <alexey@renatasystems.org>                *
 *                                                                    *
 **********************************************************************/

#include <openssl/evp.h>
#include "gosthash2012.h"
#include "gost_lcl.h"
#include "gost_digest_details.h"

static int gost_digest_init256(GOST_digest_ctx *ctx);
static int gost_digest_init512(GOST_digest_ctx *ctx);
static int gost_digest_update(GOST_digest_ctx *ctx, const void *data,
                              size_t count);
static int gost_digest_final(GOST_digest_ctx *ctx, unsigned char *md);
static int gost_digest_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from);
static int gost_digest_cleanup(GOST_digest_ctx *ctx);
static int gost_digest_ctrl_256(GOST_digest_ctx *ctx, int type, int arg,
                                void *ptr);
static int gost_digest_ctrl_512(GOST_digest_ctx *ctx, int type, int arg,
                                void *ptr);

const char micalg_256[] = "gostr3411-2012-256";
const char micalg_512[] = "gostr3411-2012-512";

GOST_digest GostR3411_2012_template_digest = {
    .input_blocksize = 64,
    .algctx_size = sizeof(gost2012_hash_ctx),
    .update = gost_digest_update,
    .final = gost_digest_final,
    .copy = gost_digest_copy,
    .cleanup = gost_digest_cleanup,
};

GOST_digest GostR3411_2012_256_digest = {
    .nid = NID_id_GostR3411_2012_256,
    .alias = "streebog256",
    .base = &GostR3411_2012_template_digest,
    .result_size = 32,
    .init = gost_digest_init256,
    .ctrl = gost_digest_ctrl_256,
};

GOST_digest GostR3411_2012_512_digest = {
    .nid = NID_id_GostR3411_2012_512,
    .alias = "streebog512",
    .base = &GostR3411_2012_template_digest,
    .result_size = 64,
    .init = gost_digest_init512,
    .ctrl = gost_digest_ctrl_512,
};

static int gost_digest_init512(GOST_digest_ctx *ctx)
{
    init_gost2012_hash_ctx((gost2012_hash_ctx *) GOST_digest_ctx_data(ctx),
                           512);
    return 1;
}

static int gost_digest_init256(GOST_digest_ctx *ctx)
{
    init_gost2012_hash_ctx((gost2012_hash_ctx *) GOST_digest_ctx_data(ctx),
                           256);
    return 1;
}

static int gost_digest_update(GOST_digest_ctx *ctx, const void *data, size_t count)
{
    gost2012_hash_block((gost2012_hash_ctx *) GOST_digest_ctx_data(ctx), data,
                        count);
    return 1;
}

static int gost_digest_final(GOST_digest_ctx *ctx, unsigned char *md)
{
    gost2012_finish_hash((gost2012_hash_ctx *) GOST_digest_ctx_data(ctx), md);
    return 1;
}

static int gost_digest_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from)
{
    if (GOST_digest_ctx_data(to) && GOST_digest_ctx_data(from))
        memcpy(GOST_digest_ctx_data(to), GOST_digest_ctx_data(from),
               sizeof(gost2012_hash_ctx));

    return 1;
}

static int gost_digest_cleanup(GOST_digest_ctx *ctx)
{
    if (GOST_digest_ctx_data(ctx))
        memset(GOST_digest_ctx_data(ctx), 0x00, sizeof(gost2012_hash_ctx));

    return 1;
}

static int gost_digest_ctrl_256(GOST_digest_ctx *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_MICALG:
        {
            *((char **)ptr) = OPENSSL_malloc(strlen(micalg_256) + 1);
            if (*((char **)ptr) != NULL) {
                strcpy(*((char **)ptr), micalg_256);
                return 1;
            }
            return 0;
        }
    default:
        return 0;
    }
}

static int gost_digest_ctrl_512(GOST_digest_ctx *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_MICALG:
        {
            *((char **)ptr) = OPENSSL_malloc(strlen(micalg_512) + 1);
            if (*((char **)ptr) != NULL) {
                strcpy(*((char **)ptr), micalg_512);
                return 1;
            }
        }
    default:
        return 0;
    }
}
