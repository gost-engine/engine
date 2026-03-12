/**********************************************************************
 *                          md_gost.c                                 *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *             Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>   *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *       OpenSSL interface to GOST R 34.11-94 hash functions          *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include "gost_lcl.h"
#include "gosthash.h"
#include "e_gost_err.h"
#include "gost_digest_details.h"

/* implementation of GOST 34.11 hash function See gost_md.c*/
static int gost_digest_init(GOST_digest_ctx *ctx);
static int gost_digest_update(GOST_digest_ctx *ctx, const void *data,
                              size_t count);
static int gost_digest_final(GOST_digest_ctx *ctx, unsigned char *md);
static int gost_digest_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from);
static int gost_digest_cleanup(GOST_digest_ctx *ctx);

GOST_digest GostR3411_94_digest = {
    .nid = NID_id_GostR3411_94,
    .result_size = 32,
    .input_blocksize = 32,
    .algctx_size = sizeof(struct ossl_gost_digest_ctx),

    .init = gost_digest_init,
    .update = gost_digest_update,
    .final = gost_digest_final,
    .copy = gost_digest_copy,
    .cleanup = gost_digest_cleanup
};

static inline struct ossl_gost_digest_ctx* impl_digest_ctx_data(const GOST_digest_ctx *ctx) {
    return (struct ossl_gost_digest_ctx*)GOST_digest_ctx_data(ctx);
}

static int gost_digest_init(GOST_digest_ctx *ctx)
{
    struct ossl_gost_digest_ctx *c = impl_digest_ctx_data(ctx);
    memset(&(c->dctx), 0, sizeof(gost_hash_ctx));
    gost_init(&(c->cctx), &GostR3411_94_CryptoProParamSet);
    c->dctx.cipher_ctx = &(c->cctx);
    return 1;
}

static int gost_digest_update(GOST_digest_ctx *ctx, const void *data, size_t count)
{
    return hash_block(&(impl_digest_ctx_data(ctx)->dctx), data, count);
}

static int gost_digest_final(GOST_digest_ctx *ctx, unsigned char *md)
{
    return finish_hash(&(impl_digest_ctx_data(ctx)->dctx), md);
}

static int gost_digest_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from)
{
    struct ossl_gost_digest_ctx *md_ctx = impl_digest_ctx_data(to);
    if (impl_digest_ctx_data(to) && impl_digest_ctx_data(from)) {
        memcpy(impl_digest_ctx_data(to), impl_digest_ctx_data(from),
               sizeof(struct ossl_gost_digest_ctx));
        md_ctx->dctx.cipher_ctx = &(md_ctx->cctx);
    }
    return 1;
}

static int gost_digest_cleanup(GOST_digest_ctx *ctx)
{
    if (impl_digest_ctx_data(ctx))
        OPENSSL_cleanse(impl_digest_ctx_data(ctx), sizeof(struct ossl_gost_digest_ctx));
    return 1;
}
/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
