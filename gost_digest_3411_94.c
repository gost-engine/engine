#include <string.h>

#include <openssl/objects.h>

#include "gost_digest_3411_94.h"
#include "gost_digest_base.h"
#include "gosthash.h"
#include "gost89.h"

static int gost_digest_init(GOST_digest_ctx *ctx);
static int gost_digest_update(GOST_digest_ctx *ctx, const void *data,
                              size_t count);
static int gost_digest_final(GOST_digest_ctx *ctx, unsigned char *md);
static int gost_digest_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from);
static int gost_digest_cleanup(GOST_digest_ctx *ctx);

struct ossl_gost_digest_ctx {
    gost_hash_ctx dctx;
    gost_ctx cctx;
};

static inline struct ossl_gost_digest_ctx* impl_digest_ctx_data(const GOST_digest_ctx *ctx) {
    return (struct ossl_gost_digest_ctx*)GOST_digest_ctx_data(ctx);
}

const GOST_digest GostR3411_94_digest = {
    INIT_MEMBER(nid, NID_id_GostR3411_94),
    INIT_MEMBER(result_size, 32),
    INIT_MEMBER(input_blocksize, 32),
    INIT_MEMBER(algctx_size, sizeof(struct ossl_gost_digest_ctx)),

    INIT_MEMBER(base, &GostR3411_digest_base),

    INIT_MEMBER(init, gost_digest_init),
    INIT_MEMBER(update, gost_digest_update),
    INIT_MEMBER(final, gost_digest_final),
    INIT_MEMBER(copy, gost_digest_copy),
    INIT_MEMBER(cleanup, gost_digest_cleanup),
};

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
