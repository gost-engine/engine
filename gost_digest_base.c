#include <openssl/evp.h>

#include "gost_digest_base.h"

static void gost_digest_static_init(const GOST_digest* d);
static void gost_digest_static_deinit(const GOST_digest* d);

static GOST_digest_ctx* gost_digest_new(const GOST_digest* d);
static void gost_digest_free(GOST_digest_ctx* vctx);

const GOST_digest GostR3411_digest_base = {
    INIT_MEMBER(static_init, gost_digest_static_init),
    INIT_MEMBER(static_deinit, gost_digest_static_deinit),
    INIT_MEMBER(new, gost_digest_new),
    INIT_MEMBER(free, gost_digest_free),
};

static GOST_digest_ctx* gost_digest_new(const GOST_digest *d)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)OPENSSL_zalloc(sizeof(GOST_digest_ctx));
    if (!ctx)
        return ctx;

    ctx->cls = d;
    ctx->algctx = OPENSSL_zalloc(GET_MEMBER(d, algctx_size));
    if (!ctx->algctx) {
        OPENSSL_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

void gost_digest_free(GOST_digest_ctx *ctx)
{
    if (!ctx)
        return;

    OPENSSL_free(ctx->algctx);
    OPENSSL_free(ctx);
}

static void gost_digest_static_init(const GOST_digest* d) {
    if (GET_MEMBER(d, alias))
        EVP_add_digest_alias(OBJ_nid2sn(GET_MEMBER(d, nid)), GET_MEMBER(d, alias));
}

static void gost_digest_static_deinit(const GOST_digest* d) {
    if (GET_MEMBER(d, alias))
        EVP_delete_digest_alias(GET_MEMBER(d, alias));
}
