#include "gost_digest.h"
#include "gost_digest_details.h"

#include <stdbool.h>

#include <openssl/evp.h>

struct gost_digest_ctx_st {
    const GOST_digest* cls;
    void* algctx;
    unsigned long flags;
    void* allocated_self;
};

size_t GOST_digest_ctx_size = sizeof(GOST_digest_ctx);

void* GOST_digest_ctx_data(const GOST_digest_ctx* ctx) {
	return ctx->algctx;
}

void GOST_digest_ctx_set_flags(GOST_digest_ctx *ctx, unsigned long flags)
{
    ctx->flags |= flags;
}

void GOST_digest_ctx_reset_flags(GOST_digest_ctx *ctx, unsigned long flags)
{
    ctx->flags &= ~flags;
}

int GOST_digest_ctx_test_flags(const GOST_digest_ctx *ctx, unsigned long flags)
{
    return (ctx->flags & flags);
}

GOST_digest_ctx* GOST_digest_ctx_new() {
    void* buf = OPENSSL_zalloc(sizeof(GOST_digest_ctx));
    if (!buf) {
        return NULL;
    }

    GOST_digest_ctx* ctx = buf;
    ctx->allocated_self = buf;
    return ctx;
}

static bool GOST_digest_ctx_initialized(const GOST_digest_ctx *ctx) {
    return ctx && ctx->cls && ctx->algctx;
}

void GOST_digest_ctx_free(GOST_digest_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->cls && ctx->algctx) {
        ctx->cls->cleanup(ctx);
    }

    OPENSSL_free(ctx->algctx);
    ctx->algctx = NULL;

    OPENSSL_free(ctx->allocated_self);
}

int GOST_digest_ctx_init(GOST_digest_ctx *ctx, const GOST_digest *cls) {
    if (!ctx) {
        return 0;
    }

    if (GOST_digest_ctx_test_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT)) {
        return 1;
    }

    if (ctx->cls && ctx->algctx && !GOST_digest_ctx_cleanup(ctx)) {
        return 0;
    }

    ctx->cls = cls;

    ctx->algctx = OPENSSL_zalloc(ctx->cls->algctx_size);
    if (ctx->cls->algctx_size && !ctx->algctx) {
        return 0;
    }

    int r = ctx->cls->init(ctx);
    if (!r) {
        OPENSSL_free(ctx->algctx);
        ctx->algctx = NULL;
    }

    return r;
}

int GOST_digest_ctx_update(GOST_digest_ctx *ctx, const void *data, size_t count) {
    if (!GOST_digest_ctx_initialized(ctx))
        return 0;

    return ctx->cls->update(ctx, data, count);
}

int GOST_digest_ctx_final(GOST_digest_ctx *ctx, unsigned char *md) {
    if (!GOST_digest_ctx_initialized(ctx))
        return 0;

    return ctx->cls->final(ctx, md);
}

int GOST_digest_ctx_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from) {
    if (!to || !from || to == from) {
        return 0;
    }

    if (!GOST_digest_ctx_initialized(from)) {
        return 0;
    }

    if (GOST_digest_ctx_initialized(to)
        && GOST_digest_ctx_data(to) == GOST_digest_ctx_data(from)) {
        to->algctx = OPENSSL_zalloc(to->cls->algctx_size);
        if (to->cls->algctx_size && !to->algctx) {
            return 0;
        }
    }

    to->flags = 0;
    if (!GOST_digest_ctx_init(to, from->cls)) {
        return 0;
    }

    to->flags = from->flags;

    return to->cls->copy(to, from);
}

int GOST_digest_ctx_cleanup(GOST_digest_ctx *ctx) {
    if (!GOST_digest_ctx_initialized(ctx))
        return 0;

    ctx->flags = 0;

    int r = ctx->cls->cleanup(ctx);

    OPENSSL_free(ctx->algctx);
    ctx->algctx = NULL;

    return r;
}

int GOST_digest_ctx_ctrl(GOST_digest_ctx *ctx, int cmd, int p1, void *p2) {
    if (!GOST_digest_ctx_initialized(ctx))
        return 0;

    return ctx->cls->ctrl(ctx, cmd, p1, p2);
}

const GOST_digest* GOST_digest_ctx_digest(GOST_digest_ctx *ctx) {
    if (!GOST_digest_ctx_initialized(ctx))
            return NULL;

    return ctx->cls;
}
