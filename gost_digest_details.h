#pragma once

#include "gost_digest.h"

struct gost_digest_st {
    struct gost_digest_st *base;
    struct gost_digest_st *this;

    int nid;
    int result_size;
    int input_blocksize;
    int flags;
    const char* alias;

    size_t algctx_size;

    int (*init)(GOST_digest_ctx *ctx);
    int (*update)(GOST_digest_ctx *ctx, const void *data, size_t count);
    int (*final)(GOST_digest_ctx *ctx, unsigned char *md);
    int (*copy)(GOST_digest_ctx *to, const GOST_digest_ctx *from);
    int (*cleanup)(GOST_digest_ctx *ctx);
    int (*ctrl)(GOST_digest_ctx *ctx, int cmd, int p1, void *p2);
};
