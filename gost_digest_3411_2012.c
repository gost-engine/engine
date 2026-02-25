#include <openssl/evp.h>
#include <openssl/objects.h>
#include "gosthash2012.h"
#include "gost_digest_3411_2012.h"
#include "gost_digest_base.h"

static int gost_digest_init(GOST_digest_ctx *ctx);
static int gost_digest_update(GOST_digest_ctx *ctx, const void *data,
                              size_t count);
static int gost_digest_final(GOST_digest_ctx *ctx, unsigned char *md);
static int gost_digest_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from);
static int gost_digest_cleanup(GOST_digest_ctx *ctx);

#define INIT_COMMON_MEMBERS() \
    INIT_MEMBER(base, &GostR3411_digest_base), \
    \
    INIT_MEMBER(input_blocksize, 64), \
    INIT_MEMBER(algctx_size, sizeof(gost2012_hash_ctx)), \
    \
    INIT_MEMBER(init, gost_digest_init), \
    INIT_MEMBER(update, gost_digest_update), \
    INIT_MEMBER(final, gost_digest_final), \
    INIT_MEMBER(copy, gost_digest_copy), \
    INIT_MEMBER(cleanup, gost_digest_cleanup)

const GOST_digest GostR3411_2012_256_digest = {
    INIT_MEMBER(nid, NID_id_GostR3411_2012_256),
    INIT_MEMBER(alias, "streebog256"),
    INIT_MEMBER(micalg, "gostr3411-2012-256"),
    INIT_MEMBER(result_size, 32),

    INIT_COMMON_MEMBERS(),    
};

const GOST_digest GostR3411_2012_512_digest = {
    INIT_MEMBER(nid, NID_id_GostR3411_2012_512),
    INIT_MEMBER(alias, "streebog512"),
    INIT_MEMBER(micalg, "gostr3411-2012-512"),
    INIT_MEMBER(result_size, 64),

    INIT_COMMON_MEMBERS(),
};

static inline gost2012_hash_ctx* impl_digest_ctx_data(const GOST_digest_ctx *ctx) {
    return (gost2012_hash_ctx*)GOST_digest_ctx_data(ctx);
}

static int gost_digest_init(GOST_digest_ctx *ctx)
{
    init_gost2012_hash_ctx(impl_digest_ctx_data(ctx), 8 * GET_MEMBER(ctx->cls, result_size));
    return 1;
}

static int gost_digest_update(GOST_digest_ctx *ctx, const void *data, size_t count)
{
    gost2012_hash_block(impl_digest_ctx_data(ctx), data, count);
    return 1;
}

static int gost_digest_final(GOST_digest_ctx *ctx, unsigned char *md)
{
    gost2012_finish_hash(impl_digest_ctx_data(ctx), md);
    return 1;
}

static int gost_digest_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from)
{
    memcpy(impl_digest_ctx_data(to), impl_digest_ctx_data(from), sizeof(gost2012_hash_ctx));

    return 1;
}

static int gost_digest_cleanup(GOST_digest_ctx *ctx)
{
    OPENSSL_cleanse(impl_digest_ctx_data(ctx), sizeof(gost2012_hash_ctx));

    return 1;
}
