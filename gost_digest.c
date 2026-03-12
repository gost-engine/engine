#include "gost_digest.h"
#include "gost_digest_details.h"

#include <openssl/evp.h>

static int default_static_init(const GOST_digest_ctx *ctx) {
    return 1;
}

static int default_static_deinit(const GOST_digest_ctx *ctx) {
    return 1;
}

static int default_init(GOST_digest_ctx *ctx) {
    return 1;
}

static int default_update(GOST_digest_ctx *ctx, const void *data, size_t count) {
    return 1;
}

static int default_final(GOST_digest_ctx *ctx, unsigned char *md) {
    return 1;
}

static int default_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from) {
    return 1;
}

static int default_cleanup(GOST_digest_ctx *ctx){
    return 1;
}

static int default_ctrl(GOST_digest_ctx *ctx, int cmd, int p1, void *p2) {
    return -2;
}

#define THIS_OR_BASE(st, field) \
    THIS_OR_BASE_OR_DEFAULT(st, field, 0)

#define THIS_OR_BASE_OR_DEFAULT(st, field, dflt) ( \
    ((st)->field) ? ((st)->field) : BASE_VAL(st, field, dflt) \
)

#define BASE_VAL(st, field, dflt) ( \
    (((st)->base && (st)->base->field) ? (st)->base->field : dflt) \
)

const GOST_digest* GOST_digest_init(GOST_digest* d) {
    if (d->this) {
        return d->this;
    }

    d->nid = THIS_OR_BASE(d, nid);
    d->result_size = THIS_OR_BASE(d, result_size);
    d->input_blocksize = THIS_OR_BASE(d, input_blocksize);
    d->flags = THIS_OR_BASE(d, flags);
    d->alias = THIS_OR_BASE(d, alias);

    d->algctx_size = THIS_OR_BASE(d, algctx_size);

    d->init = THIS_OR_BASE_OR_DEFAULT(d, init, default_init);
    d->update = THIS_OR_BASE_OR_DEFAULT(d, update, default_update);
    d->final = THIS_OR_BASE_OR_DEFAULT(d, final, default_final);
    d->copy = THIS_OR_BASE_OR_DEFAULT(d, copy, default_copy);
    d->cleanup = THIS_OR_BASE_OR_DEFAULT(d, cleanup, default_cleanup);
    d->ctrl = THIS_OR_BASE_OR_DEFAULT(d, ctrl, default_ctrl);

    if (d->alias)
        EVP_add_digest_alias(OBJ_nid2sn(d->nid), d->alias);

    d->this = d;

    return d;
}

void GOST_digest_deinit(GOST_digest* d) {
    if (!d->this) {
        return;
    }

    if (d->alias)
        EVP_delete_digest_alias(d->alias);

    d->this = NULL;
}

unsigned long GOST_digest_flags(const GOST_digest* d) {
    return d->flags;
}

int GOST_digest_type(const GOST_digest* d) {
    return d->nid;
}

int GOST_digest_block_size(const GOST_digest* d) {
    return d->input_blocksize;
}

int GOST_digest_size(const GOST_digest* d) {
    return d->result_size;
}

int (*GOST_digest_meth_get_init(const GOST_digest *d))(GOST_digest_ctx *) {
    return d->init;
}
