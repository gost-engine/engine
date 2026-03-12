#include <string.h>

#include <openssl/evp.h>

#include "gost_eng_digest.h"
#include "gost_lcl.h"
#include "gost_digest_details.h"

static int gost_digest_init(EVP_MD_CTX *ctx);
static int gost_digest_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int gost_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int gost_digest_cleanup(EVP_MD_CTX *ctx);

static const GOST_digest* digests[] = {
    &GostR3411_94_digest,
    &GostR3411_2012_256_digest,
    &GostR3411_2012_512_digest,
    &Gost28147_89_mac,
    &Gost28147_89_mac_12,
    &magma_omac_mac,
    &grasshopper_omac_mac,
    &magma_ctracpkm_mac,
    &grasshopper_ctracpkm_mac
};

static const GOST_digest* get_digest(int nid) {
    size_t i = 0;
    for (; i < sizeof(digests)/sizeof(digests[0]); ++i){
        if (digests[i]->nid == nid) {
            return digests[i];
        }
    }
    return NULL;
}

static int gost_digest_init(EVP_MD_CTX *c)
{
    const EVP_MD *md = EVP_MD_CTX_get0_md(c);
    const GOST_digest *d = get_digest(EVP_MD_nid(md));
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    if (GOST_digest_ctx_test_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT))
        return 1;

    return GOST_digest_ctx_init(ctx, d);
}

static int gost_digest_update(EVP_MD_CTX *c, const void *data, size_t count)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    return GOST_digest_ctx_update(ctx, data, count);
}

static int gost_digest_final(EVP_MD_CTX *c, unsigned char *md)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    return GOST_digest_ctx_final(ctx, md);
}

static int gost_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    GOST_digest_ctx *to_ctx = EVP_MD_CTX_md_data(to);
    GOST_digest_ctx *from_ctx = EVP_MD_CTX_md_data(from);

    if (!to_ctx || !from_ctx) {
        return 1;
    }

    return GOST_digest_ctx_copy(to_ctx, from_ctx);
}

static int gost_digest_cleanup(EVP_MD_CTX *c)
{
    GOST_digest_ctx *ctx = (GOST_digest_ctx*)EVP_MD_CTX_md_data(c);
    if (!ctx) {
        return 0;
    }
    return GOST_digest_ctx_cleanup(ctx);
}

EVP_MD *GOST_eng_digest_init_impl(GOST_digest *digest, digest_ctrl_fn* ctrl)
{
    const GOST_digest* d = GOST_digest_init(digest);
    EVP_MD *md;
    if (!(md = EVP_MD_meth_new(d->nid, NID_undef))
        || !EVP_MD_meth_set_result_size(md, d->result_size)
        || !EVP_MD_meth_set_input_blocksize(md, d->input_blocksize)
        || !EVP_MD_meth_set_app_datasize(md, GOST_digest_ctx_size)
        || !EVP_MD_meth_set_flags(md, d->flags)
        || !EVP_MD_meth_set_init(md, gost_digest_init)
        || !EVP_MD_meth_set_update(md, gost_digest_update)
        || !EVP_MD_meth_set_final(md, gost_digest_final)
        || !EVP_MD_meth_set_copy(md, gost_digest_copy)
        || !EVP_MD_meth_set_cleanup(md, gost_digest_cleanup)
        || !EVP_MD_meth_set_ctrl(md, ctrl)) {
        EVP_MD_meth_free(md);
        md = NULL;
    }

    return md;
}

EVP_MD *GOST_eng_digest_init(GOST_eng_digest *d)
{
    if (d->md)
        return d->md;

    EVP_MD *md = GOST_eng_digest_init_impl(d->digest, d->ctrl);

    d->md = md;
    return md;
}

void GOST_eng_digest_deinit(GOST_eng_digest *d)
{
    GOST_digest_deinit(d->digest);

    EVP_MD_meth_free(d->md);

    d->md = NULL;
}

int GOST_eng_digest_nid(const GOST_eng_digest *d) {
    return GOST_digest_type(d->digest);
}
