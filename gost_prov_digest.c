/**********************************************************************
 *             gost_prov_digest.c - Initialize all digests            *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *         OpenSSL provider interface to GOST digest functions        *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "gost_prov.h"
#include "gost_prov_digest.h"
#include "gost_digest_3411_94.h"
#include "gost_digest_3411_2012.h"

/*
 * Forward declarations of all OSSL_DISPATCH functions, to make sure they
 * are correctly defined further down.
 */
static OSSL_FUNC_digest_dupctx_fn digest_dupctx;
static OSSL_FUNC_digest_freectx_fn digest_freectx;
static OSSL_FUNC_digest_init_fn digest_init;
static OSSL_FUNC_digest_update_fn digest_update;
static OSSL_FUNC_digest_final_fn digest_final;


struct gost_prov_crypt_ctx_st {
    PROV_CTX *provctx;
    const GOST_digest *descriptor;

    GOST_digest_ctx *dctx;
};
typedef struct gost_prov_crypt_ctx_st GOST_CTX;

static void digest_freectx(void *vgctx)
{
    GOST_CTX *gctx = vgctx;
    if (!gctx)
        return;

    GET_MEMBER(gctx->descriptor, free)(gctx->dctx);
    OPENSSL_free(gctx);
}

static GOST_CTX *digest_newctx(void *provctx, const GOST_digest *descriptor)
{
    GOST_CTX *gctx = NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        gctx->descriptor = descriptor;
        
        gctx->dctx = GET_MEMBER(gctx->descriptor, new)(gctx->descriptor);
        if (gctx->dctx == NULL) {
            digest_freectx(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void *digest_dupctx(void *vsrc)
{
    GOST_CTX *src = vsrc;
    GOST_CTX *dst = digest_newctx(src->provctx, src->descriptor);

    if (dst != NULL)
        GET_MEMBER(src->descriptor, copy)(dst->dctx, src->dctx);

    return dst;
}

static int digest_get_params(const GOST_digest *descriptor, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (((p = OSSL_PARAM_locate(params, "blocksize")) != NULL
         && !OSSL_PARAM_set_size_t(p, GET_MEMBER(descriptor, input_blocksize)))
        || ((p = OSSL_PARAM_locate(params, "size")) != NULL
            && !OSSL_PARAM_set_size_t(p, GET_MEMBER(descriptor, result_size)))
        || ((p = OSSL_PARAM_locate(params, "xof")) != NULL
            && !OSSL_PARAM_set_size_t(p, GET_MEMBER(descriptor, flags) & EVP_MD_FLAG_XOF)))
        return 0;
    return 1;
}

static int digest_init(void *vgctx, const OSSL_PARAM unused_params[])
{
    GOST_CTX *gctx = vgctx;

    return GET_MEMBER(gctx->descriptor, init)(gctx->dctx) > 0;
}

static int digest_update(void *vgctx, const unsigned char *in, size_t inl)
{
    GOST_CTX *gctx = vgctx;

    return GET_MEMBER(gctx->descriptor, update)(gctx->dctx, in, inl) > 0;
}

static int digest_final(void *vgctx,
                        unsigned char *out, size_t *outl, size_t outsize)
{
    GOST_CTX *gctx = vgctx;

    if (outsize < GET_MEMBER(gctx->descriptor, result_size))
        return 0;

    int res = GET_MEMBER(gctx->descriptor, final)(gctx->dctx, out);

    GET_MEMBER(gctx->descriptor, cleanup)(gctx->dctx);

    if (res > 0 && outl != NULL)
        *outl = GET_MEMBER(gctx->descriptor, result_size);

    return res > 0;
}

/*
 * These are named like the EVP_MD templates in gost_md.c etc, with the
 * added suffix "_functions".  Hopefully, that makes it easy to find the
 * actual implementation.
 */
typedef void (*fptr_t)(void);
#define MAKE_FUNCTIONS(name)                                            \
    static OSSL_FUNC_digest_get_params_fn name##_get_params;            \
    static int name##_get_params(OSSL_PARAM *params)                    \
    {                                                                   \
        return digest_get_params(&name, params);                        \
    }                                                                   \
    static OSSL_FUNC_digest_newctx_fn name##_newctx;                    \
    static void *name##_newctx(void *provctx)                           \
    {                                                                   \
        return digest_newctx(provctx, &name);                           \
    }                                                                   \
    static const OSSL_DISPATCH name##_functions[] = {                   \
        { OSSL_FUNC_DIGEST_GET_PARAMS, (fptr_t)name##_get_params },     \
        { OSSL_FUNC_DIGEST_NEWCTX, (fptr_t)name##_newctx },             \
        { OSSL_FUNC_DIGEST_DUPCTX, (fptr_t)digest_dupctx },             \
        { OSSL_FUNC_DIGEST_FREECTX, (fptr_t)digest_freectx },           \
        { OSSL_FUNC_DIGEST_INIT, (fptr_t)digest_init },                 \
        { OSSL_FUNC_DIGEST_UPDATE, (fptr_t)digest_update },             \
        { OSSL_FUNC_DIGEST_FINAL, (fptr_t)digest_final },               \
    }

MAKE_FUNCTIONS(GostR3411_94_digest);
MAKE_FUNCTIONS(GostR3411_2012_256_digest);
MAKE_FUNCTIONS(GostR3411_2012_512_digest);

/* The OSSL_ALGORITHM for the provider's operation query function */
const OSSL_ALGORITHM GOST_prov_digests[] = {
    /*
     * Described in RFC 6986, first name from
     * https://www.ietf.org/archive/id/draft-deremin-rfc4491-bis-06.txt
     * (is there not an RFC namming these?)
     */
    { SN_id_GostR3411_2012_256":id-tc26-gost3411-12-256:1.2.643.7.1.1.2.2", NULL,
      GostR3411_2012_256_digest_functions,
      "GOST R 34.11-2012 with 256 bit hash" },
    { SN_id_GostR3411_2012_512":id-tc26-gost3411-12-512:1.2.643.7.1.1.2.3", NULL,
      GostR3411_2012_512_digest_functions,
      "GOST R 34.11-2012 with 512 bit hash" },

    /* Described in RFC 5831, first name from RFC 4357, section 10.4 */
    { SN_id_GostR3411_94":id-GostR3411-94:1.2.643.2.2.9", NULL,
      GostR3411_94_digest_functions, "GOST R 34.11-94" },
    { NULL , NULL, NULL }
};

static const GOST_digest *digests[] = {
    &GostR3411_94_digest,
    &GostR3411_2012_256_digest,
    &GostR3411_2012_512_digest,
};

#define arraysize(l) (sizeof(l) / sizeof(l[0]))

void GOST_prov_init_digests(void) {
    size_t i;
    for (i = 0; i < arraysize(digests); i++)
        GET_MEMBER(digests[i], static_init)(digests[i]);
}

void GOST_prov_deinit_digests(void) {
    size_t i;
    for (i = 0; i < arraysize(digests); i++)
        GET_MEMBER(digests[i], static_deinit)(digests[i]);
}
