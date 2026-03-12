/**********************************************************************
 *               gost_prov_mac.c - Initialize all macs                *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *          OpenSSL provider interface to GOST mac functions          *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "gost_prov.h"
#include "gost_digest.h"
#include "gost_lcl.h"

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the algorithm specific ones
 * MAKE_FUNCTIONS() does it for us.
 */

static OSSL_FUNC_mac_dupctx_fn mac_dupctx;
static OSSL_FUNC_mac_freectx_fn mac_freectx;
static OSSL_FUNC_mac_init_fn mac_init;
static OSSL_FUNC_mac_update_fn mac_update;
static OSSL_FUNC_mac_final_fn mac_final;
static OSSL_FUNC_mac_get_ctx_params_fn mac_get_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn mac_set_ctx_params;

struct gost_prov_mac_desc_st {
    /*
     * In the GOST engine, the MAC implementation bases itself heavily on
     * digests with the same name.  We can re-use that part.
     */
    GOST_digest *digest_desc;
    size_t initial_mac_size;
};
typedef struct gost_prov_mac_desc_st GOST_DESC;

struct gost_prov_mac_ctx_st {
    /* Provider context */
    PROV_CTX *provctx;
    const GOST_DESC *descriptor;

    /* Output MAC size */
    size_t mac_size;
    /* XOF mode, where applicable */
    int xof_mode;

    /*
     * Since existing functionality is mainly designed as EVP_MDs for
     * ENGINEs, the functions in this file are accomodated and are simply
     * wrappers that use a local EVP_MD and EVP_MD_CTX.
     * Future development should take a more direct approach and have the
     * appropriate digest functions and digest data directly in this context.
     */

    /* The EVP_MD created from |descriptor| */
    const GOST_digest *digest;
    /* The context for the EVP_MD functions */
    GOST_digest_ctx *dctx;
};
typedef struct gost_prov_mac_ctx_st GOST_CTX;

static void mac_freectx(void *vgctx)
{
    GOST_CTX *gctx = vgctx;
    if (!gctx)
        return;

    /*
     * We don't free gctx->digest here.
     * That will be done by the provider teardown, via
     * GOST_prov_deinit_macs() (defined at the bottom of this file).
     */
    GOST_digest_ctx_free(gctx->dctx);
    OPENSSL_free(gctx);
}

static GOST_CTX *mac_newctx(void *provctx, const GOST_DESC *descriptor)
{
    GOST_CTX *gctx = NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        gctx->descriptor = descriptor;
        gctx->mac_size = descriptor->initial_mac_size;
        gctx->digest = GOST_digest_init(descriptor->digest_desc);
        gctx->dctx = GOST_digest_ctx_new();

        if (gctx->digest == NULL
            || gctx->dctx == NULL
            || GOST_digest_ctx_init(gctx->dctx, gctx->digest) <= 0) {
            mac_freectx(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void *mac_dupctx(void *vsrc)
{
    GOST_CTX *src = vsrc;
    if (src == NULL) {
        return NULL;
    }

    GOST_CTX *dst = mac_newctx(src->provctx, src->descriptor);
    if (dst == NULL) {
        return dst;
    }

    if (GOST_digest_ctx_copy(dst->dctx, src->dctx) <= 0) {
        mac_freectx(dst);
        return NULL;
    }

    dst->mac_size = src->mac_size;
    dst->xof_mode = src->xof_mode;

    return dst;
}

static int mac_init(void *mctx, const unsigned char *key,
                    size_t keylen, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = mctx;

    return mac_set_ctx_params(gctx, params)
        && (key == NULL
            || GOST_digest_ctx_ctrl(gctx->dctx, EVP_MD_CTRL_SET_KEY,
                               (int)keylen, (void *)key) > 0);
}

static int mac_update(void *mctx, const unsigned char *in, size_t inl)
{
    GOST_CTX *gctx = mctx;

    return GOST_digest_ctx_update(gctx->dctx, in, inl) > 0;
}

static int mac_final(void *mctx, unsigned char *out, size_t *outl,
                     size_t outsize)
{
    GOST_CTX *gctx = mctx;
    int ret = 0;

    if (outl == NULL)
        return 0;

    if (out == NULL) {
        *outl = (size_t)gctx->mac_size;
        return 1;
    }

    if (outsize < gctx->mac_size)
        return 0;

    /* We ignore the error for GOST MDs that don't support setting the size */
    GOST_digest_ctx_ctrl(gctx->dctx, EVP_MD_CTRL_XOF_LEN, gctx->mac_size, NULL);
    ret = GOST_digest_ctx_final(gctx->dctx, out);
    if (ret > 0) {
        *outl = (size_t)gctx->mac_size;
    }

    return ret;
}

static const OSSL_PARAM *mac_gettable_params(void *provctx,
                                             const GOST_DESC * descriptor)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("size", NULL),
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_END
    };

    return params;
}

static const OSSL_PARAM *mac_gettable_ctx_params(void *mctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("size", NULL),
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_END
    };

    return params;
}

static const OSSL_PARAM *mac_settable_ctx_params(void *mctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t("size", NULL),
        OSSL_PARAM_octet_string("key", NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

static int mac_get_params(const GOST_DESC * descriptor, OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;

    if (((p = OSSL_PARAM_locate(params, "size")) != NULL
         && !OSSL_PARAM_set_size_t(p, descriptor->initial_mac_size))
        || ((p = OSSL_PARAM_locate(params, "keylen")) != NULL
            && !OSSL_PARAM_set_size_t(p, 32)))
        return 0;
    return 1;
}

static int mac_get_ctx_params(void *mctx, OSSL_PARAM params[])
{
    GOST_CTX *gctx = mctx;
    OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate(params, "size")) != NULL
        && !OSSL_PARAM_set_size_t(p, gctx->mac_size))
        return 0;

    if ((p = OSSL_PARAM_locate(params, "keylen")) != NULL) {
        unsigned int len = 0;

        if (GOST_digest_ctx_ctrl(gctx->dctx, EVP_MD_CTRL_KEY_LEN, 0, &len) <= 0
            || !OSSL_PARAM_set_size_t(p, len))
            return 0;
    }

    if ((p = OSSL_PARAM_locate(params, "xof")) != NULL
        && (!(GOST_digest_flags(GOST_digest_ctx_digest(gctx->dctx)) & EVP_MD_FLAG_XOF)
            || !OSSL_PARAM_set_int(p, gctx->xof_mode)))
        return 0;

    return 1;
}

static int mac_set_ctx_params(void *mctx, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = mctx;
    const OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate_const(params, "size")) != NULL
        && !OSSL_PARAM_get_size_t(p, &gctx->mac_size))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, "key")) != NULL) {
        const unsigned char *key = NULL;
        size_t keylen = 0;
        int ret;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&key, &keylen))
            return 0;

        ret = GOST_digest_ctx_ctrl(gctx->dctx, EVP_MD_CTRL_SET_KEY,
                              (int)keylen, (void *)key);
        if (ret <= 0 && ret != -2)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, "xof")) != NULL
        && (!(GOST_digest_flags(GOST_digest_ctx_digest(gctx->dctx)) & EVP_MD_FLAG_XOF)
            || !OSSL_PARAM_get_int(p, &gctx->xof_mode)))
        return 0;
    if ((p = OSSL_PARAM_locate_const(params, "key-mesh")) != NULL) {
        size_t key_mesh = 0;
        int i_cipher_key_mesh = 0, *p_cipher_key_mesh = NULL;

        if (!OSSL_PARAM_get_size_t(p, &key_mesh))
            return 0;

        if ((p = OSSL_PARAM_locate_const(params, "cipher-key-mesh")) != NULL) {
            size_t cipher_key_mesh = 0;

            if (!OSSL_PARAM_get_size_t(p, &cipher_key_mesh)) {
                return 0;
            } else {
                i_cipher_key_mesh = (int)cipher_key_mesh;
                p_cipher_key_mesh = &i_cipher_key_mesh;
            }
        }

        if (GOST_digest_ctx_ctrl(gctx->dctx, EVP_CTRL_KEY_MESH,
                            key_mesh, p_cipher_key_mesh) <= 0)
            return 0;
    }
    return 1;
}

typedef void (*fptr_t)(void);
#define MAKE_FUNCTIONS(name, macsize)                                   \
    const GOST_DESC name##_desc = {                                     \
        &name,                                                          \
        macsize,                                                        \
    };                                                                  \
    static OSSL_FUNC_mac_newctx_fn name##_newctx;                       \
    static void *name##_newctx(void *provctx)                           \
    {                                                                   \
        return mac_newctx(provctx, &name##_desc);                       \
    }                                                                   \
    static OSSL_FUNC_mac_gettable_params_fn name##_gettable_params;     \
    static const OSSL_PARAM *name##_gettable_params(void *provctx)      \
    {                                                                   \
        return mac_gettable_params(provctx, &name##_desc);              \
    }                                                                   \
    static OSSL_FUNC_mac_get_params_fn name##_get_params;               \
    static int name##_get_params(OSSL_PARAM *params)                    \
    {                                                                   \
        return mac_get_params(&name##_desc, params);                    \
    }                                                                   \
    static const OSSL_DISPATCH name##_functions[] = {                   \
        { OSSL_FUNC_MAC_GETTABLE_PARAMS,                                \
          (fptr_t)name##_gettable_params },                             \
        { OSSL_FUNC_MAC_GET_PARAMS, (fptr_t)name##_get_params },        \
        { OSSL_FUNC_MAC_NEWCTX, (fptr_t)name##_newctx },                \
        { OSSL_FUNC_MAC_DUPCTX, (fptr_t)mac_dupctx },                   \
        { OSSL_FUNC_MAC_FREECTX, (fptr_t)mac_freectx },                 \
        { OSSL_FUNC_MAC_INIT, (fptr_t)mac_init },                       \
        { OSSL_FUNC_MAC_UPDATE, (fptr_t)mac_update },                   \
        { OSSL_FUNC_MAC_FINAL, (fptr_t)mac_final },                     \
        { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,                            \
          (fptr_t)mac_gettable_ctx_params },                            \
        { OSSL_FUNC_MAC_GET_CTX_PARAMS, (fptr_t)mac_get_ctx_params },   \
        { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,                            \
          (fptr_t)mac_settable_ctx_params },                            \
        { OSSL_FUNC_MAC_SET_CTX_PARAMS, (fptr_t)mac_set_ctx_params },   \
    }

MAKE_FUNCTIONS(Gost28147_89_mac, 4);
MAKE_FUNCTIONS(Gost28147_89_mac_12, 4);
MAKE_FUNCTIONS(magma_omac_mac, 8);
MAKE_FUNCTIONS(grasshopper_omac_mac, 16);
MAKE_FUNCTIONS(grasshopper_ctracpkm_mac, 16);
MAKE_FUNCTIONS(magma_ctracpkm_mac, 8);

/* The OSSL_ALGORITHM for the provider's operation query function */
const OSSL_ALGORITHM GOST_prov_macs[] = {
    { SN_id_Gost28147_89_MAC ":1.2.643.2.2.22", NULL,
      Gost28147_89_mac_functions, "GOST 28147-89 MAC" },
    { SN_gost_mac_12, NULL, Gost28147_89_mac_12_functions },
    { SN_magma_mac, NULL, magma_omac_mac_functions },
    { SN_grasshopper_mac, NULL, grasshopper_omac_mac_functions },
    { SN_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac
      ":1.2.643.7.1.1.5.2.2", NULL,
      grasshopper_ctracpkm_mac_functions },
    { SN_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac
      ":1.2.643.7.1.1.5.1.2", NULL, magma_ctracpkm_mac_functions },
    { NULL , NULL, NULL }
};

static GOST_digest *digests[] = {
    &Gost28147_89_mac,
    &Gost28147_89_mac_12,
    &magma_omac_mac,
    &grasshopper_omac_mac,
    &grasshopper_ctracpkm_mac,
    &magma_ctracpkm_mac
};

#define arraysize(l) (sizeof(l) / sizeof(l[0]))

void GOST_prov_init_macs(void) {
    size_t i;
    for (i = 0; i < arraysize(digests); i++)
        GOST_digest_init(digests[i]);
}

void GOST_prov_deinit_macs(void) {
    size_t i;
    for (i = 0; i < arraysize(digests); i++)
        GOST_digest_deinit(digests[i]);
}
