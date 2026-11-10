/**********************************************************************
 *       gost_prov_signature_mac.c - MAC over signature API           *
 *                                                                    *
 *      This file is distributed under the same license as OpenSSL    *
 *                                                                    *
 *     Provider signature interface for GOST MAC secret keys          *
 *     (gost-mac, gost-mac-12, magma-mac, kuznyechik-mac),            *
 *     requires OpenSSL 3.0                                           *
 **********************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "gost_prov.h"
#include "gost_lcl.h"

#define MAC_KEY_SIZE 32

/*
 * MAC computation over the OSSL_OP_SIGNATURE interface.
 * The underlying MAC implementations are the same as 
 * used in gost_prov_mac.c, so we reuse the
 * GOST_digest / GOST_digest_ctx wrappers.
 */
struct gost_sig_mac_desc_st {
    GOST_digest *digest;
    size_t initial_mac_size;
};
typedef struct gost_sig_mac_desc_st GOST_SIG_MAC_DESC;

struct gost_sig_mac_ctx_st {
    PROV_CTX *provctx;
    const GOST_SIG_MAC_DESC *descriptor;
    /* Output MAC size */
    size_t mac_size;
    /* Saved key, needed to reset the MAC state for one-shot sign */
    unsigned char key[MAC_KEY_SIZE];
    GOST_digest_ctx *dctx;
};
typedef struct gost_sig_mac_ctx_st GOST_SIG_MAC_CTX;

static void sig_mac_freectx(void *vsigctx)
{
    GOST_SIG_MAC_CTX *sigctx = vsigctx;

    if (!sigctx)
        return;

    /*
     * We don't free sigctx->descriptor->digest here.
     * That will be done by the provider teardown, via
     * GOST_prov_deinit_macs() (defined in gost_prov_mac.c).
     */
    OPENSSL_cleanse(sigctx->key, sizeof(sigctx->key));
    GOST_digest_ctx_free(sigctx->dctx);
    OPENSSL_free(sigctx);
}

static GOST_SIG_MAC_CTX *sig_mac_newctx(void *provctx,
                                        const GOST_SIG_MAC_DESC *descriptor)
{
    GOST_SIG_MAC_CTX *sigctx = NULL;
    const GOST_digest *digest = NULL;

    if ((sigctx = OPENSSL_zalloc(sizeof(*sigctx))) != NULL) {
        sigctx->provctx = provctx;
        sigctx->descriptor = descriptor;
        sigctx->mac_size = descriptor->initial_mac_size;
        digest = GOST_digest_init(descriptor->digest);
        sigctx->dctx = GOST_digest_ctx_new();

        if (digest == NULL
            || sigctx->dctx == NULL
            || GOST_digest_ctx_init(sigctx->dctx, digest) <= 0) {
            sig_mac_freectx(sigctx);
            sigctx = NULL;
        }
    }
    return sigctx;
}

static void *sig_mac_dupctx(void *vsigctx)
{
    GOST_SIG_MAC_CTX *src = vsigctx;
    GOST_SIG_MAC_CTX *dst = NULL;

    if (!src)
        return NULL;

    dst = sig_mac_newctx(src->provctx, src->descriptor);
    if (!dst)
        return NULL;

    if (GOST_digest_ctx_copy(dst->dctx, src->dctx) <= 0) {
        sig_mac_freectx(dst);
        return NULL;
    }

    dst->mac_size = src->mac_size;

    return dst;
}

static int sig_mac_digest_sign_init(void *vsigctx, const char *mdname,
                                    void *provkey, const OSSL_PARAM params[])
{
    GOST_SIG_MAC_CTX *sigctx = vsigctx;
    GOST_MAC_KEY_DATA *key = provkey;

    (void)mdname;
    (void)params;

    if (!sigctx || !key)
        return 0;

    memcpy(sigctx->key, key->key, MAC_KEY_SIZE);

    return GOST_digest_ctx_ctrl(sigctx->dctx, EVP_MD_CTRL_SET_KEY,
                                MAC_KEY_SIZE, sigctx->key) > 0;
}

static int sig_mac_digest_sign_update(void *vsigctx, const unsigned char *data,
                                      size_t datalen)
{
    GOST_SIG_MAC_CTX *sigctx = vsigctx;

    if (!sigctx)
        return 0;

    return GOST_digest_ctx_update(sigctx->dctx, data, datalen) > 0;
}

static int sig_mac_final(GOST_SIG_MAC_CTX *sigctx, unsigned char *sig,
                         size_t *siglen, size_t sigsize)
{
    int ret = 0;

    if (siglen == NULL)
        return 0;

    if (sig == NULL) {
        *siglen = sigctx->mac_size;
        return 1;
    }

    if (sigsize < sigctx->mac_size)
        return 0;

    /* We ignore the error for GOST MDs that don't support setting the size */
    GOST_digest_ctx_ctrl(sigctx->dctx, EVP_MD_CTRL_XOF_LEN,
                         (int)sigctx->mac_size, NULL);
    ret = GOST_digest_ctx_final(sigctx->dctx, sig);
    if (ret > 0) {
        *siglen = sigctx->mac_size;
    }

    return ret;
}

static int sig_mac_digest_sign_final(void *vsigctx, unsigned char *sig,
                                     size_t *siglen, size_t sigsize)
{
    GOST_SIG_MAC_CTX *sigctx = vsigctx;

    if (!sigctx)
        return 0;

    return sig_mac_final(sigctx, sig, siglen, sigsize);
}

static int sig_mac_digest_sign(void *vsigctx, unsigned char *sig,
                               size_t *siglen, size_t sigsize,
                               const unsigned char *tbs, size_t tbslen)
{
    GOST_SIG_MAC_CTX *sigctx = vsigctx;

    if (!sigctx)
        return 0;

    /*
     * One-shot sign is independent of any previously processed data.
     * EVP_DigestSign() may be called twice (to query the size and to
     * compute the signature), so reset the MAC state by setting the
     * key again: the SET_KEY ctrl re-initializes the underlying
     * digest context.
     */
    if (GOST_digest_ctx_ctrl(sigctx->dctx, EVP_MD_CTRL_SET_KEY,
                             MAC_KEY_SIZE, sigctx->key) <= 0)
        return 0;

    if (!sig_mac_digest_sign_update(sigctx, tbs, tbslen))
        return 0;

    return sig_mac_final(sigctx, sig, siglen, sigsize);
}

/* https://github.com/openssl/openssl/pull/29921 */
#ifndef OSSL_DIGEST_PARAM_TLSTREE
#define OSSL_DIGEST_PARAM_TLSTREE "tlstree" 
#endif

static int sig_mac_set_ctx_md_params(void *vsigctx, const OSSL_PARAM params[])
{
    GOST_SIG_MAC_CTX *sigctx = vsigctx;
    const OSSL_PARAM *p = NULL;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_TLSTREE);
    if (p != NULL) {
        const void *tlstree = NULL;
        size_t tlstree_len = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, &tlstree, &tlstree_len))
            return 0;

        if (GOST_digest_ctx_ctrl(sigctx->dctx, EVP_MD_CTRL_TLSTREE,
                                 0, (void *)tlstree) <= 0)
            return 0;
    }

    return 1;
}

static const OSSL_PARAM sig_mac_settable_ctx_md_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_DIGEST_PARAM_TLSTREE, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sig_mac_settable_ctx_md_params(void *vsigctx,
                                                        void *provctx)
{
    (void)vsigctx;
    (void)provctx;
    return sig_mac_settable_ctx_md_params_list;
}

typedef void (*fptr_t)(void);
#define MAKE_SIG_MAC_FUNCTIONS(name, macsize)                                   \
    const GOST_SIG_MAC_DESC name##_sig_mac_desc = {                             \
        &name,                                                                  \
        macsize,                                                                \
    };                                                                          \
    static OSSL_FUNC_signature_newctx_fn name##_newctx;                         \
    static void *name##_newctx(void *provctx, const char *propq)                \
    {                                                                           \
        (void)propq;                                                            \
        return sig_mac_newctx(provctx, &name##_sig_mac_desc);                   \
    }                                                                           \
    const OSSL_DISPATCH id_##name##_signature_mac_functions[] = {               \
        { OSSL_FUNC_SIGNATURE_NEWCTX, (fptr_t)name##_newctx },                  \
        { OSSL_FUNC_SIGNATURE_FREECTX, (fptr_t)sig_mac_freectx },               \
        { OSSL_FUNC_SIGNATURE_DUPCTX, (fptr_t)sig_mac_dupctx },                 \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                 \
          (fptr_t)sig_mac_digest_sign_init },                                   \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,                               \
          (fptr_t)sig_mac_digest_sign_update },                                 \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,                                \
          (fptr_t)sig_mac_digest_sign_final },                                  \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (fptr_t)sig_mac_digest_sign },       \
        { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,                                \
          (fptr_t)sig_mac_set_ctx_md_params },                                  \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,                           \
          (fptr_t)sig_mac_settable_ctx_md_params },                             \
        OSSL_DISPATCH_END                                                       \
    }

MAKE_SIG_MAC_FUNCTIONS(Gost28147_89_mac, 4);
MAKE_SIG_MAC_FUNCTIONS(Gost28147_89_mac_12, 4);
MAKE_SIG_MAC_FUNCTIONS(magma_omac_mac, 8);
MAKE_SIG_MAC_FUNCTIONS(grasshopper_omac_mac, 16);
