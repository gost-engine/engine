/**********************************************************************
 *          gost_prov_keymgmt_mac.c - keymgmt for MAC keys            *
 *                                                                    *
 *      This file is distributed under the same license as OpenSSL    *
 *                                                                    *
 *     Provider keymgmt for GOST MAC secret keys (gost-mac,           *
 *     gost-mac-12, magma-mac, kuznyechik-mac), requires OpenSSL 3.0  *
 **********************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "gost_prov.h"
#include "gost_lcl.h"

#define MAC_KEY_SIZE 32

/*
 * Key data for GOST MAC operations is a 32-byte secret key (see
 * GOST_MAC_KEY_DATA in gost_prov.h).
 * There is no public part and no domain parameters, so most of the
 * generic keymgmt functions are stubs, like in the reference
 * rutoken-ossl-provider (src/secret/keymgmt_mac.cpp).
 */

typedef struct gost_mac_gen_ctx_st {
    unsigned char key[MAC_KEY_SIZE];
    int key_set;
} GOST_MAC_GEN_CTX;

static void *keymgmt_mac_new(void *provctx)
{
    (void)provctx;
    /* Key data can't be constructed without a key value */
    return NULL;
}

static void *keymgmt_mac_load(const void *reference, size_t reference_sz)
{
    (void)reference;
    (void)reference_sz;
    return NULL;
}

static int keymgmt_mac_has(const void *keydata, int selection)
{
    (void)keydata;
    (void)selection;
    return 0;
}

static void keymgmt_mac_free(void *keydata)
{
    GOST_MAC_KEY_DATA *key = keydata;

    if (!key)
        return;

    OPENSSL_cleanse(key->key, sizeof(key->key));
    OPENSSL_free(key);
}

static void keymgmt_mac_gen_cleanup(void *genctx)
{
    GOST_MAC_GEN_CTX *gctx = genctx;

    if (!gctx)
        return;

    OPENSSL_cleanse(gctx->key, sizeof(gctx->key));
    OPENSSL_free(gctx);
}

static const OSSL_PARAM keymgmt_mac_gen_settable_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keymgmt_mac_gen_settable_params(void *genctx,
                                                         void *provctx)
{
    (void)genctx;
    (void)provctx;
    return keymgmt_mac_gen_settable_params_list;
}

int keymgmt_mac_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    GOST_MAC_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p = NULL;

    if (!gctx)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p == NULL)
        return 1;

    if (p->data_type != OSSL_PARAM_OCTET_STRING || p->data_size != MAC_KEY_SIZE)
        return 0;

    memcpy(gctx->key, p->data, MAC_KEY_SIZE);
    gctx->key_set = 1;

    return 1;
}

static void *keymgmt_mac_gen_init(void *provctx, int selection,
                                  const OSSL_PARAM params[])
{
    (void)provctx;

    if (selection != OSSL_KEYMGMT_SELECT_KEYPAIR)
        return NULL;

    GOST_MAC_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(GOST_MAC_GEN_CTX));
    if (!gctx)
        return NULL;

    if (params && !keymgmt_mac_gen_set_params(gctx, params)) {
        keymgmt_mac_gen_cleanup(gctx);
        return NULL;
    }

    return gctx;
}

static void *keymgmt_mac_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    GOST_MAC_GEN_CTX *gctx = genctx;
    GOST_MAC_KEY_DATA *key = NULL;

    (void)osslcb;
    (void)cbarg;

    if (!gctx)
        return NULL;

    key = OPENSSL_zalloc(sizeof(GOST_MAC_KEY_DATA));
    if (!key)
        return NULL;

    if (gctx->key_set) {
        memcpy(key->key, gctx->key, MAC_KEY_SIZE);
    } else if (RAND_bytes(key->key, MAC_KEY_SIZE) <= 0) {
        keymgmt_mac_free(key);
        return NULL;
    }

    return key;
}

typedef void (*fptr_t)(void);
#define MAKE_KEYMGMT_MAC_FUNCTIONS(alg, alg_sn)                                        \
    static OSSL_FUNC_keymgmt_query_operation_name_fn alg##_query_operation_name;       \
    static const char *alg##_query_operation_name(int operation_id)                    \
    {                                                                                  \
        switch (operation_id) {                                                        \
        case OSSL_OP_SIGNATURE:                                                        \
            return alg_sn;                                                             \
        default:                                                                       \
            return NULL;                                                               \
        }                                                                              \
    }                                                                                  \
    const OSSL_DISPATCH id_##alg##_keymgmt_mac_functions[] = {                         \
        { OSSL_FUNC_KEYMGMT_NEW, (fptr_t)keymgmt_mac_new },                            \
        { OSSL_FUNC_KEYMGMT_FREE, (fptr_t)keymgmt_mac_free },                          \
        { OSSL_FUNC_KEYMGMT_HAS, (fptr_t)keymgmt_mac_has },                            \
        { OSSL_FUNC_KEYMGMT_LOAD, (fptr_t)keymgmt_mac_load },                          \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (fptr_t)keymgmt_mac_gen_init },                  \
        { OSSL_FUNC_KEYMGMT_GEN, (fptr_t)keymgmt_mac_gen },                            \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (fptr_t)keymgmt_mac_gen_cleanup },            \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (fptr_t)keymgmt_mac_gen_set_params },      \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                       \
          (fptr_t)keymgmt_mac_gen_settable_params },                                   \
        { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                      \
          (fptr_t)alg##_query_operation_name },                                        \
        OSSL_DISPATCH_END                                                              \
    };

MAKE_KEYMGMT_MAC_FUNCTIONS(gost_mac, SN_id_Gost28147_89_MAC);
MAKE_KEYMGMT_MAC_FUNCTIONS(gost_mac_12, SN_gost_mac_12);
MAKE_KEYMGMT_MAC_FUNCTIONS(magma_mac, SN_magma_mac);
MAKE_KEYMGMT_MAC_FUNCTIONS(kuznyechik_mac, SN_kuznyechik_mac);
