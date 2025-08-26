#include <openssl/core_names.h>
#include <assert.h>
#include "gost_prov.h"
#include "gost_lcl.h"

#define GOST_MAX_ECDH_LEN 128

int gost_get_max_keyexch_size(const GOST_KEY_DATA *key_data)
{
    /* You should modify this function when add new derive algorithm */
    return GOST_MAX_ECDH_LEN / 2;
}

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.
 */
static OSSL_FUNC_keyexch_newctx_fn ecdhe_newctx;
static OSSL_FUNC_keyexch_init_fn ecdhe_init;
static OSSL_FUNC_keyexch_set_peer_fn ecdhe_set_peer;
static OSSL_FUNC_keyexch_derive_fn ecdhe_derive;
static OSSL_FUNC_keyexch_freectx_fn ecdhe_freectx;

typedef struct {
    GOST_KEY_DATA *key_data;
    GOST_KEY_DATA *peer_key_data;
} GOST_ECDHE_CTX;

static void *ecdhe_newctx(void *provctx)
{
    GOST_ECDHE_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    return ctx;
}

static int ecdhe_init(void *vctx, void *vkey_data, const OSSL_PARAM params[])
{
    GOST_ECDHE_CTX *ctx = vctx;
    GOST_KEY_DATA *key_data = vkey_data;

    if (!ctx || !key_data || !key_data->ec)
        return 0;

    ctx->key_data = keymgmt_dup(key_data, (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                                           | OSSL_KEYMGMT_SELECT_PRIVATE_KEY));
    if (!ctx->key_data)
        return 0;

    return 1;
}

static int ecdhe_set_peer(void *vctx, void *vpeer_key_data)
{
    GOST_ECDHE_CTX *ctx = vctx;
    GOST_KEY_DATA *peer_key_data = vpeer_key_data;

    if (!ctx || !ctx->key_data || !ctx->key_data->ec || !peer_key_data || !peer_key_data->ec)
        return 0;

    if (!EC_KEY_get0_public_key(peer_key_data->ec))
        return 0;

    if (!keymgmt_match(ctx->key_data, peer_key_data, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
        return 0;

    keymgmt_free(ctx->peer_key_data);
    ctx->peer_key_data = keymgmt_dup(peer_key_data, (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                                                     | OSSL_KEYMGMT_SELECT_PUBLIC_KEY));
    if (!ctx->peer_key_data)
        return 0;

    return 1;
}

static void ecdhe_freectx(void *vctx)
{
    GOST_ECDHE_CTX *ctx = (GOST_ECDHE_CTX *)vctx;

    if (!ctx)
        return;

    keymgmt_free(ctx->key_data);
    keymgmt_free(ctx->peer_key_data);
    OPENSSL_free(ctx);
}

static int ecdhe_derive(void *vctx, unsigned char *secret,
                        size_t *psecretlen, size_t outlen)
{
    GOST_ECDHE_CTX *ctx = vctx;
    size_t ecdh_result_len;
    unsigned char ecdh_result[GOST_MAX_ECDH_LEN];
    const unsigned char ukm[] = {1};

    if (!psecretlen
        || !ctx
        || !ctx->key_data
        || !ctx->peer_key_data
        || !ctx->peer_key_data->ec
        || !internal_compute_ecdh(NULL, &ecdh_result_len, ukm, sizeof(ukm),
                                  EC_KEY_get0_public_key(ctx->peer_key_data->ec),
                                  ctx->key_data->ec))
        return 0;

    assert(ecdh_result_len <= sizeof(ecdh_result));

    /* Return only X coordinate */
    *psecretlen = ecdh_result_len >> 1;

    if (!secret)
        return 1;

    if (outlen < *psecretlen)
        return 0;

    if (!internal_compute_ecdh(ecdh_result, &ecdh_result_len, ukm, sizeof(ukm),
                               EC_KEY_get0_public_key(ctx->peer_key_data->ec), ctx->key_data->ec))
        return 0;

    memcpy(secret, ecdh_result, *psecretlen);
    OPENSSL_cleanse(ecdh_result, sizeof(ecdh_result));

    return 1;
}

static const OSSL_DISPATCH ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))ecdhe_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))ecdhe_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))ecdhe_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))ecdhe_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))ecdhe_freectx },
    OSSL_DISPATCH_END
};

const OSSL_ALGORITHM GOST_prov_keyexch[] = {
    { "ECDHE", NULL, ecdh_keyexch_functions },
    { NULL, NULL, NULL }
};