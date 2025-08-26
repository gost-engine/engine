#include <assert.h>
#include <openssl/core_names.h>
#include "gost_prov.h"
#include "gost_lcl.h"

#define GOST_MAX_ALG_NAME_SIZE      50 /* Algorithm name */
#define GOST_MAX_PROPQUERY_SIZE     256 /* Property query strings */
#define GOST_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#define SIGN_OPERATION 0
#define VERIFY_OPERATION 1

int gost_get_max_signature_size(const GOST_KEY_DATA *key_data)
{
    int size = -1;

    switch (key_data->type) {
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2001DH:
    case NID_id_GostR3410_2012_256:
        size = 64;
        break;
    case NID_id_GostR3410_2012_512:
        size = 128;
        break;
    default:
        assert(!"Invalid key type");
    }

    return size;
}

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.
 */
static OSSL_FUNC_signature_newctx_fn signature_newctx;
static OSSL_FUNC_signature_freectx_fn signature_free;
static OSSL_FUNC_signature_digest_sign_init_fn signature_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn signature_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn signature_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn signature_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn signature_digest_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn signature_digest_verify_final;
static OSSL_FUNC_signature_get_ctx_params_fn signature_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn signature_gettable_ctx_params;

typedef struct {
    PROV_CTX *provctx;
    GOST_KEY_DATA *key_data;
    char *propq;
    EVP_MD_CTX *mdctx;
    EVP_MD *md;
    int operation;
} GOST_SIGNATURE_CTX;

typedef struct {
    int key_type;
    const char *sn;
} GOST_SUPPORTED_HASH;

static const GOST_SUPPORTED_HASH supported_hash[] = {
    {NID_id_GostR3410_2012_256, SN_id_GostR3411_2012_256},
    {NID_id_GostR3410_2012_512, SN_id_GostR3411_2012_512},
    {NID_id_GostR3410_2001, SN_id_GostR3411_94},
};

static void signature_free(void *vctx)
{
    if (!vctx)
        return;

    GOST_SIGNATURE_CTX *ctx = vctx;

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->propq);
    keymgmt_free(ctx->key_data);
    OPENSSL_free(ctx);
}

static void *signature_newctx(void *vprovctx, const char *propq)
{
    if (!vprovctx)
        return NULL;

    GOST_SIGNATURE_CTX *ctx = OPENSSL_zalloc(sizeof(GOST_SIGNATURE_CTX));
    if (!ctx)
        return NULL;

    ctx->provctx = vprovctx;
    if (propq && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

static int is_digest_supported_for_key(int key_type, const EVP_MD *md)
{
    size_t i;

    for (i = 0; i < GOST_NELEM(supported_hash); ++i) {
        if (supported_hash[i].key_type == key_type && EVP_MD_is_a(md, supported_hash[i].sn))
            return 1;
    }

    return 0;
}

static int signature_setup_md(GOST_SIGNATURE_CTX *ctx, const char *mdname, const char *mdprops)
{
    EVP_MD *md = NULL;

    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname == NULL)
        return 0;

    md = EVP_MD_fetch(ctx->provctx->libctx, mdname, mdprops);
    if (md == NULL)
        return 0;

    if (!is_digest_supported_for_key(ctx->key_data->type, md)) {
        EVP_MD_free(md);
        return 0;
    }

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);

    ctx->mdctx = NULL;
    ctx->md = md;

    return 1;
}

static int signature_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    GOST_SIGNATURE_CTX *ctx = vctx;
    const OSSL_PARAM *p, *propsp;
    char mdname[GOST_MAX_ALG_NAME_SIZE] = "", *pmdname = mdname;
    char mdprops[GOST_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;

    if (params == NULL)
        return 1;

    propsp = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
    if (propsp != NULL
        && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL
        && !OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
        return 0;

    if ((p != NULL || propsp != NULL) && !signature_setup_md(ctx, mdname, mdprops))
        return 0;

    return 1;
}

static int signature_get_algorithm_id(GOST_SIGNATURE_CTX *ctx, OSSL_PARAM *p)
{
    int nid;
    ASN1_OBJECT *oid = NULL;
    X509_ALGOR *algor = NULL;
    unsigned char *der = NULL;
    int derlen;
    int ret = 0;

    if (ctx == NULL || ctx->key_data == NULL)
        return 0;

    switch (ctx->key_data->type) {
    case NID_id_GostR3410_2001:
        nid = NID_id_GostR3411_94_with_GostR3410_2001;
        break;
    case NID_id_GostR3410_2012_256:
        nid = NID_id_tc26_signwithdigest_gost3410_2012_256;
        break;
    case NID_id_GostR3410_2012_512:
        nid = NID_id_tc26_signwithdigest_gost3410_2012_512;
        break;
    default:
        return 0;
    }

    oid = OBJ_nid2obj(nid);
    if (oid == NULL)
        goto cleanup;

    algor = X509_ALGOR_new();
    if (algor == NULL)
        goto cleanup;

    X509_ALGOR_set0(algor, oid, V_ASN1_NULL, NULL);
    oid = NULL;

    derlen = i2d_X509_ALGOR(algor, &der);
    if (derlen <= 0)
        goto cleanup;

    if (!OSSL_PARAM_set_octet_string(p, der, derlen))
        goto cleanup;

    ret = 1;

cleanup:
    X509_ALGOR_free(algor);
    ASN1_OBJECT_free(oid);
    OPENSSL_free(der);
    return ret;
}

static int signature_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    if (vctx == NULL)
        return 0;

    GOST_SIGNATURE_CTX *ctx = vctx;

    if (params == NULL)
        return 1;

    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !signature_get_algorithm_id(ctx, p))
        return 0;

    return 1;
}

static const OSSL_PARAM signature_gettable_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *signature_gettable_ctx_params(void *vctx, void *provctx)
{
    return signature_gettable_params;
}

static int signature_signverify_init(GOST_SIGNATURE_CTX *ctx, void *key_data,
                                     const OSSL_PARAM params[], int operation)
{
    ctx->key_data = keymgmt_dup(key_data,
                                (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS |
                                 (operation == SIGN_OPERATION ?
                                  OSSL_KEYMGMT_SELECT_PRIVATE_KEY :
                                  OSSL_KEYMGMT_SELECT_PUBLIC_KEY)));
    if (ctx->key_data == NULL)
        return 0;

    ctx->operation = operation;

    if (!signature_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int signature_digest_signverify_init(GOST_SIGNATURE_CTX *ctx, const char *mdname,
                                            void *key_data, const OSSL_PARAM params[],
                                            int operation)
{
    if (!ctx
        || !ctx->provctx
        || !ctx->provctx->libctx
        || !key_data)
        goto error;

    if (!signature_signverify_init(ctx, key_data, params,
                                   operation))
        goto error;

    if ((mdname != NULL) && !signature_setup_md(ctx, mdname, NULL))
        goto error;

    if (!ctx->md)
        goto error;

    if (ctx->mdctx == NULL && ((ctx->mdctx = EVP_MD_CTX_new()) == NULL))
        goto error_clean_md;

    if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
        goto error_clean_md;

    return 1;
error_clean_md:
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->md = NULL;
    ctx->mdctx = NULL;
error:
    return 0;
}

static int signature_signverify_message_update(GOST_SIGNATURE_CTX *ctx,
                                               const unsigned char *data, size_t datalen)
{
    if (!ctx->mdctx)
        return 0;

    if (!data && datalen)
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static int signature_digest_sign_init(void *ctx, const char *mdname,
                                      void *provkey,
                                      const OSSL_PARAM params[])
{
    return signature_digest_signverify_init(ctx, mdname, provkey, params, SIGN_OPERATION);
}

static int signature_digest_sign_update(void *vctx, const unsigned char *data,
                                        size_t datalen)
{
    GOST_SIGNATURE_CTX *ctx = vctx;

    if (!ctx || ctx->operation != SIGN_OPERATION)
        return 0;

    return signature_signverify_message_update(ctx, data, datalen);
}

static int signature_digest_sign_final(void *vctx, unsigned char *sig,
                                       size_t *siglen, size_t sigsize)
{
    GOST_SIGNATURE_CTX *ctx = vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!ctx
        || !ctx->mdctx
        || !siglen
        || ctx->operation != SIGN_OPERATION)
        return 0;

    if (sig != NULL
        && !EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    *siglen = sigsize;
    return internal_pkey_ec_cp_sign(ctx->key_data->ec, ctx->key_data->type, sig,
                                    siglen, digest, dlen);
}

static int signature_digest_verify_init(void *ctx, const char *mdname,
                                        void *provkey,
                                        const OSSL_PARAM params[])
{
    return signature_digest_signverify_init(ctx, mdname, provkey, params, VERIFY_OPERATION);
}

static int signature_digest_verify_update(void *vctx, const unsigned char *data,
                                          size_t datalen)
{
    GOST_SIGNATURE_CTX *ctx = vctx;

    if (!ctx || ctx->operation != VERIFY_OPERATION)
        return 0;

    return signature_signverify_message_update(ctx, data, datalen);
}

static int signature_digest_verify_final(void *vctx, const unsigned char *sig,
                                         size_t siglen)
{
    GOST_SIGNATURE_CTX *ctx = vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!sig || !ctx || !ctx->mdctx || ctx->operation != VERIFY_OPERATION)
        return 0;

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    return internal_pkey_ec_cp_verify(ctx->key_data->ec, sig, siglen, digest, dlen);
}

typedef void (*fptr_t)(void);
static const OSSL_DISPATCH id_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (fptr_t)signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (fptr_t)signature_free },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (fptr_t)signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (fptr_t)signature_gettable_ctx_params},
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (fptr_t)signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (fptr_t)signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (fptr_t)signature_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (fptr_t)signature_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (fptr_t)signature_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (fptr_t)signature_digest_verify_final},
    { 0, NULL }
};

const OSSL_ALGORITHM GOST_prov_signature[] = {
    {
        SN_id_GostR3410_2001
        ":" SN_id_GostR3411_94_with_GostR3410_2001
        ":" LN_id_GostR3411_94_with_GostR3410_2001
        ":" OID_id_GostR3411_94_with_GostR3410_2001,
        NULL,
        id_signature_functions
    },
    {
        SN_id_GostR3410_2012_256
        ":" SN_id_tc26_signwithdigest_gost3410_2012_256
        ":" LN_id_tc26_signwithdigest_gost3410_2012_256
        ":" OID_id_tc26_signwithdigest_gost3410_2012_256,
        NULL,
        id_signature_functions
    },
    {
        SN_id_GostR3410_2012_512
        ":" SN_id_tc26_signwithdigest_gost3410_2012_512
        ":" LN_id_tc26_signwithdigest_gost3410_2012_512
        ":" OID_id_tc26_signwithdigest_gost3410_2012_512,
        NULL,
        id_signature_functions
    },
    { NULL, NULL, NULL }
};
