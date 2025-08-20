#include <openssl/core_dispatch.h>
#include "gost_prov.h"
#include "gost_lcl.h"

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the algorithm and structure specific ones
 * MAKE_ENCODER_FUNCTIONS() and MAKE_ENCODER_TEXT_FUNCTIONS() does it for us.
 */
static OSSL_FUNC_encoder_freectx_fn encoder_freectx;
static OSSL_FUNC_encoder_newctx_fn encoder_newctx;

typedef void * (st_new_fn)(void);
typedef int (ec2st_encode_fn)(void *st, const EC_KEY *key, int key_type);
typedef int (st2bio_fn)(BIO *bio, void *st);
typedef void (st_free_fn)(void *st);

static st_new_fn pkcs8_new_wrapper;
static ec2st_encode_fn pkcs8_priv_encode_wrapper;
static st2bio_fn pkcs8_write_bio_pem;
static st2bio_fn pkcs8_write_bio_der;
static st_free_fn pkcs8_free_wrapper;
static st_new_fn x509_pub_new_wrapper;
static ec2st_encode_fn x509_pub_encode_wrapper;
static st2bio_fn x509_write_bio_pem;
static st2bio_fn x509_write_bio_der;
static st_free_fn x509_pub_free_wrapper;

static void *pkcs8_new_wrapper(void)
{
    return PKCS8_PRIV_KEY_INFO_new();
}

static int pkcs8_priv_encode_wrapper(void *st, const EC_KEY *key, int key_type)
{
    return internal_priv_encode((PKCS8_PRIV_KEY_INFO *)st, (EC_KEY *)key, key_type);
}

static int pkcs8_write_bio_pem(BIO *bio, void *st)
{
    return PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, (PKCS8_PRIV_KEY_INFO *)st);
}

static int pkcs8_write_bio_der(BIO *bio, void *st)
{
    return i2d_PKCS8_PRIV_KEY_INFO_bio(bio, (PKCS8_PRIV_KEY_INFO *)st);
}

static void pkcs8_free_wrapper(void *st)
{
    PKCS8_PRIV_KEY_INFO_free((PKCS8_PRIV_KEY_INFO *)st);
}

static void *x509_pub_new_wrapper(void)
{
    return X509_PUBKEY_new();
}

static int x509_pub_encode_wrapper(void *st, const EC_KEY *key, int key_type)
{
    return internal_pub_encode_ec((X509_PUBKEY *)st, (EC_KEY *)key, key_type);
}

static int x509_write_bio_pem(BIO *bio, void *st)
{
    return PEM_write_bio_X509_PUBKEY(bio, (X509_PUBKEY *)st);
}

static int x509_write_bio_der(BIO *bio, void *st)
{
    return i2d_X509_PUBKEY_bio(bio, (X509_PUBKEY *)st);
}

static void x509_pub_free_wrapper(void *st)
{
    X509_PUBKEY_free((X509_PUBKEY *)st);
}

typedef struct {
    PROV_CTX *provctx;
} GOST_ENCODER_CTX;

static void encoder_freectx(void *ctx)
{
    GOST_ENCODER_CTX *ectx = ctx;

    OPENSSL_free(ectx);
}

static void *encoder_newctx(void *provctx)
{
    if (!provctx)
        return NULL;

    GOST_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(GOST_ENCODER_CTX));
    if (!ctx)
        return NULL;

    ctx->provctx = provctx;
    return ctx;
}

static int encoder_does_selection(int selection, int selection_mask)
{
    return FLAGS_INTERSECT(selection, selection_mask);
}

static int encoder_encode(
                          void *ctx,
                          OSSL_CORE_BIO *cbio,
                          const void *key,
                          const OSSL_PARAM key_params[],
                          int selection,
                          int selection_mask,
                          st_new_fn *st_new,
                          ec2st_encode_fn *ec2st_encode,
                          st2bio_fn *st2bio,
                          st_free_fn *st_free)
{
    int ok = 0;
    BIO *out = NULL;
    void *key_st = NULL;
    GOST_ENCODER_CTX *ectx = NULL;
    const GOST_KEY_DATA *key_data = NULL;

    if (!ctx || !cbio || !key)
        goto exit;

    if (key_params != NULL)
        goto exit;

    if (!FLAGS_INTERSECT(selection, selection_mask))
        goto exit;

    ectx = ctx;
    key_data = key;

    if (!ectx->provctx || !ectx->provctx->libctx)
        goto exit;

    out = BIO_new_from_core_bio(ectx->provctx->libctx, cbio);
    if (!out)
        goto exit;

    key_st = st_new();
    if (!key_st)
        goto exit;

    if (!ec2st_encode(key_st, key_data->ec, key_data->type))
        goto exit;

    if (!st2bio(out, key_st))
        goto exit;

    ok = 1;

exit:
    st_free(key_st);
    BIO_free(out);
    return ok;
}

static int encoder_text_encode(void *vctx, OSSL_CORE_BIO *cbio,
                               const void *key, const OSSL_PARAM key_params[],
                               int selection, int selection_mask)
{
    GOST_ENCODER_CTX *ctx = vctx;
    const GOST_KEY_DATA *key_data = key;
    BIO *out = NULL;
    int ok = 0;

    if (!ctx || !cbio || !key)
        goto exit;

    if (!FLAGS_INTERSECT(selection, selection_mask))
        goto exit;

    out = BIO_new_from_core_bio(ctx->provctx->libctx, cbio);
    if (!out)
        goto exit;

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        && !internal_print_gost_priv(out, key_data->ec, 0, key_data->type))
        goto exit;

    if (FLAGS_INTERSECT(selection, OSSL_KEYMGMT_SELECT_KEYPAIR)
        && !internal_print_gost_ec_pub(out, key_data->ec, 0, key_data->type))
        goto exit;

    if (!internal_print_gost_ec_param(out, key_data->ec, 0))
        goto exit;

    ok = 1;

exit:
    BIO_free(out);
    return ok;
}

typedef void (*fptr_t)(void);
#define MAKE_ENCODER_FUNCTIONS(alg, output, structure, st_new_fn, ec2st_encode, write_key_st, \
                               key_st_free, selection_mask) \
    static OSSL_FUNC_encoder_encode_fn alg##_##output##_##structure##_encoder_encode; \
    static int alg##_##output##_##structure##_encoder_encode( \
                                                             void *ctx, \
                                                             OSSL_CORE_BIO *cbio, \
                                                             const void *key, \
                                                             const OSSL_PARAM key_params[], \
                                                             int selection, \
                                                             OSSL_PASSPHRASE_CALLBACK *cb, \
                                                             void *cbarg) \
    { \
        return encoder_encode( \
                              ctx, cbio, key, key_params, \
                              selection, selection_mask, \
                              st_new_fn, ec2st_encode, write_key_st, key_st_free);  \
    } \
    static OSSL_FUNC_encoder_does_selection_fn \
    alg##_##output##_##structure##_encoder_does_selection; \
    static int alg##_##output##_##structure##_encoder_does_selection(void *ctx, int selection) \
    { \
        return encoder_does_selection(selection, selection_mask); \
    } \
    static const OSSL_DISPATCH id_##alg##_##output##_##structure##_encoder_functions[] = \
        { \
         { OSSL_FUNC_ENCODER_NEWCTX, (fptr_t)encoder_newctx }, \
         { OSSL_FUNC_ENCODER_FREECTX, (fptr_t)encoder_freectx }, \
         { OSSL_FUNC_ENCODER_DOES_SELECTION, \
           (fptr_t)alg##_##output##_##structure##_encoder_does_selection }, \
         { OSSL_FUNC_ENCODER_ENCODE, (fptr_t)alg##_##output##_##structure##_encoder_encode }, \
         { 0, NULL } \
        }; \

#define MAKE_ENCODER_TEXT_FUNCTIONS(alg, output, selection_mask) \
    static OSSL_FUNC_encoder_encode_fn alg##_##output##_encoder_text_encode; \
    static int alg##_##output##_encoder_text_encode( \
                                                    void *vctx, \
                                                    OSSL_CORE_BIO *cbio, \
                                                    const void *key, \
                                                    const OSSL_PARAM key_params[], \
                                                    int selection, \
                                                    OSSL_PASSPHRASE_CALLBACK *cb, \
                                                    void *cbarg) \
    { \
        if (key_params != NULL) {                                     \
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);     \
            return 0;                                                   \
        } \
        return encoder_text_encode( \
                                   vctx, cbio, key, key_params, \
                                   selection, selection_mask); \
    } \
    static OSSL_FUNC_encoder_does_selection_fn \
    alg##_##output##_encoder_does_selection; \
    static int alg##_##output##_encoder_does_selection(void *ctx, int selection) \
    { \
        return encoder_does_selection(selection, selection_mask); \
    } \
    static const OSSL_DISPATCH id_##alg##_##output##_encoder_text_functions[] = \
        { \
         { OSSL_FUNC_ENCODER_NEWCTX, (fptr_t)encoder_newctx }, \
         { OSSL_FUNC_ENCODER_FREECTX, (fptr_t)encoder_freectx }, \
         { OSSL_FUNC_ENCODER_DOES_SELECTION, \
           (fptr_t)alg##_##output##_encoder_does_selection }, \
         { OSSL_FUNC_ENCODER_ENCODE, \
           (fptr_t)alg##_##output##_encoder_text_encode }, \
         { 0, NULL } \
        };

#define ENCODER(sn_name, name, output, structure) \
    { \
        sn_name, \
        "provider=gostprov,output=" #output \
        ",structure=" #structure, \
        (id_##name##_##output##_##structure##_encoder_functions) \
    }

#define ENCODER_TEXT(sn_name, name, output) \
    { \
        sn_name, \
        "provider=gostprov,output=" #output, \
        (id_##name##_##output##_encoder_text_functions) \
    }

MAKE_ENCODER_FUNCTIONS(gost2001, pem, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_pem,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2001dh, pem, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_pem,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_256, pem, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_pem,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_512, pem, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_pem,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2001, der, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_der,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2001dh, der, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_der,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_256, der, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_der,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_512, der, PrivateKeyInfo,
                       pkcs8_new_wrapper,
                       pkcs8_priv_encode_wrapper,
                       pkcs8_write_bio_der,
                       pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_ENCODER_FUNCTIONS(gost2001, pem, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_pem,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_FUNCTIONS(gost2001dh, pem, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_pem,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_256, pem, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_pem,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_512, pem, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_pem,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_FUNCTIONS(gost2001, der, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_der,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_FUNCTIONS(gost2001dh, der, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_der,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_256, der, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_der,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_FUNCTIONS(gost2012_512, der, SubjectPublicKeyInfo,
                       x509_pub_new_wrapper,
                       x509_pub_encode_wrapper,
                       x509_write_bio_der,
                       x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

MAKE_ENCODER_TEXT_FUNCTIONS(gost2001, text,
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                            | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

MAKE_ENCODER_TEXT_FUNCTIONS(gost2001dh, text,
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                            | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

MAKE_ENCODER_TEXT_FUNCTIONS(gost2012_256, text,
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                            | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

MAKE_ENCODER_TEXT_FUNCTIONS(gost2012_512, text,
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                            | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

const OSSL_ALGORITHM GOST_prov_encoder[] = {
    ENCODER(ALG_NAME_GOST2001, gost2001, pem, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2001, gost2001, der, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2001, gost2001, pem, SubjectPublicKeyInfo),
    ENCODER(ALG_NAME_GOST2001, gost2001, der, SubjectPublicKeyInfo),
    ENCODER_TEXT(ALG_NAME_GOST2001, gost2001, text),
    ENCODER(ALG_NAME_GOST2001DH, gost2001dh, pem, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2001DH, gost2001dh, der, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2001DH, gost2001dh, pem, SubjectPublicKeyInfo),
    ENCODER(ALG_NAME_GOST2001DH, gost2001dh, der, SubjectPublicKeyInfo),
    ENCODER_TEXT(ALG_NAME_GOST2001DH, gost2001dh, text),
    ENCODER(ALG_NAME_GOST2012_256, gost2012_256, pem, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2012_256, gost2012_256, der, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2012_256, gost2012_256, pem, SubjectPublicKeyInfo),
    ENCODER(ALG_NAME_GOST2012_256, gost2012_256, der, SubjectPublicKeyInfo),
    ENCODER_TEXT(ALG_NAME_GOST2012_256, gost2012_256, text),
    ENCODER(ALG_NAME_GOST2012_512, gost2012_512, pem, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2012_512, gost2012_512, der, PrivateKeyInfo),
    ENCODER(ALG_NAME_GOST2012_512, gost2012_512, pem, SubjectPublicKeyInfo),
    ENCODER(ALG_NAME_GOST2012_512, gost2012_512, der, SubjectPublicKeyInfo),
    ENCODER_TEXT(ALG_NAME_GOST2012_512, gost2012_512, text),
    { NULL, NULL, NULL }
};