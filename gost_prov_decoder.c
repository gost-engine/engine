#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include "gost_prov.h"
#include "gost_lcl.h"
#include <openssl/asn1t.h>
#include <ctype.h>

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the structure specific ones
 * MAKE_DECODER_FUNCTIONS() does it for us.
 */
static OSSL_FUNC_decoder_newctx_fn decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn decoder_freectx;

typedef struct {
    PROV_CTX *provctx;
} GOST_DECODER_CTX;

typedef int  (st2ec_fn)(EC_KEY *ec, int *key_type, const void *st);
typedef void *(bio2st_fn)(BIO *bio, void **st);
typedef void (st_free_fn)(void *st);

typedef struct {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;
} x509_pubkey_st;

typedef struct {
    int key_type;
    unsigned char *data;
    long int data_size;
} params_st;

ASN1_NDEF_SEQUENCE(x509_pubkey_st) = {
    ASN1_SIMPLE(x509_pubkey_st, algor, X509_ALGOR),
    ASN1_SIMPLE(x509_pubkey_st, public_key, ASN1_BIT_STRING)
} ASN1_NDEF_SEQUENCE_END(x509_pubkey_st)

IMPLEMENT_ASN1_FUNCTIONS(x509_pubkey_st)

static st2ec_fn pkcs8_decode_wrapper;
static bio2st_fn pkcs8_read_bio_der_wrapper;
static st_free_fn pkcs8_free_wrapper;

static st2ec_fn x509_pub_decode_wrapper;
static bio2st_fn x509_pub_read_bio_der_wrapper;
static st_free_fn x509_pub_free_wrapper;

static st2ec_fn param_decode_wrapper;
static bio2st_fn param_read_bio_pem_wrapper;
static st_free_fn param_free_wrapper;

static int pkcs8_decode_wrapper(EC_KEY *ec, int *key_type, const void *st)
{
    return internal_priv_decode(ec, key_type, (PKCS8_PRIV_KEY_INFO *)st);
}
static void *pkcs8_read_bio_der_wrapper(BIO *bio, void **st)
{
    return d2i_PKCS8_PRIV_KEY_INFO_bio(bio, (PKCS8_PRIV_KEY_INFO **)st);
}
static void pkcs8_free_wrapper(void *st)
{
    PKCS8_PRIV_KEY_INFO_free((PKCS8_PRIV_KEY_INFO *)st);
}

static int x509_pub_decode_wrapper(EC_KEY *ec, int *key_type, const void *st)
{
    return internal_pub_decode_ec(ec, key_type,
                                  ((x509_pubkey_st *)st)->algor,
                                  ((x509_pubkey_st *)st)->public_key->data,
                                  ((x509_pubkey_st *)st)->public_key->length);
}
static void *x509_pub_read_bio_der_wrapper(BIO *bio, void **st)
{
    unsigned char *data = NULL;
    size_t dlen;

    dlen = BIO_get_mem_data(bio, &data);
    if (!dlen)
        return 0;
    return d2i_x509_pubkey_st((x509_pubkey_st **)st, (const unsigned char **) &data, dlen);
}
static void x509_pub_free_wrapper(void *st)
{
    x509_pubkey_st_free((x509_pubkey_st *)st);
}

static int param_decode_wrapper(EC_KEY *ec, int *key_type, const void *st)
{
    const params_st *params = (const params_st *)st;
    const unsigned char *pdata = params->data;

    if (!internal_gost2001_param_decode(ec, &pdata, params->data_size))
        return 0;

    *key_type = params->key_type;

    return 1;
}

static int get_key_type_from_pem_name(char *pem_name)
{
    if (!pem_name)
        return NID_undef;

    char *space_pos = strchr(pem_name, ' ');
    if (space_pos)
        *space_pos = '\0';

    size_t i;
    for (i = 0; pem_name[i]; ++i)
        pem_name[i] = tolower((unsigned char)pem_name[i]);

    return OBJ_sn2nid(pem_name);
}

static void *param_read_bio_pem_wrapper(BIO *bio, void **st)
{
    params_st *params = NULL;
    char *name = NULL;
    char *header = NULL;

    params = OPENSSL_zalloc(sizeof(params_st));
    if (!params)
        goto exit;

    int len = PEM_read_bio(bio, &name, &header,
                           &params->data,
                           &params->data_size);

    if (len <= 0 || name == NULL)
        goto exit;

    params->key_type = get_key_type_from_pem_name(name);
    if (params->key_type == NID_undef)
        goto exit;
exit:
    OPENSSL_free(name);
    OPENSSL_free(header);

    *st = params;
    return *st;
}

static void param_free_wrapper(void *st)
{
    params_st *params = (params_st *)st;

    if (!params)
        return;

    OPENSSL_free(params->data);
    OPENSSL_free(params);
}

static void *decoder_newctx(void *provctx)
{
    if (!provctx)
        return NULL;

    GOST_DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(GOST_DECODER_CTX));
    if (!ctx)
        return NULL;

    ctx->provctx = provctx;
    return ctx;
}

static void decoder_freectx(void *ctx)
{
    GOST_DECODER_CTX *ectx = ctx;

    OPENSSL_free(ectx);
}

static int decoder_does_selection(int selection, int selection_mask)
{
    return FLAGS_INTERSECT(selection, selection_mask);
}

static int decoder_decode(void *ctx, OSSL_CORE_BIO *cbio, int selection,
                          int selection_mask, OSSL_CALLBACK *data_cb,
                          void *data_cdarg, bio2st_fn *bio2st,
                          st2ec_fn *st2ec, st_free_fn *st_free)
{
    GOST_DECODER_CTX *dctx = NULL;
    GOST_KEY_DATA *key_data = NULL;
    BIO *bio = NULL;
    void *st = NULL;
    int ret = 1;

    if (!FLAGS_INTERSECT(selection, selection_mask))
        goto exit;

    if (!cbio || !data_cb)
        goto exit;

    dctx = ctx;
    if (!dctx || !dctx->provctx || !dctx->provctx->libctx)
        goto exit;

    bio = BIO_new_from_core_bio(dctx->provctx->libctx, cbio);
    if (!bio)
        goto exit;

    if (!bio2st(bio, &st))
        goto exit;

    key_data = OPENSSL_zalloc(sizeof(GOST_KEY_DATA));
    if (!key_data) {
        ret = 0;
        goto exit;
    }

    key_data->ec = EC_KEY_new();
    if (!key_data->ec) {
        ret = 0;
        goto exit;
    }

    if (!st2ec(key_data->ec, &key_data->type, st))
        goto exit;

    key_data->param_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key_data->ec));
    if (key_data->param_nid == NID_undef) {
        ret = 0;
        goto exit;
    }

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)OBJ_nid2sn(key_data->type), 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &key_data, sizeof(key_data));
    params[3] = OSSL_PARAM_construct_end();

    ret = data_cb(params, data_cdarg);

exit:

    keymgmt_free(key_data);
    BIO_free(bio);
    st_free(st);
    return ret;
}

typedef void (*fptr_t)(void);
#define MAKE_DECODER_FUNCTIONS(input, structure, bio2st, st2ec, st_free, selection_mask) \
    static OSSL_FUNC_decoder_decode_fn input##_##structure##_decoder_decode; \
    static int input##_##structure##_decoder_decode(void *ctx, OSSL_CORE_BIO *cbio, \
                                                    int selection, \
                                                    OSSL_CALLBACK *data_cb, \
                                                    void *data_cdarg, \
                                                    OSSL_PASSPHRASE_CALLBACK *cb, \
                                                    void *cbarg) \
    { \
        return decoder_decode(ctx, cbio, selection, selection_mask, data_cb, data_cdarg, \
                              bio2st, st2ec, st_free); \
    } \
    static OSSL_FUNC_decoder_does_selection_fn \
    input##_##structure##_decoder_does_selection; \
    static int input##_##structure##_decoder_does_selection(void *ctx, \
                                                            int selection) \
    { \
        return decoder_does_selection(selection, selection_mask); \
    } \
    static const OSSL_DISPATCH id_##input##_##structure##_decoder_functions[] = { \
        { OSSL_FUNC_DECODER_NEWCTX, (fptr_t)decoder_newctx }, \
        { OSSL_FUNC_DECODER_FREECTX, (fptr_t)decoder_freectx }, \
        { OSSL_FUNC_DECODER_DOES_SELECTION, \
          (fptr_t)input##_##structure##_decoder_does_selection }, \
        { OSSL_FUNC_DECODER_DECODE, (fptr_t)input##_##structure##_decoder_decode }, \
        { 0, NULL } \
    };

#define DECODER(decoder_name, input, structure) \
    { \
        decoder_name, \
        "provider=gostprov,input=" #input ",structure=" #structure, \
        (id_##input##_##structure##_decoder_functions) \
    }

MAKE_DECODER_FUNCTIONS(der, PrivateKeyInfo, pkcs8_read_bio_der_wrapper,
                       pkcs8_decode_wrapper, pkcs8_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PRIVATE_KEY)

MAKE_DECODER_FUNCTIONS(der, SubjectPublicKeyInfo, x509_pub_read_bio_der_wrapper,
                       x509_pub_decode_wrapper, x509_pub_free_wrapper,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
MAKE_DECODER_FUNCTIONS(pem, type_specific, param_read_bio_pem_wrapper,
                       param_decode_wrapper, param_free_wrapper,
                       OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

/*
 * Each algorithm of PRIVATE KEYS (PrivateKeyInfo) and PUBLIC KEYS (SubjectPublicKeyInfo)
 * is registered separately because OpenSSL extracts the algorithm OID from ASN.1
 * structure and directly maps it to the specific decoder (no iteration needed).
 *
 * Decoding of the keys from PEM to DER happens in default provider, while the key
 * parameters (type_specific) are decoded directly from PEM since the PEM header
 * is crucial for the algorithm identification.
 */
const OSSL_ALGORITHM GOST_prov_decoder[] = {
    DECODER(ALG_NAME_GOST2001, der, SubjectPublicKeyInfo),
    DECODER(ALG_NAME_GOST2001, pem, type_specific), /* Decode domain parameters */
    DECODER(ALG_NAME_GOST2001DH, der, SubjectPublicKeyInfo),
    DECODER(ALG_NAME_GOST2012_256, der, SubjectPublicKeyInfo),
    DECODER(ALG_NAME_GOST2012_512, der, SubjectPublicKeyInfo),
    DECODER(ALG_NAME_GOST2001, der, PrivateKeyInfo),
    DECODER(ALG_NAME_GOST2001DH, der, PrivateKeyInfo),
    DECODER(ALG_NAME_GOST2012_256, der, PrivateKeyInfo),
    DECODER(ALG_NAME_GOST2012_512, der, PrivateKeyInfo),
    { NULL, NULL, NULL }
};
