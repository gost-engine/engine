/**********************************************************************
 *                     gost_prov_asym_cipher.c                        *
 *                                                                    *
 *        Provider key transport (OSSL_OP_ASYM_CIPHER) for GOST       *
 *                                                                    *
 *   Implements the CryptoPro key transport (RFC 4357 6.3/6.4 via     *
 *   GOST_KEY_TRANSPORT) and the KEG/KExp15 transport (RFC 9189 /     *
 *   R 1323565.1.020-2018 via PSKeyTransport_gost), mirroring the     *
 *   engine pmeth callbacks in gost_ec_keyx.c                         *
 *                                                                    *
 *         This file is distributed under the same license as OpenSSL *
 **********************************************************************/

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <string.h>

#include "gost_prov.h"
#include "gost_lcl.h"
#include "gost_keywrap.h"
#include "gost_tls12_additional.h"
#include "e_gost_err.h"

/*
 * Parameter name used by newer OpenSSL versions. Define it here for
 * builds against OpenSSL without it (same string as upstream).
 */
#ifndef OSSL_ASYM_CIPHER_PARAM_KEY_ENC_ALGORITHM_ID
# define OSSL_ASYM_CIPHER_PARAM_KEY_ENC_ALGORITHM_ID "key-enc-algorithm-id"
#endif

#define GKT_UKM_SIZE   8
#define KEG_UKM_SIZE   32
#define GKT_KEY_LEN    32

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.
 */
static OSSL_FUNC_asym_cipher_newctx_fn gost_asym_cipher_newctx;
static OSSL_FUNC_asym_cipher_freectx_fn gost_asym_cipher_freectx;
static OSSL_FUNC_asym_cipher_dupctx_fn gost_asym_cipher_dupctx;
static OSSL_FUNC_asym_cipher_encrypt_init_fn gost_asym_cipher_encrypt_init;
static OSSL_FUNC_asym_cipher_decrypt_init_fn gost_asym_cipher_decrypt_init;
static OSSL_FUNC_asym_cipher_encrypt_fn gost_asym_cipher_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_fn gost_asym_cipher_decrypt;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn gost_asym_cipher_get_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn gost_asym_cipher_set_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
    gost_asym_cipher_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn
    gost_asym_cipher_settable_ctx_params;

typedef struct gost_asym_cipher_ctx_st {
    GOST_KEY_DATA *key_data;
    int is_encrypt;
    int cipher_nid;             /* NID_id_Gost28147_89 or NID_{magma,kuznyechik}_ctr */
    unsigned char ukm[KEG_UKM_SIZE];
    size_t ukm_size;
} GOST_ASYM_CIPHER_CTX;

static void *gost_asym_cipher_newctx(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(GOST_ASYM_CIPHER_CTX));
}

static void gost_asym_cipher_freectx(void *vctx)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;

    if (!ctx)
        return;

    keymgmt_free(ctx->key_data);
    OPENSSL_cleanse(ctx->ukm, sizeof(ctx->ukm));
    OPENSSL_free(ctx);
}

static void *gost_asym_cipher_dupctx(void *vctx)
{
    GOST_ASYM_CIPHER_CTX *src = vctx;
    GOST_ASYM_CIPHER_CTX *dst;

    if (!src)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->is_encrypt = src->is_encrypt;
    dst->cipher_nid = src->cipher_nid;
    memcpy(dst->ukm, src->ukm, sizeof(dst->ukm));
    dst->ukm_size = src->ukm_size;

    if (src->key_data != NULL) {
        dst->key_data = keymgmt_dup(src->key_data,
                                    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                                    | OSSL_KEYMGMT_SELECT_KEYPAIR);
        if (dst->key_data == NULL) {
            OPENSSL_free(dst);
            return NULL;
        }
    }

    return dst;
}

static int gost_asym_cipher_init(void *vctx, void *vkey_data,
                                 const OSSL_PARAM params[], int is_encrypt)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;
    GOST_KEY_DATA *key_data = vkey_data;
    int selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

    if (!ctx || !key_data || !key_data->ec)
        return 0;

    if (EC_KEY_get0_private_key(key_data->ec) != NULL)
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    if (EC_KEY_get0_public_key(key_data->ec) != NULL)
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    keymgmt_free(ctx->key_data);
    ctx->key_data = keymgmt_dup(key_data, selection);
    if (!ctx->key_data)
        return 0;

    ctx->is_encrypt = is_encrypt;
    ctx->cipher_nid = NID_id_Gost28147_89;
    ctx->ukm_size = 0;

    return gost_asym_cipher_set_ctx_params(ctx, params);
}

static int gost_asym_cipher_encrypt_init(void *vctx, void *vkey_data,
                                         const OSSL_PARAM params[])
{
    return gost_asym_cipher_init(vctx, vkey_data, params, 1);
}

static int gost_asym_cipher_decrypt_init(void *vctx, void *vkey_data,
                                         const OSSL_PARAM params[])
{
    return gost_asym_cipher_init(vctx, vkey_data, params, 0);
}

static int vko_dgst_nid_from_key_type(int key_type)
{
    switch (key_type) {
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2001DH:
        return NID_id_GostR3411_94;
    case NID_id_GostR3410_2012_256:
        return NID_id_GostR3411_2012_256;
    case NID_id_GostR3410_2012_512:
        /* VKO 256 for 512 */
        return NID_id_GostR3411_2012_256;
    default:
        return NID_undef;
    }
}

/*
 * Decode the ephemeral public key of the transport structure into a
 * plain EC_KEY (no engine/provider decoding machinery involved).
 */
static EC_KEY *decode_ephemeral_key(const X509_PUBKEY *pub)
{
    const unsigned char *pubkey_buf = NULL;
    int pubkey_len = 0;
    X509_ALGOR *palg = NULL;
    int key_type = NID_undef;
    EC_KEY *ec = NULL;

    if (pub == NULL)
        return NULL;

    ec = EC_KEY_new();
    if (ec == NULL)
        return NULL;

    if (!X509_PUBKEY_get0_param(NULL, &pubkey_buf, &pubkey_len, &palg, pub)
        || !internal_pub_decode_ec(ec, &key_type, palg, pubkey_buf, pubkey_len)) {
        EC_KEY_free(ec);
        return NULL;
    }

    return ec;
}

/* Generate ephemeral key pair on the same curve as key_data->ec */
static EC_KEY *generate_ephemeral_key(const EC_KEY *recipient)
{
    EC_KEY *eph = EC_KEY_new();

    if (eph == NULL)
        return NULL;

    if (!EC_KEY_set_group(eph, EC_KEY_get0_group(recipient))
        || !gost_ec_keygen(eph)) {
        EC_KEY_free(eph);
        return NULL;
    }

    return eph;
}

/* Fill in the ephem_key field of a transport structure */
static int set_ephemeral_pubkey(X509_PUBKEY **pub, EC_KEY *ec, int key_type)
{
    if (ec == NULL || pub == NULL)
        return 0;

    if (*pub == NULL && (*pub = X509_PUBKEY_new()) == NULL)
        return 0;

    return internal_pub_encode_ec(*pub, ec, key_type);
}

/*********************************************************************
 *
 *  CryptoPro key transport (RFC 4357 6.3/6.4, GOST_KEY_TRANSPORT)
 *
 *****/

static int gost_asym_cipher_gkt_encrypt(void *vctx, unsigned char *out,
                                        size_t *out_len, size_t out_size,
                                        const unsigned char *key,
                                        size_t key_len)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;
    GOST_KEY_TRANSPORT *gkt = NULL;
    unsigned char ukm[GKT_UKM_SIZE], shared_key[32], crypted_key[44];
    gost_ctx cctx;
    const struct gost_cipher_info *param = NULL;
    ASN1_OBJECT *crypt_params_obj = NULL;
    EC_KEY *eph_ec = NULL;
    int pkey_nid = ctx->key_data->type;
    int res_len = 0;
    int ret = 0;

    if (ctx->ukm_size == GKT_UKM_SIZE) {
        memcpy(ukm, ctx->ukm, GKT_UKM_SIZE);
    } else if (ctx->ukm_size == 0) {
        if (RAND_bytes(ukm, GKT_UKM_SIZE) <= 0) {
            GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT, GOST_R_RNG_ERROR);
            return 0;
        }
        memcpy(ctx->ukm, ukm, GKT_UKM_SIZE);
        ctx->ukm_size = GKT_UKM_SIZE;
    } else {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT, GOST_R_INVALID_IV_LENGTH);
        return 0;
    }

    crypt_params_obj =
        (pkey_nid == NID_id_GostR3410_2001 || pkey_nid == NID_id_GostR3410_2001DH) ?
        OBJ_nid2obj(NID_id_Gost28147_89_CryptoPro_A_ParamSet) :
        OBJ_nid2obj(NID_id_tc26_gost_28147_param_Z);
    param = get_encryption_params(crypt_params_obj);
    if (!param) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT, GOST_R_INVALID_CIPHER);
        goto err;
    }

    if (out != NULL) {
        int dgst_nid = vko_dgst_nid_from_key_type(pkey_nid);

        if (key == NULL || key_len != GKT_KEY_LEN) {
            GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT,
                    GOST_R_KEY_IS_NOT_INITIALIZED);
            goto err;
        }

        eph_ec = generate_ephemeral_key(ctx->key_data->ec);
        if (eph_ec == NULL) {
            GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT,
                    GOST_R_ERROR_COMPUTING_SHARED_KEY);
            goto err;
        }

        if (!VKO_compute_key(shared_key,
                             EC_KEY_get0_public_key(ctx->key_data->ec),
                             eph_ec, ukm, GKT_UKM_SIZE, dgst_nid)) {
            GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT,
                    GOST_R_ERROR_COMPUTING_SHARED_KEY);
            goto err;
        }

        gost_init(&cctx, param->sblock);
        if (!keyWrapCryptoPro(&cctx, shared_key, ukm, key, crypted_key)) {
            GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT,
                    GOST_R_ERROR_COMPUTING_SHARED_KEY);
            goto err;
        }
    }

    gkt = GOST_KEY_TRANSPORT_new();
    if (gkt == NULL)
        goto err;

    if (!ASN1_OCTET_STRING_set(gkt->key_agreement_info->eph_iv, ukm,
                               GKT_UKM_SIZE)
        || !ASN1_OCTET_STRING_set(gkt->key_info->imit, crypted_key + 40, 4)
        || !ASN1_OCTET_STRING_set(gkt->key_info->encrypted_key,
                                  crypted_key + 8, 32))
        goto err;

    if (!set_ephemeral_pubkey(&gkt->key_agreement_info->ephem_key,
                              out ? eph_ec : ctx->key_data->ec, pkey_nid)) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT,
                GOST_R_CANNOT_PACK_EPHEMERAL_KEY);
        goto err;
    }

    ASN1_OBJECT_free(gkt->key_agreement_info->cipher);
    gkt->key_agreement_info->cipher = OBJ_nid2obj(param->nid);

    res_len = i2d_GOST_KEY_TRANSPORT(gkt, NULL);
    if (res_len <= 0) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT, ERR_R_ASN1_LIB);
        goto err;
    }

    if (out == NULL) {
        *out_len = res_len;
        ret = 1;
    } else {
        if ((size_t)res_len > out_size) {
            GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT, GOST_R_INVALID_BUFFER_SIZE);
            goto err;
        }
        if ((*out_len = i2d_GOST_KEY_TRANSPORT(gkt, &out)) > 0)
            ret = 1;
        else
            GOSTerr(GOST_F_PKEY_GOST_ECCP_ENCRYPT, ERR_R_ASN1_LIB);
    }

 err:
    OPENSSL_cleanse(shared_key, sizeof(shared_key));
    EC_KEY_free(eph_ec);
    GOST_KEY_TRANSPORT_free(gkt);
    return ret;
}

static int gost_asym_cipher_gkt_decrypt(void *vctx, unsigned char *key,
                                        size_t *key_len,
                                        const unsigned char *in, size_t in_len)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;
    const unsigned char *p = in;
    GOST_KEY_TRANSPORT *gkt = NULL;
    unsigned char wrappedKey[44];
    unsigned char sharedKey[32];
    gost_ctx cctx;
    const struct gost_cipher_info *param = NULL;
    EC_KEY *eph_ec = NULL;
    int dgst_nid = NID_undef;
    int ret = 0;

    gkt = d2i_GOST_KEY_TRANSPORT(NULL, (const unsigned char **)&p, in_len);
    if (gkt == NULL) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_DECRYPT,
                GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO);
        return 0;
    }

    eph_ec = decode_ephemeral_key(gkt->key_agreement_info->ephem_key);
    if (eph_ec == NULL) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_DECRYPT, GOST_R_INCOMPATIBLE_PEER_KEY);
        goto err;
    }

    param = get_encryption_params(gkt->key_agreement_info->cipher);
    if (param == NULL) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_DECRYPT, GOST_R_INVALID_CIPHER);
        goto err;
    }

    if (ASN1_STRING_length(gkt->key_agreement_info->eph_iv) != 8
        || ASN1_STRING_length(gkt->key_info->encrypted_key) != 32
        || ASN1_STRING_length(gkt->key_info->imit) != 4) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_DECRYPT,
                GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO);
        goto err;
    }

    memcpy(wrappedKey, ASN1_STRING_get0_data(gkt->key_agreement_info->eph_iv), 8);
    memcpy(wrappedKey + 8,
           ASN1_STRING_get0_data(gkt->key_info->encrypted_key), 32);
    memcpy(wrappedKey + 40, ASN1_STRING_get0_data(gkt->key_info->imit), 4);

    dgst_nid = vko_dgst_nid_from_key_type(ctx->key_data->type);

    if (!VKO_compute_key(sharedKey,
                         EC_KEY_get0_public_key(eph_ec),
                         ctx->key_data->ec, wrappedKey, GKT_UKM_SIZE,
                         dgst_nid)) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_DECRYPT,
                GOST_R_ERROR_COMPUTING_SHARED_KEY);
        goto err;
    }

    gost_init(&cctx, param->sblock);
    if (!keyUnwrapCryptoPro(&cctx, sharedKey, wrappedKey, key)) {
        GOSTerr(GOST_F_PKEY_GOST_ECCP_DECRYPT,
                GOST_R_ERROR_COMPUTING_SHARED_KEY);
        goto err;
    }

    *key_len = GKT_KEY_LEN;
    ret = 1;
 err:
    OPENSSL_cleanse(sharedKey, sizeof(sharedKey));
    EC_KEY_free(eph_ec);
    GOST_KEY_TRANSPORT_free(gkt);
    return ret;
}

/*********************************************************************
 *
 *  KEG / KExp15 key transport (R 1323565.1.020-2018, PSKeyTransport)
 *
 *****/

static int keg_mac_and_iv(int cipher_nid, int *mac_nid, int *iv_len)
{
    switch (cipher_nid) {
    case NID_magma_ctr:
        *mac_nid = NID_magma_mac;
        *iv_len = 4;
        return 1;
    case NID_kuznyechik_ctr:
        *mac_nid = NID_grasshopper_mac;
        *iv_len = 8;
        return 1;
    default:
        return 0;
    }
}

static int gost_asym_cipher_keg_encrypt(void *vctx, unsigned char *out,
                                        size_t *out_len, size_t out_size,
                                        const unsigned char *key,
                                        size_t key_len)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;
    PSKeyTransport_gost *pst = NULL;
    unsigned char expkeys[64];
    unsigned char *exp_buf = NULL;
    int exp_len = 0;
    int mac_nid = NID_undef;
    int iv_len = 0;
    EC_KEY *eph_ec = NULL;
    int pkey_nid = ctx->key_data->type;
    int res_len = 0;
    int ret = 0;

    if (ctx->ukm_size == 0) {
        if (RAND_bytes(ctx->ukm, KEG_UKM_SIZE) <= 0) {
            GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        ctx->ukm_size = KEG_UKM_SIZE;
    } else if (ctx->ukm_size != KEG_UKM_SIZE) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, GOST_R_INVALID_IV_LENGTH);
        return 0;
    }

    if (!keg_mac_and_iv(ctx->cipher_nid, &mac_nid, &iv_len)) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, GOST_R_INVALID_CIPHER);
        return 0;
    }

    exp_len = key_len + (mac_nid == NID_magma_mac ? 8 : 16);
    exp_buf = OPENSSL_malloc(exp_len);
    if (exp_buf == NULL) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    eph_ec = generate_ephemeral_key(ctx->key_data->ec);
    if (eph_ec == NULL) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT,
                GOST_R_ERROR_COMPUTING_SHARED_KEY);
        goto err;
    }

    if (gost_keg(ctx->ukm, pkey_nid,
                 EC_KEY_get0_public_key(ctx->key_data->ec),
                 eph_ec, expkeys) <= 0) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT,
                GOST_R_ERROR_COMPUTING_EXPORT_KEYS);
        goto err;
    }

    if (gost_kexp15(key, key_len, ctx->cipher_nid, expkeys + 32,
                    mac_nid, expkeys + 0, ctx->ukm + 24, iv_len,
                    exp_buf, &exp_len) <= 0) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT,
                GOST_R_CANNOT_PACK_EPHEMERAL_KEY);
        goto err;
    }

    pst = PSKeyTransport_gost_new();
    if (pst == NULL) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pst->ukm = ASN1_OCTET_STRING_new();
    if (pst->ukm == NULL
        || !ASN1_OCTET_STRING_set(pst->ukm, ctx->ukm, ctx->ukm_size)) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!ASN1_OCTET_STRING_set(pst->psexp, exp_buf, exp_len)) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!set_ephemeral_pubkey(&pst->ephem_key, eph_ec, pkey_nid)) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT,
                GOST_R_CANNOT_PACK_EPHEMERAL_KEY);
        goto err;
    }

    res_len = i2d_PSKeyTransport_gost(pst, NULL);
    if (res_len <= 0) {
        GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, ERR_R_ASN1_LIB);
        goto err;
    }

    if (out == NULL) {
        *out_len = res_len;
        ret = 1;
    } else {
        if ((size_t)res_len > out_size) {
            GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, GOST_R_INVALID_BUFFER_SIZE);
            goto err;
        }
        if ((*out_len = i2d_PSKeyTransport_gost(pst, &out)) > 0)
            ret = 1;
        else
            GOSTerr(GOST_F_PKEY_GOST2018_ENCRYPT, ERR_R_ASN1_LIB);
    }

 err:
    OPENSSL_cleanse(expkeys, sizeof(expkeys));
    if (exp_buf != NULL)
        OPENSSL_cleanse(exp_buf, exp_len);
    OPENSSL_free(exp_buf);
    EC_KEY_free(eph_ec);
    PSKeyTransport_gost_free(pst);
    return ret;
}

static int gost_asym_cipher_keg_decrypt(void *vctx, unsigned char *key,
                                        size_t *key_len,
                                        const unsigned char *in, size_t in_len)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;
    const unsigned char *p = in;
    PSKeyTransport_gost *pst = NULL;
    unsigned char expkeys[64];
    int mac_nid = NID_undef;
    int iv_len = 0;
    EC_KEY *eph_ec = NULL;
    int pkey_nid = ctx->key_data->type;
    int ret = 0;

    pst = d2i_PSKeyTransport_gost(NULL, (const unsigned char **)&p, in_len);
    if (pst == NULL) {
        GOSTerr(GOST_F_PKEY_GOST2018_DECRYPT,
                GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO);
        return 0;
    }

    if (ctx->ukm_size == 0 && pst->ukm != NULL) {
        int ukm_len = ASN1_STRING_length(pst->ukm);

        if (ukm_len != KEG_UKM_SIZE) {
            GOSTerr(GOST_F_PKEY_GOST2018_DECRYPT, GOST_R_UKM_NOT_SET);
            goto err;
        }
        memcpy(ctx->ukm, ASN1_STRING_get0_data(pst->ukm), KEG_UKM_SIZE);
        ctx->ukm_size = KEG_UKM_SIZE;
    }

    if (!keg_mac_and_iv(ctx->cipher_nid, &mac_nid, &iv_len)) {
        GOSTerr(GOST_F_PKEY_GOST2018_DECRYPT, GOST_R_INVALID_CIPHER);
        goto err;
    }

    eph_ec = decode_ephemeral_key(pst->ephem_key);
    if (eph_ec == NULL) {
        GOSTerr(GOST_F_PKEY_GOST2018_DECRYPT,
                GOST_R_ERROR_COMPUTING_EXPORT_KEYS);
        goto err;
    }

    if (gost_keg(ctx->ukm, pkey_nid,
                 EC_KEY_get0_public_key(eph_ec),
                 ctx->key_data->ec, expkeys) <= 0) {
        GOSTerr(GOST_F_PKEY_GOST2018_DECRYPT,
                GOST_R_ERROR_COMPUTING_EXPORT_KEYS);
        goto err;
    }

    if (gost_kimp15(ASN1_STRING_get0_data(pst->psexp),
                    ASN1_STRING_length(pst->psexp), ctx->cipher_nid,
                    expkeys + 32, mac_nid, expkeys + 0, ctx->ukm + 24,
                    iv_len, key) <= 0) {
        GOSTerr(GOST_F_PKEY_GOST2018_DECRYPT,
                GOST_R_CANNOT_UNPACK_EPHEMERAL_KEY);
        goto err;
    }

    *key_len = GKT_KEY_LEN;
    ret = 1;
 err:
    OPENSSL_cleanse(expkeys, sizeof(expkeys));
    EC_KEY_free(eph_ec);
    PSKeyTransport_gost_free(pst);
    return ret;
}

/*********************************************************************
 *
 *  Dispatch
 *
 *****/

static int gost_asym_cipher_encrypt(void *vctx, unsigned char *out,
                                    size_t *out_len, size_t out_size,
                                    const unsigned char *key, size_t key_len)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;

    if (!ctx || !ctx->key_data || !ctx->key_data->ec)
        return 0;

    switch (ctx->cipher_nid) {
    case NID_id_Gost28147_89:
        return gost_asym_cipher_gkt_encrypt(ctx, out, out_len, out_size,
                                            key, key_len);
    case NID_magma_ctr:
    case NID_kuznyechik_ctr:
        if (ctx->key_data->type == NID_id_GostR3410_2001
            || ctx->key_data->type == NID_id_GostR3410_2001DH) {
            GOSTerr(GOST_F_PKEY_GOST_ENCRYPT, GOST_R_INVALID_CIPHER);
            return 0;
        }
        return gost_asym_cipher_keg_encrypt(ctx, out, out_len, out_size,
                                            key, key_len);
    default:
        GOSTerr(GOST_F_PKEY_GOST_ENCRYPT, GOST_R_INVALID_CIPHER);
        return 0;
    }
}

static int gost_asym_cipher_decrypt(void *vctx, unsigned char *out,
                                    size_t *out_len, size_t out_size,
                                    const unsigned char *in, size_t in_len)
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;

    if (!ctx || !ctx->key_data || !ctx->key_data->ec
        || EC_KEY_get0_private_key(ctx->key_data->ec) == NULL)
        return 0;

    if (out == NULL) {
        *out_len = GKT_KEY_LEN;
        return 1;
    }

    if (out_size < GKT_KEY_LEN) {
        GOSTerr(GOST_F_PKEY_GOST_DECRYPT, GOST_R_INVALID_BUFFER_SIZE);
        return 0;
    }

    switch (ctx->cipher_nid) {
    case NID_id_Gost28147_89:
        return gost_asym_cipher_gkt_decrypt(ctx, out, out_len, in, in_len);
    case NID_magma_ctr:
    case NID_kuznyechik_ctr:
        if (ctx->key_data->type == NID_id_GostR3410_2001
            || ctx->key_data->type == NID_id_GostR3410_2001DH) {
            GOSTerr(GOST_F_PKEY_GOST_DECRYPT, GOST_R_INVALID_CIPHER);
            return 0;
        }
        return gost_asym_cipher_keg_decrypt(ctx, out, out_len, in, in_len);
    default:
        GOSTerr(GOST_F_PKEY_GOST_DECRYPT, GOST_R_INVALID_CIPHER);
        return 0;
    }
}

/*********************************************************************
 *
 *  Parameters
 *
 *****/

static int can_contain_hash_alg(int paramset_nid)
{
    switch (paramset_nid) {
    case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet:
    case NID_id_tc26_gost_3410_2012_256_paramSetA:
    case NID_id_tc26_gost_3410_2012_512_paramSetA:
    case NID_id_tc26_gost_3410_2012_512_paramSetB:
    case NID_id_tc26_gost_3410_2012_512_paramSetC:
        return 1;
    default:
        return 0;
    }
}

static int hash_nid_for_alg(int alg_nid)
{
    switch (alg_nid) {
    case NID_id_GostR3410_2001:
        return NID_id_GostR3411_94_CryptoProParamSet;
    case NID_id_GostR3410_2012_256:
        return NID_id_GostR3411_2012_256;
    case NID_id_GostR3410_2012_512:
        return NID_id_GostR3411_2012_512;
    default:
        return NID_undef;
    }
}

static ASN1_STRING *encode_gost_key_params(int alg_nid, int param_nid)
{
    GOST_KEY_PARAMS *gkp = GOST_KEY_PARAMS_new();
    ASN1_STRING *params = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    unsigned char *der = NULL;
    int der_len;

    if (gkp == NULL || params == NULL)
        goto err;

    gkp->key_params = OBJ_nid2obj(param_nid);

    if (can_contain_hash_alg(param_nid)) {
        int hash_nid = hash_nid_for_alg(alg_nid);
        if (hash_nid == NID_undef)
            goto err;
        gkp->hash_params = OBJ_nid2obj(hash_nid);
    }

    der_len = i2d_GOST_KEY_PARAMS(gkp, &der);
    if (der_len <= 0)
        goto err;

    ASN1_STRING_set0(params, der, der_len);
    GOST_KEY_PARAMS_free(gkp);
    return params;

 err:
    GOST_KEY_PARAMS_free(gkp);
    ASN1_STRING_free(params);
    return NULL;
}

static ASN1_STRING *encode_cms_params(int ka_nid)
{
    /* We have only one OID here, so GOST_KEY_PARAMS (a sequence of
     * 3 OIDs, the 1st one mandatory, the rest optional) can be used */
    GOST_KEY_PARAMS *gkp = GOST_KEY_PARAMS_new();
    ASN1_STRING *params = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    unsigned char *der = NULL;
    int der_len;

    if (gkp == NULL || params == NULL)
        goto err;

    gkp->key_params = OBJ_nid2obj(ka_nid);

    der_len = i2d_GOST_KEY_PARAMS(gkp, &der);
    if (der_len <= 0)
        goto err;

    ASN1_STRING_set0(params, der, der_len);
    GOST_KEY_PARAMS_free(gkp);
    return params;

 err:
    GOST_KEY_PARAMS_free(gkp);
    ASN1_STRING_free(params);
    return NULL;
}

static int gost_asym_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;
    OSSL_PARAM *p;
    int alg_nid;
    int ka_nid = NID_undef;
    ASN1_STRING *cms_params = NULL;
    X509_ALGOR *alg = NULL;
    unsigned char *aid = NULL;
    int aid_len;
    int ret = 0;

    if (!ctx || !ctx->key_data)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_KEY_ENC_ALGORITHM_ID);
    if (p == NULL)
        return 1;

    switch (ctx->cipher_nid) {
    case NID_magma_ctr:
        alg_nid = NID_magma_kexp15;
        ka_nid = (ctx->key_data->type == NID_id_GostR3410_2012_256) ?
            NID_id_tc26_agreement_gost_3410_2012_256 :
            NID_id_tc26_agreement_gost_3410_2012_512;
        cms_params = encode_cms_params(ka_nid);
        break;
    case NID_kuznyechik_ctr:
        alg_nid = NID_kuznyechik_kexp15;
        ka_nid = (ctx->key_data->type == NID_id_GostR3410_2012_256) ?
            NID_id_tc26_agreement_gost_3410_2012_256 :
            NID_id_tc26_agreement_gost_3410_2012_512;
        cms_params = encode_cms_params(ka_nid);
        break;
    case NID_id_Gost28147_89:
    default:
        alg_nid = ctx->key_data->type;
        cms_params = encode_gost_key_params(alg_nid, ctx->key_data->param_nid);
        break;
    }

    if (cms_params == NULL)
        return 0;

    alg = X509_ALGOR_new();
    if (alg == NULL || !X509_ALGOR_set0(alg, OBJ_nid2obj(alg_nid),
                                        V_ASN1_SEQUENCE, cms_params))
        goto err;
    cms_params = NULL;          /* ownership transferred to alg */

    aid_len = i2d_X509_ALGOR(alg, &aid);
    if (aid_len <= 0)
        goto err;

    ret = OSSL_PARAM_set_octet_string(p, aid, aid_len);
    OPENSSL_free(aid);

 err:
    X509_ALGOR_free(alg);
    ASN1_STRING_free(cms_params);
    return ret;
}

static int gost_asym_cipher_set_ctx_params(void *vctx,
                                           const OSSL_PARAM params[])
{
    GOST_ASYM_CIPHER_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (!ctx || !params)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_EXCHANGE_PARAM_KDF_UKM)) != NULL) {
        const void *data = NULL;
        size_t data_len;

        if (OSSL_PARAM_get_octet_string_ptr(p, &data, &data_len) != 1
            || (data_len != KEG_UKM_SIZE && data_len != GKT_UKM_SIZE)) {
            GOSTerr(GOST_F_PKEY_GOST_CTRL, GOST_R_INVALID_IV_LENGTH);
            return 0;
        }

        memcpy(ctx->ukm, data, data_len);
        ctx->ukm_size = data_len;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_CIPHER)) != NULL) {
        const char *data = NULL;
        int cipher_nid;

        if (OSSL_PARAM_get_utf8_string_ptr(p, &data) != 1) {
            GOSTerr(GOST_F_PKEY_GOST_CTRL, GOST_R_INVALID_CIPHER);
            return 0;
        }

        cipher_nid = OBJ_sn2nid(data);
        switch (cipher_nid) {
        case NID_magma_ctr:
        case NID_magma_ctr_acpkm:
        case NID_magma_ctr_acpkm_omac:
        case NID_magma_kexp15:
            ctx->cipher_nid = NID_magma_ctr;
            break;
        case NID_kuznyechik_ctr:
        case NID_kuznyechik_ctr_acpkm:
        case NID_kuznyechik_ctr_acpkm_omac:
        case NID_kuznyechik_kexp15:
            ctx->cipher_nid = NID_kuznyechik_ctr;
            break;
        case NID_id_Gost28147_89:
            ctx->cipher_nid = NID_id_Gost28147_89;
            break;
        default:
            GOSTerr(GOST_F_PKEY_GOST_CTRL, GOST_R_INVALID_CIPHER);
            return 0;
        }
    }

    /* keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier */
    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_ASYM_CIPHER_PARAM_KEY_ENC_ALGORITHM_ID)) != NULL) {
        unsigned char *aid = NULL;
        size_t aid_len;
        X509_ALGOR *alg = NULL;
        int ret = 0;

        if (!OSSL_PARAM_get_octet_string(p, (void **)&aid, 0, &aid_len))
            return 0;

        alg = d2i_X509_ALGOR(NULL, (const unsigned char **)&aid, aid_len);
        if (alg == NULL)
            goto out;

        switch (OBJ_obj2nid(alg->algorithm)) {
        case NID_kuznyechik_kexp15:
            ctx->cipher_nid = NID_kuznyechik_ctr;
            ret = 1;
            break;
        case NID_magma_kexp15:
            ctx->cipher_nid = NID_magma_ctr;
            ret = 1;
            break;
        case NID_id_GostR3410_2001:
        case NID_id_GostR3410_2001DH:
        case NID_id_GostR3410_2012_256:
        case NID_id_GostR3410_2012_512:
            ctx->cipher_nid = NID_id_Gost28147_89;
            ret = 1;
            break;
        default:
            GOSTerr(GOST_F_PKEY_GOST_CTRL, GOST_R_INVALID_CIPHER);
            break;
        }

 out:
        X509_ALGOR_free(alg);
        OPENSSL_free(aid);
        return ret;
    }

    return 1;
}

static const OSSL_PARAM gost_asym_cipher_known_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_KEY_ENC_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *
gost_asym_cipher_settable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    return gost_asym_cipher_known_ctx_params;
}

static const OSSL_PARAM *
gost_asym_cipher_gettable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    return gost_asym_cipher_known_ctx_params;
}

static const OSSL_DISPATCH gost_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))gost_asym_cipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
      (void (*)(void))gost_asym_cipher_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))gost_asym_cipher_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
      (void (*)(void))gost_asym_cipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))gost_asym_cipher_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))gost_asym_cipher_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))gost_asym_cipher_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))gost_asym_cipher_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))gost_asym_cipher_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))gost_asym_cipher_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))gost_asym_cipher_settable_ctx_params },
    OSSL_DISPATCH_END
};

const OSSL_ALGORITHM GOST_prov_asym_cipher[] = {
    { ALG_NAME_GOST2001, NULL, gost_asym_cipher_functions },
    { ALG_NAME_GOST2012_256, NULL, gost_asym_cipher_functions },
    { ALG_NAME_GOST2012_512, NULL, gost_asym_cipher_functions },
    { NULL, NULL, NULL }
};
/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
