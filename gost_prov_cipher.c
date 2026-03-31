/**********************************************************************
 *             gost_prov_crypt.c - Initialize all ciphers             *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *         OpenSSL provider interface to GOST cipher functions        *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <limits.h>
#include "gost_prov.h"
#include "gost_cipher_ctx.h"
#include "gost_lcl.h"

/*
 * This definitions are added in the patch to OpenSSL 3.4.2 version to support
 * GOST TLS 1.3. Definitions below must be removed when the patch is added to
 * OpenSSL upstream.
 */
#ifndef OSSL_CIPHER_PARAM_TLSTREE
# if defined(_MSC_VER)
#  pragma message("Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE definition in OpenSSL is expected.")
# else
#  warning "Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE definition in OpenSSL is expected. TLSTREE is not supported by \
the provider for cipher operations."
# endif
# define OSSL_CIPHER_PARAM_TLSTREE "tlstree"
#endif

#ifndef OSSL_CIPHER_PARAM_TLSTREE_MODE
# if defined(_MSC_VER)
#  pragma message("Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE_MODE definition in OpenSSL is expected.")
# else
#  warning "Gost-engine is built against not fully supported version of OpenSSL. \
OSSL_CIPHER_PARAM_TLSTREE_MODE definition in OpenSSL is expected. TLSTREE modes are not supported by \
the provider for encryption/decryption operations. ."
# endif
# define OSSL_CIPHER_PARAM_TLSTREE_MODE "tlstree_mode"
#endif

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the algorithm specific ones
 * MAKE_FUNCTIONS() does it for us.
 */
static OSSL_FUNC_cipher_dupctx_fn cipher_dupctx;
static OSSL_FUNC_cipher_freectx_fn cipher_freectx;
static OSSL_FUNC_cipher_get_ctx_params_fn cipher_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn cipher_set_ctx_params;
static OSSL_FUNC_cipher_encrypt_init_fn cipher_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn cipher_decrypt_init;
static OSSL_FUNC_cipher_update_fn cipher_update;
static OSSL_FUNC_cipher_final_fn cipher_final;

struct gost_prov_crypt_ctx_st {
    /* Provider context */
    PROV_CTX *provctx;
    /* GOST_cipher descriptor */
    GOST_cipher *cipher;
    /* The context for the GOST_cipher functions */
    GOST_cipher_ctx *cctx;
};
typedef struct gost_prov_crypt_ctx_st GOST_CTX;

static int cipher_validate_init_inputs(const GOST_CTX *gctx,
                                       const unsigned char *key, size_t keylen,
                                       const unsigned char *iv, size_t ivlen)
{
    if (key != NULL && keylen != (size_t)GOST_cipher_key_length(gctx->cipher))
        return 0;

    if (iv != NULL) {
        if ((GOST_cipher_flags(gctx->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0) {
            if (ivlen == 0 || ivlen > EVP_MAX_IV_LENGTH)
                return 0;
        } else if (ivlen != (size_t)GOST_cipher_iv_length(gctx->cipher)) {
            return 0;
        }
    }

    return 1;
}

static void cipher_freectx(void *vgctx)
{
    GOST_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;
    GOST_cipher_ctx_free(gctx->cctx);
    OPENSSL_free(gctx);
}

static GOST_CTX *cipher_newctx(void *provctx, GOST_cipher *cipher)
{
    GOST_CTX *gctx = NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        gctx->cipher = cipher;
        if ((gctx->cctx = GOST_cipher_ctx_new()) == NULL) {
            cipher_freectx(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void *cipher_dupctx(void *vsrc)
{
    GOST_CTX *src = vsrc;
    GOST_CTX *dst = cipher_newctx(src->provctx, src->cipher);

    if (dst != NULL && !GOST_cipher_ctx_copy(dst->cctx, src->cctx)) {
        cipher_freectx(dst);
        dst = NULL;
    }
    return dst;
}

static int cipher_get_params(const GOST_cipher *c, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (c == NULL)
        return 0;
    if (((p = OSSL_PARAM_locate(params, "blocksize")) != NULL
         && !OSSL_PARAM_set_size_t(p, (size_t)GOST_cipher_block_size(c)))
        || ((p = OSSL_PARAM_locate(params, "ivlen")) != NULL
            && !OSSL_PARAM_set_size_t(p, (size_t)GOST_cipher_iv_length(c)))
        || ((p = OSSL_PARAM_locate(params, "keylen")) != NULL
            && !OSSL_PARAM_set_size_t(p, (size_t)GOST_cipher_key_length(c)))
        || ((p = OSSL_PARAM_locate(params, "mode")) != NULL
            && !OSSL_PARAM_set_uint(p, (unsigned int)GOST_cipher_mode(c)))
        || ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) != NULL
            && (c == &magma_mgm_cipher || c == &grasshopper_mgm_cipher)
            && !OSSL_PARAM_set_int(p, 1)))
        return 0;
    return 1;
}

static int cipher_get_ctx_params(void *vgctx, OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;
    OSSL_PARAM *p;

    if (!cipher_get_params(gctx->cipher, params))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "alg_id_param")) != NULL) {
        ASN1_TYPE *algidparam = NULL;
        unsigned char *der = NULL;
        int derlen = 0;
        int ret;

        ret = (algidparam = ASN1_TYPE_new()) != NULL
            && (GOST_cipher_set_asn1_parameters_fn(gctx->cipher) == NULL
                || GOST_cipher_set_asn1_parameters_fn(gctx->cipher)(gctx->cctx,
                                                                    algidparam) > 0)
            && (derlen = i2d_ASN1_TYPE(algidparam, &der)) >= 0
            && OSSL_PARAM_set_octet_string(p, der, (size_t)derlen);

        OPENSSL_free(der);
        ASN1_TYPE_free(algidparam);
        return ret;
    }
    if ((p = OSSL_PARAM_locate(params, "updated-iv")) != NULL) {
        const void *iv = GOST_cipher_ctx_iv(gctx->cctx);
        size_t ivlen = (size_t)GOST_cipher_ctx_iv_length(gctx->cctx);

        if (!OSSL_PARAM_set_octet_ptr(p, iv, ivlen)
            && !OSSL_PARAM_set_octet_string(p, iv, ivlen))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        void *tag = NULL;
        size_t taglen = 0;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&tag, &taglen)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_AEAD_GET_TAG,
                                    (int)taglen, tag) <= 0)
            return 0;
    }
    return 1;
}

static int cipher_set_ctx_params(void *vgctx, const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, "alg_id_param")) != NULL) {
        ASN1_TYPE *algidparam = NULL;
        const unsigned char *der = NULL;
        size_t derlen = 0;
        int ret;

        ret = OSSL_PARAM_get_octet_string_ptr(p, (const void **)&der, &derlen)
            && (algidparam = d2i_ASN1_TYPE(NULL, &der, (long)derlen)) != NULL
            && (GOST_cipher_get_asn1_parameters_fn(gctx->cipher) == NULL
                || GOST_cipher_get_asn1_parameters_fn(gctx->cipher)(gctx->cctx,
                                                                    algidparam) > 0);

        ASN1_TYPE_free(algidparam);
        return ret;
    }
    if ((p = OSSL_PARAM_locate_const(params, "padding")) != NULL) {
        unsigned int pad = 0;
        if (!OSSL_PARAM_get_uint(p, &pad)
            || !GOST_cipher_ctx_set_padding(gctx->cctx, (int)pad))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, "key-mesh")) != NULL) {
        size_t key_mesh = 0;
        if (!OSSL_PARAM_get_size_t(p, &key_mesh)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_KEY_MESH,
                                    (int)key_mesh, NULL) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL) {
        size_t ivlen = 0;
        if (!OSSL_PARAM_get_size_t(p, &ivlen)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    (int)ivlen, NULL) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        char tag[1024];
        void *val = (void *)tag;
        size_t taglen = 0;

        if (!OSSL_PARAM_get_octet_string(p, &val, sizeof(tag), &taglen)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_AEAD_SET_TAG,
                                    (int)taglen, tag) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE)) != NULL) {
        const void *val = NULL;
        size_t arg = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &val, &arg)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_TLSTREE,
                                    (int)arg, (void *)val) <= 0)
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLSTREE_MODE)) != NULL) {
        const void *val = NULL;
        size_t arg = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &val, &arg)
            || GOST_cipher_ctx_ctrl(gctx->cctx, EVP_CTRL_SET_TLSTREE_PARAMS,
                                    (int)arg, (void *)val) <= 0)
            return 0;
    }
    return 1;
}

static int cipher_encrypt_init(void *vgctx,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    if (!cipher_set_ctx_params(vgctx, params)
        || !cipher_validate_init_inputs(gctx, key, keylen, iv, ivlen))
        return 0;

    return GOST_CipherInit_ex(gctx->cctx, gctx->cipher, key, iv, 1);
}

static int cipher_decrypt_init(void *vgctx,
                               const unsigned char *key, size_t keylen,
                               const unsigned char *iv, size_t ivlen,
                               const OSSL_PARAM params[])
{
    GOST_CTX *gctx = vgctx;

    if (!cipher_set_ctx_params(vgctx, params)
        || !cipher_validate_init_inputs(gctx, key, keylen, iv, ivlen))
        return 0;
    return GOST_CipherInit_ex(gctx->cctx, gctx->cipher, key, iv, 0);
}

static int cipher_update(void *vgctx,
                         unsigned char *out, size_t *outl, size_t outsize,
                         const unsigned char *in, size_t inl)
{
    GOST_CTX *gctx = vgctx;

    int int_outl = outl != NULL ? *outl : 0;
    int res = GOST_CipherUpdate(gctx->cctx, out, &int_outl, in, (int)inl);

    if (res > 0 && outl != NULL)
        *outl = (size_t)int_outl;
    return res > 0;
}

static int cipher_final(void *vgctx,
                        unsigned char *out, size_t *outl, size_t outsize)
{
    GOST_CTX *gctx = vgctx;
    int int_outl = outl != NULL ? *outl : 0;
    int res = GOST_CipherFinal(gctx->cctx, out, &int_outl);

    if (res > 0 && outl != NULL)
        *outl = (size_t)int_outl;
    return res > 0;
}

/*
 * These are named like the EVP_CIPHER templates in gost_crypt.c, with the
 * added suffix "_functions".  Hopefully, that makes it easy to find the
 * actual implementation.
 */
typedef void (*fptr_t)(void);
#define MAKE_FUNCTIONS(name)                                            \
    static OSSL_FUNC_cipher_get_params_fn name##_get_params;            \
    static int name##_get_params(OSSL_PARAM *params)                    \
    {                                                                   \
        return cipher_get_params(&name, params);                        \
    }                                                                   \
    static OSSL_FUNC_cipher_newctx_fn name##_newctx;                    \
    static void *name##_newctx(void *provctx)                           \
    {                                                                   \
        return cipher_newctx(provctx, &name);                           \
    }                                                                   \
    static const OSSL_DISPATCH name##_functions[] = {                   \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (fptr_t)name##_get_params },     \
        { OSSL_FUNC_CIPHER_NEWCTX, (fptr_t)name##_newctx },             \
        { OSSL_FUNC_CIPHER_DUPCTX, (fptr_t)cipher_dupctx },             \
        { OSSL_FUNC_CIPHER_FREECTX, (fptr_t)cipher_freectx },           \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (fptr_t)cipher_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (fptr_t)cipher_set_ctx_params }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (fptr_t)cipher_encrypt_init }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (fptr_t)cipher_decrypt_init }, \
        { OSSL_FUNC_CIPHER_UPDATE, (fptr_t)cipher_update },             \
        { OSSL_FUNC_CIPHER_FINAL, (fptr_t)cipher_final },               \
        { 0, NULL },                                                    \
    }

MAKE_FUNCTIONS(Gost28147_89_cipher);
MAKE_FUNCTIONS(Gost28147_89_cnt_cipher);
MAKE_FUNCTIONS(Gost28147_89_cnt_12_cipher);
MAKE_FUNCTIONS(Gost28147_89_cbc_cipher);
MAKE_FUNCTIONS(grasshopper_ecb_cipher);
MAKE_FUNCTIONS(grasshopper_cbc_cipher);
MAKE_FUNCTIONS(grasshopper_cfb_cipher);
MAKE_FUNCTIONS(grasshopper_ofb_cipher);
MAKE_FUNCTIONS(grasshopper_ctr_cipher);
MAKE_FUNCTIONS(magma_cbc_cipher);
MAKE_FUNCTIONS(magma_ctr_cipher);
MAKE_FUNCTIONS(magma_ctr_acpkm_cipher);
MAKE_FUNCTIONS(magma_ctr_acpkm_omac_cipher);
MAKE_FUNCTIONS(magma_mgm_cipher);
MAKE_FUNCTIONS(grasshopper_ctr_acpkm_cipher);
MAKE_FUNCTIONS(grasshopper_ctr_acpkm_omac_cipher);
MAKE_FUNCTIONS(grasshopper_mgm_cipher);

/* The OSSL_ALGORITHM for the provider's operation query function */
const OSSL_ALGORITHM GOST_prov_ciphers[] = {
    { SN_id_Gost28147_89 ":gost89:GOST 28147-89:1.2.643.2.2.21", NULL,
      Gost28147_89_cipher_functions },
    { SN_gost89_cnt, NULL, Gost28147_89_cnt_cipher_functions },
    { SN_gost89_cnt_12, NULL, Gost28147_89_cnt_12_cipher_functions },
    { SN_gost89_cbc, NULL, Gost28147_89_cbc_cipher_functions },
    { SN_grasshopper_ecb, NULL, grasshopper_ecb_cipher_functions },
    { SN_grasshopper_cbc, NULL, grasshopper_cbc_cipher_functions },
    { SN_grasshopper_cfb, NULL, grasshopper_cfb_cipher_functions },
    { SN_grasshopper_ofb, NULL, grasshopper_ofb_cipher_functions },
    { SN_grasshopper_ctr, NULL, grasshopper_ctr_cipher_functions },
    { SN_magma_cbc, NULL, magma_cbc_cipher_functions },
    { SN_magma_ctr, NULL, magma_ctr_cipher_functions },
    { SN_magma_ctr_acpkm ":1.2.643.7.1.1.5.1.1", NULL,
      magma_ctr_acpkm_cipher_functions },
    { SN_magma_ctr_acpkm_omac ":1.2.643.7.1.1.5.1.2", NULL,
      magma_ctr_acpkm_omac_cipher_functions },
    { "magma-mgm", NULL, magma_mgm_cipher_functions },
    { SN_kuznyechik_ctr_acpkm ":1.2.643.7.1.1.5.2.1", NULL,
      grasshopper_ctr_acpkm_cipher_functions },
    { SN_kuznyechik_ctr_acpkm_omac ":1.2.643.7.1.1.5.2.2", NULL,
      grasshopper_ctr_acpkm_omac_cipher_functions },
    { "kuznyechik-mgm", NULL, grasshopper_mgm_cipher_functions },
#if 0                           /* Not yet implemented */
    { SN_magma_kexp15 ":1.2.643.7.1.1.7.1.1", NULL,
      magma_kexp15_cipher_functions },
    { SN_kuznyechik_kexp15 ":1.2.643.7.1.1.7.2.1", NULL,
      kuznyechik_kexp15_cipher_functions },
#endif
    { NULL , NULL, NULL }
};
