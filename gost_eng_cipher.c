#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "gost_lcl.h"
#include "gost_eng_cipher.h"

struct gost_eng_cipher_st {
    GOST_cipher *cipher;
    EVP_CIPHER *evp_cipher;
};

/* Engine backend helpers */
int GOST_cipher_init_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx,
                         const unsigned char *key, const unsigned char *iv,
                         int enc);
int GOST_cipher_do_cipher_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx,
                              unsigned char *out, const unsigned char *in,
                              size_t inl);
int GOST_cipher_cleanup_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx);
int GOST_cipher_ctrl_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx,
                         int type, int arg, void *ptr);
int GOST_cipher_set_asn1_parameters_evp(const GOST_cipher *cipher,
                                        EVP_CIPHER_CTX *ctx,
                                        ASN1_TYPE *params);
int GOST_cipher_get_asn1_parameters_evp(const GOST_cipher *cipher,
                                        EVP_CIPHER_CTX *ctx,
                                        ASN1_TYPE *params);

int gost_engine_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc);
int gost_engine_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl);
int gost_engine_cipher_cleanup(EVP_CIPHER_CTX *ctx);
int gost_engine_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int gost_engine_cipher_set_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params);
int gost_engine_cipher_get_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params);

static EVP_CIPHER *GOST_init_cipher(GOST_cipher *c)
{
    /* Some sanity checking. */
    int flags = GOST_cipher_flags(c) | EVP_CIPH_CUSTOM_COPY;
    int block_size = GOST_cipher_block_size(c);

    switch (flags & EVP_CIPH_MODE) {
    case EVP_CIPH_CBC_MODE:
    case EVP_CIPH_ECB_MODE:
    case EVP_CIPH_WRAP_MODE:
        OPENSSL_assert(block_size != 1);
        OPENSSL_assert(!(flags & EVP_CIPH_NO_PADDING));
        break;
    default:
        OPENSSL_assert(block_size == 1);
        OPENSSL_assert(flags & EVP_CIPH_NO_PADDING);
    }

    if (GOST_cipher_iv_length(c) != 0)
        OPENSSL_assert(flags & EVP_CIPH_CUSTOM_IV);
    else
        OPENSSL_assert(!(flags & EVP_CIPH_CUSTOM_IV));

    EVP_CIPHER *cipher = NULL;
    if (!(cipher = EVP_CIPHER_meth_new(GOST_cipher_nid(c), block_size,
                                       GOST_cipher_key_length(c)))
        || !EVP_CIPHER_meth_set_iv_length(cipher, GOST_cipher_iv_length(c))
        || !EVP_CIPHER_meth_set_flags(cipher, flags)
        || !EVP_CIPHER_meth_set_init(cipher, gost_engine_cipher_init)
        || !EVP_CIPHER_meth_set_do_cipher(cipher, gost_engine_cipher_do_cipher)
        || !EVP_CIPHER_meth_set_cleanup(cipher, gost_engine_cipher_cleanup)
        || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, GOST_cipher_ctx_size(c))
        || !EVP_CIPHER_meth_set_set_asn1_params(cipher, gost_engine_cipher_set_asn1_parameters)
        || !EVP_CIPHER_meth_set_get_asn1_params(cipher, gost_engine_cipher_get_asn1_parameters)
        || !EVP_CIPHER_meth_set_ctrl(cipher, gost_engine_cipher_ctrl)) {
        EVP_CIPHER_meth_free(cipher);
        cipher = NULL;
    }
    return cipher;
}

/* Wrapper functions to expose GOST_cipher descriptors as EVP_CIPHER objects
 * cached in GOST_eng_cipher structures. */
EVP_CIPHER *GOST_eng_cipher_init(GOST_eng_cipher *c)
{
    if (c->evp_cipher)
        return c->evp_cipher;

    EVP_CIPHER *m = GOST_init_cipher(c->cipher);
    c->evp_cipher = m;
    return m;
}

void GOST_eng_cipher_deinit(GOST_eng_cipher *c)
{
    EVP_CIPHER_meth_free(c->evp_cipher);
    c->evp_cipher = NULL;
}

int GOST_eng_cipher_nid(const GOST_eng_cipher *c)
{
    return GOST_cipher_nid(c->cipher);
}

static const GOST_cipher *gost_cipher_from_nid(int nid)
{
    GOST_cipher *list[] = {
        &Gost28147_89_cipher,
        &Gost28147_89_cbc_cipher,
        &Gost28147_89_cnt_cipher,
        &Gost28147_89_cnt_12_cipher,
        &magma_ctr_cipher,
        &magma_ctr_acpkm_cipher,
        &magma_ctr_acpkm_omac_cipher,
        &magma_ecb_cipher,
        &magma_cbc_cipher,
        &magma_mgm_cipher,
        &grasshopper_ecb_cipher,
        &grasshopper_cbc_cipher,
        &grasshopper_cfb_cipher,
        &grasshopper_ofb_cipher,
        &grasshopper_ctr_cipher,
        &grasshopper_mgm_cipher,
        &grasshopper_ctr_acpkm_cipher,
        &grasshopper_ctr_acpkm_omac_cipher,
        &magma_kexp15_cipher,
        &kuznyechik_kexp15_cipher
    };
    size_t i;

    for (i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (GOST_cipher_nid(list[i]) == nid)
            return list[i];
    }
    return NULL;
}

static const GOST_cipher *gost_engine_cipher_desc(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *cipher;

    if (ctx == NULL)
        return NULL;
    cipher = EVP_CIPHER_CTX_cipher(ctx);
    if (cipher == NULL)
        return NULL;

    return gost_cipher_from_nid(EVP_CIPHER_nid(cipher));
}

int gost_engine_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    const GOST_cipher *cipher = gost_engine_cipher_desc(ctx);

    if (cipher == NULL)
        return 0;
    return GOST_cipher_init_evp(cipher, ctx, key, iv, enc);
}

int gost_engine_cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl)
{
    const GOST_cipher *cipher = gost_engine_cipher_desc(ctx);

    if (cipher == NULL)
        return 0;
    return GOST_cipher_do_cipher_evp(cipher, ctx, out, in, inl);
}

int gost_engine_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    const GOST_cipher *cipher = gost_engine_cipher_desc(ctx);

    if (cipher == NULL)
        return 0;
    return GOST_cipher_cleanup_evp(cipher, ctx);
}

int gost_engine_cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    const GOST_cipher *cipher = gost_engine_cipher_desc(ctx);

    if (cipher == NULL)
        return 0;
    return GOST_cipher_ctrl_evp(cipher, ctx, type, arg, ptr);
}

int gost_engine_cipher_set_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params)
{
    const GOST_cipher *cipher = gost_engine_cipher_desc(ctx);

    if (cipher == NULL)
        return 0;
    return GOST_cipher_set_asn1_parameters_evp(cipher, ctx, params);
}

int gost_engine_cipher_get_asn1_parameters(EVP_CIPHER_CTX *ctx,
                                           ASN1_TYPE *params)
{
    const GOST_cipher *cipher = gost_engine_cipher_desc(ctx);

    if (cipher == NULL)
        return 0;
    return GOST_cipher_get_asn1_parameters_evp(cipher, ctx, params);
}

/* Define engine-exposed instances for all GOST ciphers */
#define DEF_CIPHER(name) \
    GOST_eng_cipher ENG_CIPHER_NAME(name) = { &name, NULL }

DEF_CIPHER(Gost28147_89_cipher);
DEF_CIPHER(Gost28147_89_cbc_cipher);
DEF_CIPHER(Gost28147_89_cnt_cipher);
DEF_CIPHER(Gost28147_89_cnt_12_cipher);
DEF_CIPHER(magma_ctr_cipher);
DEF_CIPHER(magma_ctr_acpkm_cipher);
DEF_CIPHER(magma_ctr_acpkm_omac_cipher);
DEF_CIPHER(magma_ecb_cipher);
DEF_CIPHER(magma_cbc_cipher);
DEF_CIPHER(magma_mgm_cipher);
DEF_CIPHER(grasshopper_ecb_cipher);
DEF_CIPHER(grasshopper_cbc_cipher);
DEF_CIPHER(grasshopper_cfb_cipher);
DEF_CIPHER(grasshopper_ofb_cipher);
DEF_CIPHER(grasshopper_ctr_cipher);
DEF_CIPHER(grasshopper_mgm_cipher);
DEF_CIPHER(grasshopper_ctr_acpkm_cipher);
DEF_CIPHER(grasshopper_ctr_acpkm_omac_cipher);
DEF_CIPHER(magma_kexp15_cipher);
DEF_CIPHER(kuznyechik_kexp15_cipher);
