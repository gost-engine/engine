/*
 * Copyright (c) 2020 Dmitry Belyavskiy <beldmit@gmail.com>
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */
#include "gost_lcl.h"
#include "gost_gost2015.h"
#include "e_gost_err.h"
#include <string.h>
#include <openssl/rand.h>

int gost2015_final_call(EVP_CIPHER_CTX *ctx, EVP_MD_CTX *omac_ctx, size_t mac_size,
    unsigned char *encrypted_mac,
    int (*do_cipher) (EVP_CIPHER_CTX *ctx,
    unsigned char *out,
    const unsigned char *in,
    size_t inl))
{
    unsigned char calculated_mac[KUZNYECHIK_MAC_MAX_SIZE];
    memset(calculated_mac, 0, KUZNYECHIK_MAC_MAX_SIZE);

    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        EVP_DigestSignFinal(omac_ctx, calculated_mac, &mac_size);

        if (do_cipher(ctx, encrypted_mac, calculated_mac, mac_size) <= 0) {
            return -1;
        }
    } else {
        unsigned char expected_mac[KUZNYECHIK_MAC_MAX_SIZE];

        memset(expected_mac, 0, KUZNYECHIK_MAC_MAX_SIZE);
        EVP_DigestSignFinal(omac_ctx, calculated_mac, &mac_size);

        if (do_cipher(ctx, expected_mac, encrypted_mac, mac_size) <= 0) {
            return -1;
        }

        if (CRYPTO_memcmp(expected_mac, calculated_mac, mac_size) != 0)
            return -1;
    }
    return 0;
}

/*
 * UKM = iv|kdf_seed
 * */
#define MAX_GOST2015_UKM_SIZE 16
#define KDF_SEED_SIZE 8
int gost2015_get_asn1_params(const ASN1_TYPE *params, size_t ukm_size,
    unsigned char *iv, size_t ukm_offset, unsigned char *kdf_seed)
{
    int iv_len = 16;
    GOST2015_CIPHER_PARAMS *gcp = NULL;

    unsigned char *p = NULL;

    memset(iv, 0, iv_len);

    /* Проверяем тип params */
    if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE) {
        GOSTerr(GOST_F_GOST2015_GET_ASN1_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        return 0;
    }

    p = params->value.sequence->data;
    /* Извлекаем структуру параметров */
    gcp = d2i_GOST2015_CIPHER_PARAMS(NULL, (const unsigned char **)&p, params->value.sequence->length);
    if (gcp == NULL) {
        GOSTerr(GOST_F_GOST2015_GET_ASN1_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        return 0;
    }

    /* Проверяем длину синхропосылки */
    if (gcp->ukm->length != (int)ukm_size) {
        GOSTerr(GOST_F_GOST2015_GET_ASN1_PARAMS, GOST_R_INVALID_CIPHER_PARAMS);
        GOST2015_CIPHER_PARAMS_free(gcp);
        return 0;
    }

    memcpy(iv, gcp->ukm->data, ukm_offset);
    memcpy(kdf_seed, gcp->ukm->data+ukm_offset, KDF_SEED_SIZE);

    GOST2015_CIPHER_PARAMS_free(gcp);
    return 1;
}

int gost2015_set_asn1_params(ASN1_TYPE *params,
    const unsigned char *iv, size_t iv_size, const unsigned char *kdf_seed)
{
    GOST2015_CIPHER_PARAMS *gcp = GOST2015_CIPHER_PARAMS_new();
    int ret = 0, len = 0;

    ASN1_OCTET_STRING *os = NULL;
    unsigned char ukm_buf[MAX_GOST2015_UKM_SIZE];
    unsigned char *buf = NULL;

    if (gcp == NULL) {
        GOSTerr(GOST_F_GOST2015_SET_ASN1_PARAMS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    memcpy(ukm_buf, iv, iv_size);
    memcpy(ukm_buf+iv_size, kdf_seed, KDF_SEED_SIZE);

    if (ASN1_STRING_set(gcp->ukm, ukm_buf, iv_size + KDF_SEED_SIZE) == 0) {
        GOSTerr(GOST_F_GOST2015_SET_ASN1_PARAMS, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    len = i2d_GOST2015_CIPHER_PARAMS(gcp, &buf);

    if (len <= 0
       || (os = ASN1_OCTET_STRING_new()) == NULL
       || ASN1_OCTET_STRING_set(os, buf, len) == 0) {
        goto end;
  }

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);
    ret = 1;

end:
    OPENSSL_free(buf);
    if (ret <= 0 && os)
        ASN1_OCTET_STRING_free(os);

    GOST2015_CIPHER_PARAMS_free(gcp);
    return ret;
}

int gost2015_process_unprotected_attributes(
    STACK_OF(X509_ATTRIBUTE) *attrs,
    int encryption, size_t mac_len, unsigned char *final_tag)
{
    if (encryption == 0) /*Decrypting*/ {
        ASN1_OCTET_STRING *osExpectedMac = X509at_get0_data_by_OBJ(attrs,
            OBJ_txt2obj(OID_GOST_CMS_MAC, 1), -3, V_ASN1_OCTET_STRING);

        if (!osExpectedMac || osExpectedMac->length != (int)mac_len)
            return -1;

        memcpy(final_tag, osExpectedMac->data, osExpectedMac->length);
    } else {
        if (attrs == NULL)
            return -1;
        return (X509at_add1_attr_by_OBJ(&attrs,
               OBJ_txt2obj(OID_GOST_CMS_MAC, 1),
               V_ASN1_OCTET_STRING, final_tag,
               mac_len) == NULL) ? -1 : 1;
    }
    return 1;
}

int gost2015_acpkm_omac_init(int nid, int enc, const unsigned char *inkey,
                             EVP_MD_CTX *omac_ctx,
                             unsigned char *outkey, unsigned char *kdf_seed)
{
    int ret = 0;
    unsigned char keys[64];
    const EVP_MD *md = EVP_get_digestbynid(nid);
    EVP_PKEY *mac_key;

    if (md == NULL)
        return 0;

    if (enc) {
        if (RAND_bytes(kdf_seed, 8) != 1)
            return 0;
    }

    if (gost_kdftree2012_256(keys, 64, inkey, 32,
       (const unsigned char *)"kdf tree", 8, kdf_seed, 8, 1) <= 0)
        return 0;

    mac_key = EVP_PKEY_new_mac_key(nid, NULL, keys+32, 32);

    if (mac_key == NULL)
        goto end;

    if (EVP_DigestInit_ex(omac_ctx, md, NULL) <= 0 ||
       EVP_DigestSignInit(omac_ctx, NULL, md, NULL, mac_key) <= 0)
        goto end;

    memcpy(outkey, keys, 32);

    ret = 1;
end:
    EVP_PKEY_free(mac_key);
    OPENSSL_cleanse(keys, sizeof(keys));

    return ret;
}

int init_zero_kdf_seed(unsigned char *kdf_seed)
{
    int is_zero_kdfseed = 1, i;
    for (i = 0; i < 8; i++) {
        if (kdf_seed[i] != 0)
            is_zero_kdfseed = 0;
    }

    return is_zero_kdfseed ? RAND_bytes(kdf_seed, 8) : 1;
}
