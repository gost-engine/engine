#include "gost_lcl.h"
#include "gost_gost2015.h"
#include "e_gost_err.h"
#include <string.h>

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

int gost2015_process_unprotected_attributes(STACK_OF(X509_ATTRIBUTE) *attrs,
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
    return (X509at_add1_attr_by_OBJ(&attrs, OBJ_txt2obj(OID_GOST_CMS_MAC, 1),
          V_ASN1_OCTET_STRING, final_tag, mac_len) == NULL) ? -1 : 1;
  }
  return 1;
}
