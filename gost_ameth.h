#pragma once

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

void pkey_free_gost_ec(EVP_PKEY *key);
int priv_decode_gost(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO* p8inf);
int priv_encode_gost(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY* pk);
int priv_print_gost_ec(BIO *out, const EVP_PKEY* pkey, int indent,
                              ASN1_PCTX *pctx);

int gost2001_param_encode(const EVP_PKEY *pkey, unsigned char **pder);
int gost2001_param_decode(EVP_PKEY *pkey, const unsigned char **pder,
                                 int derlen);
int param_missing_gost_ec(const EVP_PKEY *pk);
int param_copy_gost_ec(EVP_PKEY *to, const EVP_PKEY* from);
int param_cmp_gost_ec(const EVP_PKEY *a, const EVP_PKEY* b);
int param_print_gost_ec(BIO *out, const EVP_PKEY *pkey, int indent,
                        ASN1_PCTX *pctx);

int pub_decode_gost_ec(EVP_PKEY *pk, const X509_PUBKEY* pub);
int pub_encode_gost_ec(X509_PUBKEY *pub, const EVP_PKEY* pk);
int pub_cmp_gost_ec(const EVP_PKEY *a, const EVP_PKEY* b);
int pub_print_gost_ec(BIO *out, const EVP_PKEY *pkey, int indent,
                             ASN1_PCTX *pctx);
int pkey_size_gost(const EVP_PKEY *pk);
int pkey_bits_gost(const EVP_PKEY *pk);
int gost_set_raw_pub_key(EVP_PKEY *pk, const unsigned char *pub, size_t len);
int gost_get_raw_priv_key(const EVP_PKEY *pk, unsigned char *priv, size_t *len);
int gost_get_raw_pub_key(const EVP_PKEY *pk, unsigned char *pub, size_t *len);
int pkey_ctrl_gost(EVP_PKEY *pkey, int op, long arg1, void* arg2);

void mackey_free_gost(EVP_PKEY *pk);
int mac_ctrl_gost(EVP_PKEY *pkey, int op, long arg1, void* arg2);
int mac_ctrl_gost_12(EVP_PKEY *pkey, int op, long arg1, void* arg2);
int mac_ctrl_magma(EVP_PKEY *pkey, int op, long arg1, void* arg2);
int mac_ctrl_grasshopper(EVP_PKEY *pkey, int op, long arg1, void* arg2);
