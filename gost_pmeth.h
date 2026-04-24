#pragma once

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/opensslv.h>

#define ossl3_const
#ifdef OPENSSL_VERSION_MAJOR
#undef ossl3_const
#define ossl3_const const
#endif

int pkey_gost_init(EVP_PKEY_CTX *ctx);
int pkey_gost_copy(EVP_PKEY_CTX *dst, ossl3_const EVP_PKEY_CTX *src);
void pkey_gost_cleanup(EVP_PKEY_CTX *ctx);

int pkey_gost_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int pkey_gost_ec_ctrl_str_256(EVP_PKEY_CTX *ctx, const char *type, const char *value);
int pkey_gost_ec_ctrl_str_512(EVP_PKEY_CTX *ctx, const char *type, const char *value);

int pkey_gost_paramgen_init(EVP_PKEY_CTX *ctx);
int pkey_gost2001_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int pkey_gost2012_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int pkey_gost2001cp_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int pkey_gost2012cp_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

int pkey_gost_ec_cp_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbs_len);
int pkey_gost_ec_cp_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbs_len);

int pkey_gost_encrypt_init(EVP_PKEY_CTX *ctx);
int pkey_gost_derive_init(EVP_PKEY_CTX *ctx);

int pkey_gost_mac_init(EVP_PKEY_CTX *ctx);
void pkey_gost_mac_cleanup(EVP_PKEY_CTX *ctx);
int pkey_gost_mac_copy(EVP_PKEY_CTX *dst, ossl3_const EVP_PKEY_CTX *src);

int pkey_gost_magma_mac_init(EVP_PKEY_CTX *ctx);
int pkey_gost_grasshopper_mac_init(EVP_PKEY_CTX *ctx);

int pkey_gost_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
int pkey_gost_magma_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
int pkey_gost_grasshopper_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

int pkey_gost_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int pkey_gost_mac_keygen_12(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int pkey_gost_magma_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
int pkey_gost_grasshopper_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

int pkey_gost_check(EVP_PKEY *pkey);
