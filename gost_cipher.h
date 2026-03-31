#pragma once

#include <stddef.h>
#include <openssl/types.h>

struct gost_cipher_ctx_st;
struct gost_cipher_st;
typedef struct gost_cipher_st GOST_cipher;

int GOST_cipher_type(const GOST_cipher *c);
int GOST_cipher_nid(const GOST_cipher *c);
int GOST_cipher_flags(const GOST_cipher *c);
int GOST_cipher_key_length(const GOST_cipher *c);
int GOST_cipher_iv_length(const GOST_cipher *c);
int GOST_cipher_block_size(const GOST_cipher *c);
int GOST_cipher_mode(const GOST_cipher *c);
int GOST_cipher_ctx_size(const GOST_cipher *c);
int (*GOST_cipher_init_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                 const unsigned char *key,
                                                 const unsigned char *iv,
                                                 int enc);
// Fill ASN1_TYPE *params struct based on ctx
int (*GOST_cipher_set_asn1_parameters_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                                ASN1_TYPE *params);
// Modify ctx based on ASN1_TYPE *params struct
int (*GOST_cipher_get_asn1_parameters_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                                ASN1_TYPE *params);
int (*GOST_cipher_do_cipher_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                      unsigned char *out,
                                                      const unsigned char *in,
                                                      size_t inl);
int (*GOST_cipher_cleanup_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx);
int (*GOST_cipher_ctrl_fn(const GOST_cipher *c))(struct gost_cipher_ctx_st *ctx,
                                                 int type, int arg,
                                                 void *ptr);
