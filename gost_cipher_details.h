#pragma once

#include <openssl/evp.h>

#include "gost_cipher.h"

/* Internal cipher descriptor layout. Public users must treat GOST_cipher as opaque. */
struct gost_cipher_st {
    struct gost_cipher_st *template; /* template struct */
    int nid;
    int block_size;     /* (bytes) */
    int key_len;        /* (bytes) */
    int iv_len;
    int flags;
    int (*init) (struct gost_cipher_ctx_st *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    int (*do_cipher)(struct gost_cipher_ctx_st *ctx, unsigned char *out,
                     const unsigned char *in, size_t inl);
    int (*cleanup)(struct gost_cipher_ctx_st *);
    int ctx_size;
    int (*set_asn1_parameters)(struct gost_cipher_ctx_st *, ASN1_TYPE *);
    int (*get_asn1_parameters)(struct gost_cipher_ctx_st *, ASN1_TYPE *);
    int (*ctrl)(struct gost_cipher_ctx_st *, int type, int arg, void *ptr);
};
