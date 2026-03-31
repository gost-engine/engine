/*
 * Maxim Tishkov 2016
 * This file is distributed under the same license as OpenSSL
 */

#ifndef GOST_GRASSHOPPER_CIPHER_H
#define GOST_GRASSHOPPER_CIPHER_H

#define SN_kuznyechik_mgm      "kuznyechik-mgm"

#if defined(__cplusplus)
extern "C" {
#endif

#include "gost_grasshopper_defines.h"
#include "gost_cipher_ctx.h"

#include "gost_lcl.h"
#include <openssl/evp.h>

// not thread safe
// because of buffers
typedef struct {
    uint8_t type;
    grasshopper_key_t master_key;
    grasshopper_key_t key;
    grasshopper_round_keys_t encrypt_round_keys;
    grasshopper_round_keys_t decrypt_round_keys;
    grasshopper_w128_t buffer;
} gost_grasshopper_cipher_ctx;

typedef struct {
    gost_grasshopper_cipher_ctx c;
    grasshopper_w128_t partial_buffer;
    unsigned int section_size;  /* After how much bytes mesh the key,
				   if 0 never mesh and work like plain ctr. */
    unsigned char kdf_seed[8];
		unsigned char tag[16];
		EVP_MD_CTX *omac_ctx;
} gost_grasshopper_cipher_ctx_ctr;

static void gost_grasshopper_cipher_key(gost_grasshopper_cipher_ctx* c, const uint8_t* k);

static void gost_grasshopper_cipher_destroy(gost_grasshopper_cipher_ctx* c);

static int gost_grasshopper_cipher_init_ecb(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_cbc(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ofb(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_cfb(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctr(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctracpkm(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_ctracpkm_omac(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init_mgm(GOST_cipher_ctx* ctx,
    const unsigned char* key, const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_init(GOST_cipher_ctx* ctx, const unsigned char* key,
    const unsigned char* iv, int enc);

static int gost_grasshopper_cipher_do(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ecb(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_cbc(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ofb(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_cfb(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ctr(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ctracpkm(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_ctracpkm_omac(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_do_mgm(GOST_cipher_ctx* ctx, unsigned char* out,
    const unsigned char* in, size_t inl);

static int gost_grasshopper_cipher_cleanup(GOST_cipher_ctx* ctx);

static int gost_grasshopper_mgm_cleanup(GOST_cipher_ctx *c);

static int gost_grasshopper_set_asn1_parameters(GOST_cipher_ctx* ctx, ASN1_TYPE* params);

static int gost_grasshopper_get_asn1_parameters(GOST_cipher_ctx* ctx, ASN1_TYPE* params);

static int gost_grasshopper_cipher_ctl(GOST_cipher_ctx* ctx, int type, int arg, void* ptr);

static int gost_grasshopper_mgm_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr);

#if defined(__cplusplus)
}
#endif

#endif
