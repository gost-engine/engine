/*
 * Copyright (c) 2019 Dmitry Belyavskiy <beldmit@gmail.com>
 * Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#include "gost_lcl.h"
#include "gost_gost2015.h"
#include "gost_grasshopper_cipher.h"
#include "gost_tls12_additional.h"
#include "e_gost_err.h"
#include "gost_cipher_details.h"

#define GOST_WRAP_FLAGS  EVP_CIPH_CTRL_INIT | EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1

#define MAGMA_MAC_WRAP_LEN 8
#define KUZNYECHIK_MAC_WRAP_LEN 16
#define MAX_MAC_WRAP_LEN KUZNYECHIK_MAC_WRAP_LEN
#define GOSTKEYLEN 32
#define MAGMA_WRAPPED_KEY_LEN GOSTKEYLEN + MAGMA_MAC_WRAP_LEN
#define KUZNYECHIK_WRAPPED_KEY_LEN GOSTKEYLEN + KUZNYECHIK_MAC_WRAP_LEN
#define MAX_WRAPPED_KEY_LEN KUZNYECHIK_WRAPPED_KEY_LEN

typedef struct {
	unsigned char iv[8];   /* Max IV size is half of base cipher block length */
	unsigned char key[GOSTKEYLEN*2]; /* Combined cipher and mac keys */
	unsigned char wrapped[MAX_WRAPPED_KEY_LEN]; /* Max size */
	size_t wrap_count;
} GOST_WRAP_CTX;

static int magma_wrap_init(GOST_cipher_ctx *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	GOST_WRAP_CTX *cctx = GOST_cipher_ctx_get_cipher_data(ctx);
	memset(cctx->wrapped, 0, MAX_WRAPPED_KEY_LEN);
	cctx->wrap_count = 0;

	if (iv) {
		memset(cctx->iv, 0, 8);
		memcpy(cctx->iv, iv, 4);
	}

	if (key) {
		memcpy(cctx->key, key, GOSTKEYLEN*2);
	}
	return 1;
}

static int magma_wrap_do(GOST_cipher_ctx *ctx, unsigned char *out,
	const unsigned char *in, size_t inl)
{
	GOST_WRAP_CTX *cctx = GOST_cipher_ctx_get_cipher_data(ctx);
	int enc = GOST_cipher_ctx_encrypting(ctx) ? 1 : 0;

	if (out == NULL)
		return GOSTKEYLEN;

	if (inl <= MAGMA_WRAPPED_KEY_LEN) {
		if (cctx->wrap_count + inl > MAGMA_WRAPPED_KEY_LEN)
			return -1;

		if (cctx->wrap_count + inl <= MAGMA_WRAPPED_KEY_LEN)
		{
			memcpy(cctx->wrapped+cctx->wrap_count, in, inl);
			cctx->wrap_count += inl;
		}
	}

	if (cctx->wrap_count < MAGMA_WRAPPED_KEY_LEN)
		return 0;

	if (enc) {
#if 0
		return gost_kexp15(cctx->key, 32, NID_magma_ctr, in, NID_magma_mac,
			cctx->key, /* FIXME mac_key, */ cctx->iv, 4, out, &outl);
#endif
		return -1;
	} else {
		return gost_kimp15(cctx->wrapped, cctx->wrap_count, NID_magma_ctr,
		cctx->key+GOSTKEYLEN, NID_magma_mac, cctx->key, cctx->iv, 4, out) > 0 ? GOSTKEYLEN : 0;
	}
}

static int kuznyechik_wrap_init(GOST_cipher_ctx *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	GOST_WRAP_CTX *cctx = GOST_cipher_ctx_get_cipher_data(ctx);
	memset(cctx->wrapped, 0, KUZNYECHIK_WRAPPED_KEY_LEN);
	cctx->wrap_count = 0;

	if (iv) {
		memset(cctx->iv, 0, 8);
		memcpy(cctx->iv, iv, 8);
	}

	if (key) {
		memcpy(cctx->key, key, GOSTKEYLEN*2);
	}
	return 1;
}

static int kuznyechik_wrap_do(GOST_cipher_ctx *ctx, unsigned char *out,
	const unsigned char *in, size_t inl)
{
	GOST_WRAP_CTX *cctx = GOST_cipher_ctx_get_cipher_data(ctx);
	int enc = GOST_cipher_ctx_encrypting(ctx) ? 1 : 0;

	if (out == NULL)
		return GOSTKEYLEN;

	if (inl <= KUZNYECHIK_WRAPPED_KEY_LEN) {
		if (cctx->wrap_count + inl > KUZNYECHIK_WRAPPED_KEY_LEN)
			return -1;

		if (cctx->wrap_count + inl <= KUZNYECHIK_WRAPPED_KEY_LEN)
		{
			memcpy(cctx->wrapped+cctx->wrap_count, in, inl);
			cctx->wrap_count += inl;
		}
	}

	if (cctx->wrap_count < KUZNYECHIK_WRAPPED_KEY_LEN)
		return 0;

	if (enc) {
#if 0
		return gost_kexp15(cctx->key, 32, NID_magma_ctr, in, NID_magma_mac,
			cctx->key, /* FIXME mac_key, */ cctx->iv, 4, out, &outl);
#endif
		return -1;
	} else {
		return gost_kimp15(cctx->wrapped, cctx->wrap_count, NID_kuznyechik_ctr,
		cctx->key+GOSTKEYLEN, NID_kuznyechik_mac, cctx->key, cctx->iv, 8, out) > 0 ? GOSTKEYLEN : 0;
	}
}

static int wrap_ctrl (GOST_cipher_ctx *ctx, int type, int arg, void *ptr)
{
	switch(type)
	{
		case EVP_CTRL_INIT:
			GOST_cipher_ctx_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
			return 1;
		default:
			return -2;
	}
}

static GOST_cipher wrap_template_cipher = {
    .key_len = GOSTKEYLEN * 2,
    .flags = GOST_WRAP_FLAGS,
    .ctx_size = sizeof(GOST_WRAP_CTX),
    .ctrl = wrap_ctrl,
};

GOST_cipher magma_kexp15_cipher = {
    .template = &wrap_template_cipher,
    .nid = NID_magma_kexp15,
    .block_size = 8,
    .iv_len = 4,
    .init = magma_wrap_init,
    .do_cipher = magma_wrap_do,
};

GOST_cipher kuznyechik_kexp15_cipher = {
    .template = &wrap_template_cipher,
    .nid = NID_kuznyechik_kexp15,
    .block_size = 16,
    .iv_len = 8,
    .init = kuznyechik_wrap_init,
    .do_cipher = kuznyechik_wrap_do,
};
/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
