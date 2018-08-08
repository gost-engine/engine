/*
 * Shim to provide small subset of openssl-1.1.0 API by openssl-1.0.2
 *
 * Copyright (C) 2018 vt@altlinux.org. All Rights Reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#ifndef _GOST_COMPAT_H
#define _GOST_COMPAT_H

# include <openssl/opensslv.h>
# if (OPENSSL_VERSION_NUMBER <= 0x10002100L)

# include <string.h>

# include <openssl/crypto.h>
# include <openssl/dsa.h>
# include <openssl/evp.h>

/*
 * for crypto.h
 */

# define OPENSSL_zalloc(num)     CRYPTO_zalloc(num, __FILE__, __LINE__)
# define OPENSSL_clear_free(addr, num) \
    CRYPTO_clear_free(addr, num, __FILE__, __LINE__)

static inline void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc(num, file, line);

    if (ret != NULL)
	memset(ret, 0, num);
    return ret;
}

static inline void CRYPTO_clear_free(void *str, size_t num, const char *file, int line)
{
    if (str == NULL)
	return;
    if (num)
	OPENSSL_cleanse(str, num);
    CRYPTO_free(str);
}

/*
 * for dsa.h
 */

static inline void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
	*pr = sig->r;
    if (ps != NULL)
	*ps = sig->s;
}

static inline int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
	return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

/*
 * for evp.h
 */

#ifndef OPENSSL_FILE
# ifdef OPENSSL_NO_FILENAMES
#  define OPENSSL_FILE ""
#  define OPENSSL_LINE 0
# else
#  define OPENSSL_FILE __FILE__
#  define OPENSSL_LINE __LINE__
# endif
#endif

static inline void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

static inline const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->oiv;
}

static inline unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

static inline int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx)
{
    return ctx->encrypt;
}

static inline unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->buf;
}

static inline int EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx)
{
    return ctx->num;
}

static inline void EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num)
{
    ctx->num = num;
}

static inline EVP_CIPHER *EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len)
{
    EVP_CIPHER *cipher = OPENSSL_zalloc(sizeof(EVP_CIPHER));

    if (cipher != NULL) {
	cipher->nid = cipher_type;
	cipher->block_size = block_size;
	cipher->key_len = key_len;
    }
    return cipher;
}

static inline int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER *cipher, int iv_len)
{
    cipher->iv_len = iv_len;
    return 1;
}

static inline int EVP_CIPHER_meth_set_flags(EVP_CIPHER *cipher, unsigned long flags)
{
    cipher->flags = flags;
    return 1;
}

static inline int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER *cipher,
    int (*cleanup) (EVP_CIPHER_CTX *))
{
    cipher->cleanup = cleanup;
    return 1;
}

static inline int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER *cipher,
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *,
	ASN1_TYPE *))
{
    cipher->set_asn1_parameters = set_asn1_parameters;
    return 1;
}

static inline int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER *cipher,
    int (*ctrl) (EVP_CIPHER_CTX *, int type,
	int arg, void *ptr))
{
    cipher->ctrl = ctrl;
    return 1;
}

static inline int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER *cipher,
    int (*do_cipher) (EVP_CIPHER_CTX *ctx,
	unsigned char *out,
	const unsigned char *in,
	size_t inl))
{
    cipher->do_cipher = do_cipher;
    return 1;
}

static inline int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER *cipher,
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *,
	ASN1_TYPE *))
{
    cipher->get_asn1_parameters = get_asn1_parameters;
    return 1;
}

static inline int EVP_CIPHER_meth_set_init(EVP_CIPHER *cipher,
    int (*init) (EVP_CIPHER_CTX *ctx,
	const unsigned char *key,
	const unsigned char *iv,
	int enc))
{
    cipher->init = init;
    return 1;
}

static inline int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER *cipher, int ctx_size)
{
    cipher->ctx_size = ctx_size;
    return 1;
}

static inline void EVP_CIPHER_meth_free(EVP_CIPHER *cipher)
{
    OPENSSL_free(cipher);
}

static inline EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

int ENGINE_finish(ENGINE *e);
static inline int EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
    if (ctx == NULL)
	return 1;
    if (ctx->digest && ctx->digest->cleanup
	&& !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_CLEANED))
	ctx->digest->cleanup(ctx);
    if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
	&& !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) {
	OPENSSL_clear_free(ctx->md_data, ctx->digest->ctx_size);
    }
    EVP_PKEY_CTX_free(ctx->pctx);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(ctx->engine);
#endif
    OPENSSL_cleanse(ctx, sizeof(*ctx));

    return 1;
}

static inline void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_reset(ctx);
    OPENSSL_free(ctx);
}

static inline EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type)
{
    EVP_MD *md = OPENSSL_zalloc(sizeof(*md));

    if (md != NULL) {
	md->type = md_type;
	md->pkey_type = pkey_type;
    }
    return md;
}

static inline int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize)
{
    md->md_size = resultsize;
    return 1;
}

static int EVP_MD_meth_get_result_size(const EVP_MD *md)
{
    return md->md_size;
}

static inline int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize)
{
    md->block_size = blocksize;
    return 1;
}

static inline int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize)
{
    md->ctx_size = datasize;
    return 1;
}

static inline int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags)
{
    md->flags = flags;
    return 1;
}

static inline int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx))
{
    md->init = init;
    return 1;
}

static inline int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
	const void *data,
	size_t count))
{
    md->update = update;
    return 1;
}

static inline int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
	unsigned char *md))
{
    md->final = final;
    return 1;
}

static inline int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
	const EVP_MD_CTX *from))
{
    md->copy = copy;
    return 1;
}

static inline int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx))
{
    md->cleanup = cleanup;
    return 1;
}

static inline int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd,
	int p1, void *p2))
{
    md->md_ctrl = ctrl;
    return 1;
}

static inline void EVP_MD_meth_free(EVP_MD *md)
{
    OPENSSL_free(md);
}

static inline const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

static inline void *EVP_MD_CTX_md_data(const EVP_MD_CTX *ctx)
{
    return ctx->md_data;
}

static inline int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->init;
}

static inline int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
    int p1, void *p2)
{
    return md->md_ctrl;
}

# endif /* (OPENSSL_VERSION_NUMBER <= 0x10002100L) */

# ifndef NID_id_tc26_cipher_gostr3412_2015_kuznyechik
#  define NID_id_tc26_cipher_gostr3412_2015_kuznyechik                  1176
#  define NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm         1177
#  define NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac    1178
#  define NID_magma_ecb							1187
#  define NID_magma_ctr							1188
#  define NID_magma_ofb							1189
#  define NID_magma_cbc							1190
#  define NID_magma_cfb							1191
#  define NID_magma_mac							1192
# endif

#endif /* !_GOST_COMPAT_H */
