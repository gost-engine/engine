#include "gost_cipher_ctx.h"

struct gost_cipher_ctx_st {
    const GOST_cipher *cipher;
    EVP_CIPHER_CTX *cctx;
};

static int gost_cipher_ctx_init_evp(GOST_cipher_ctx *ctx,
                                    const GOST_cipher *cipher,
                                    EVP_CIPHER_CTX *cctx)
{
    if (ctx == NULL || cipher == NULL || cctx == NULL)
        return 0;

    ctx->cipher = cipher;
    ctx->cctx = cctx;
    return 1;
}

int GOST_cipher_init_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx,
                         const unsigned char *key, const unsigned char *iv,
                         int enc)
{
    GOST_cipher_ctx gctx;

    if (!gost_cipher_ctx_init_evp(&gctx, cipher, ctx))
        return 0;
    if (GOST_cipher_init_fn(cipher) == NULL)
        return 1;

    return GOST_cipher_init_fn(cipher)(&gctx, key, iv, enc);
}

int GOST_cipher_do_cipher_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx,
                              unsigned char *out, const unsigned char *in,
                              size_t inl)
{
    GOST_cipher_ctx gctx;

    if (!gost_cipher_ctx_init_evp(&gctx, cipher, ctx))
        return 0;
    if (GOST_cipher_do_cipher_fn(cipher) == NULL)
        return 1;

    return GOST_cipher_do_cipher_fn(cipher)(&gctx, out, in, inl);
}

int GOST_cipher_cleanup_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx)
{
    GOST_cipher_ctx gctx;

    if (!gost_cipher_ctx_init_evp(&gctx, cipher, ctx))
        return 0;
    if (GOST_cipher_cleanup_fn(cipher) == NULL)
        return 1;

    return GOST_cipher_cleanup_fn(cipher)(&gctx);
}

int GOST_cipher_ctrl_evp(const GOST_cipher *cipher, EVP_CIPHER_CTX *ctx,
                         int type, int arg, void *ptr)
{
    GOST_cipher_ctx gctx;

    if (!gost_cipher_ctx_init_evp(&gctx, cipher, ctx))
        return 0;
    if (type == EVP_CTRL_COPY) {
        GOST_cipher_ctx out_ctx;
        EVP_CIPHER_CTX *out = ptr;

        if (out == NULL || !gost_cipher_ctx_init_evp(&out_ctx, cipher, out))
            return 0;

        return GOST_cipher_ctx_copy(&out_ctx, &gctx);
    }
    if (GOST_cipher_ctrl_fn(cipher) == NULL)
        return -2;

    return GOST_cipher_ctrl_fn(cipher)(&gctx, type, arg, ptr);
}

int GOST_cipher_set_asn1_parameters_evp(const GOST_cipher *cipher,
                                        EVP_CIPHER_CTX *ctx,
                                        ASN1_TYPE *params)
{
    GOST_cipher_ctx gctx;

    if (!gost_cipher_ctx_init_evp(&gctx, cipher, ctx))
        return 0;
    if (GOST_cipher_set_asn1_parameters_fn(cipher) == NULL)
        return 1;

    return GOST_cipher_set_asn1_parameters_fn(cipher)(&gctx, params);
}

int GOST_cipher_get_asn1_parameters_evp(const GOST_cipher *cipher,
                                        EVP_CIPHER_CTX *ctx,
                                        ASN1_TYPE *params)
{
    GOST_cipher_ctx gctx;

    if (!gost_cipher_ctx_init_evp(&gctx, cipher, ctx))
        return 0;
    if (GOST_cipher_get_asn1_parameters_fn(cipher) == NULL)
        return 1;

    return GOST_cipher_get_asn1_parameters_fn(cipher)(&gctx, params);
}

int GOST_cipher_ctx_copy(GOST_cipher_ctx *out, const GOST_cipher_ctx *in)
{
    if (out == NULL || in == NULL || out->cctx == NULL || in->cctx == NULL)
        return 0;

    out->cipher = in->cipher;
    if (EVP_CIPHER_CTX_get_app_data(in->cctx) == EVP_CIPHER_CTX_get_cipher_data(in->cctx))
        EVP_CIPHER_CTX_set_app_data(out->cctx, EVP_CIPHER_CTX_get_cipher_data(out->cctx));

    if (out == in)
        return 1;
    if (out->cipher != NULL
        && (GOST_cipher_flags(out->cipher) & EVP_CIPH_CUSTOM_COPY) != 0
        && GOST_cipher_ctrl_fn(out->cipher) != NULL)
        return GOST_cipher_ctrl_fn(out->cipher)((GOST_cipher_ctx *)in,
                                                EVP_CTRL_COPY, 0, out) > 0;

    return 1;
}

unsigned char *GOST_cipher_ctx_buf_noconst(GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_buf_noconst(ctx->cctx) : NULL;
}

const GOST_cipher *GOST_cipher_ctx_cipher(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->cipher : NULL;
}

int GOST_cipher_ctx_encrypting(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_encrypting(ctx->cctx) : 0;
}

int GOST_cipher_ctx_iv_length(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_iv_length(ctx->cctx) : 0;
}

const unsigned char *GOST_cipher_ctx_iv(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_iv(ctx->cctx) : NULL;
}

unsigned char *GOST_cipher_ctx_iv_noconst(GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_iv_noconst(ctx->cctx) : NULL;
}

int GOST_cipher_ctx_key_length(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_key_length(ctx->cctx) : 0;
}

int GOST_cipher_ctx_mode(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_mode(ctx->cctx) : 0;
}

int GOST_cipher_ctx_nid(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_nid(ctx->cctx) : NID_undef;
}

int GOST_cipher_ctx_num(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_num(ctx->cctx) : 0;
}

const unsigned char *GOST_cipher_ctx_original_iv(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_original_iv(ctx->cctx) : NULL;
}

void *GOST_cipher_ctx_get_app_data(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_get_app_data(ctx->cctx) : NULL;
}

void *GOST_cipher_ctx_get_cipher_data(GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_get_cipher_data(ctx->cctx) : NULL;
}

int GOST_cipher_ctx_set_num(GOST_cipher_ctx *ctx, int num)
{
    if (ctx == NULL)
        return 0;

    EVP_CIPHER_CTX_set_num(ctx->cctx, num);
    return 1;
}

int GOST_cipher_ctx_set_padding(GOST_cipher_ctx *ctx, int pad)
{
    return ctx != NULL && ctx->cctx != NULL ? EVP_CIPHER_CTX_set_padding(ctx->cctx, pad) : 0;
}

int GOST_cipher_ctx_set_flags(GOST_cipher_ctx *ctx, int flags)
{
    if (ctx == NULL)
        return 0;

    EVP_CIPHER_CTX_set_flags(ctx->cctx, flags);
    return 1;
}

void GOST_cipher_ctx_set_app_data(GOST_cipher_ctx *ctx, void *data)
{
    if (ctx != NULL && ctx->cctx != NULL)
        EVP_CIPHER_CTX_set_app_data(ctx->cctx, data);
}

int GOST_cipher_ctx_cleanup(GOST_cipher_ctx *ctx)
{
    if (ctx == NULL || ctx->cipher == NULL)
        return 0;
    if (GOST_cipher_cleanup_fn(ctx->cipher) == NULL)
        return 1;

    return GOST_cipher_cleanup_fn(ctx->cipher)(ctx);
}

int GOST_cipher_ctx_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr)
{
    if (ctx == NULL || ctx->cipher == NULL || GOST_cipher_ctrl_fn(ctx->cipher) == NULL)
        return -2;

    return GOST_cipher_ctrl_fn(ctx->cipher)(ctx, type, arg, ptr);
}
