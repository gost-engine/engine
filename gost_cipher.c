#include "gost_cipher_details.h"
#include "gost_cipher_ctx.h"

#define TPL_VAL(st, field) (((st) != NULL && (st)->template != NULL) \
                            ? (st)->template->field : 0)

int GOST_cipher_type(const GOST_cipher *c)
{
    return c != NULL ? c->nid : NID_undef;
}

int GOST_cipher_nid(const GOST_cipher *c)
{
    return GOST_cipher_type(c);
}

int GOST_cipher_flags(const GOST_cipher *c)
{
    return c != NULL ? (c->flags | TPL_VAL(c, flags)) : 0;
}

int GOST_cipher_key_length(const GOST_cipher *c)
{
    if (c == NULL)
        return 0;

    return c->key_len != 0 ? c->key_len : TPL_VAL(c, key_len);
}

int GOST_cipher_iv_length(const GOST_cipher *c)
{
    if (c == NULL)
        return 0;

    return c->iv_len != 0 ? c->iv_len : TPL_VAL(c, iv_len);
}

int GOST_cipher_block_size(const GOST_cipher *c)
{
    if (c == NULL)
        return 0;

    return c->block_size != 0 ? c->block_size : TPL_VAL(c, block_size);
}

int GOST_cipher_mode(const GOST_cipher *c)
{
    return c != NULL ? (c->flags & EVP_CIPH_MODE) : 0;
}

int GOST_cipher_ctx_size(const GOST_cipher *c)
{
    if (c == NULL)
        return 0;

    return c->ctx_size != 0 ? c->ctx_size : TPL_VAL(c, ctx_size);
}

int (*GOST_cipher_init_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 const unsigned char *key,
                                                 const unsigned char *iv,
                                                 int enc)
{
    if (c == NULL)
        return NULL;

    return c->init != NULL ? c->init : TPL_VAL(c, init);
}

int (*GOST_cipher_set_asn1_parameters_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                                ASN1_TYPE *params)
{
    if (c == NULL)
        return NULL;

    return c->set_asn1_parameters != NULL
        ? c->set_asn1_parameters : TPL_VAL(c, set_asn1_parameters);
}

int (*GOST_cipher_get_asn1_parameters_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                                ASN1_TYPE *params)
{
    if (c == NULL)
        return NULL;

    return c->get_asn1_parameters != NULL
        ? c->get_asn1_parameters : TPL_VAL(c, get_asn1_parameters);
}

int (*GOST_cipher_do_cipher_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                      unsigned char *out,
                                                      const unsigned char *in,
                                                      size_t inl)
{
    if (c == NULL)
        return NULL;

    return c->do_cipher != NULL ? c->do_cipher : TPL_VAL(c, do_cipher);
}

int (*GOST_cipher_cleanup_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx)
{
    if (c == NULL)
        return NULL;

    return c->cleanup != NULL ? c->cleanup : TPL_VAL(c, cleanup);
}

int (*GOST_cipher_ctrl_fn(const GOST_cipher *c))(GOST_cipher_ctx *ctx,
                                                 int type, int arg,
                                                 void *ptr)
{
    if (c == NULL)
        return NULL;

    return c->ctrl != NULL ? c->ctrl : TPL_VAL(c, ctrl);
}
