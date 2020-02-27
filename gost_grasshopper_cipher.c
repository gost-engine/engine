/*
 * Maxim Tishkov 2016
 * This file is distributed under the same license as OpenSSL
 */

#include "gost_grasshopper_cipher.h"
#include "gost_grasshopper_defines.h"
#include "gost_grasshopper_math.h"
#include "gost_grasshopper_core.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#include "gost_lcl.h"
#include "e_gost_err.h"

enum GRASSHOPPER_CIPHER_TYPE {
    GRASSHOPPER_CIPHER_ECB = 0,
    GRASSHOPPER_CIPHER_CBC,
    GRASSHOPPER_CIPHER_OFB,
    GRASSHOPPER_CIPHER_CFB,
    GRASSHOPPER_CIPHER_CTR,
    GRASSHOPPER_CIPHER_CTRACPKM,
};

static EVP_CIPHER *gost_grasshopper_ciphers[6] = {
    NULL, NULL, NULL, NULL, NULL, NULL,
};

static GRASSHOPPER_INLINE void
gost_grasshopper_cipher_destroy_ctr(gost_grasshopper_cipher_ctx * c);

struct GRASSHOPPER_CIPHER_PARAMS {
    int nid;
    grasshopper_init_cipher_func init_cipher;
    grasshopper_do_cipher_func do_cipher;
    grasshopper_destroy_cipher_func destroy_cipher;
    int block_size;
    int ctx_size;
    int iv_size;
    bool padding;
};

static struct GRASSHOPPER_CIPHER_PARAMS gost_cipher_params[6] = {
 {
                                NID_grasshopper_ecb,
                                gost_grasshopper_cipher_init_ecb,
                                gost_grasshopper_cipher_do_ecb,
                                NULL,
                                16,
                                sizeof(gost_grasshopper_cipher_ctx),
                                0,
                                true}
    ,
    {
                                NID_grasshopper_cbc,
                                gost_grasshopper_cipher_init_cbc,
                                gost_grasshopper_cipher_do_cbc,
                                NULL,
                                16,
                                sizeof(gost_grasshopper_cipher_ctx),
                                16,
                                true}
    ,
    {
                                NID_grasshopper_ofb,
                                gost_grasshopper_cipher_init_ofb,
                                gost_grasshopper_cipher_do_ofb,
                                NULL,
                                1,
                                sizeof(gost_grasshopper_cipher_ctx),
                                16,
                                false}
    ,
    {
                                NID_grasshopper_cfb,
                                gost_grasshopper_cipher_init_cfb,
                                gost_grasshopper_cipher_do_cfb,
                                NULL,
                                1,
                                sizeof(gost_grasshopper_cipher_ctx),
                                16,
                                false}
    ,
    {
                                NID_grasshopper_ctr,
                                gost_grasshopper_cipher_init_ctr,
                                gost_grasshopper_cipher_do_ctr,
                                gost_grasshopper_cipher_destroy_ctr,
                                1,
                                sizeof(gost_grasshopper_cipher_ctx_ctr),
                                /* IV size is set to match full block, to make it responsibility of
                                 * user to assign correct values (IV || 0), and to make naive context
                                 * copy possible (for software such as openssh) */
                                16,
                                false}
    ,
    {
                                     NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm,
                                     gost_grasshopper_cipher_init_ctracpkm,
                                     gost_grasshopper_cipher_do_ctracpkm,
                                     gost_grasshopper_cipher_destroy_ctr,
                                     1,
                                     sizeof(gost_grasshopper_cipher_ctx_ctr),
                                     16,
                                     false}
    ,
};

/* first 256 bit of D from draft-irtf-cfrg-re-keying-12 */
static const unsigned char ACPKM_D_2018[] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, /*  64 bit */
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, /* 128 bit */
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, /* 256 bit */
};

static void acpkm_next(gost_grasshopper_cipher_ctx * c)
{
    unsigned char newkey[GRASSHOPPER_KEY_SIZE];
    const int J = GRASSHOPPER_KEY_SIZE / GRASSHOPPER_BLOCK_SIZE;
    int n;

    for (n = 0; n < J; n++) {
        const unsigned char *D_n = &ACPKM_D_2018[n * GRASSHOPPER_BLOCK_SIZE];

        grasshopper_encrypt_block(&c->encrypt_round_keys,
                                  (grasshopper_w128_t *) D_n,
                                  (grasshopper_w128_t *) & newkey[n *
                                                                  GRASSHOPPER_BLOCK_SIZE],
                                  &c->buffer);
    }
    gost_grasshopper_cipher_key(c, newkey);
}

/* Set 256 bit  key into context */
GRASSHOPPER_INLINE void
gost_grasshopper_cipher_key(gost_grasshopper_cipher_ctx * c, const uint8_t *k)
{
    int i;
    for (i = 0; i < 2; i++) {
        grasshopper_copy128(&c->key.k.k[i],
                            (const grasshopper_w128_t *)(k + i * 16));
    }

    grasshopper_set_encrypt_key(&c->encrypt_round_keys, &c->key);
    grasshopper_set_decrypt_key(&c->decrypt_round_keys, &c->key);
}

/* Set master 256-bit key to be used in TLSTREE calculation into context */
GRASSHOPPER_INLINE void
gost_grasshopper_master_key(gost_grasshopper_cipher_ctx * c, const uint8_t *k)
{
    int i;
    for (i = 0; i < 2; i++) {
        grasshopper_copy128(&c->master_key.k.k[i],
                            (const grasshopper_w128_t *)(k + i * 16));
    }
}

/* Cleans up key from context */
GRASSHOPPER_INLINE void
gost_grasshopper_cipher_destroy(gost_grasshopper_cipher_ctx * c)
{
    int i;
    for (i = 0; i < 2; i++) {
        grasshopper_zero128(&c->key.k.k[i]);
        grasshopper_zero128(&c->master_key.k.k[i]);
    }
    for (i = 0; i < GRASSHOPPER_ROUND_KEYS_COUNT; i++) {
        grasshopper_zero128(&c->encrypt_round_keys.k[i]);
    }
    for (i = 0; i < GRASSHOPPER_ROUND_KEYS_COUNT; i++) {
        grasshopper_zero128(&c->decrypt_round_keys.k[i]);
    }
    grasshopper_zero128(&c->buffer);
}

static GRASSHOPPER_INLINE void
gost_grasshopper_cipher_destroy_ctr(gost_grasshopper_cipher_ctx * c)
{
    gost_grasshopper_cipher_ctx_ctr *ctx =
        (gost_grasshopper_cipher_ctx_ctr *) c;

    grasshopper_zero128(&ctx->partial_buffer);
}

int gost_grasshopper_cipher_init(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (EVP_CIPHER_CTX_get_app_data(ctx) == NULL) {
        EVP_CIPHER_CTX_set_app_data(ctx, EVP_CIPHER_CTX_get_cipher_data(ctx));
    }

    if (key != NULL) {
        gost_grasshopper_cipher_key(c, key);
        gost_grasshopper_master_key(c, key);
    }

    if (iv != NULL) {
        memcpy((unsigned char *)EVP_CIPHER_CTX_original_iv(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    }

    memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
           EVP_CIPHER_CTX_original_iv(ctx), EVP_CIPHER_CTX_iv_length(ctx));

    grasshopper_zero128(&c->buffer);

    return 1;
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_init_ecb(EVP_CIPHER_CTX *ctx, const unsigned char
                                                        *key, const unsigned char
                                                        *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_ECB;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_init_cbc(EVP_CIPHER_CTX *ctx, const unsigned char
                                                        *key, const unsigned char
                                                        *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_CBC;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_init_ofb(EVP_CIPHER_CTX *ctx, const unsigned char
                                                        *key, const unsigned char
                                                        *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_OFB;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_init_cfb(EVP_CIPHER_CTX *ctx, const unsigned char
                                                        *key, const unsigned char
                                                        *iv, int enc)
{
    gost_grasshopper_cipher_ctx *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    c->type = GRASSHOPPER_CIPHER_CFB;
    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_init_ctr(EVP_CIPHER_CTX *ctx, const unsigned char
                                                        *key, const unsigned char
                                                        *iv, int enc)
{
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    c->c.type = GRASSHOPPER_CIPHER_CTR;
    EVP_CIPHER_CTX_set_num(ctx, 0);

    grasshopper_zero128(&c->partial_buffer);

    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_init_ctracpkm(EVP_CIPHER_CTX
                                                             *ctx, const unsigned
                                                             char *key, const unsigned
                                                             char *iv, int enc)
{
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    /* NB: setting type makes EVP do_cipher callback useless */
    c->c.type = GRASSHOPPER_CIPHER_CTRACPKM;
    EVP_CIPHER_CTX_set_num(ctx, 0);
    c->section_size = 4096;

    return gost_grasshopper_cipher_init(ctx, key, iv, enc);
}

GRASSHOPPER_INLINE int gost_grasshopper_cipher_do(EVP_CIPHER_CTX *ctx,
                                                  unsigned char *out,
                                                  const unsigned char *in,
                                                  size_t inl)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct GRASSHOPPER_CIPHER_PARAMS *params = &gost_cipher_params[c->type];

    return params->do_cipher(ctx, out, in, inl);
}

int gost_grasshopper_cipher_do_ecb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    bool encrypting = (bool) EVP_CIPHER_CTX_encrypting(ctx);
    const unsigned char *current_in = in;
    unsigned char *current_out = out;
    size_t blocks = inl / GRASSHOPPER_BLOCK_SIZE;
    size_t i;

    for (i = 0; i < blocks;
         i++, current_in += GRASSHOPPER_BLOCK_SIZE, current_out +=
         GRASSHOPPER_BLOCK_SIZE) {
        if (encrypting) {
            grasshopper_encrypt_block(&c->encrypt_round_keys,
                                      (grasshopper_w128_t *) current_in,
                                      (grasshopper_w128_t *) current_out,
                                      &c->buffer);
        } else {
            grasshopper_decrypt_block(&c->decrypt_round_keys,
                                      (grasshopper_w128_t *) current_in,
                                      (grasshopper_w128_t *) current_out,
                                      &c->buffer);
        }
    }

    return 1;
}

int gost_grasshopper_cipher_do_cbc(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    bool encrypting = (bool) EVP_CIPHER_CTX_encrypting(ctx);
    const unsigned char *current_in = in;
    unsigned char *current_out = out;
    size_t blocks = inl / GRASSHOPPER_BLOCK_SIZE;
    size_t i;
    grasshopper_w128_t *currentBlock;

    currentBlock = (grasshopper_w128_t *) iv;

    for (i = 0; i < blocks;
         i++, current_in += GRASSHOPPER_BLOCK_SIZE, current_out +=
         GRASSHOPPER_BLOCK_SIZE) {
        grasshopper_w128_t *currentInputBlock = (grasshopper_w128_t *) current_in;
        grasshopper_w128_t *currentOutputBlock = (grasshopper_w128_t *) current_out;
        if (encrypting) {
            grasshopper_append128(currentBlock, currentInputBlock);
            grasshopper_encrypt_block(&c->encrypt_round_keys, currentBlock,
                                      currentOutputBlock, &c->buffer);
            grasshopper_copy128(currentBlock, currentOutputBlock);
        } else {
            grasshopper_w128_t tmp;

            grasshopper_copy128(&tmp, currentInputBlock);
            grasshopper_decrypt_block(&c->decrypt_round_keys,
                                      currentInputBlock, currentOutputBlock,
                                      &c->buffer);
            grasshopper_append128(currentOutputBlock, currentBlock);
            grasshopper_copy128(currentBlock, &tmp);
        }
    }

    return 1;
}

void inc_counter(unsigned char *counter, size_t counter_bytes)
{
    unsigned int n = counter_bytes;

    do {
        unsigned char c;
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter)
{
    inc_counter(counter, 16);
}

int gost_grasshopper_cipher_do_ctr(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx_ctr *c = (gost_grasshopper_cipher_ctx_ctr *)
        EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    const unsigned char *current_in = in;
    unsigned char *current_out = out;
    grasshopper_w128_t *currentInputBlock;
    grasshopper_w128_t *currentOutputBlock;
    unsigned int n = EVP_CIPHER_CTX_num(ctx);
    size_t lasted;
    size_t i;
    size_t blocks;
    grasshopper_w128_t *iv_buffer;
    grasshopper_w128_t tmp;

    while (n && inl) {
        *(current_out++) = *(current_in++) ^ c->partial_buffer.b[n];
        --inl;
        n = (n + 1) % GRASSHOPPER_BLOCK_SIZE;
    }
    EVP_CIPHER_CTX_set_num(ctx, n);
    blocks = inl / GRASSHOPPER_BLOCK_SIZE;

    iv_buffer = (grasshopper_w128_t *) iv;

    // full parts
    for (i = 0; i < blocks; i++) {
        currentInputBlock = (grasshopper_w128_t *) current_in;
        currentOutputBlock = (grasshopper_w128_t *) current_out;
        grasshopper_encrypt_block(&c->c.encrypt_round_keys, iv_buffer,
                                  &c->partial_buffer, &c->c.buffer);
        grasshopper_plus128(&tmp, &c->partial_buffer, currentInputBlock);
        grasshopper_copy128(currentOutputBlock, &tmp);
        ctr128_inc(iv_buffer->b);
        current_in += GRASSHOPPER_BLOCK_SIZE;
        current_out += GRASSHOPPER_BLOCK_SIZE;
    }

    // last part
    lasted = inl - blocks * GRASSHOPPER_BLOCK_SIZE;
    if (lasted > 0) {
        currentInputBlock = (grasshopper_w128_t *) current_in;
        currentOutputBlock = (grasshopper_w128_t *) current_out;
        grasshopper_encrypt_block(&c->c.encrypt_round_keys, iv_buffer,
                                  &c->partial_buffer, &c->c.buffer);
        for (i = 0; i < lasted; i++) {
            currentOutputBlock->b[i] =
                c->partial_buffer.b[i] ^ currentInputBlock->b[i];
        }
        EVP_CIPHER_CTX_set_num(ctx, i);
        ctr128_inc(iv_buffer->b);
    }

    return 1;
}

#define GRASSHOPPER_BLOCK_MASK (GRASSHOPPER_BLOCK_SIZE - 1)
static inline void apply_acpkm_grasshopper(gost_grasshopper_cipher_ctx_ctr *
                                           ctx, unsigned int *num)
{
    if (!ctx->section_size || (*num < ctx->section_size))
        return;
    acpkm_next(&ctx->c);
    *num &= GRASSHOPPER_BLOCK_MASK;
}

/* If meshing is not configured via ctrl (setting section_size)
 * this function works exactly like plain ctr */
int gost_grasshopper_cipher_do_ctracpkm(EVP_CIPHER_CTX *ctx,
                                        unsigned char *out,
                                        const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx_ctr *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    size_t blocks, i, lasted;
    grasshopper_w128_t tmp;

    while ((num & GRASSHOPPER_BLOCK_MASK) && inl) {
        *out++ = *in++ ^ c->partial_buffer.b[num & GRASSHOPPER_BLOCK_MASK];
        --inl;
        num++;
    }
    blocks = inl / GRASSHOPPER_BLOCK_SIZE;

    // full parts
    for (i = 0; i < blocks; i++) {
        apply_acpkm_grasshopper(c, &num);
        grasshopper_encrypt_block(&c->c.encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) & c->partial_buffer,
                                  &c->c.buffer);
        grasshopper_plus128(&tmp, &c->partial_buffer,
                            (grasshopper_w128_t *) in);
        grasshopper_copy128((grasshopper_w128_t *) out, &tmp);
        ctr128_inc(iv);
        in += GRASSHOPPER_BLOCK_SIZE;
        out += GRASSHOPPER_BLOCK_SIZE;
        num += GRASSHOPPER_BLOCK_SIZE;
    }

    // last part
    lasted = inl - blocks * GRASSHOPPER_BLOCK_SIZE;
    if (lasted > 0) {
        apply_acpkm_grasshopper(c, &num);
        grasshopper_encrypt_block(&c->c.encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  &c->partial_buffer, &c->c.buffer);
        for (i = 0; i < lasted; i++)
            out[i] = c->partial_buffer.b[i] ^ in[i];
        ctr128_inc(iv);
        num += lasted;
    }
    EVP_CIPHER_CTX_set_num(ctx, num);

    return 1;
}

/*
 * Fixed 128-bit IV implementation make shift regiser redundant.
 */
static void gost_grasshopper_cnt_next(gost_grasshopper_cipher_ctx * ctx,
                                      grasshopper_w128_t * iv,
                                      grasshopper_w128_t * buf)
{
    grasshopper_w128_t tmp;
    memcpy(&tmp, iv, 16);
    grasshopper_encrypt_block(&ctx->encrypt_round_keys, &tmp,
                              buf, &ctx->buffer);
    memcpy(iv, buf, 16);
}

int gost_grasshopper_cipher_do_ofb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c = (gost_grasshopper_cipher_ctx *)
        EVP_CIPHER_CTX_get_cipher_data(ctx);
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    int num = EVP_CIPHER_CTX_num(ctx);
    size_t i = 0;
    size_t j;

    /* process partial block if any */
    if (num > 0) {
        for (j = (size_t)num, i = 0; j < GRASSHOPPER_BLOCK_SIZE && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            *out_ptr = buf[j] ^ (*in_ptr);
        }
        if (j == GRASSHOPPER_BLOCK_SIZE) {
            EVP_CIPHER_CTX_set_num(ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_num(ctx, (int)j);
            return 1;
        }
    }

    for (; i + GRASSHOPPER_BLOCK_SIZE <
         inl;
         i += GRASSHOPPER_BLOCK_SIZE, in_ptr +=
         GRASSHOPPER_BLOCK_SIZE, out_ptr += GRASSHOPPER_BLOCK_SIZE) {
        /*
         * block cipher current iv
         */
        /* Encrypt */
        gost_grasshopper_cnt_next(c, (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf);

        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        for (j = 0; j < GRASSHOPPER_BLOCK_SIZE; j++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
    }

    /* Process rest of buffer */
    if (i < inl) {
        gost_grasshopper_cnt_next(c, (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf);
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        EVP_CIPHER_CTX_set_num(ctx, (int)j);
    } else {
        EVP_CIPHER_CTX_set_num(ctx, 0);
    }

    return 1;
}

int gost_grasshopper_cipher_do_cfb(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   const unsigned char *in, size_t inl)
{
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
    const unsigned char *in_ptr = in;
    unsigned char *out_ptr = out;
    unsigned char *buf = EVP_CIPHER_CTX_buf_noconst(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    bool encrypting = (bool) EVP_CIPHER_CTX_encrypting(ctx);
    int num = EVP_CIPHER_CTX_num(ctx);
    size_t i = 0;
    size_t j = 0;

    /* process partial block if any */
    if (num > 0) {
        for (j = (size_t)num, i = 0; j < GRASSHOPPER_BLOCK_SIZE && i < inl;
             j++, i++, in_ptr++, out_ptr++) {
            if (!encrypting) {
                buf[j + GRASSHOPPER_BLOCK_SIZE] = *in_ptr;
            }
            *out_ptr = buf[j] ^ (*in_ptr);
            if (encrypting) {
                buf[j + GRASSHOPPER_BLOCK_SIZE] = *out_ptr;
            }
        }
        if (j == GRASSHOPPER_BLOCK_SIZE) {
            memcpy(iv, buf + GRASSHOPPER_BLOCK_SIZE, GRASSHOPPER_BLOCK_SIZE);
            EVP_CIPHER_CTX_set_num(ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_num(ctx, (int)j);
            return 1;
        }
    }

    for (; i + GRASSHOPPER_BLOCK_SIZE <
         inl;
         i += GRASSHOPPER_BLOCK_SIZE, in_ptr +=
         GRASSHOPPER_BLOCK_SIZE, out_ptr += GRASSHOPPER_BLOCK_SIZE) {
        /*
         * block cipher current iv
         */
        grasshopper_encrypt_block(&c->encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf, &c->buffer);
        /*
         * xor next block of input text with it and output it
         */
        /*
         * output this block
         */
        if (!encrypting) {
            memcpy(iv, in_ptr, GRASSHOPPER_BLOCK_SIZE);
        }
        for (j = 0; j < GRASSHOPPER_BLOCK_SIZE; j++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        /* Encrypt */
        /* Next iv is next block of cipher text */
        if (encrypting) {
            memcpy(iv, out_ptr, GRASSHOPPER_BLOCK_SIZE);
        }
    }

    /* Process rest of buffer */
    if (i < inl) {
        grasshopper_encrypt_block(&c->encrypt_round_keys,
                                  (grasshopper_w128_t *) iv,
                                  (grasshopper_w128_t *) buf, &c->buffer);
        if (!encrypting) {
            memcpy(buf + GRASSHOPPER_BLOCK_SIZE, in_ptr, inl - i);
        }
        for (j = 0; i < inl; j++, i++) {
            out_ptr[j] = buf[j] ^ in_ptr[j];
        }
        EVP_CIPHER_CTX_set_num(ctx, (int)j);
        if (encrypting) {
            memcpy(buf + GRASSHOPPER_BLOCK_SIZE, out_ptr, j);
        }
    } else {
        EVP_CIPHER_CTX_set_num(ctx, 0);
    }

    return 1;
}

int gost_grasshopper_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct GRASSHOPPER_CIPHER_PARAMS *params;
    gost_grasshopper_cipher_ctx *c =
        (gost_grasshopper_cipher_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (!c)
        return 1;

    params = &gost_cipher_params[c->type];

    gost_grasshopper_cipher_destroy(c);
    if (params->destroy_cipher != NULL) {
        params->destroy_cipher(c);
    }

    EVP_CIPHER_CTX_set_app_data(ctx, NULL);

    return 1;
}

int gost_grasshopper_set_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
    int len = 0;
    unsigned char *buf = NULL;
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();

    if (!os || !ASN1_OCTET_STRING_set(os, buf, len)) {
        ASN1_OCTET_STRING_free(os);
        OPENSSL_free(buf);
        GOSTerr(GOST_F_GOST_GRASSHOPPER_SET_ASN1_PARAMETERS,
                ERR_R_MALLOC_FAILURE);
        return 0;
    }
    OPENSSL_free(buf);

    ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);
    return 1;
}

GRASSHOPPER_INLINE int gost_grasshopper_get_asn1_parameters(EVP_CIPHER_CTX
                                                            *ctx, ASN1_TYPE
                                                            *params)
{
    if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE) {
        return -1;
    }

    return 1;
}

int gost_grasshopper_cipher_ctl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                void *ptr)
{
    switch (type) {
    case EVP_CTRL_RAND_KEY:{
            if (RAND_priv_bytes
                ((unsigned char *)ptr, EVP_CIPHER_CTX_key_length(ctx)) <= 0) {
                GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_CTL, GOST_R_RNG_ERROR);
                return -1;
            }
            break;
        }
    case EVP_CTRL_KEY_MESH:{
            gost_grasshopper_cipher_ctx_ctr *c =
                EVP_CIPHER_CTX_get_cipher_data(ctx);
            if (c->c.type != GRASSHOPPER_CIPHER_CTRACPKM || !arg
                || (arg % GRASSHOPPER_BLOCK_SIZE))
                return -1;
            c->section_size = arg;
            break;
        }
#ifdef EVP_CTRL_TLS1_2_TLSTREE
    case EVP_CTRL_TLS1_2_TLSTREE:
        {
          unsigned char newkey[32];
          int mode = EVP_CIPHER_CTX_mode(ctx);
          static const unsigned char zeroseq[8];
          gost_grasshopper_cipher_ctx_ctr *ctr_ctx = NULL;
          gost_grasshopper_cipher_ctx *c = NULL;

          unsigned char adjusted_iv[16];
          unsigned char seq[8];
          int j, carry;
          if (mode != EVP_CIPH_CTR_MODE)
            return -1;

          ctr_ctx = (gost_grasshopper_cipher_ctx_ctr *)
            EVP_CIPHER_CTX_get_cipher_data(ctx);
          c = &(ctr_ctx->c);

          memcpy(seq, ptr, 8);
          if (EVP_CIPHER_CTX_encrypting(ctx)) {
            /*
             * OpenSSL increments seq after mac calculation.
             * As we have Mac-Then-Encrypt, we need decrement it here on encryption
             * to derive the key correctly.
             * */
            if (memcmp(seq, zeroseq, 8) != 0)
            {
              for(j=7; j>=0; j--)
              {
                if (seq[j] != 0) {seq[j]--; break;}
                else seq[j]  = 0xFF;
              }
            }
          }
          if (gost_tlstree(NID_grasshopper_cbc, c->master_key.k.b, newkey,
                (const unsigned char *)seq) > 0) {
            memset(adjusted_iv, 0, 16);
            memcpy(adjusted_iv, EVP_CIPHER_CTX_original_iv(ctx), 8);
            for(j=7,carry=0; j>=0; j--)
            {
              int adj_byte = adjusted_iv[j]+seq[j]+carry;
              carry = (adj_byte > 255) ? 1 : 0;
              adjusted_iv[j] = adj_byte & 0xFF;
            }
            EVP_CIPHER_CTX_set_num(ctx, 0);
            memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), adjusted_iv, 16);

            gost_grasshopper_cipher_key(c, newkey);
            return 1;
          }
        }
        return -1;
#endif
    default:
        GOSTerr(GOST_F_GOST_GRASSHOPPER_CIPHER_CTL,
                GOST_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
        return -1;
    }
    return 1;
}

GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_create(int
                                                              cipher_type, int
                                                              block_size)
{
    return EVP_CIPHER_meth_new(cipher_type, block_size /* block_size */ ,
                               GRASSHOPPER_KEY_SIZE /* key_size */ );
}

const int cipher_gost_grasshopper_setup(EVP_CIPHER *cipher, uint8_t mode,
                                        int iv_size, bool padding)
{
    return EVP_CIPHER_meth_set_iv_length(cipher, iv_size)
        && EVP_CIPHER_meth_set_flags(cipher,
                                     (unsigned long)(mode |
                                                     ((!padding) ?
                                                      EVP_CIPH_NO_PADDING :
                                                      0) | ((iv_size >
                                                             0) ?
                                                            EVP_CIPH_CUSTOM_IV
                                                            : 0) |
                                                     EVP_CIPH_RAND_KEY |
                                                     EVP_CIPH_ALWAYS_CALL_INIT)
        )
        && EVP_CIPHER_meth_set_cleanup(cipher, gost_grasshopper_cipher_cleanup)
        && EVP_CIPHER_meth_set_set_asn1_params(cipher,
                                               gost_grasshopper_set_asn1_parameters)
        && EVP_CIPHER_meth_set_get_asn1_params(cipher,
                                               gost_grasshopper_get_asn1_parameters)
        && EVP_CIPHER_meth_set_ctrl(cipher, gost_grasshopper_cipher_ctl)
        && EVP_CIPHER_meth_set_do_cipher(cipher, gost_grasshopper_cipher_do);
}

const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper(uint8_t mode,
                                                             uint8_t num)
{
    EVP_CIPHER **cipher;
    struct GRASSHOPPER_CIPHER_PARAMS *params;

    cipher = &gost_grasshopper_ciphers[num];

    if (*cipher == NULL) {
        grasshopper_init_cipher_func init_cipher;
        int nid, block_size, ctx_size, iv_size;
        bool padding;

        params = &gost_cipher_params[num];

        nid = params->nid;
        init_cipher = params->init_cipher;
        block_size = params->block_size;
        ctx_size = params->ctx_size;
        iv_size = params->iv_size;
        padding = params->padding;

        *cipher = cipher_gost_grasshopper_create(nid, block_size);
        if (*cipher == NULL) {
            return NULL;
        }

        if (!cipher_gost_grasshopper_setup(*cipher, mode, iv_size, padding)
            || !EVP_CIPHER_meth_set_init(*cipher, init_cipher)
            || !EVP_CIPHER_meth_set_impl_ctx_size(*cipher, ctx_size)) {
            EVP_CIPHER_meth_free(*cipher);
            *cipher = NULL;
        }
    }

    return *cipher;
}

const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_ecb()
{
    return cipher_gost_grasshopper(EVP_CIPH_ECB_MODE, GRASSHOPPER_CIPHER_ECB);
}

const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_cbc()
{
    return cipher_gost_grasshopper(EVP_CIPH_CBC_MODE, GRASSHOPPER_CIPHER_CBC);
}

const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_ofb()
{
    return cipher_gost_grasshopper(EVP_CIPH_OFB_MODE, GRASSHOPPER_CIPHER_OFB);
}

const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_cfb()
{
    return cipher_gost_grasshopper(EVP_CIPH_CFB_MODE, GRASSHOPPER_CIPHER_CFB);
}

const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_ctr()
{
    return cipher_gost_grasshopper(EVP_CIPH_CTR_MODE, GRASSHOPPER_CIPHER_CTR);
}

const GRASSHOPPER_INLINE EVP_CIPHER *cipher_gost_grasshopper_ctracpkm()
{
    return cipher_gost_grasshopper(EVP_CIPH_CTR_MODE,
                                   GRASSHOPPER_CIPHER_CTRACPKM);
}

void cipher_gost_grasshopper_destroy(void)
{
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_ECB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_ECB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CBC]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CBC] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_OFB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_OFB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CFB]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CFB] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTR]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTR] = NULL;
    EVP_CIPHER_meth_free(gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTRACPKM]);
    gost_grasshopper_ciphers[GRASSHOPPER_CIPHER_CTRACPKM] = NULL;
}
