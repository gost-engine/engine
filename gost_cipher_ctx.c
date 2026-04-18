#include "gost_cipher_ctx.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/e_os2.h>      /* For ossl_inline */

/*
 * Source: openssl/include/internal/safe_math.h
 * openssl v3.6.0 7b371d80d959ec9ab4139d09d78e83c090de9779
 */
# ifndef OPENSSL_NO_BUILTIN_OVERFLOW_CHECKING
#  ifdef __has_builtin
#   define has(func) __has_builtin(func)
#  elif defined(__GNUC__)
#   if __GNUC__ > 5
#    define has(func) 1
#   endif
#  endif
# endif /* OPENSSL_NO_BUILTIN_OVERFLOW_CHECKING */

# ifndef has
#  define has(func) 0
# endif

# if has(__builtin_add_overflow)
#  define OSSL_SAFE_MATH_ADDS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        type r;                                                              \
                                                                             \
        if (!__builtin_add_overflow(a, b, &r))                               \
            return r;                                                        \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }

# else  /* has(__builtin_add_overflow) */
#  define OSSL_SAFE_MATH_ADDS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_add_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if ((a < 0) ^ (b < 0)                                                \
                || (a > 0 && b <= max - a)                                   \
                || (a < 0 && b >= min - a)                                   \
                || a == 0)                                                   \
            return a + b;                                                    \
        *err |= 1;                                                           \
        return a < 0 ? min : max;                                            \
    }

# endif /* has(__builtin_add_overflow) */

# define OSSL_SAFE_MATH_MODS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_mod_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return 0;                                                        \
        }                                                                    \
        if (b == -1 && a == min) {                                           \
            *err |= 1;                                                       \
            return max;                                                      \
        }                                                                    \
        return a % b;                                                        \
    }

/*
 * Safe division helpers
 */
# define OSSL_SAFE_MATH_DIVS(type_name, type, min, max) \
    static ossl_inline ossl_unused type safe_div_ ## type_name(type a,       \
                                                               type b,       \
                                                               int *err)     \
    {                                                                        \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return a < 0 ? min : max;                                        \
        }                                                                    \
        if (b == -1 && a == min) {                                           \
            *err |= 1;                                                       \
            return max;                                                      \
        }                                                                    \
        return a / b;                                                        \
    }

/*
 * Calculate a / b rounding up:
 *     i.e. a / b + (a % b != 0)
 * Which is usually (less safely) converted to (a + b - 1) / b
 * If you *know* that b != 0, then it's safe to ignore err.
 */
#define OSSL_SAFE_MATH_DIV_ROUND_UP(type_name, type, max) \
    static ossl_inline ossl_unused type safe_div_round_up_ ## type_name      \
        (type a, type b, int *errp)                                          \
    {                                                                        \
        type x;                                                              \
        int *err, err_local = 0;                                             \
                                                                             \
        /* Allow errors to be ignored by callers */                          \
        err = errp != NULL ? errp : &err_local;                              \
        /* Fast path, both positive */                                       \
        if (b > 0 && a > 0) {                                                \
            /* Faster path: no overflow concerns */                          \
            if (a < max - b)                                                 \
                return (a + b - 1) / b;                                      \
            return a / b + (a % b != 0);                                     \
        }                                                                    \
        if (b == 0) {                                                        \
            *err |= 1;                                                       \
            return a == 0 ? 0 : max;                                         \
        }                                                                    \
        if (a == 0)                                                          \
            return 0;                                                        \
        /* Rather slow path because there are negatives involved */          \
        x = safe_mod_ ## type_name(a, b, err);                               \
        return safe_add_ ## type_name(safe_div_ ## type_name(a, b, err),     \
                                      x != 0, err);                          \
    }

/*
 * End of source: openssl/include/internal/safe_math.h
 * openssl v3.6.0 7b371d80d959ec9ab4139d09d78e83c090de9779
 */

OSSL_SAFE_MATH_ADDS(int, int, INT_MIN, INT_MAX)
OSSL_SAFE_MATH_MODS(int, int, INT_MIN, INT_MAX)
OSSL_SAFE_MATH_DIVS(int, int, INT_MIN, INT_MAX)
OSSL_SAFE_MATH_DIV_ROUND_UP(int, int, INT_MAX)

/*
 * Local adaptation for EVP_CIPHER_CTX interface
 *
 * Sources:
 * * openssl/crypto/evp/evp_local.h
 * * openssl/crypto/evp/evp_enc.c
 * * openssl/crypto/evp/evp_lib.c
 *
 * openssl v3.6.0 7b371d80d959ec9ab4139d09d78e83c090de9779
 */

struct gost_cipher_ctx_st {
    const GOST_cipher *cipher;
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    int iv_len;                 /* IV length */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* GOST_cipher_ctx */ ;

static int GOST_cipher_ctx_reset(GOST_cipher_ctx *ctx) {
    if (ctx == NULL)
        return 1;

    if (ctx->cipher != NULL) {
        if (GOST_cipher_cleanup_fn(ctx->cipher) && !GOST_cipher_cleanup_fn(ctx->cipher)(ctx))
            return 0;
        /* Cleanse cipher context data */
        if (ctx->cipher_data && GOST_cipher_ctx_size(ctx->cipher))
            OPENSSL_cleanse(ctx->cipher_data, GOST_cipher_ctx_size(ctx->cipher));
    }
    OPENSSL_free(ctx->cipher_data);

    memset(ctx, 0, sizeof(*ctx));
    ctx->iv_len = -1;
    return 1;
}

GOST_cipher_ctx *GOST_cipher_ctx_new(void)
{
    GOST_cipher_ctx *ctx;

    ctx = OPENSSL_zalloc(sizeof(GOST_cipher_ctx));
    if (ctx == NULL)
        return NULL;

    ctx->iv_len = -1;
    return ctx;
}

void GOST_cipher_ctx_free(GOST_cipher_ctx *ctx)
{
    if (ctx == NULL)
        return;
    GOST_cipher_ctx_reset(ctx);
    OPENSSL_free(ctx);
}

int GOST_cipher_ctx_copy(GOST_cipher_ctx *out, const GOST_cipher_ctx *in)
{
    if ((in == NULL) || (in->cipher == NULL)) {
        return 0;
    }

    GOST_cipher_ctx_reset(out);
    memcpy(out, in, sizeof(*out));

    if (in->cipher_data && GOST_cipher_ctx_size(in->cipher)) {
        out->cipher_data = OPENSSL_malloc(GOST_cipher_ctx_size(in->cipher));
        if (out->cipher_data == NULL) {
            out->cipher = NULL;
            return 0;
        }
        memcpy(out->cipher_data, in->cipher_data, GOST_cipher_ctx_size(in->cipher));
    }

    if (GOST_cipher_flags(in->cipher) & EVP_CIPH_CUSTOM_COPY)
        if ((GOST_cipher_ctrl_fn(in->cipher) == NULL)
            || !GOST_cipher_ctrl_fn(in->cipher)((GOST_cipher_ctx *)in, EVP_CTRL_COPY, 0, out)) {
            out->cipher = NULL;
            return 0;
        }
    return 1;
}

unsigned char *GOST_cipher_ctx_buf_noconst(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->buf : NULL;
}

const GOST_cipher *GOST_cipher_ctx_cipher(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->cipher : NULL;
}

int GOST_cipher_ctx_encrypting(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->encrypt : 0;
}

int GOST_cipher_ctx_iv_length(const GOST_cipher_ctx *ctx)
{
    if (ctx == NULL)
        return 0;

    if (ctx->cipher == NULL)
        return 0;

    if (ctx->iv_len < 0) {
        int rv, len = GOST_cipher_iv_length(ctx->cipher);

        if ((GOST_cipher_flags(ctx->cipher)
                  & EVP_CIPH_CUSTOM_IV_LENGTH) != 0) {
            rv = GOST_cipher_ctx_ctrl((GOST_cipher_ctx *)ctx, EVP_CTRL_GET_IVLEN,
                                     0, &len);
            if (rv <= 0) {
                assert(0 && "Bad cipher definition");
                return 0;
            }
        }

        ((GOST_cipher_ctx *)ctx)->iv_len = len;
    }
    return ctx->iv_len;
}

const unsigned char *GOST_cipher_ctx_iv(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->iv : NULL;
}

unsigned char *GOST_cipher_ctx_iv_noconst(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->iv : NULL;
}

int GOST_cipher_ctx_key_length(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->key_len : 0;
}

int GOST_cipher_ctx_mode(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cipher != NULL ? GOST_cipher_mode(ctx->cipher) : 0;
}

int GOST_cipher_ctx_nid(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL && ctx->cipher != NULL ? GOST_cipher_nid(ctx->cipher) : NID_undef;
}

int GOST_cipher_ctx_num(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->num : 0;
}

const unsigned char *GOST_cipher_ctx_original_iv(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->oiv : NULL;
}

void *GOST_cipher_ctx_get_app_data(const GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->app_data : NULL;
}

void *GOST_cipher_ctx_get_cipher_data(GOST_cipher_ctx *ctx)
{
    return ctx != NULL ? ctx->cipher_data : NULL;
}

int GOST_cipher_ctx_set_num(GOST_cipher_ctx *ctx, int num)
{
    if (ctx == NULL)
        return 0;

    ctx->num = num;
    return 1;
}

int GOST_cipher_ctx_set_padding(GOST_cipher_ctx *ctx, int pad)
{
    if (ctx == NULL)
        return 0;

    if (pad)
        ctx->flags &= ~EVP_CIPH_NO_PADDING;
    else
        ctx->flags |= EVP_CIPH_NO_PADDING;

    return 1;
}

int GOST_cipher_ctx_set_flags(GOST_cipher_ctx *ctx, int flags)
{
    if (ctx == NULL)
        return 0;

    ctx->flags |= flags;
    return 1;
}

void GOST_cipher_ctx_set_app_data(GOST_cipher_ctx *ctx, void *data)
{
    if (ctx != NULL)
        ctx->app_data = data;
}

int GOST_cipher_ctx_cleanup(GOST_cipher_ctx *ctx)
{
    return GOST_cipher_ctx_reset(ctx);
}

int GOST_cipher_ctx_ctrl(GOST_cipher_ctx *ctx, int type, int arg, void *ptr)
{
    if (ctx == NULL || ctx->cipher == NULL) {
        return 0;
    }

    if (GOST_cipher_ctrl_fn(ctx->cipher) == NULL) {
        return 0;
    }

    return GOST_cipher_ctrl_fn(ctx->cipher)(ctx, type, arg, ptr);

}

static int GOST_cipher_ctx_test_flags(const GOST_cipher_ctx *ctx, int flags)
{
    return (ctx->flags & flags);
}

static int gost_cipher_init_internal(GOST_cipher_ctx *ctx,
                                     const GOST_cipher *cipher,
                                     const unsigned char *key,
                                     const unsigned char *iv, int enc)
{
    int n;

    /*
     * enc == 1 means we are encrypting.
     * enc == 0 means we are decrypting.
     * enc == -1 means, use the previously initialised value for encrypt/decrypt
     */
    if (enc == -1) {
        enc = ctx->encrypt;
    } else {
        if (enc)
            enc = 1;
        ctx->encrypt = enc;
    }

    if (cipher == NULL && ctx->cipher == NULL) {
        return 0;
    }

    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     */
    if (ctx->cipher
        && (cipher == NULL || cipher == ctx->cipher))
        goto skip_to_init;

    if (cipher != NULL) {
        /*
         * Ensure a context left lying around from last time is cleared (we
         * previously attempted to avoid this if the same ENGINE and
         * EVP_CIPHER could be used).
         */
        if (ctx->cipher) {
            unsigned long flags = ctx->flags;
            GOST_cipher_ctx_reset(ctx);
            /* Restore encrypt and flags */
            ctx->encrypt = enc;
            ctx->flags = flags;
        }

        ctx->cipher = cipher;
        if (GOST_cipher_ctx_size(ctx->cipher)) {
            ctx->cipher_data = OPENSSL_zalloc(GOST_cipher_ctx_size(ctx->cipher));
            if (ctx->cipher_data == NULL) {
                ctx->cipher = NULL;
                return 0;
            }
        } else {
            ctx->cipher_data = NULL;
        }
        ctx->key_len = GOST_cipher_key_length(cipher);
        /* Preserve wrap enable flag, zero everything else */
        ctx->flags &= EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;
        if (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_CTRL_INIT) {
            if (GOST_cipher_ctx_ctrl(ctx, EVP_CTRL_INIT, 0, NULL) <= 0) {
                ctx->cipher = NULL;
                return 0;
            }
        }
    }

 skip_to_init:
    if (ctx->cipher == NULL)
        return 0;

    /* we assume block size is a power of 2 in *cryptUpdate */
    OPENSSL_assert(GOST_cipher_block_size(ctx->cipher) == 1
                   || GOST_cipher_block_size(ctx->cipher) == 8
                   || GOST_cipher_block_size(ctx->cipher) == 16);

    if (!(ctx->flags & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
        && GOST_cipher_mode(ctx->cipher) == EVP_CIPH_WRAP_MODE) {
        return 0;
    }

    if ((GOST_cipher_flags(ctx->cipher)
                & EVP_CIPH_CUSTOM_IV) == 0) {
        switch (GOST_cipher_mode(ctx->cipher)) {

        case EVP_CIPH_STREAM_CIPHER:
        case EVP_CIPH_ECB_MODE:
            break;

        case EVP_CIPH_CFB_MODE:
        case EVP_CIPH_OFB_MODE:

            ctx->num = 0;
            /* fall-through */

        case EVP_CIPH_CBC_MODE:
            n = GOST_cipher_ctx_iv_length(ctx);
            if (n < 0 || n > (int)sizeof(ctx->iv)) {
                return 0;
            }
            if (iv != NULL)
                memcpy(ctx->oiv, iv, n);
            memcpy(ctx->iv, ctx->oiv, n);
            break;

        case EVP_CIPH_CTR_MODE:
            ctx->num = 0;
            /* Don't reuse IV for CTR mode */
            if (iv != NULL) {
                n = GOST_cipher_ctx_iv_length(ctx);
                if (n <= 0 || n > (int)sizeof(ctx->iv)) {
                    return 0;
                }
                memcpy(ctx->iv, iv, n);
            }
            break;

        default:
            return 0;
        }
    }

    if (key != NULL || (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_ALWAYS_CALL_INIT)) {
        if (!GOST_cipher_init_fn(ctx->cipher)(ctx, key, iv, enc))
            return 0;
    }
    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = GOST_cipher_block_size(ctx->cipher) - 1;

    return 1;
}


int GOST_CipherInit_ex(GOST_cipher_ctx *ctx, const GOST_cipher *cipher,
                    const unsigned char *key, const unsigned char *iv,
                    int enc)
{
    return gost_cipher_init_internal(ctx, cipher, key, iv, enc);
}

/*
 * According to the letter of standard difference between pointers
 * is specified to be valid only within same object. This makes
 * it formally challenging to determine if input and output buffers
 * are not partially overlapping with standard pointer arithmetic.
 */
#ifdef PTRDIFF_T
# undef PTRDIFF_T
#endif
#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE==64
/*
 * Then we have VMS that distinguishes itself by adhering to
 * sizeof(size_t)==4 even in 64-bit builds, which means that
 * difference between two pointers might be truncated to 32 bits.
 * In the context one can even wonder how comparison for
 * equality is implemented. To be on the safe side we adhere to
 * PTRDIFF_T even for comparison for equality.
 */
# define PTRDIFF_T uint64_t
#else
# define PTRDIFF_T size_t
#endif

static int gost_cipher_is_partially_overlapping(const void *ptr1,
                                                const void *ptr2,
                                                size_t len)
{
    PTRDIFF_T diff = (PTRDIFF_T)ptr1-(PTRDIFF_T)ptr2;
    /*
     * Check for partially overlapping buffers. [Binary logical
     * operations are used instead of boolean to minimize number
     * of conditional branches.]
     */
    int overlapped = (len > 0) & (diff != 0) & ((diff < (PTRDIFF_T)len) |
                                                (diff > (0 - (PTRDIFF_T)len)));

    return overlapped;
}

static int gost_cipher_EncryptDecryptUpdate(GOST_cipher_ctx *ctx,
                                                unsigned char *out, int *outl,
                                                const unsigned char *in, int inl)
{
    int i, j, bl, cmpl = inl;

    if (GOST_cipher_ctx_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = safe_div_round_up_int(cmpl, 8, NULL);

    bl = GOST_cipher_block_size(ctx->cipher);

    if ((GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0) {
        /* If block size > 1 then the cipher will have to do this check */
        if (bl == 1 && gost_cipher_is_partially_overlapping(out, in, cmpl)) {
            return 0;
        }

        i = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, inl);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }
    if (gost_cipher_is_partially_overlapping(out + ctx->buf_len, in, cmpl)) {
        return 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, inl)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
    OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
    if (i != 0) {
        if (bl - i > inl) {
            memcpy(&(ctx->buf[i]), in, inl);
            ctx->buf_len += inl;
            *outl = 0;
            return 1;
        } else {
            j = bl - i;

            /*
             * Once we've processed the first j bytes from in, the amount of
             * data left that is a multiple of the block length is:
             * (inl - j) & ~(bl - 1)
             * We must ensure that this amount of data, plus the one block that
             * we process from ctx->buf does not exceed INT_MAX
             */
            if (((inl - j) & ~(bl - 1)) > INT_MAX - bl) {
                return 0;
            }
            memcpy(&(ctx->buf[i]), in, j);
            inl -= j;
            in += j;
            if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, ctx->buf, bl))
                return 0;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, inl))
            return 0;
        *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}

static int GOST_EncryptUpdate(GOST_cipher_ctx *ctx, unsigned char *out, int *outl,
                              const unsigned char *in, int inl)
{
    if (outl != NULL) {
        *outl = 0;
    } else {
        return 0;
    }

    if (!ctx->encrypt) {
        return 0;
    }

    if (ctx->cipher == NULL) {
        return 0;
    }

    return gost_cipher_EncryptDecryptUpdate(ctx, out, outl, in, inl);
}

static int GOST_DecryptUpdate(GOST_cipher_ctx *ctx, unsigned char *out, int *outl,
                              const unsigned char *in, int inl)
{
    int fix_len, cmpl = inl;
    unsigned int b;

    if (outl != NULL) {
        *outl = 0;
    } else {
        return 0;
    }

    if (ctx->encrypt) {
        return 0;
    }

    if (ctx->cipher == NULL) {
        return 0;
    }

    b = GOST_cipher_block_size(ctx->cipher);

    if (GOST_cipher_ctx_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS))
        cmpl = safe_div_round_up_int(cmpl, 8, NULL);

    if (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        if (b == 1 && gost_cipher_is_partially_overlapping(out, in, cmpl)) {
            return 0;
        }

        fix_len = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, in, inl);
        if (fix_len < 0) {
            *outl = 0;
            return 0;
        } else
            *outl = fix_len;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING)
        return gost_cipher_EncryptDecryptUpdate(ctx, out, outl, in, inl);

    OPENSSL_assert(b <= sizeof(ctx->final));

    if (ctx->final_used) {
        /* see comment about PTRDIFF_T comparison above */
        if (((PTRDIFF_T)out == (PTRDIFF_T)in)
            || gost_cipher_is_partially_overlapping(out, in, b)) {
            return 0;
        }
        /*
         * final_used is only ever set if buf_len is 0. Therefore the maximum
         * length output we will ever see from evp_EncryptDecryptUpdate is
         * the maximum multiple of the block length that is <= inl, or just:
         * inl & ~(b - 1)
         * Since final_used has been set then the final output length is:
         * (inl & ~(b - 1)) + b
         * This must never exceed INT_MAX
         */
        if ((inl & ~(b - 1)) > INT_MAX - b) {
            return 0;
        }
        memcpy(out, ctx->final, b);
        out += b;
        fix_len = 1;
    } else
        fix_len = 0;

    if (!gost_cipher_EncryptDecryptUpdate(ctx, out, outl, in, inl))
        return 0;

    /*
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     */
    if (b > 1 && !ctx->buf_len) {
        *outl -= b;
        ctx->final_used = 1;
        memcpy(ctx->final, &out[*outl], b);
    } else
        ctx->final_used = 0;

    if (fix_len)
        *outl += b;

    return 1;
}

int GOST_CipherUpdate(GOST_cipher_ctx *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    if (ctx->encrypt)
        return GOST_EncryptUpdate(ctx, out, outl, in, inl);
    else
        return GOST_DecryptUpdate(ctx, out, outl, in, inl);
}

static int GOST_EncryptFinal(GOST_cipher_ctx *ctx, unsigned char *out, int *outl)
{
    int n, ret;
    unsigned int i, b, bl;

    if (outl != NULL) {
        *outl = 0;
    } else {
        return 0;
    }

    /* Prevent accidental use of decryption context when encrypting */
    if (!ctx->encrypt) {
        return 0;
    }

    if (ctx->cipher == NULL) {
        return 0;
    }

    if (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        ret = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, NULL, 0);
        if (ret < 0)
            return 0;
        else
            *outl = ret;
        return 1;
    }

    b = GOST_cipher_block_size(ctx->cipher);
    OPENSSL_assert(b <= sizeof(ctx->buf));
    if (b == 1) {
        *outl = 0;
        return 1;
    }
    bl = ctx->buf_len;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (bl) {
            return 0;
        }
        *outl = 0;
        return 1;
    }

    n = b - bl;
    for (i = bl; i < b; i++)
        ctx->buf[i] = n;
    ret = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, ctx->buf, b);

    if (ret)
        *outl = b;

    return ret;
}

static int GOST_DecryptFinal(GOST_cipher_ctx *ctx, unsigned char *out, int *outl)
{
    int i, n;
    unsigned int b;

    if (outl != NULL) {
        *outl = 0;
    } else {
        return 0;
    }

    /* Prevent accidental use of encryption context when decrypting */
    if (ctx->encrypt) {
        return 0;
    }

    if (ctx->cipher == NULL) {
        return 0;
    }

    *outl = 0;
    if (GOST_cipher_flags(ctx->cipher) & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = GOST_cipher_do_cipher_fn(ctx->cipher)(ctx, out, NULL, 0);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    b = GOST_cipher_block_size(ctx->cipher);
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len) {
            return 0;
        }
        *outl = 0;
        return 1;
    }
    if (b > 1) {
        if (ctx->buf_len || !ctx->final_used) {
            return 0;
        }
        OPENSSL_assert(b <= sizeof(ctx->final));

        /*
         * The following assumes that the ciphertext has been authenticated.
         * Otherwise it provides a padding oracle.
         */
        n = ctx->final[b - 1];
        if (n == 0 || n > (int)b) {
            return 0;
        }
        for (i = 0; i < n; i++) {
            if (ctx->final[--b] != n) {
                return 0;
            }
        }
        n = GOST_cipher_block_size(ctx->cipher) - n;
        for (i = 0; i < n; i++)
            out[i] = ctx->final[i];
        *outl = n;
    }
    return 1;
}

int GOST_CipherFinal(GOST_cipher_ctx *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return GOST_EncryptFinal(ctx, out, outl);
    else
        return GOST_DecryptFinal(ctx, out, outl);
}
