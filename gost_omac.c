/*
 * Copyright (c) 2019 Dmitry Belyavskiy <beldmit@gmail.com>
 * Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */
#include <string.h>
#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "e_gost_err.h"
#include "gost_lcl.h"
#include "gost_tls12_additional.h"
#include "gost_digest_details.h"

#define min(a,b) (((a) < (b)) ? (a) : (b))

typedef struct omac_ctx {
    CMAC_CTX *cmac_ctx;
    size_t dgst_size;
    const char *cipher_name;
    int key_set;
/* 
 * Here begins stuff related to TLSTREE processing
 * We MUST store the original key to derive TLSTREE keys from it
 * and TLS seq no.
 * */
    unsigned char key[32];
/*
 * TODO
 * TLSTREE intermediate values should be recalculated only when 
 * C_i & (seq_no+1) != C_i & (seq_no)
 * so somewhen we will store C_i & (seq_no) in this structure 
 * to avoid redundant hash calculations.
 * */
} OMAC_CTX;

#define MAX_GOST_OMAC_SIZE 16

static int omac_init(GOST_digest_ctx *ctx, const char *cipher_name)
{
    OMAC_CTX *c = GOST_digest_ctx_data(ctx);
    if (c == NULL) {
        return 0;
    }

    memset(c, 0, sizeof(OMAC_CTX));
    c->cipher_name = cipher_name;
    c->key_set = 0;

    switch (OBJ_txt2nid(cipher_name)) {
    case NID_magma_cbc:
        c->dgst_size = 8;
        break;

    case NID_grasshopper_cbc:
        c->dgst_size = 16;
        break;
    }

    return 1;
}

static int magma_imit_init(GOST_digest_ctx *ctx)
{
    return omac_init(ctx, SN_magma_cbc);
}

static int grasshopper_imit_init(GOST_digest_ctx *ctx)
{
    return omac_init(ctx, SN_grasshopper_cbc);
}

static int omac_imit_update(GOST_digest_ctx *ctx, const void *data, size_t count)
{
    OMAC_CTX *c = GOST_digest_ctx_data(ctx);
    if (!c->key_set) {
        GOSTerr(GOST_F_OMAC_IMIT_UPDATE, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }

    return CMAC_Update(c->cmac_ctx, data, count);
}

static int omac_imit_final(GOST_digest_ctx *ctx, unsigned char *md)
{
    OMAC_CTX *c = GOST_digest_ctx_data(ctx);
    unsigned char mac[MAX_GOST_OMAC_SIZE];
    size_t mac_size = sizeof(mac);

    if (!c->key_set) {
        GOSTerr(GOST_F_OMAC_IMIT_FINAL, GOST_R_MAC_KEY_NOT_SET);
        return 0;
    }

    CMAC_Final(c->cmac_ctx, mac, &mac_size);

    memcpy(md, mac, c->dgst_size);
    return 1;
}

static int omac_imit_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from)
{
    OMAC_CTX *c_to = GOST_digest_ctx_data(to);
    const OMAC_CTX *c_from = GOST_digest_ctx_data(from);

    if (c_from && c_to) {
        c_to->dgst_size = c_from->dgst_size;
        c_to->cipher_name = c_from->cipher_name;
        c_to->key_set = c_from->key_set;
        memcpy(c_to->key, c_from->key, 32);
    } else {
        return 0;
    }
    if (!c_from->cmac_ctx) {
        if (c_to->cmac_ctx) {
            CMAC_CTX_free(c_to->cmac_ctx);
            c_to->cmac_ctx = NULL;
        }
        return 1;
    }
    if (c_to->cmac_ctx == c_from->cmac_ctx || !c_to->cmac_ctx) {
        c_to->cmac_ctx = CMAC_CTX_new();
    }
    if (!c_to->cmac_ctx) {
        return 0;
    }
    return CMAC_CTX_copy(c_to->cmac_ctx, c_from->cmac_ctx);
}

/* Clean up imit ctx */
static int omac_imit_cleanup(GOST_digest_ctx *ctx)
{
    OMAC_CTX *c = GOST_digest_ctx_data(ctx);

    if (c) {
        CMAC_CTX_free(c->cmac_ctx);
        memset(GOST_digest_ctx_data(ctx), 0, sizeof(OMAC_CTX));
    }
    return 1;
}

static int omac_key(OMAC_CTX * c, const EVP_CIPHER *cipher,
                    const unsigned char *key, size_t key_size)
{
    int ret = 0;

    CMAC_CTX_free(c->cmac_ctx);
    c->cmac_ctx = CMAC_CTX_new();
    if (c->cmac_ctx == NULL) {
        GOSTerr(GOST_F_OMAC_KEY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ret = CMAC_Init(c->cmac_ctx, key, key_size, cipher, NULL);
    if (ret > 0) {
        c->key_set = 1;
    }
    return 1;
}

static int omac_imit_ctrl(GOST_digest_ctx *ctx, int type, int arg, void *ptr)
{
    switch (type) {
    case EVP_MD_CTRL_KEY_LEN:
        *((unsigned int *)(ptr)) = 32;
        return 1;
    case EVP_MD_CTRL_SET_KEY:
        {
            OMAC_CTX *c = GOST_digest_ctx_data(ctx);
            EVP_CIPHER *cipher = NULL;
            int ret = 0;
            const char* cipher_name = NULL;

            if (!c || c->cipher_name == NULL) {
                if (GOST_digest_type(GOST_digest_ctx_digest(ctx)) == NID_magma_mac)
                    cipher_name = SN_magma_cbc;
                else if (GOST_digest_type(GOST_digest_ctx_digest(ctx)) == NID_grasshopper_mac)
                    cipher_name = SN_grasshopper_cbc;
            } else {
                cipher_name = c->cipher_name;
            }
            if ((cipher =
                 (EVP_CIPHER *)EVP_get_cipherbyname(cipher_name)) == NULL
                && (cipher =
                    EVP_CIPHER_fetch(NULL, cipher_name, NULL)) == NULL) {
                GOSTerr(GOST_F_OMAC_IMIT_CTRL, GOST_R_CIPHER_NOT_FOUND);
                goto set_key_end;
            }

            if (GOST_digest_meth_get_init(GOST_digest_ctx_digest(ctx))(ctx) <= 0) {
                GOSTerr(GOST_F_OMAC_IMIT_CTRL, GOST_R_MAC_KEY_NOT_SET);
                goto set_key_end;
            }
            GOST_digest_ctx_set_flags(ctx, EVP_MD_CTX_FLAG_NO_INIT);

            c = GOST_digest_ctx_data(ctx);
            if (c->key_set) {
                GOSTerr(GOST_F_OMAC_IMIT_CTRL, GOST_R_BAD_ORDER);
                goto set_key_end;
            }

            if (arg == 0) {
                struct gost_mac_key *key = (struct gost_mac_key *)ptr;
                ret = omac_key(c, cipher, key->key, 32);
                if (ret > 0)
                    memcpy(c->key, key->key, 32);
                goto set_key_end;
            } else if (arg == 32) {
                ret = omac_key(c, cipher, ptr, 32);
                if (ret > 0)
                    memcpy(c->key, ptr, 32);
                goto set_key_end;
            }
            GOSTerr(GOST_F_OMAC_IMIT_CTRL, GOST_R_INVALID_MAC_KEY_SIZE);
          set_key_end:
            EVP_CIPHER_free(cipher);
            if (ret > 0)
                return ret;
            return 0;
        }
    case EVP_MD_CTRL_XOF_LEN:   /* Supported in OpenSSL */
        {
            OMAC_CTX *c = GOST_digest_ctx_data(ctx);
            switch (OBJ_txt2nid(c->cipher_name)) {
            case NID_magma_cbc:
                if (arg < 1 || arg > 8) {
                    GOSTerr(GOST_F_OMAC_IMIT_CTRL, GOST_R_INVALID_MAC_SIZE);
                    return 0;
                }
                c->dgst_size = arg;
                break;
            case NID_grasshopper_cbc:
                if (arg < 1 || arg > 16) {
                    GOSTerr(GOST_F_OMAC_IMIT_CTRL, GOST_R_INVALID_MAC_SIZE);
                    return 0;
                }
                c->dgst_size = arg;
                break;
            default:
                return 0;
            }
            return 1;
        }
#ifdef EVP_MD_CTRL_TLSTREE
    case EVP_MD_CTRL_TLSTREE:
        {
            OMAC_CTX *c = GOST_digest_ctx_data(ctx);
            if (c->key_set) {
                unsigned char diversed_key[32];
                int ret = 0;
                switch (OBJ_txt2nid(c->cipher_name)) {
                case NID_magma_cbc:
                    ret = gost_tlstree_magma_cbc(c->key, diversed_key,
                                                 (const unsigned char *)ptr,
                                                 TLSTREE_MODE_NONE);
                    break;
                case NID_grasshopper_cbc:
                    ret = gost_tlstree_grasshopper_cbc(c->key, diversed_key,
                                                       (const unsigned char *)ptr,
                                                       TLSTREE_MODE_NONE);
                    break;
                default:
                    return 0;
                }
                if (!ret)
                    return 0;

                EVP_CIPHER *cipher;
                if ((cipher = (EVP_CIPHER *)EVP_get_cipherbyname(c->cipher_name))
                    || (cipher = EVP_CIPHER_fetch(NULL, c->cipher_name, NULL)))
                    ret = omac_key(c, cipher, diversed_key, 32);
                EVP_CIPHER_free(cipher);
                OPENSSL_cleanse(diversed_key, sizeof(diversed_key));

                return ret;
            }
            GOSTerr(GOST_F_OMAC_IMIT_CTRL, GOST_R_BAD_ORDER);
            return 0;
        }
#endif
    default:
        return 0;
    }
}

static GOST_digest omac_template_digest = {
    .input_blocksize = 8,
    .algctx_size = sizeof(OMAC_CTX),
    .flags = EVP_MD_FLAG_XOF,
    .update = omac_imit_update,
    .final = omac_imit_final,
    .copy = omac_imit_copy,
    .cleanup = omac_imit_cleanup,
    .ctrl = omac_imit_ctrl,
};

GOST_digest magma_omac_mac = {
    .nid = NID_magma_mac,
    .base = &omac_template_digest,
    .result_size = 8,
    .init = magma_imit_init,
};

GOST_digest grasshopper_omac_mac = {
    .nid = NID_grasshopper_mac,
    .base = &omac_template_digest,
    .result_size = 16,
    .init = grasshopper_imit_init,
};
