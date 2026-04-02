#include <string.h>

#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "gost_tls12_additional.h"
#include "e_gost_err.h"

static uint32_t be32(uint32_t host)
{
#ifdef L_ENDIAN
    return (host & 0xff000000) >> 24 |
           (host & 0x00ff0000) >> 8  |
           (host & 0x0000ff00) << 8  |
           (host & 0x000000ff) << 24;
#else
    return host;
#endif
}

int gost_kdftree2012_256(unsigned char *keyout, size_t keyout_len,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *label, size_t label_len,
                         const unsigned char *seed, size_t seed_len,
                         const size_t representation)
{
    int iters, i = 0;
    unsigned char zero = 0;
    unsigned char *ptr = keyout;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    unsigned char *len_ptr = NULL;
    uint32_t len_repr = be32(keyout_len * 8);
    size_t len_repr_len = 4;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST,
                               (char *)SN_id_GostR3411_2012_256, 0),
        OSSL_PARAM_END
    };

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if (mac == NULL) {
        GOSTerr(GOST_F_GOST_KDFTREE2012_256, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        GOSTerr(GOST_F_GOST_KDFTREE2012_256, ERR_R_MALLOC_FAILURE);
        EVP_MAC_free(mac);
        return 0;
    }

    if ((keyout_len == 0) || (keyout_len % 32 != 0)) {
        GOSTerr(GOST_F_GOST_KDFTREE2012_256, ERR_R_INTERNAL_ERROR);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 0;
    }
    iters = keyout_len / 32;

    len_ptr = (unsigned char *)&len_repr;
    while (*len_ptr == 0) {
        len_ptr++;
        len_repr_len--;
    }

    for (i = 1; i <= iters; i++) {
        uint32_t iter_net = be32(i);
        unsigned char *rep_ptr =
            ((unsigned char *)&iter_net) + (4 - representation);
        size_t out_len = 0;

        if (EVP_MAC_init(ctx, key, keylen, params) <= 0
            || EVP_MAC_update(ctx, rep_ptr, representation) <= 0
            || EVP_MAC_update(ctx, label, label_len) <= 0
            || EVP_MAC_update(ctx, &zero, 1) <= 0
            || EVP_MAC_update(ctx, seed, seed_len) <= 0
            || EVP_MAC_update(ctx, len_ptr, len_repr_len) <= 0
            || EVP_MAC_final(ctx, ptr, &out_len, 32) <= 0
            || out_len != 32) {
            GOSTerr(GOST_F_GOST_KDFTREE2012_256, ERR_R_INTERNAL_ERROR);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            return 0;
        }

        ptr += 32;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return 1;
}
