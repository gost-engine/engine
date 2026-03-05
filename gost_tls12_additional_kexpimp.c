/*
 * Copyright (c) 2019 Dmitry Belyavskiy <beldmit@gmail.com>
 * Copyright (c) 2020 Vitaly Chikunov <vt@altlinux.org>
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "gost_tls12_additional_kexpimp.h"
#include "gost_mac.h"
#include "e_gost_err.h"

/*
 * Function expects that out is a preallocated buffer of length
 * defined as sum of shared_len and mac length defined by mac_nid
 * */
int gost_kexp15(const unsigned char *shared_key, const int shared_len,
                int cipher_nid, const unsigned char *cipher_key,
                int mac_nid, unsigned char *mac_key,
                const unsigned char *iv, const size_t ivlen,
                unsigned char *out, int *out_len)
{
    unsigned char iv_full[16], mac_buf[16];
    unsigned int mac_len;

    EVP_CIPHER_CTX *ciph = NULL;
    EVP_MD_CTX *mac = NULL;

    int ret = 0;
    int len;

    mac_len = (cipher_nid == NID_magma_ctr) ? 8 :
        (cipher_nid == NID_grasshopper_ctr) ? 16 : 0;

    if (mac_len == 0) {
        GOSTerr(GOST_F_GOST_KEXP15, GOST_R_INVALID_CIPHER);
        goto err;
    }

    if (shared_len + mac_len > (unsigned int)(*out_len)) {
        GOSTerr(GOST_F_GOST_KEXP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* we expect IV of half length */
    memset(iv_full, 0, 16);
    memcpy(iv_full, iv, ivlen);

    mac = EVP_MD_CTX_new();
    if (mac == NULL) {
        GOSTerr(GOST_F_GOST_KEXP15, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_DigestInit_ex(mac, EVP_get_digestbynid(mac_nid), NULL) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_SET_KEY, 32, mac_key) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_XOF_LEN, mac_len, NULL) <= 0
        || EVP_DigestUpdate(mac, iv, ivlen) <= 0
        || EVP_DigestUpdate(mac, shared_key, shared_len) <= 0
        /* As we set MAC length directly, we should not allow overwriting it */
        || EVP_DigestFinalXOF(mac, mac_buf, mac_len) <= 0) {
        GOSTerr(GOST_F_GOST_KEXP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ciph = EVP_CIPHER_CTX_new();
    if (ciph == NULL) {
        GOSTerr(GOST_F_GOST_KEXP15, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_CipherInit_ex
        (ciph, EVP_get_cipherbynid(cipher_nid), NULL, NULL, NULL, 1) <= 0
        || EVP_CipherInit_ex(ciph, NULL, NULL, cipher_key, iv_full, 1) <= 0
        || EVP_CipherUpdate(ciph, out, &len, shared_key, shared_len) <= 0
        || EVP_CipherUpdate(ciph, out + shared_len, &len, mac_buf, mac_len) <= 0
        || EVP_CipherFinal_ex(ciph, out + shared_len + len, out_len) <= 0) {
        GOSTerr(GOST_F_GOST_KEXP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    *out_len = shared_len + mac_len;

    ret = 1;

 err:
    OPENSSL_cleanse(mac_buf, mac_len);
    EVP_MD_CTX_free(mac);
    EVP_CIPHER_CTX_free(ciph);

    return ret;
}

/*
 * Function expects that shared_key is a preallocated buffer
 * with length defined as expkeylen + mac_len defined by mac_nid
 * */
int gost_kimp15(const unsigned char *expkey, const size_t expkeylen,
                int cipher_nid, const unsigned char *cipher_key,
                int mac_nid, unsigned char *mac_key,
                const unsigned char *iv, const size_t ivlen,
                unsigned char *shared_key)
{
    unsigned char iv_full[16], out[48], mac_buf[16];
    unsigned int mac_len;
    const size_t shared_len = 32;

    EVP_CIPHER_CTX *ciph = NULL;
    EVP_MD_CTX *mac = NULL;

    int ret = 0;
    int len;

    mac_len = (cipher_nid == NID_magma_ctr) ? 8 :
        (cipher_nid == NID_grasshopper_ctr) ? 16 : 0;

    if (mac_len == 0) {
        GOSTerr(GOST_F_GOST_KIMP15, GOST_R_INVALID_CIPHER);
        goto err;
    }

    if (expkeylen > sizeof(out)) {
        GOSTerr(GOST_F_GOST_KIMP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (ivlen > 16) {
        GOSTerr(GOST_F_GOST_KIMP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* we expect IV of half length */
    memset(iv_full, 0, 16);
    memcpy(iv_full, iv, ivlen);

    ciph = EVP_CIPHER_CTX_new();
    if (ciph == NULL) {
        GOSTerr(GOST_F_GOST_KIMP15, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_CipherInit_ex
        (ciph, EVP_get_cipherbynid(cipher_nid), NULL, NULL, NULL, 0) <= 0
        || EVP_CipherInit_ex(ciph, NULL, NULL, cipher_key, iv_full, 0) <= 0
        || EVP_CipherUpdate(ciph, out, &len, expkey, expkeylen) <= 0
        || EVP_CipherFinal_ex(ciph, out + len, &len) <= 0) {
        GOSTerr(GOST_F_GOST_KIMP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*Now we have shared key and mac in out[] */

    mac = EVP_MD_CTX_new();
    if (mac == NULL) {
        GOSTerr(GOST_F_GOST_KIMP15, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_DigestInit_ex(mac, EVP_get_digestbynid(mac_nid), NULL) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_SET_KEY, 32, mac_key) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_XOF_LEN, mac_len, NULL) <= 0
        || EVP_DigestUpdate(mac, iv, ivlen) <= 0
        || EVP_DigestUpdate(mac, out, shared_len) <= 0
        /* As we set MAC length directly, we should not allow overwriting it */
        || EVP_DigestFinalXOF(mac, mac_buf, mac_len) <= 0) {
        GOSTerr(GOST_F_GOST_KIMP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (CRYPTO_memcmp(mac_buf, out + shared_len, mac_len) != 0) {
        GOSTerr(GOST_F_GOST_KIMP15, GOST_R_BAD_MAC);
        goto err;
    }

    memcpy(shared_key, out, shared_len);
    ret = 1;

 err:
    OPENSSL_cleanse(out, sizeof(out));
    EVP_MD_CTX_free(mac);
    EVP_CIPHER_CTX_free(ciph);
    return ret;
}
