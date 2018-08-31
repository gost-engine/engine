#include <string.h>
#include <openssl/evp.h>

#include "gost_lcl.h"
#include "e_gost_err.h"

/*
 * Function expects that out is a preallocated buffer of length
 * defined as sum of shared_len and mac length defined by mac_nid
 * */
int gost_kexp15(const unsigned char *shared_key, const int shared_len,
                int cipher_nid, const unsigned char *cipher_key,
                const size_t cipher_key_len, int mac_nid,
                unsigned char *mac_key, const size_t mac_key_len,
                const unsigned char *iv, const size_t ivlen, unsigned char *out,
                int *out_len)
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

    /* we expect IV of half length */
    memset(iv_full, 0, 16);
    memcpy(iv_full, iv, ivlen);

    mac = EVP_MD_CTX_new();
    if (mac == NULL) {
        GOSTerr(GOST_F_GOST_KEXP15, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_DigestInit_ex(mac, EVP_get_digestbynid(mac_nid), NULL) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_SET_KEY, mac_key_len, mac_key) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_MAC_LEN, mac_len, NULL) <= 0
        || EVP_DigestUpdate(mac, iv, ivlen) <= 0
        || EVP_DigestUpdate(mac, shared_key, shared_len) <= 0
        /* As we set MAC length directly, we should not allow overwriting it */
        || EVP_DigestFinal_ex(mac, mac_buf, NULL) <= 0) {
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

int gost_kimp15(const unsigned char *expkey, const size_t expkeylen,
                int cipher_nid, const unsigned char *cipher_key,
                const size_t cipher_key_len, int mac_nid, char *mac_key,
                const size_t mac_key_len, const char *iv, const size_t ivlen,
                char *shared_key, size_t shared_len)
{
    unsigned char iv_full[16], out[48], mac_buf[16];
    unsigned int mac_len;

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

    /* we expect IV of half length */
    memset(iv_full, 0, 16);
    memcpy(iv_full, iv, ivlen);

    if (EVP_CipherInit_ex
        (ciph, EVP_get_cipherbynid(cipher_nid), NULL, NULL, NULL, 0) <= 0
        || EVP_CipherInit_ex(ciph, NULL, NULL, cipher_key, iv_full, 0) <= 0
        || EVP_CipherUpdate(ciph, out, &len, expkey, expkeylen) <= 0
        || EVP_CipherFinal_ex(ciph, out + len, &len) <= 0) {
        GOSTerr(GOST_F_GOST_KIMP15, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*Now we have shared key and mac in out[] */

    if (EVP_DigestInit_ex(mac, EVP_get_digestbynid(mac_nid), NULL) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_SET_KEY, mac_key_len, mac_key) <= 0
        || EVP_MD_CTX_ctrl(mac, EVP_MD_CTRL_MAC_LEN, mac_len, NULL) <= 0
        || EVP_DigestUpdate(mac, iv, ivlen) <= 0
        || EVP_DigestUpdate(mac, out, shared_len) <= 0
        /* As we set MAC length directly, we should not allow overwriting it */
        || EVP_DigestFinal_ex(mac, mac_buf, NULL) <= 0) {
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

/*
 * keyout expected to be 64 bytes
 * */
int gost_keg(const unsigned char *seckey, const size_t seckey_len,
             const EC_POINT *pub, const unsigned char *h, unsigned char *keyout)
{
    return 0;
}

#ifdef ENABLE_UNIT_TESTS
# include <stdio.h>
# include <string.h>
# include <openssl/obj_mac.h>

static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
    int n = 0;

    fprintf(f, "%s", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0)
            fprintf(f, "\n%04x", n);
        fprintf(f, " %02x", s[n]);
    }
    fprintf(f, "\n");
}

int main(void)
{
    const unsigned char key[] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    const unsigned char magma_key[] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    };

    unsigned char mac_magma_key[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };

    const unsigned char magma_iv[] = { 0x67, 0xBE, 0xD6, 0x54 };

    const unsigned char magma_export[] =
        { 0xCF, 0xD5, 0xA1, 0x2D, 0x5B, 0x81, 0xB6, 0xE1, 0xE9, 0x9C, 0x91,
        0x6D, 0x07, 0x90, 0x0C, 0x6A,
        0xC1, 0x27, 0x03, 0xFB, 0x3A, 0xBD, 0xED, 0x55, 0x56, 0x7B, 0xF3, 0x74,
        0x2C, 0x89, 0x9C, 0x75,
        0x5D, 0xAF, 0xE7, 0xB4, 0x2E, 0x3A, 0x8B, 0xD9
    };

    unsigned char buf[32 + 16];
    int ret = 0;
    int outlen = 40;

    OpenSSL_add_all_algorithms();
    memset(buf, 0, sizeof(buf));

    ret = gost_kexp15(key, 32,
                      NID_magma_ctr, magma_key, 32,
                      NID_magma_mac, mac_magma_key, 32,
                      magma_iv, 4, buf, &outlen);

    if (ret <= 0)
        ERR_print_errors_fp(stderr);
    else {
        hexdump(stdout, "Magma key export", buf, 40);
        if (memcmp(buf, magma_export, 40) != 0) {
            fprintf(stdout, "ERROR! test failed\n");
        }
    }

    return 0;
}

#endif
