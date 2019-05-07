#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <byteswap.h>

const unsigned char gh_key[] = {
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
};

const unsigned char gh_nonce[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC,
        0xBB, 0xAA, 0x99, 0x88
};

const unsigned char gh_adata[] = {
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03,
    0xEA, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
};

const unsigned char gh_pdata[] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC,
        0xBB, 0xAA, 0x99, 0x88,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xEE, 0xFF, 0x0A,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        0xEE, 0xFF, 0x0A, 0x00,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE,
        0xFF, 0x0A, 0x00, 0x11,
    0xAA, 0xBB, 0xCC
};

const unsigned char etalon_cdata[] = {
    0xA9, 0x75, 0x7B, 0x81, 0x47, 0x95, 0x6E, 0x90, 0x55, 0xB8, 0xA3, 0x3D,
        0xE8, 0x9F, 0x42, 0xFC,
    0x80, 0x75, 0xD2, 0x21, 0x2B, 0xF9, 0xFD, 0x5B, 0xD3, 0xF7, 0x06, 0x9A,
        0xAD, 0xC1, 0x6B, 0x39,
    0x49, 0x7A, 0xB1, 0x59, 0x15, 0xA6, 0xBA, 0x85, 0x93, 0x6B, 0x5D, 0x0E,
        0xA9, 0xF6, 0x85, 0x1C,
    0xC6, 0x0C, 0x14, 0xD4, 0xD3, 0xF8, 0x83, 0xD0, 0xAB, 0x94, 0x42, 0x06,
        0x95, 0xC7, 0x6D, 0xEB,
    0x2C, 0x75, 0x52
};

const unsigned char etalon_tag[] = {
    0xCF, 0x5D, 0x65, 0x6F, 0x40, 0xC3, 0x4F, 0x5C, 0x46, 0xE8, 0xBB, 0x0E,
        0x29, 0xFC, 0xDB, 0x4C
};

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

void grasshopper_enc_mgm_big(const EVP_CIPHER *ciph)
{
    unsigned char tag[16];
    unsigned char gh_cdata[sizeof(gh_pdata)];
    unsigned char *pcdata = gh_cdata;

    int asize = sizeof(gh_adata);
    int psize = sizeof(gh_pdata);
    int fsize = 0;

    EVP_CIPHER_CTX *enc = NULL;

    int i;

    enc = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc, ciph, NULL, gh_key, gh_nonce);

    EVP_EncryptUpdate(enc, NULL, &asize, gh_adata, sizeof(gh_adata));
    EVP_EncryptUpdate(enc, gh_cdata, &psize, gh_pdata, sizeof(gh_pdata));
    EVP_EncryptFinal_ex(enc, NULL, &fsize);

    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_GET_TAG, 16, tag);

    if (memcmp(etalon_cdata, gh_cdata, sizeof(gh_cdata))) {
        fprintf(stderr, "Shit happens - encryption!\n");
        hexdump(stderr, "Etalon cdata", etalon_cdata, sizeof(etalon_cdata));
        hexdump(stderr, "Got cdata", gh_cdata, sizeof(gh_cdata));
        return;
    }

    if (memcmp(tag, etalon_tag, 16)) {
        fprintf(stderr, "Shit happens!\n");
        hexdump(stderr, "Etalon tag", etalon_tag, 16);
        hexdump(stderr, "Got tag", tag, 16);
        return;
    }
    fprintf(stderr, "OK encryption - big chunks!\n");
    EVP_CIPHER_CTX_free(enc);
}

void grasshopper_enc_mgm_small(const EVP_CIPHER *ciph)
{
    unsigned char tag[16];
    unsigned char gh_cdata[sizeof(gh_pdata)];
    unsigned char *pcdata = gh_cdata;

    int asize = sizeof(gh_adata);
    int psize = sizeof(gh_pdata);
    int fsize = 0;

    EVP_CIPHER_CTX *enc = NULL;

    int i;

    enc = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc, ciph, NULL, gh_key, gh_nonce);
    for (i = 0; i < sizeof(gh_adata); i++) {
        asize = 1;
        EVP_EncryptUpdate(enc, NULL, &asize, gh_adata + i, 1);
    }
    for (i = 0; i < sizeof(gh_pdata); i++) {
        psize = 1;
        EVP_EncryptUpdate(enc, pcdata, &psize, gh_pdata + i, 1);
        pcdata += psize;
    }

    EVP_EncryptFinal_ex(enc, NULL, &fsize);

    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_GET_TAG, 16, tag);

    if (memcmp(etalon_cdata, gh_cdata, sizeof(gh_cdata))) {
        fprintf(stderr, "Shit happens - encryption!\n");
        hexdump(stderr, "Etalon cdata", etalon_cdata, sizeof(etalon_cdata));
        hexdump(stderr, "Got cdata", gh_cdata, sizeof(gh_cdata));
        return;
    }

    if (memcmp(tag, etalon_tag, 16)) {
        fprintf(stderr, "Shit happens!\n");
        hexdump(stderr, "Etalon tag", etalon_tag, 16);
        hexdump(stderr, "Got tag", tag, 16);
        return;
    }
    fprintf(stderr, "OK encryption - small chunks!\n");
    EVP_CIPHER_CTX_free(enc);

}

#define L_ENDIAN 1
static void gf128_mul_uint64(uint64_t *z, uint64_t *x, uint64_t *y)
{
    int i = 0, n = 0;
    uint64_t t, s0, s1;

    BUF_reverse((unsigned char *)x, NULL, 16);
    BUF_reverse((unsigned char *)y, NULL, 16);

#ifdef L_ENDIAN
    s0 = x[0];
    s1 = x[1];
#else
    s0 = bswap_64(x[0]);
    s1 = bswap_64(x[1]);
#endif

    memset(z, 0, sizeof(uint64_t) * 2);

    /* lower half */
#ifdef L_ENDIAN
    t = y[0];
#else
    t = bswap_64(y[0]);
#endif

    for (i = 0; i < 64; i++) {
        if (t & 0x1) {
            z[0] ^= s0;
            z[1] ^= s1;
        }
        t >>= 1;
        n = s1 >> 63;
        s1 <<= 1;
        s1 ^= (s0 >> 63);
        s0 <<= 1;
        if (n)
            s0 ^= 0x87;
    }

    /* upper half */
#ifdef L_ENDIAN
    t = y[1];
#else
    t = bswap_64(y[1]);
#endif

    for (i = 0; i < 63; i++) {
        if (t & 0x1) {
            z[0] ^= s0;
            z[1] ^= s1;
        }
        t >>= 1;
        n = s1 >> 63;
        s1 <<= 1;
        s1 ^= (s0 >> 63);
        s0 <<= 1;
        if (n)
            s0 ^= 0x87;
    }

    if (t & 0x1) {
        z[0] ^= s0;
        z[1] ^= s1;
    }
#ifndef L_ENDIAN
    z[0] = bswap_64(z[0]);
    z[1] = bswap_64(z[1]);
#endif
    BUF_reverse((unsigned char *)z, NULL, 16);
}

void gf_mul(void)
{
    unsigned char H[16] = {
        0x8D, 0xB1, 0x87, 0xD6, 0x53, 0x83, 0x0E, 0xA4, 0xBC, 0x44, 0x64, 0x76,
            0x95, 0x2C, 0x30, 0x0B
    };

    unsigned char A[16] = {
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01
    };

    unsigned char etalon[16] = {
        0x4C, 0xF4, 0x27, 0xF4, 0xAD, 0xB7, 0x5C, 0xF4, 0xC0, 0xDA, 0x39, 0xD5,
            0xAB, 0x48, 0xCF, 0x38
    };

    unsigned char result_bd[16];
    gf128_mul_uint64((uint64_t *)result_bd, (uint64_t *)H, (uint64_t *)A);

    hexdump(stderr, "Etalon", etalon, 16);

    if (memcmp(etalon, result_bd, 16)) {
        fprintf(stderr, "Shit happens - BD!\n");
        hexdump(stderr, "Result - BD", result_bd, 16);
    } else
        fprintf(stderr, "OK - BD!\n");

    return;
}

void grasshopper_dec_mgm_big(const EVP_CIPHER *ciph)
{
    unsigned char tag[16];
    unsigned char gh_cdata[sizeof(gh_pdata)];
    unsigned char *pcdata = gh_cdata;

    int asize = sizeof(gh_adata);
    int psize = sizeof(gh_pdata);
    int fsize = 0;

    EVP_CIPHER_CTX *enc = NULL;

    int i;

    memcpy(tag, etalon_tag, 16);

    enc = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(enc, ciph, NULL, gh_key, gh_nonce);
    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_TAG, 16, tag);

    EVP_DecryptUpdate(enc, NULL, &asize, gh_adata, sizeof(gh_adata));
    EVP_DecryptUpdate(enc, gh_cdata, &psize, etalon_cdata,
                      sizeof(etalon_cdata));

    if (EVP_DecryptFinal_ex(enc, NULL, &fsize) <= 0) {
        fprintf(stderr, "Shit happens - bad tag!\n");
        return;
    }

    if (memcmp(gh_pdata, gh_cdata, sizeof(gh_cdata))) {
        fprintf(stderr, "Shit happens - decryption!\n");
        hexdump(stderr, "Etalon cdata", gh_pdata, sizeof(gh_pdata));
        hexdump(stderr, "Got cdata", gh_cdata, sizeof(gh_cdata));
        return;
    }

    fprintf(stderr, "OK decryption - big chunks!\n");
    EVP_CIPHER_CTX_free(enc);
}

void grasshopper_dec_mgm_small(const EVP_CIPHER *ciph)
{
    unsigned char tag[16];
    unsigned char gh_cdata[sizeof(gh_pdata)];
    unsigned char *pcdata = gh_cdata;

    int asize = sizeof(gh_adata);
    int psize = sizeof(gh_pdata);
    int fsize = 0;

    EVP_CIPHER_CTX *enc = NULL;

    int i;

    memcpy(tag, etalon_tag, 16);

    enc = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(enc, ciph, NULL, gh_key, gh_nonce);
    EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_TAG, 16, tag);

    for (i = 0; i < sizeof(gh_adata); i++) {
        asize = 1;
        EVP_DecryptUpdate(enc, NULL, &asize, gh_adata + i, 1);
    }
    for (i = 0; i < sizeof(gh_pdata); i++) {
        psize = 1;
        EVP_DecryptUpdate(enc, pcdata, &psize, etalon_cdata + i, 1);
        pcdata += psize;
    }

    if (EVP_DecryptFinal_ex(enc, NULL, &fsize) <= 0) {
        fprintf(stderr, "Shit happens - bad tag!\n");
        return;
    }

    if (memcmp(gh_pdata, gh_cdata, sizeof(gh_cdata))) {
        fprintf(stderr, "Shit happens - decryption!\n");
        hexdump(stderr, "Etalon cdata", gh_pdata, sizeof(gh_pdata));
        hexdump(stderr, "Got cdata", gh_cdata, sizeof(gh_cdata));
        return;
    }

    fprintf(stderr, "OK decryption - small chunks!\n");
    EVP_CIPHER_CTX_free(enc);
}

int main(void)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    const EVP_CIPHER *ciph;
    ciph = EVP_get_cipherbynid(NID_kuznyechik_mgm);
    if (ciph == NULL) {
        fprintf(stderr, "Could not obtain cipher");
        exit(1);
    }
//      gf_mul();
    grasshopper_enc_mgm_big(ciph);
    grasshopper_enc_mgm_small(ciph);
    grasshopper_dec_mgm_big(ciph);
    grasshopper_dec_mgm_small(ciph);
    ERR_print_errors_fp(stderr);

    return 0;
}
