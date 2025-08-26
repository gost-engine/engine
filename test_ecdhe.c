#include <openssl/ec.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "gost_lcl.h"

#define T(e) \
    if (!(e)) { \
        ERR_print_errors_fp(stderr); \
        OpenSSLDie(__FILE__, __LINE__, #e); \
    }

#define cRED    "\033[1;31m"
#define cGREEN  "\033[1;32m"
#define cNORM   "\033[m"

static EVP_PKEY *load_private_key(int key_nid, int param_nid, const char *pk,
                                  const char *pub)
{
    EVP_PKEY_CTX *ctx;

    T(ctx = EVP_PKEY_CTX_new_id(key_nid, NULL));
    T(EVP_PKEY_paramgen_init(ctx));
    T(EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GOST_PARAMSET, param_nid,
                        NULL));
    EVP_PKEY *key = NULL;
    T((EVP_PKEY_paramgen(ctx, &key)) == 1);
    EVP_PKEY_CTX_free(ctx);

    EC_KEY *ec;
    T(ec = EVP_PKEY_get0(key));

    const int len = EVP_PKEY_bits(key) / 8;
    BN_CTX *bc;
    T(bc = BN_CTX_secure_new());
    BN_CTX_start(bc);
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    EC_POINT *pkey = NULL;
    if (pk) {
        /* Read private key. */
        BIGNUM *d = NULL;

        T(d = BN_lebin2bn((const unsigned char *)pk, len, NULL));
        T(EC_KEY_set_private_key(ec, d));

        /* Compute public key. */
        T(pkey = EC_POINT_new(group));
        T(EC_POINT_mul(group, pkey, d, NULL, NULL, bc));
        BN_free(d);
        T(EC_KEY_set_public_key(ec, pkey));
    } else {
        /* Read public key. */
        BIGNUM *x, *y;

        T(x = BN_lebin2bn((const unsigned char *)pub, len, NULL));
        T(y = BN_lebin2bn((const unsigned char *)pub + len, len, NULL));
        EC_POINT *xy = EC_POINT_new(group);
        T(EC_POINT_set_affine_coordinates(group, xy, x, y, bc));
        BN_free(x);
        BN_free(y);
        T(EC_KEY_set_public_key(ec, xy));
        EC_POINT_free(xy);
    }

#ifdef DEBUG
    BIO *bp = BIO_new_fd(1, BIO_NOCLOSE);
    if (pk)
        PEM_write_bio_PrivateKey(bp, key, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_PUBKEY(bp, key);
    BIO_free(bp);
#endif

    /* Verify public key. */
    if (pk && pub) {
        BIGNUM *x, *y;

        T(x = BN_lebin2bn((const unsigned char *)pub, len, NULL));
        T(y = BN_lebin2bn((const unsigned char *)pub + len, len, NULL));
        EC_POINT *xy = EC_POINT_new(group);
        T(EC_POINT_set_affine_coordinates(group, xy, x, y, bc));
        BN_free(x);
        BN_free(y);
        if (EC_POINT_cmp(group, pkey, xy, bc) == 0)
            printf("Public key %08x matches private key %08x\n",
                   *(int *)pub, *(int *)pk);
        else
        {
            printf(cRED "Public key mismatch!" cNORM "\n");
            exit(1);
        }
        EC_POINT_free(xy);
    }
    EC_POINT_free(pkey);
    BN_CTX_end(bc);
    BN_CTX_free(bc);

    return key;
}

int main()
{
    OpenSSL_add_all_algorithms();

    const char client_private_key[] =
        "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04"
        "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04";

    const char server_private_key[] =
        "\xB6\x6B\x18\xAC\xD9\x25\x59\x02\x19\xB8\x8D\xF3\xC4\xE8\xD2\x64"
        "\x84\x84\x84\x84\x84\x84\x84\x84\x84\x84\x84\x84\x84\x84\x84\x04";

    const char server_public_key[] =
        "\xF8\x55\xF9\x3A\xE4\x0B\xC3\xDD\x2B\xCF\xDB\xAC\x99\xD4\xC3\xF9"
        "\xD6\xCF\x16\xED\xB8\x1F\x87\xC6\x84\x68\xB6\x1B\xAF\x2E\xF6\xB2"
        "\x0C\x18\x4E\xD5\xEC\xB5\x46\x2B\x1E\x18\x7C\x7E\xCB\x84\x40\xAF"
        "\x41\xD7\x28\xAA\x45\x84\x2F\xC7\xDB\xD2\xC4\x74\x74\x85\x9F\xD2";

    const char client_public_key[] =
        "\x9E\x44\x41\x7A\x31\x6B\x95\xC5\x4B\xC0\x04\x63\x05\xFA\x60\x9C"
        "\x85\xE5\x05\x78\x2D\x26\x1B\xA9\x87\xBF\xF8\xC7\x4B\xEE\x51\xD8"
        "\x3B\xF9\xE8\x35\xB9\x33\x18\x2C\x70\xF4\xDE\x50\x04\x75\xB1\x36"
        "\xBC\xE4\xD3\x48\xC3\x05\x19\x0A\x60\x8E\xC1\xB1\x28\x70\x56\xEB";

    EVP_PKEY *client_key = load_private_key(NID_id_GostR3410_2012_256,
                                            NID_id_tc26_gost_3410_2012_256_paramSetA,
                                            client_private_key, client_public_key);
    EVP_PKEY *server_key = load_private_key(NID_id_GostR3410_2012_256,
                                            NID_id_tc26_gost_3410_2012_256_paramSetA,
                                            server_private_key, server_public_key);

    unsigned char expected_result[] = {0xD5, 0x56, 0xB0, 0xBC, 0x8F, 0x86, 0xE1, 0x46,
                                       0x6C, 0xF1, 0x30, 0xD9, 0xE7, 0xDB, 0x80, 0x69,
                                       0x73, 0xC1, 0x8E, 0xE0, 0x73, 0x8C, 0x33, 0xC6,
                                       0x73, 0xE0, 0x16, 0x17, 0x70, 0xE3, 0x6B, 0x80};

    unsigned char *client_result = NULL, *server_result = NULL;
    size_t client_result_len = 0, server_result_len = 0;
    uint8_t ukm = 1;
    int ret = 1;

    if (!internal_compute_ecdh(NULL, &client_result_len, &ukm, 1,
                               EC_KEY_get0_public_key(EVP_PKEY_get0(server_key)),
                               EVP_PKEY_get0(client_key)))
        goto exit;
    
    if (!internal_compute_ecdh(NULL, &server_result_len, &ukm, 1,
                               EC_KEY_get0_public_key(EVP_PKEY_get0(client_key)),
                               EVP_PKEY_get0(server_key)))
        goto exit;

    if ((client_result = OPENSSL_malloc(client_result_len)) == NULL)
        goto exit;

    if ((server_result = OPENSSL_malloc(server_result_len)) == NULL)
        goto exit;

    if (!internal_compute_ecdh(client_result, &client_result_len, &ukm, 1,
                               EC_KEY_get0_public_key(EVP_PKEY_get0(server_key)),
                               EVP_PKEY_get0(client_key))) {
        printf(cRED "ECDH compute client key internal error!" cNORM "\n");
        goto exit;
    }

    if (!internal_compute_ecdh(server_result, &server_result_len, &ukm, 1,
                               EC_KEY_get0_public_key(EVP_PKEY_get0(client_key)),
                               EVP_PKEY_get0(server_key))) {
        printf(cRED "ECDH compute server key internal error!" cNORM "\n");
        goto exit;
    }

    if (client_result_len != server_result_len
        || memcmp(client_result, server_result, client_result_len)) {
        printf(cRED "client key and server key mismatch!" cNORM "\n");
        goto exit;
    }

    printf(cGREEN "client ECDH and server ECDH match!" cNORM "\n");

    if (memcmp(client_result, expected_result, client_result_len / 2)) {
        printf(cRED "Reference ECDHE and computed ECDHE mismatch!" cNORM "\n");
        goto exit;
    }
    
    printf(cGREEN "Reference ECDHE and computed ECDHE match!" cNORM "\n");

    ret = 0;
exit:

    EVP_PKEY_free(client_key);
    EVP_PKEY_free(server_key);
    OPENSSL_free(server_result);
    OPENSSL_free(client_result);

    return ret;
}