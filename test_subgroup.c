/*
 * Test public key subgroup membership check on cofactor h > 1 curves
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#ifdef _MSC_VER
# pragma warning(push, 3)
# include <openssl/applink.c>
# pragma warning(pop)
#endif
#include "gost_lcl.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <string.h>
#include <stdlib.h>

#define T(e) \
    if (!(e)) { \
        ERR_print_errors_fp(stderr); \
        OpenSSLDie(__FILE__, __LINE__, #e); \
    }

#define cRED	"\033[1;31m"
#define cGREEN	"\033[1;32m"
#define cNORM	"\033[m"

/* Point of order 4 on id-tc26-gost-3410-2012-256-paramSetA.
 * No private key d with d*G == Q4 exists. */
#define Q4_X "7F7F80C60535007538B45A5D95C39353BC5D80D1F36A9DC0ACE7C5118C2F5977"
#define Q4_Y "81817DADF060FEA055E2F0E73EB54604CAE77D8A25C026BDF948B0CB5B71EECA"

static EC_POINT *q4_point(const EC_GROUP *group)
{
    EC_POINT *p = NULL;
    BIGNUM *x = NULL, *y = NULL;

    T(BN_hex2bn(&x, Q4_X));
    T(BN_hex2bn(&y, Q4_Y));
    p = EC_POINT_new(group);
    T(p != NULL);
    T(EC_POINT_set_affine_coordinates(group, p, x, y, NULL));
    T(EC_POINT_is_on_curve(group, p, NULL));
    BN_free(x);
    BN_free(y);
    return p;
}

/* Order-4 point must fail the subgroup check and gost_ec_verify() */
static void test_verify_rejects_small_order(void)
{
    EC_KEY *ec = NULL;
    const EC_GROUP *group;
    EC_POINT *q4 = NULL;
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    unsigned char digest[32];

    printf("Small-order point is rejected by gost_ec_verify:");

    ec = EC_KEY_new();
    T(ec != NULL);
    T(fill_GOST_EC_params(ec, NID_id_tc26_gost_3410_2012_256_paramSetA));
    group = EC_KEY_get0_group(ec);

    q4 = q4_point(group);
    T(!gost_ec_pub_key_subgroup_check(group, q4));

    /* Bypass the decoding checks to test gost_ec_verify() itself */
    T(EC_KEY_set_public_key(ec, q4));

    memset(digest, 0x42, sizeof(digest));
    sig = ECDSA_SIG_new();
    T(sig != NULL);
    T(BN_hex2bn(&r, "0102030405060708091011121314151617181920212223242526272829303132"));
    T(BN_hex2bn(&s, "31302928272625242322212019181716151413121110090807060504030201"));
    T(ECDSA_SIG_set0(sig, r, s));
    ERR_clear_error();
    T(gost_ec_verify(digest, sizeof(digest), sig, ec) == 0);

    ECDSA_SIG_free(sig);
    EC_POINT_free(q4);
    EC_KEY_free(ec);
    printf(cGREEN "  passed" cNORM "\n");
}

/* Order-4 point must be rejected on public key decoding */
static void test_decode_rejects_small_order(void)
{
    EC_KEY *ec_legit = NULL, *ec_dec = NULL;
    X509_PUBKEY *xp = NULL;
    X509_ALGOR *palg = NULL;
    const unsigned char *pub_der = NULL;
    int pub_der_len = 0;
    int key_type = NID_undef;
    unsigned char wire[2 + 64];
    unsigned char wire_long[2 + 65];
    BIGNUM *x = NULL, *y = NULL;
    const EC_POINT *pub;

    printf("Small-order point is rejected by internal_pub_decode_ec:");

    /* Encode a legitimate key just to obtain a valid X509_ALGOR */
    ec_legit = EC_KEY_new();
    T(ec_legit != NULL);
    T(fill_GOST_EC_params(ec_legit, NID_id_tc26_gost_3410_2012_256_paramSetA));
    T(gost_ec_keygen(ec_legit));
    xp = X509_PUBKEY_new();
    T(xp != NULL);
    T(internal_pub_encode_ec(xp, ec_legit, NID_id_GostR3410_2012_256));
    T(X509_PUBKEY_get0_param(NULL, &pub_der, &pub_der_len, &palg, xp));

    pub = EC_KEY_get0_public_key(ec_legit);
    T(pub != NULL);

    /* Legitimate key decodes fine */
    ec_dec = EC_KEY_new();
    T(ec_dec != NULL);
    key_type = NID_undef;
    T(internal_pub_decode_ec(ec_dec, &key_type, palg, pub_der, pub_der_len));
    EC_KEY_free(ec_dec);

    /* Wire format is a DER OCTET STRING of reverse(Y_be || X_be) */
    T(BN_hex2bn(&x, Q4_X));
    T(BN_hex2bn(&y, Q4_Y));
    wire[0] = V_ASN1_OCTET_STRING;
    wire[1] = 64;
    T(BN_bn2lebinpad(x, wire + 2, 32) == 32);
    T(BN_bn2lebinpad(y, wire + 2 + 32, 32) == 32);

    ec_dec = EC_KEY_new();
    T(ec_dec != NULL);
    key_type = NID_undef;
    ERR_clear_error();
    T(internal_pub_decode_ec(ec_dec, &key_type, palg, wire, sizeof(wire)) == 0);
    EC_KEY_free(ec_dec);

    /* Key material of non-exact length is rejected as well */
    wire_long[0] = V_ASN1_OCTET_STRING;
    wire_long[1] = 65;
    memcpy(wire_long + 2, wire + 2, 64);
    wire_long[2 + 64] = 0xaa;
    ec_dec = EC_KEY_new();
    T(ec_dec != NULL);
    key_type = NID_undef;
    ERR_clear_error();
    T(internal_pub_decode_ec(ec_dec, &key_type, palg, wire_long,
                             sizeof(wire_long)) == 0);
    EC_KEY_free(ec_dec);

    BN_free(x);
    BN_free(y);
    X509_PUBKEY_free(xp);
    EC_KEY_free(ec_legit);
    printf(cGREEN "  passed" cNORM "\n");
}

/* Sign/verify roundtrip on a cofactor h = 4 parameter set */
static void test_legit_roundtrip_cofactor4(void)
{
    EC_KEY *ec = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *sig = NULL;
    unsigned char digest[32];

    printf("Legitimate key on id-tc26-gost-3410-2012-256-paramSetA (h=4):");

    ec = EC_KEY_new();
    T(ec != NULL);
    T(fill_GOST_EC_params(ec, NID_id_tc26_gost_3410_2012_256_paramSetA));
    T(gost_ec_keygen(ec));
    group = EC_KEY_get0_group(ec);
    T(gost_ec_pub_key_subgroup_check(group, EC_KEY_get0_public_key(ec)));

    memset(digest, 0x24, sizeof(digest));
    sig = gost_ec_sign(digest, sizeof(digest), ec);
    T(sig != NULL);
    T(gost_ec_verify(digest, sizeof(digest), sig, ec) == 1);

    ECDSA_SIG_free(sig);
    EC_KEY_free(ec);
    printf(cGREEN "  passed" cNORM "\n");
}

/* Only the exact signature size is accepted */
static void test_signature_exact_length(void)
{
    unsigned char sigbuf[128];
    ECDSA_SIG *sig = NULL;

    printf("Signature parser accepts only the exact size:");

    memset(sigbuf, 0x55, sizeof(sigbuf));

    sig = unpack_cp_signature(sigbuf, 64, 64);
    T(sig != NULL);
    ECDSA_SIG_free(sig);
    sig = unpack_cp_signature(sigbuf, 128, 128);
    T(sig != NULL);
    ECDSA_SIG_free(sig);

    ERR_clear_error();
    T(unpack_cp_signature(sigbuf, 65, 64) == NULL);  /* trailing byte */
    ERR_clear_error();
    T(unpack_cp_signature(sigbuf, 66, 64) == NULL);  /* zero-padded halves */
    ERR_clear_error();
    T(unpack_cp_signature(sigbuf, 128, 64) == NULL); /* double-size padding */
    ERR_clear_error();
    T(unpack_cp_signature(sigbuf, 64, 128) == NULL);
    ERR_clear_error();
    T(unpack_cp_signature(sigbuf, 63, 64) == NULL);

    printf(cGREEN "  passed" cNORM "\n");
}

int main(void)
{
    test_verify_rejects_small_order();
    test_decode_rejects_small_order();
    test_legit_roundtrip_cofactor4();
    test_signature_exact_length();
    printf("All subgroup check tests passed\n");
    return 0;
}
