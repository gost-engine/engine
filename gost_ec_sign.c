/**********************************************************************
 *                        gost_ec_sign.c                              *
 *             Copyright (c) 2005-2013 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *          Implementation of GOST R 34.10-2001                       *
 *          Requires OpenSSL 1.0.0+ for compilation                   *
 **********************************************************************/
#include "gost_lcl.h"
#include <string.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include "e_gost_err.h"
#ifdef DEBUG_SIGN
extern
void dump_signature(const char *message, const unsigned char *buffer,
                    size_t len);
void dump_dsa_sig(const char *message, ECDSA_SIG *sig);
#else

# define dump_signature(a,b,c)
# define dump_dsa_sig(a,b)
#endif

static R3410_ec_params *gost_nid2params(int nid)
{
    R3410_ec_params *params;

    /* Map tc26-2012 256-bit parameters to cp-2001 parameters */
    switch (nid) {
    case NID_id_tc26_gost_3410_2012_256_paramSetB:
        nid = NID_id_GostR3410_2001_CryptoPro_A_ParamSet;
        break;
    case NID_id_tc26_gost_3410_2012_256_paramSetC:
        nid = NID_id_GostR3410_2001_CryptoPro_B_ParamSet;
        break;
    case NID_id_tc26_gost_3410_2012_256_paramSetD:
        nid = NID_id_GostR3410_2001_CryptoPro_C_ParamSet;
    }

    /* Search nid in 2012 paramset */
    params = R3410_2012_512_paramset;
    while (params->nid != NID_undef) {
        if (params->nid == nid)
            return params;
        params++;
    }

    /* Search nid in 2001 paramset */
    params = R3410_2001_paramset;
    while (params->nid != NID_undef) {
        if (params->nid == nid)
            return params;
        params++;
    }

    return NULL;
}

/*
 * Fills EC_KEY structure hidden in the app_data field of DSA structure
 * with parameter information, extracted from parameter array in
 * params.c file.
 *
 * Also fils DSA->q field with copy of EC_GROUP order field to make
 * DSA_size function work
 */
int fill_GOST_EC_params(EC_KEY *eckey, int nid)
{
    R3410_ec_params *params = gost_nid2params(nid);
    EC_GROUP *grp = NULL;
    EC_POINT *P = NULL;
    BIGNUM *p = NULL, *q = NULL, *a = NULL, *b = NULL, *x = NULL, *y =
        NULL, *cofactor = NULL;
    BN_CTX *ctx;
    int ok = 0;

    if (!eckey || !params) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, GOST_R_UNSUPPORTED_PARAMETER_SET);
        return 0;
    }

    if (!(ctx = BN_CTX_new())) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    cofactor = BN_CTX_get(ctx);
    if (!p || !a || !b || !x || !y || !q || !cofactor) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!BN_hex2bn(&p, params->p)
        || !BN_hex2bn(&a, params->a)
        || !BN_hex2bn(&b, params->b)
        || !BN_hex2bn(&cofactor, params->cofactor)) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    grp = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    if (!grp) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    P = EC_POINT_new(grp);
    if (!P) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!BN_hex2bn(&x, params->x)
        || !BN_hex2bn(&y, params->y)
        || !EC_POINT_set_affine_coordinates(grp, P, x, y, ctx)
        || !BN_hex2bn(&q, params->q)) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (!EC_GROUP_set_generator(grp, P, q, cofactor)) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_INTERNAL_ERROR);
        goto end;
    }
    EC_GROUP_set_curve_name(grp, nid);
    if (!EC_KEY_set_group(eckey, grp)) {
        GOSTerr(GOST_F_FILL_GOST_EC_PARAMS, ERR_R_INTERNAL_ERROR);
        goto end;
    }
    ok = 1;
 end:
    if (P)
        EC_POINT_free(P);
    if (grp)
        EC_GROUP_free(grp);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

/*
 * Computes gost_ec signature as ECDSA_SIG structure
 *
 */
ECDSA_SIG *gost_ec_sign(const unsigned char *dgst, int dlen, EC_KEY *eckey)
{
    ECDSA_SIG *newsig = NULL, *ret = NULL;
    BIGNUM *md = NULL;
    BIGNUM *order = NULL;
    const EC_GROUP *group;
    const BIGNUM *priv_key;
    BIGNUM *r = NULL, *s = NULL, *X = NULL, *tmp = NULL, *tmp2 = NULL,
        *k = NULL, *e = NULL;

    BIGNUM *new_r = NULL, *new_s = NULL;

    EC_POINT *C = NULL;
    BN_CTX *ctx;

    OPENSSL_assert(dgst != NULL && eckey != NULL);

    if (!(ctx = BN_CTX_secure_new())) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    BN_CTX_start(ctx);
    OPENSSL_assert(dlen == 32 || dlen == 64);
    md = BN_lebin2bn(dgst, dlen, NULL);
    newsig = ECDSA_SIG_new();
    if (!newsig || !md) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    group = EC_KEY_get0_group(eckey);
    if (!group) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    order = BN_CTX_get(ctx);
    if (!order || !EC_GROUP_get_order(group, order, ctx)) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    priv_key = EC_KEY_get0_private_key(eckey);
    if (!priv_key) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    e = BN_CTX_get(ctx);
    if (!e || !BN_mod(e, md, order, ctx)) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef DEBUG_SIGN
    fprintf(stderr, "digest as bignum=");
    BN_print_fp(stderr, md);
    fprintf(stderr, "\ndigest mod q=");
    BN_print_fp(stderr, e);
    fprintf(stderr, "\n");
#endif
    if (BN_is_zero(e)) {
        BN_one(e);
    }
    k = BN_CTX_get(ctx);
    C = EC_POINT_new(group);
    if (!k || !C) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    do {
        do {
            if (!BN_rand_range(k, order)) {
                GOSTerr(GOST_F_GOST_EC_SIGN, GOST_R_RNG_ERROR);
                goto err;
            }
            if (!gost_ec_point_mul(group, C, k, NULL, NULL, ctx)) {
                GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_EC_LIB);
                goto err;
            }
            if (!X)
                X = BN_CTX_get(ctx);
            if (!r)
                r = BN_CTX_get(ctx);
            if (!X || !r) {
                GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            if (!EC_POINT_get_affine_coordinates(group, C, X, NULL, ctx)) {
                GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_EC_LIB);
                goto err;
            }

            if (!BN_nnmod(r, X, order, ctx)) {
                GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        while (BN_is_zero(r));
        /* s =  (r*priv_key+k*e) mod order */
        if (!tmp)
            tmp = BN_CTX_get(ctx);
        if (!tmp2)
            tmp2 = BN_CTX_get(ctx);
        if (!s)
            s = BN_CTX_get(ctx);
        if (!tmp || !tmp2 || !s) {
            GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (!BN_mod_mul(tmp, priv_key, r, order, ctx)
            || !BN_mod_mul(tmp2, k, e, order, ctx)
            || !BN_mod_add(s, tmp, tmp2, order, ctx)) {
            GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    while (BN_is_zero(s));

    new_s = BN_dup(s);
    new_r = BN_dup(r);
    if (!new_s || !new_r) {
        GOSTerr(GOST_F_GOST_EC_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ECDSA_SIG_set0(newsig, new_r, new_s);

    ret = newsig;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (C)
        EC_POINT_free(C);
    if (md)
        BN_free(md);
    if (!ret && newsig) {
        ECDSA_SIG_free(newsig);
    }
    return ret;
}

/*
 * Verifies gost ec signature
 *
 */
int gost_ec_verify(const unsigned char *dgst, int dgst_len,
                   ECDSA_SIG *sig, EC_KEY *ec)
{
    BN_CTX *ctx;
    const EC_GROUP *group = (ec) ? EC_KEY_get0_group(ec) : NULL;
    BIGNUM *order;
    BIGNUM *md = NULL, *e = NULL, *R = NULL, *v = NULL, *z1 = NULL, *z2 = NULL;
    const BIGNUM *sig_s = NULL, *sig_r = NULL;
    BIGNUM *X = NULL, *tmp = NULL;
    EC_POINT *C = NULL;
    const EC_POINT *pub_key = NULL;
    int ok = 0;

    OPENSSL_assert(dgst != NULL && sig != NULL && group != NULL);

    if (!(ctx = BN_CTX_new())) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    z1 = BN_CTX_get(ctx);
    z2 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    R = BN_CTX_get(ctx);
    v = BN_CTX_get(ctx);
    if (!order || !e || !z1 || !z2 || !tmp || !X || !R || !v) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pub_key = EC_KEY_get0_public_key(ec);
    if (!pub_key || !EC_GROUP_get_order(group, order, ctx)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ECDSA_SIG_get0(sig, &sig_r, &sig_s);

    if (BN_is_zero(sig_s) || BN_is_zero(sig_r) ||
        (BN_cmp(sig_s, order) >= 1) || (BN_cmp(sig_r, order) >= 1)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, GOST_R_SIGNATURE_PARTS_GREATER_THAN_Q);
        goto err;

    }

    OPENSSL_assert(dgst_len == 32 || dgst_len == 64);
    md = BN_lebin2bn(dgst, dgst_len, NULL);
    if (!md || !BN_mod(e, md, order, ctx)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef DEBUG_SIGN
    fprintf(stderr, "digest as bignum: ");
    BN_print_fp(stderr, md);
    fprintf(stderr, "\ndigest mod q: ");
    BN_print_fp(stderr, e);
#endif
    if (BN_is_zero(e) && !BN_one(e)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    v = BN_mod_inverse(v, e, order, ctx);
    if (!v || !BN_mod_mul(z1, sig_s, v, order, ctx)
        || !BN_sub(tmp, order, sig_r)
        || !BN_mod_mul(z2, tmp, v, order, ctx)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef DEBUG_SIGN
    fprintf(stderr, "\nInverted digest value: ");
    BN_print_fp(stderr, v);
    fprintf(stderr, "\nz1: ");
    BN_print_fp(stderr, z1);
    fprintf(stderr, "\nz2: ");
    BN_print_fp(stderr, z2);
#endif
    C = EC_POINT_new(group);
    if (!C) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!gost_ec_point_mul(group, C, z1, pub_key, z2, ctx)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_get_affine_coordinates(group, C, X, NULL, ctx)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (!BN_mod(R, X, order, ctx)) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef DEBUG_SIGN
    fprintf(stderr, "\nX=");
    BN_print_fp(stderr, X);
    fprintf(stderr, "\nX mod q=");
    BN_print_fp(stderr, R);
    fprintf(stderr, "\n");
#endif
    if (BN_cmp(R, sig_r) != 0) {
        GOSTerr(GOST_F_GOST_EC_VERIFY, GOST_R_SIGNATURE_MISMATCH);
    } else {
        ok = 1;
    }
 err:
    if (C)
        EC_POINT_free(C);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (md)
        BN_free(md);
    return ok;
}

/*
 * Computes GOST R 34.10-2001 public key
 * or GOST R 34.10-2012 public key
 *
 */
int gost_ec_compute_public(EC_KEY *ec)
{
    const EC_GROUP *group = (ec) ? EC_KEY_get0_group(ec) : NULL;
    EC_POINT *pub_key = NULL;
    const BIGNUM *priv_key = NULL;
    BN_CTX *ctx = NULL;
    int ok = 0;

    if (!group) {
        GOSTerr(GOST_F_GOST_EC_COMPUTE_PUBLIC, GOST_R_KEY_IS_NOT_INITIALIZED);
        return 0;
    }

    ctx = BN_CTX_secure_new();
    if (!ctx) {
        GOSTerr(GOST_F_GOST_EC_COMPUTE_PUBLIC, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    BN_CTX_start(ctx);
    priv_key = EC_KEY_get0_private_key(ec);
    if (!priv_key) {
        GOSTerr(GOST_F_GOST_EC_COMPUTE_PUBLIC, ERR_R_EC_LIB);
        goto err;
    }

    pub_key = EC_POINT_new(group);
    if (!pub_key) {
        GOSTerr(GOST_F_GOST_EC_COMPUTE_PUBLIC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!gost_ec_point_mul(group, pub_key, priv_key, NULL, NULL, ctx)) {
        GOSTerr(GOST_F_GOST_EC_COMPUTE_PUBLIC, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_KEY_set_public_key(ec, pub_key)) {
        GOSTerr(GOST_F_GOST_EC_COMPUTE_PUBLIC, ERR_R_EC_LIB);
        goto err;
    }
    ok = 1;
 err:
    if (pub_key)
        EC_POINT_free(pub_key);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

int gost_ec_point_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
                      const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx)
{
    if (group == NULL || r == NULL || ctx == NULL)
        return 0;

    if (m != NULL && n != NULL) {
        /* verification */
        if (q == NULL)
            return 0;
        switch(EC_GROUP_get_curve_name(group)) {
            case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
            case NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetB:
                return point_mul_two_id_GostR3410_2001_CryptoPro_A_ParamSet(group, r, n, q, m, ctx);
            case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetC:
                return point_mul_two_id_GostR3410_2001_CryptoPro_B_ParamSet(group, r, n, q, m, ctx);
            case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
            case NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetD:
                return point_mul_two_id_GostR3410_2001_CryptoPro_C_ParamSet(group, r, n, q, m, ctx);
            case NID_id_GostR3410_2001_TestParamSet:
                return point_mul_two_id_GostR3410_2001_TestParamSet(group, r, n, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_256_paramSetA:
                return point_mul_two_id_tc26_gost_3410_2012_256_paramSetA(group, r, n, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetA:
                return point_mul_two_id_tc26_gost_3410_2012_512_paramSetA(group, r, n, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetB:
                return point_mul_two_id_tc26_gost_3410_2012_512_paramSetB(group, r, n, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetC:
                return point_mul_two_id_tc26_gost_3410_2012_512_paramSetC(group, r, n, q, m, ctx);
            default:
                return EC_POINT_mul(group, r, n, q, m, ctx);
        }
    } else if (n != NULL) {
        /* mul g */
        switch(EC_GROUP_get_curve_name(group)) {
            case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
            case NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetB:
                return point_mul_g_id_GostR3410_2001_CryptoPro_A_ParamSet(group, r, n, ctx);
            case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetC:
                return point_mul_g_id_GostR3410_2001_CryptoPro_B_ParamSet(group, r, n, ctx);
            case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
            case NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetD:
                return point_mul_g_id_GostR3410_2001_CryptoPro_C_ParamSet(group, r, n, ctx);
            case NID_id_GostR3410_2001_TestParamSet:
                return point_mul_g_id_GostR3410_2001_TestParamSet(group, r, n, ctx);
            case NID_id_tc26_gost_3410_2012_256_paramSetA:
                return point_mul_g_id_tc26_gost_3410_2012_256_paramSetA(group, r, n, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetA:
                return point_mul_g_id_tc26_gost_3410_2012_512_paramSetA(group, r, n, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetB:
                return point_mul_g_id_tc26_gost_3410_2012_512_paramSetB(group, r, n, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetC:
                return point_mul_g_id_tc26_gost_3410_2012_512_paramSetC(group, r, n, ctx);
            default:
                return EC_POINT_mul(group, r, n, q, m, ctx);
        }
    } else if (m != NULL) {
        if (q == NULL)
            return 0;
        /* mul */
        switch(EC_GROUP_get_curve_name(group)) {
            case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
            case NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetB:
                return point_mul_id_GostR3410_2001_CryptoPro_A_ParamSet(group, r, q, m, ctx);
            case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetC:
                return point_mul_id_GostR3410_2001_CryptoPro_B_ParamSet(group, r, q, m, ctx);
            case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
            case NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet:
            case NID_id_tc26_gost_3410_2012_256_paramSetD:
                return point_mul_id_GostR3410_2001_CryptoPro_C_ParamSet(group, r, q, m, ctx);
            case NID_id_GostR3410_2001_TestParamSet:
                return point_mul_id_GostR3410_2001_TestParamSet(group, r, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_256_paramSetA:
                return point_mul_id_tc26_gost_3410_2012_256_paramSetA(group, r, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetA:
                return point_mul_id_tc26_gost_3410_2012_512_paramSetA(group, r, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetB:
                return point_mul_id_tc26_gost_3410_2012_512_paramSetB(group, r, q, m, ctx);
            case NID_id_tc26_gost_3410_2012_512_paramSetC:
                return point_mul_id_tc26_gost_3410_2012_512_paramSetC(group, r, q, m, ctx);
            default:
                return EC_POINT_mul(group, r, n, q, m, ctx);
        }
    }
    return 0;
}

/*
 *
 * Generates GOST R 34.10-2001
 * or GOST R 34.10-2012 keypair
 *
 */
int gost_ec_keygen(EC_KEY *ec)
{
    BIGNUM *order = NULL, *d = NULL;
    const EC_GROUP *group = (ec) ? EC_KEY_get0_group(ec) : NULL;
    int ok = 0;

    if (!group) {
        GOSTerr(GOST_F_GOST_EC_KEYGEN, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    order = BN_new();
    d = BN_secure_new();
    if (!order || !d) {
        GOSTerr(GOST_F_GOST_EC_KEYGEN, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!EC_GROUP_get_order(group, order, NULL)) {
        GOSTerr(GOST_F_GOST_EC_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    do {
        if (!BN_rand_range(d, order)) {
            GOSTerr(GOST_F_GOST_EC_KEYGEN, GOST_R_RNG_ERROR);
            goto end;
        }
    }
    while (BN_is_zero(d));

    if (!EC_KEY_set_private_key(ec, d)) {
        GOSTerr(GOST_F_GOST_EC_KEYGEN, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    ok = 1;
 end:
    if (d)
        BN_free(d);
    if (order)
        BN_free(order);

    return (ok) ? gost_ec_compute_public(ec) : 0;
}

int gost_ec_oct2point(const EC_GROUP *group, EC_POINT *point,
                      const unsigned char *buf, size_t len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *x, *y, *p;
    size_t field_len, enc_len;
    int ret = 0;
    
    if (len == 0) {
        GOSTerr(GOST_F_GOST_EC_OCT2POINT, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    field_len = (EC_GROUP_get_degree(group) + 7) / 8;
    enc_len = 2 * field_len;

    if (len != enc_len) {
        GOSTerr(GOST_F_GOST_EC_OCT2POINT, EC_R_INVALID_ENCODING);
        return 0;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    if (!EC_GROUP_get_curve(group, p, NULL, NULL, NULL))
        goto err;

    if (!BN_lebin2bn(buf, field_len, x))
        goto err;
    if (BN_ucmp(x, p) >= 0) {
        GOSTerr(GOST_F_GOST_EC_OCT2POINT, EC_R_INVALID_ENCODING);
        goto err;
    }

    if (!BN_lebin2bn(buf + field_len, field_len, y))
        goto err;
    if (BN_ucmp(y, p) >= 0) {
        GOSTerr(GOST_F_GOST_EC_OCT2POINT, EC_R_INVALID_ENCODING);
        goto err;
    }

    /*
    * EC_POINT_set_affine_coordinates is responsible for checking that
    * the point is on the curve.
    */
    if (!EC_POINT_set_affine_coordinates(group, point, x, y, ctx))
        goto err;

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}


size_t gost_ec_point2oct(const EC_GROUP *group, const EC_POINT *point,
                         unsigned char *buf, size_t len)
{
    size_t ret;
    BN_CTX *ctx = NULL;
    int used_ctx = 0;
    BIGNUM *x, *y;
    size_t field_len;

    field_len = (EC_GROUP_get_degree(group) + 7) / 8;
    ret = 2 * field_len;

    if (buf != NULL) {
        if (len < ret) {
            GOSTerr(GOST_F_GOST_EC_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
            goto err;
        }

        ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;

        BN_CTX_start(ctx);
        used_ctx = 1;
        x = BN_CTX_get(ctx);
        y = BN_CTX_get(ctx);
        if (y == NULL)
            goto err;

        if (!EC_POINT_get_affine_coordinates(group, point, x, y, ctx))
            goto err;

        if (BN_bn2lebinpad(x, buf, field_len) != field_len
            || BN_bn2lebinpad(y, buf + field_len, field_len) != field_len)
        goto err;
    }

    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
    
  err:
    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}

size_t gost_ec_key2buf(const EC_KEY *key, unsigned char **pbuf)
{
    size_t len;
    unsigned char *buf;
    const EC_GROUP *grp = NULL;
    const EC_POINT *pkey = NULL;
    
    pkey = EC_KEY_get0_public_key(key);
    grp = EC_KEY_get0_group(key);

    if(pkey == NULL || grp == NULL)
        return 0;

    len = gost_ec_point2oct(grp, pkey, NULL, 0);
    if (len == 0)
        return 0;
    if ((buf = OPENSSL_malloc(len)) == NULL) {
        GOSTerr(GOST_F_GOST_EC_KEY2BUF, ERR_R_MALLOC_FAILURE); 
        return 0;
    }
    len = gost_ec_point2oct(grp, pkey, buf, len);
    if (len == 0) {
        OPENSSL_free(buf);
        return 0;
    }
    *pbuf = buf;
    return len;
}

int gost_ec_oct2key(EC_KEY *key, const unsigned char *buf, size_t len)
{
    const EC_GROUP *group = NULL;
    const EC_POINT *pub_key = NULL;
    EC_POINT *point = NULL;
    int ok = 0;
    
    if (key == NULL || (group = EC_KEY_get0_group(key)) == NULL)
        return 0;

    if ((pub_key = EC_KEY_get0_public_key(key)) == NULL) {
        if((point = EC_POINT_new(group)) == NULL ||
           !EC_KEY_set_public_key(key, point))
           goto err;
        pub_key = EC_KEY_get0_public_key(key);
    }
        
    if (gost_ec_oct2point(group, (EC_POINT *)pub_key, buf, len) == 0)
        goto err;

    ok = 1;

 err:
    if (point)
        EC_POINT_free(point);
    return ok;
}
