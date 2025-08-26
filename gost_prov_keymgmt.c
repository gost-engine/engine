#include <openssl/ec.h>
#include <openssl/core_names.h>
#include "gost_prov.h"
#include "gost_lcl.h"

#define PARAMSET_NID "paramset_nid"

#define GOST_MAX(X, Y) ((X) > (Y) ? (X) : (Y))

/*
 * Forward declarations of all generic OSSL_DISPATCH functions, to make sure
 * they are correctly defined further down.  For the algorithm specific ones
 * MAKE_FUNCTIONS() does it for us.
 */
static OSSL_FUNC_keymgmt_set_params_fn keymgmt_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn keymgmt_settable_params;
static OSSL_FUNC_keymgmt_gen_set_params_fn keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_fn keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_has_fn keymgmt_has;
static OSSL_FUNC_keymgmt_get_params_fn keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_gen_get_params_fn keymgmt_gen_get_params;
static OSSL_FUNC_keymgmt_gen_gettable_params_fn keymgmt_gen_gettable_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_load_fn keymgmt_load;
static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_gost2001_operation_name;
static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_gost2012_256_operation_name;
static OSSL_FUNC_keymgmt_query_operation_name_fn keymgmt_gost2012_512_operation_name;
static OSSL_FUNC_keymgmt_validate_fn keymgmt_validate;

typedef struct gost_gen_ctx_st {
    int type;
    int sign_param_nid;
    int selection;
} GOST_GEN_CTX;

static const char *keymgmt_gost2012_256_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return SN_id_GostR3410_2012_256;
    case OSSL_OP_KEYEXCH:
        return "ECDHE";
    default:
        return NULL;
    }
}

static const char *keymgmt_gost2012_512_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return SN_id_GostR3410_2012_512;
    case OSSL_OP_KEYEXCH:
        return "ECDHE";
    default:
        return NULL;
    }
}

static const char *keymgmt_gost2001_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_SIGNATURE)
        return SN_id_GostR3410_2001;
    return NULL;
}

static void *keymgmt_new(void *vprovctx, int type)
{
    GOST_KEY_DATA *key_data = NULL;

    key_data = OPENSSL_zalloc(sizeof(GOST_KEY_DATA));
    if (!key_data)
        return NULL;

    key_data->type = type;
    key_data->param_nid = NID_undef;
    key_data->ec = EC_KEY_new();
    if (!key_data->ec) {
        OPENSSL_free(key_data);
        return NULL;
    }

    return key_data;
}

void keymgmt_free(void *vkctx)
{
    GOST_KEY_DATA *key_data = vkctx;

    if (!key_data)
        return;
    EC_KEY_free(key_data->ec);
    OPENSSL_free(key_data);
}

static int keymgmt_has(const void *vkctx, int selection)
{
    const GOST_KEY_DATA *key_data = vkctx;
    int ok = 1;

    if (!vkctx)
        return !ok;

    if (!FLAGS_INTERSECT(selection, OSSL_KEYMGMT_SELECT_ALL))
        return ok;

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        ok = ok && (EC_KEY_get0_public_key(key_data->ec) != NULL);

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        ok = ok && (EC_KEY_get0_private_key(key_data->ec) != NULL);

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
        ok = ok && (EC_KEY_get0_group(key_data->ec) != NULL);

    return ok;
}

static void *keymgmt_load(const void *reference, size_t reference_sz)
{
    GOST_KEY_DATA *key_data = NULL;

    if (!reference)
        return NULL;

    if (reference_sz != sizeof(key_data))
        return NULL;

    key_data = *(GOST_KEY_DATA **)reference;

    /* Questionable hack of changing the constant value by pointer */
    *(GOST_KEY_DATA **)reference = NULL;

    return key_data;
}

static void keymgmt_gen_cleanup(void *genctx)
{
    if (!genctx)
        return;

    GOST_GEN_CTX *gctx = genctx;
    OPENSSL_free(gctx);
}

void *keymgmt_gen_init(int selection, const OSSL_PARAM params[], int type)
{
    if (!FLAGS_INTERSECT(selection, OSSL_KEYMGMT_SELECT_ALL))
        return NULL;

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        && !FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return NULL;

    GOST_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(GOST_GEN_CTX));
    if (!gctx)
        return NULL;

    gctx->type = type;
    gctx->selection = selection;
    gctx->sign_param_nid = NID_undef;

    if (params && !keymgmt_gen_set_params(gctx, params)) {
        keymgmt_gen_cleanup(gctx);
        return NULL;
    }

    return gctx;
}

/*
 * The callback arguments (osslcb & cbarg) are not used by EC_KEY generation
 */
static void *keymgmt_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    GOST_GEN_CTX *gctx = genctx;
    GOST_KEY_DATA *key_data = NULL;

    if (!gctx)
        goto end;

    if (gctx->sign_param_nid == NID_undef)
        goto end;

    key_data = OPENSSL_zalloc(sizeof(GOST_KEY_DATA));
    if (!key_data)
        goto end;

    key_data->type = gctx->type;
    key_data->param_nid = gctx->sign_param_nid;

    key_data->ec = internal_ec_paramgen(key_data->param_nid);
    if (!key_data->ec)
        goto end;

    if (FLAGS_CONTAIN(gctx->selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        && !gost_ec_keygen(key_data->ec))
        goto end;

    return key_data;

end:
    keymgmt_free(key_data);
    return NULL;
}

static const OSSL_PARAM known_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keymgmt_settable_params(void *provctx)
{
    return known_settable_params;
}

static int set_encoded_key(GOST_KEY_DATA *key_data, const OSSL_PARAM *p)
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *x = NULL, *y = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);
    const unsigned char *pub_key_buf = NULL;
    size_t pub_key_buflen = 0;

    if (!group)
        goto end;

    if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pub_key_buf, &pub_key_buflen))
        goto end;

    size_t coord_len = pub_key_buflen / 2;
    if (pub_key_buflen % 2 != 0 || coord_len == 0)
        goto end;

    ctx = BN_CTX_new();
    if (!ctx)
        goto end;
    BN_CTX_start(ctx);

    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (!x || !y)
        goto end;

    if (!BN_lebin2bn(pub_key_buf, coord_len, x))
        goto end;
    if (!BN_lebin2bn(pub_key_buf + coord_len, coord_len, y))
        goto end;

    point = EC_POINT_new(group);
    if (!point)
        goto end;

    if (!EC_POINT_set_affine_coordinates(group, point, x, y, ctx))
        goto end;
    if (!EC_KEY_set_public_key(key_data->ec, point))
        goto end;

    ret = 1;

end:
    EC_POINT_free(point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

static int keymgmt_set_params(void *key, const OSSL_PARAM params[])
{
    if (key == NULL)
        return 0;
    if (params == NULL)
        return 1;

    GOST_KEY_DATA *key_data = key;
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);

    if (p != NULL && !set_encoded_key(key_data, p))
        return 0;

    return 1;
}

const OSSL_PARAM *keymgmt_gen_settable_params(void *genctx, void *provctx)
{
    static const OSSL_PARAM settable_params[] = {
        OSSL_PARAM_utf8_string(param_ctrl_string, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };

    return settable_params;
}

static int keygmgmt_gen_set_paramset_param(GOST_GEN_CTX *genctx, const OSSL_PARAM *param)
{
    int result = 0;
    const char *paramset = NULL;

    if (!OSSL_PARAM_get_utf8_string_ptr(param, &paramset))
        goto exit;

    int sign_param_nid = NID_undef;

    switch (genctx->type) {
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2001DH:
    case NID_id_GostR3410_2012_256:
        result = internal_param_str_to_nid_256(paramset, &sign_param_nid);
        break;
    case NID_id_GostR3410_2012_512:
        result = internal_param_str_to_nid_512(paramset, &sign_param_nid);
        break;
    }

    if (!result)
        goto exit;

    genctx->sign_param_nid = sign_param_nid;

exit:
    return result;
}

int keymgmt_gen_set_params(void *p0, const OSSL_PARAM params[])
{
    GOST_GEN_CTX *gctx = p0;

    if (!gctx)
        return 0;
    if (!params)
        return 1;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, param_ctrl_string);
    if (p != NULL && !keygmgmt_gen_set_paramset_param(gctx, p))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL && !keygmgmt_gen_set_paramset_param(gctx, p))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *keymgmt_gettable_params(void *provctx)
{
    return known_gettable_params;
}

static int get_encoded_key(const GOST_KEY_DATA *key_data, OSSL_PARAM *p)
{
    BN_CTX *ctx = NULL;
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *buf = NULL;
    int ret = 0;
    const EC_POINT *pub = EC_KEY_get0_public_key(key_data->ec);
    const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);

    if (!pub || !group)
        goto end;

    ctx = BN_CTX_new();
    if (!ctx)
        goto end;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (!x || !y)
        goto end;

    if (!EC_POINT_get_affine_coordinates(group, pub, x, y, ctx))
        goto end;

    int field_size = (EC_GROUP_get_degree(group) + 7) / 8;
    buf = OPENSSL_zalloc(2 * field_size);
    if (!buf)
        goto end;

    if (BN_bn2lebinpad(x, buf, field_size) != field_size ||
        BN_bn2lebinpad(y, buf + field_size, field_size) != field_size)
        goto end;

    if (!OSSL_PARAM_set_octet_string(p, buf, 2 * field_size))
        goto end;

    ret = 1;

end:
    OPENSSL_free(buf);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

static int get_bits(GOST_KEY_DATA *key_data, OSSL_PARAM *p)
{
    const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);

    if (!group)
        return 0;
    return OSSL_PARAM_set_int(p, EC_GROUP_get_degree(group));
}

static int get_security_bits(GOST_KEY_DATA *key_data, OSSL_PARAM *p)
{
    const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);

    if (!group)
        return 0;

    int sec_bits = EC_GROUP_get_degree(group) >> 1;
    return OSSL_PARAM_set_int(p, sec_bits);
}

static int get_default_digest_name(const GOST_KEY_DATA *key_data, OSSL_PARAM *p)
{
    const char *digest = NULL;

    switch (key_data->type) {
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2001DH:
        digest = SN_id_GostR3411_94;
        break;

    case NID_id_GostR3410_2012_256:
        digest = SN_id_GostR3411_2012_256;
        break;

    case NID_id_GostR3410_2012_512:
        digest = SN_id_GostR3411_2012_512;
        break;

    default:
        return 0;
    }

    return OSSL_PARAM_set_utf8_string(p, digest);
}

static int get_max_size(const GOST_KEY_DATA *key_data, OSSL_PARAM *p)
{
    int max_signature_size =  gost_get_max_signature_size(key_data);

    if (max_signature_size == -1)
        return 0;

    int size = GOST_MAX(max_signature_size, gost_get_max_keyexch_size(key_data));

    return OSSL_PARAM_set_int(p, size);
}

static int keymgmt_get_params(void *key, OSSL_PARAM params[])
{
    if (key == NULL)
        return 0;
    if (params == NULL)
        return 1;

    GOST_KEY_DATA *key_data = key;
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p && !get_max_size(key_data, p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p && !get_encoded_key(key_data, p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p && !get_bits(key_data, p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p && !get_security_bits(key_data, p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p && !get_default_digest_name(key_data, p))
        return 0;

    return 1;
}

static int keymgmt_gen_get_params(void *genctx, OSSL_PARAM params[])
{
    int ret = 0;

    if (!genctx || !params)
        goto end;

    GOST_GEN_CTX *gctx = genctx;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, PARAMSET_NID);
    if (p != NULL && !OSSL_PARAM_set_int(p, gctx->sign_param_nid))
        goto end;

    ret = 1;

end:
    return ret;
}

const OSSL_PARAM *keymgmt_gen_gettable_params(void *provctx, void *unused)
{
    static const OSSL_PARAM gettable_params[] = {
        OSSL_PARAM_int(PARAMSET_NID, NULL),
        OSSL_PARAM_END
    };
    return gettable_params;
}

void *keymgmt_dup(const void *src, int selection)
{
    const GOST_KEY_DATA *src_data = src;
    GOST_KEY_DATA *dst = NULL;

    if (!src_data || !src_data->ec)
        goto err;
    if (!FLAGS_INTERSECT(selection, OSSL_KEYMGMT_SELECT_ALL))
        goto err;
    dst = OPENSSL_zalloc(sizeof(GOST_KEY_DATA));
    if (!dst)
        goto err;

    dst->type = src_data->type;
    dst->param_nid = src_data->param_nid;

    dst->ec = EC_KEY_new();
    if (!dst->ec)
        goto err;

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) {
        const EC_GROUP *group = EC_KEY_get0_group(src_data->ec);

        if (!group || !EC_KEY_set_group(dst->ec, group))
            goto err;
    }

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        const EC_POINT *pub = EC_KEY_get0_public_key(src_data->ec);
        const EC_GROUP *group = EC_KEY_get0_group(dst->ec);

        if (!pub || !group || !EC_KEY_set_public_key(dst->ec, pub))
            goto err;
    }

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        const BIGNUM *priv = EC_KEY_get0_private_key(src_data->ec);
        const EC_GROUP *group = EC_KEY_get0_group(dst->ec);

        if (!priv || !group || !EC_KEY_set_private_key(dst->ec, priv))
            goto err;
    }

    return dst;

err:
    keymgmt_free(dst);
    return NULL;
}

int keymgmt_match(const void *vkctx1, const void *vkctx2, int selection)
{
    GOST_KEY_DATA *key_data1 = (GOST_KEY_DATA *)vkctx1;
    GOST_KEY_DATA *key_data2 = (GOST_KEY_DATA *)vkctx2;
    int ok = 1;

    if (!key_data1 || !key_data2 || !key_data1->ec || !key_data2->ec)
        return 0;

    if (!FLAGS_INTERSECT(selection, OSSL_KEYMGMT_SELECT_ALL))
        return 1;

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        const EC_POINT *pub_key1 = EC_KEY_get0_public_key(key_data1->ec);
        const EC_POINT *pub_key2 = EC_KEY_get0_public_key(key_data2->ec);
        const EC_GROUP *group1 = EC_KEY_get0_group(key_data1->ec);
        const EC_GROUP *group2 = EC_KEY_get0_group(key_data2->ec);

        if (!pub_key1 || !pub_key2 || !group1 || !group2)
            return 0;

        if (EC_GROUP_cmp(group1, group2, NULL) != 0)
            return 0;

        ok = ok && (EC_POINT_cmp(group1, pub_key1, pub_key2, NULL) == 0);
    }

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        const BIGNUM *priv_key1 = EC_KEY_get0_private_key(key_data1->ec);
        const BIGNUM *priv_key2 = EC_KEY_get0_private_key(key_data2->ec);

        if (!priv_key1 || !priv_key2)
            return 0;

        ok = ok && (BN_cmp(priv_key1, priv_key2) == 0);
    }

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) {
        const EC_GROUP *group1 = EC_KEY_get0_group(key_data1->ec);
        const EC_GROUP *group2 = EC_KEY_get0_group(key_data2->ec);

        if (!group1 || !group2)
            return 0;

        ok = ok && (EC_GROUP_cmp(group1, group2, NULL) == 0);
    }

    return ok;
}

int gost_key_public_check(const EC_POINT *pub_key, const EC_GROUP *group)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *p = NULL;
    BIGNUM *order = NULL;
    BN_CTX *ctx = NULL;
    int ret = 0;

    ctx = BN_CTX_new();
    if (!ctx)
        goto exit;

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);

    if (!p || !x || !y || !order)
        goto exit;

    if (EC_POINT_is_at_infinity(group, pub_key))
        goto exit;

    if (!EC_POINT_get_affine_coordinates(group, pub_key, x, y, NULL))
        goto exit;

    if (!EC_GROUP_get_curve(group, p, NULL, NULL, NULL))
        goto exit;

    if (BN_cmp(x, p) >= 0 || BN_cmp(y, p) >= 0)
        goto exit;

    if (EC_POINT_is_on_curve(group, pub_key, NULL) <= 0)
        goto exit;

    if (EC_GROUP_get_order(group, order, NULL) == 0)
        goto exit;

    if (BN_cmp(order, BN_value_one()) <= 0)
        goto exit;

    ret = 1;
exit:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

static int keymgmt_validate(const void *vkctx, int selection, int checktype)
{
    GOST_KEY_DATA *key_data = (GOST_KEY_DATA *)vkctx;

    if (!key_data || !key_data->ec)
        return 0;

    if (!FLAGS_INTERSECT(selection, OSSL_KEYMGMT_SELECT_ALL))
        return 1;

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) {
        const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);

        if (!group || !EC_GROUP_check(group, NULL))
            return 0;
    }
    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        const EC_POINT *pub_key = EC_KEY_get0_public_key(key_data->ec);
        const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);

        if (!pub_key || !group || !gost_key_public_check(pub_key, group))
            return 0;
    }

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        const BIGNUM *priv_key = EC_KEY_get0_private_key(key_data->ec);
        const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);

        if (!priv_key || !group)
            return 0;

        BIGNUM *order = BN_new();
        if (!order
            || !EC_GROUP_get_order(group, order, NULL)
            || !((BN_cmp(priv_key, BN_value_one()) >= 0) && (BN_cmp(priv_key, order) < 0))) {
            BN_free(order);
            return 0;
        }

        BN_free(order);
    }

    if (FLAGS_CONTAIN(selection, OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        const EC_POINT *pub_key = EC_KEY_get0_public_key(key_data->ec);
        const BIGNUM *priv_key = EC_KEY_get0_private_key(key_data->ec);
        const EC_GROUP *group = EC_KEY_get0_group(key_data->ec);

        if (!pub_key || !priv_key || !group)
            return 0;

        EC_POINT *tmp_pub_key = EC_POINT_new(group);
        if (!tmp_pub_key
            || !EC_POINT_mul(group, tmp_pub_key,
                             priv_key, NULL, NULL, NULL)
            || EC_POINT_cmp(group, pub_key, tmp_pub_key, NULL)) {
            EC_POINT_free(tmp_pub_key);
            return 0;
        }

        EC_POINT_free(tmp_pub_key);
    }

    return 1;
}

static int keymgmt_gen_set_template(void *genctx, void *template)
{
    GOST_GEN_CTX *gctx = genctx;
    GOST_KEY_DATA *template_key_data = template;

    if (!genctx || !template)
        return 0;

    if (gctx->type != template_key_data->type)
        return 0;

    gctx->sign_param_nid = template_key_data->param_nid;
    return 1;
}

typedef void (*fptr_t)(void);
#define MAKE_KEYMGMT_FUNCTIONS(alg, type, operation_name_fn)                                   \
    static OSSL_FUNC_keymgmt_gen_init_fn alg##_gen_init;                                       \
    static void *alg##_gen_init(void *provctx, int selection, const OSSL_PARAM params[])       \
    {                                                                                          \
        return keymgmt_gen_init(selection, params, type);                                      \
    }                                                                                          \
    static OSSL_FUNC_keymgmt_new_fn alg##_new;                                                 \
    static void *alg##_new(void *provctx)                                                      \
    {                                                                                          \
        return keymgmt_new(provctx, type);                                                     \
    }                                                                                          \
    static const OSSL_DISPATCH id_##alg##_keymgmt_functions[] = {                              \
        { OSSL_FUNC_KEYMGMT_NEW, (fptr_t)alg##_new},                                           \
        { OSSL_FUNC_KEYMGMT_FREE, (fptr_t)keymgmt_free },                                      \
        { OSSL_FUNC_KEYMGMT_HAS, (fptr_t)keymgmt_has },                                        \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (fptr_t)alg##_gen_init },                                \
        { OSSL_FUNC_KEYMGMT_GEN, (fptr_t)keymgmt_gen },                                        \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (fptr_t)keymgmt_gen_cleanup },                        \
        { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (fptr_t)keymgmt_gen_set_template},               \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (fptr_t)keymgmt_set_params },                          \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (fptr_t)keymgmt_settable_params },                \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (fptr_t)keymgmt_gen_set_params },                  \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (fptr_t)keymgmt_gen_settable_params },        \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (fptr_t)keymgmt_get_params},                           \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (fptr_t)keymgmt_gettable_params},                 \
        { OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (fptr_t)keymgmt_gen_get_params},                   \
        { OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (fptr_t)keymgmt_gen_gettable_params},         \
        { OSSL_FUNC_KEYMGMT_LOAD, (fptr_t)keymgmt_load},                                       \
        { OSSL_FUNC_KEYMGMT_MATCH, (fptr_t)keymgmt_match},                                     \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (fptr_t)keymgmt_validate},                               \
        { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (fptr_t)operation_name_fn},                  \
        { OSSL_FUNC_KEYMGMT_DUP, (fptr_t)keymgmt_dup},                                         \
        OSSL_DISPATCH_END                                                                      \
    };

MAKE_KEYMGMT_FUNCTIONS(gost2001, NID_id_GostR3410_2001, keymgmt_gost2001_operation_name);
MAKE_KEYMGMT_FUNCTIONS(gost2001dh, NID_id_GostR3410_2001DH, NULL);
MAKE_KEYMGMT_FUNCTIONS(gost2012_256, NID_id_GostR3410_2012_256,
                       keymgmt_gost2012_256_operation_name);
MAKE_KEYMGMT_FUNCTIONS(gost2012_512, NID_id_GostR3410_2012_512,
                       keymgmt_gost2012_512_operation_name);

/* The OSSL_ALGORITHM for the provider's operation query function */
const OSSL_ALGORITHM GOST_prov_keymgmt[] = {
    { ALG_NAME_GOST2001, NULL, id_gost2001_keymgmt_functions },
    { ALG_NAME_GOST2001DH, NULL, id_gost2001dh_keymgmt_functions },
    { ALG_NAME_GOST2012_256, NULL, id_gost2012_256_keymgmt_functions },
    { ALG_NAME_GOST2012_512, NULL, id_gost2012_512_keymgmt_functions },
    { NULL, NULL, NULL }
};