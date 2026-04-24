#include "gost_eng_pmeth.h"

#include <string.h>
#include <stdlib.h>

#include <openssl/objects.h>
#include <openssl/x509v3.h>

#include "gost_lcl.h"
#include "gost_pmeth.h"
#include "e_gost_err.h"

static int pkey_gost_mac_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
    struct gost_mac_pmeth_data* data =
        (struct gost_mac_pmeth_data*)EVP_PKEY_CTX_get_data(ctx);

    switch (type) {
    case EVP_PKEY_CTRL_MD:
    {
        int nid = EVP_MD_type((const EVP_MD*)p2);
        if (nid != NID_id_Gost28147_89_MAC && nid != NID_gost_mac_12) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL,
                GOST_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        data->md = (EVP_MD*)p2;
        return 1;
    }

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD**)p2 = data->md;
        return 1;

    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
        return 1;
    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if (p1 != 32) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL, GOST_R_INVALID_MAC_KEY_LENGTH);
            return 0;
        }

        memcpy(data->key, p2, 32);
        data->key_set = 1;
        return 1;
    case EVP_PKEY_CTRL_GOST_PARAMSET:
    {
        struct gost_cipher_info* param = p2;
        data->mac_param_nid = param->nid;
        return 1;
    }
    case EVP_PKEY_CTRL_DIGESTINIT:
    {
        EVP_MD_CTX* mctx = p2;
        if (!data->key_set) {
            struct gost_mac_key* key;
            EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
            if (!pkey) {
                GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL,
                    GOST_R_MAC_KEY_NOT_SET);
                return 0;
            }
            key = EVP_PKEY_get0(pkey);
            if (!key) {
                GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL,
                    GOST_R_MAC_KEY_NOT_SET);
                return 0;
            }
            return EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(mctx))
                (mctx, EVP_MD_CTRL_SET_KEY, 0, key);
        }
        else {
            return EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(mctx))
                (mctx, EVP_MD_CTRL_SET_KEY, 32, &(data->key));
        }
    }
    case EVP_PKEY_CTRL_MAC_LEN:
    {
        if (p1 < 1 || p1 > 8) {

            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL, GOST_R_INVALID_MAC_SIZE);
            return 0;
        }
        data->mac_size = p1;
        return 1;
    }
    }
    return -2;
}

static int pkey_gost_mac_ctrl_str(EVP_PKEY_CTX* ctx,
    const char* type, const char* value)
{
    if (strcmp(type, key_ctrl_string) == 0) {
        if (strlen(value) != 32) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR,
                GOST_R_INVALID_MAC_KEY_LENGTH);
            return 0;
        }
        return pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY,
            32, (char*)value);
    }
    if (strcmp(type, hexkey_ctrl_string) == 0) {
        long keylen;
        int ret;
        unsigned char* keybuf = string_to_hex(value, &keylen);
        if (!keybuf || keylen != 32) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR,
                GOST_R_INVALID_MAC_KEY_LENGTH);
            OPENSSL_free(keybuf);
            return 0;
        }
        ret = pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, 32, keybuf);
        OPENSSL_free(keybuf);
        return ret;

    }
    if (!strcmp(type, maclen_ctrl_string)) {
        char* endptr;
        long size = strtol(value, &endptr, 10);
        if (*endptr != '\0') {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR, GOST_R_INVALID_MAC_SIZE);
            return 0;
        }
        return pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_MAC_LEN, size, NULL);
    }
    if (strcmp(type, param_ctrl_string) == 0) {
        ASN1_OBJECT* obj = OBJ_txt2obj(value, 0);
        const struct gost_cipher_info* param = NULL;
        if (obj == NULL) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR, GOST_R_INVALID_MAC_PARAMS);
            return 0;
        }

        param = get_encryption_params(obj);
        ASN1_OBJECT_free(obj);
        if (param == NULL) {
            GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR, GOST_R_INVALID_MAC_PARAMS);
            return 0;
        }


        return pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_GOST_PARAMSET, 0,
            (void*)param);
    }
    return -2;
}

static int pkey_gost_omac_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2, size_t max_size)
{
    struct gost_mac_pmeth_data* data =
        (struct gost_mac_pmeth_data*)EVP_PKEY_CTX_get_data(ctx);

    switch (type) {
    case EVP_PKEY_CTRL_MD:
    {
        int nid = EVP_MD_type((const EVP_MD*)p2);
        if (nid != NID_magma_mac && nid != NID_grasshopper_mac
            && nid != NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac /* FIXME beldmit */
            && nid != NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac) {
            GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL,
                GOST_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        data->md = (EVP_MD*)p2;
        return 1;
    }

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD**)p2 = data->md;
        return 1;

    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
        return 1;
    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if (p1 != 32) {
            GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL, GOST_R_INVALID_MAC_KEY_LENGTH);
            return 0;
        }

        memcpy(data->key, p2, 32);
        data->key_set = 1;
        return 1;
    case EVP_PKEY_CTRL_DIGESTINIT:
    {
        EVP_MD_CTX* mctx = p2;
        if (!data->key_set) {
            struct gost_mac_key* key;
            EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
            if (!pkey) {
                GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL,
                    GOST_R_MAC_KEY_NOT_SET);
                return 0;
            }
            key = EVP_PKEY_get0(pkey);
            if (!key) {
                GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL,
                    GOST_R_MAC_KEY_NOT_SET);
                return 0;
            }
            return EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(mctx))
                (mctx, EVP_MD_CTRL_SET_KEY, 0, key);
        }
        else {
            return EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(mctx))
                (mctx, EVP_MD_CTRL_SET_KEY, 32, &(data->key));
        }
    }
    case EVP_PKEY_CTRL_MAC_LEN:
    {
        if (p1 < 1 || p1 > max_size) {

            GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL, GOST_R_INVALID_MAC_SIZE);
            return 0;
        }
        data->mac_size = p1;
        return 1;
    }
    }
    return -2;
}

static int pkey_gost_magma_mac_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
    return pkey_gost_omac_ctrl(ctx, type, p1, p2, 8);
}

static int pkey_gost_grasshopper_mac_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)
{
    return pkey_gost_omac_ctrl(ctx, type, p1, p2, 16);
}

static int pkey_gost_omac_ctrl_str(EVP_PKEY_CTX* ctx,
    const char* type, const char* value, size_t max_size)
{
    if (strcmp(type, key_ctrl_string) == 0) {
        if (strlen(value) != 32) {
            GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL_STR,
                GOST_R_INVALID_MAC_KEY_LENGTH);
            return 0;
        }
        return pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY,
            32, (char*)value);
    }
    if (strcmp(type, hexkey_ctrl_string) == 0) {
        long keylen;
        int ret;
        unsigned char* keybuf = string_to_hex(value, &keylen);
        if (!keybuf || keylen != 32) {
            GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL_STR,
                GOST_R_INVALID_MAC_KEY_LENGTH);
            OPENSSL_free(keybuf);
            return 0;
        }
        ret = pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, 32, keybuf);
        OPENSSL_free(keybuf);
        return ret;

    }
    if (!strcmp(type, maclen_ctrl_string)) {
        char* endptr;
        long size = strtol(value, &endptr, 10);
        if (*endptr != '\0') {
            GOSTerr(GOST_F_PKEY_GOST_OMAC_CTRL_STR, GOST_R_INVALID_MAC_SIZE);
            return 0;
        }
        return pkey_gost_omac_ctrl(ctx, EVP_PKEY_CTRL_MAC_LEN, size, NULL, max_size);
    }
    return -2;
}

static int pkey_gost_magma_mac_ctrl_str(EVP_PKEY_CTX* ctx,
    const char* type, const char* value)
{
    return pkey_gost_omac_ctrl_str(ctx, type, value, 8);
}

static int pkey_gost_grasshopper_mac_ctrl_str(EVP_PKEY_CTX* ctx,
    const char* type, const char* value)
{
    return pkey_gost_omac_ctrl_str(ctx, type, value, 16);
}

static int pkey_gost_mac_signctx(EVP_PKEY_CTX* ctx, unsigned char* sig,
    size_t* siglen, EVP_MD_CTX* mctx)
{
    unsigned int tmpsiglen;
    int ret;
    struct gost_mac_pmeth_data* data = EVP_PKEY_CTX_get_data(ctx);

    if (!siglen)
        return 0;
    tmpsiglen = *siglen;        /* for platforms where sizeof(int) !=
                                 * sizeof(size_t) */

    if (!sig) {
        *siglen = data->mac_size;
        return 1;
    }

    EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(mctx))
        (mctx, EVP_MD_CTRL_XOF_LEN, data->mac_size, NULL);
    ret = EVP_DigestFinal_ex(mctx, sig, &tmpsiglen);
    *siglen = data->mac_size;
    return ret;
}


/* ----------------------------------------------------------------*/
int register_pmeth_gost(int id, EVP_PKEY_METHOD** pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (!*pmeth)
        return 0;

    switch (id) {
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2001DH:
        EVP_PKEY_meth_set_ctrl(*pmeth,
            pkey_gost_ctrl, pkey_gost_ec_ctrl_str_256);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);

        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost2001cp_keygen);

        EVP_PKEY_meth_set_encrypt(*pmeth,
            pkey_gost_encrypt_init,
            pkey_gost_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_gost_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
            pkey_gost_derive_init, pkey_gost_ec_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth, pkey_gost_paramgen_init,
            pkey_gost2001_paramgen);
        EVP_PKEY_meth_set_check(*pmeth, pkey_gost_check);
        EVP_PKEY_meth_set_public_check(*pmeth, pkey_gost_check);
        break;
    case NID_id_GostR3410_2012_256:
        EVP_PKEY_meth_set_ctrl(*pmeth,
            pkey_gost_ctrl, pkey_gost_ec_ctrl_str_256);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);

        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost2012cp_keygen);

        EVP_PKEY_meth_set_encrypt(*pmeth,
            pkey_gost_encrypt_init,
            pkey_gost_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_gost_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
            pkey_gost_derive_init, pkey_gost_ec_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth,
            pkey_gost_paramgen_init,
            pkey_gost2012_paramgen);
        EVP_PKEY_meth_set_check(*pmeth, pkey_gost_check);
        EVP_PKEY_meth_set_public_check(*pmeth, pkey_gost_check);
        break;
    case NID_id_GostR3410_2012_512:
        EVP_PKEY_meth_set_ctrl(*pmeth,
            pkey_gost_ctrl, pkey_gost_ec_ctrl_str_512);
        EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_gost_ec_cp_sign);
        EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_gost_ec_cp_verify);

        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost2012cp_keygen);

        EVP_PKEY_meth_set_encrypt(*pmeth,
            pkey_gost_encrypt_init,
            pkey_gost_encrypt);
        EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_gost_decrypt);
        EVP_PKEY_meth_set_derive(*pmeth,
            pkey_gost_derive_init, pkey_gost_ec_derive);
        EVP_PKEY_meth_set_paramgen(*pmeth,
            pkey_gost_paramgen_init,
            pkey_gost2012_paramgen);
        EVP_PKEY_meth_set_check(*pmeth, pkey_gost_check);
        EVP_PKEY_meth_set_public_check(*pmeth, pkey_gost_check);
        break;
    case NID_id_Gost28147_89_MAC:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_mac_ctrl,
            pkey_gost_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_mac_signctx_init,
            pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_mac_keygen);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;
    case NID_gost_mac_12:
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_mac_ctrl,
            pkey_gost_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_mac_signctx_init,
            pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_mac_keygen_12);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;
    case NID_magma_mac:
    case NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac:  /* FIXME beldmit */
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_magma_mac_ctrl,
            pkey_gost_magma_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_magma_mac_signctx_init,
            pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_magma_mac_keygen);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_magma_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;
    case NID_grasshopper_mac:
    case NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac: /* FIXME beldmit */
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_grasshopper_mac_ctrl,
            pkey_gost_grasshopper_mac_ctrl_str);
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_grasshopper_mac_signctx_init,
            pkey_gost_mac_signctx);
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_grasshopper_mac_keygen);
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_grasshopper_mac_init);
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_mac_copy);
        return 1;
    default:                   /* Unsupported method */
        return 0;
    }
    EVP_PKEY_meth_set_init(*pmeth, pkey_gost_init);
    EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_cleanup);

    EVP_PKEY_meth_set_copy(*pmeth, pkey_gost_copy);
    /*
     * FIXME derive etc...
     */

    return 1;
}
