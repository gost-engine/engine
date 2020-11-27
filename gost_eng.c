/**********************************************************************
 *                          gost_eng.c                                *
 *              Main file of GOST engine                              *
 *                                                                    *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *             Copyright (c) 2020 Chikunov Vitaly <vt@altlinux.org>   *
 *                                                                    *
 *       This file is distributed under the same license as OpenSSL   *
 *                                                                    *
 **********************************************************************/
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include "e_gost_err.h"
#include "gost_lcl.h"

#include "gost_grasshopper_cipher.h"

static const char* engine_gost_id = "gost";

static const char* engine_gost_name =
        "Reference implementation of GOST engine";

/* Symmetric cipher and digest function registrar */

static int gost_ciphers(ENGINE* e, const EVP_CIPHER** cipher,
                        const int** nids, int nid);

static int gost_digests(ENGINE* e, const EVP_MD** digest,
                        const int** nids, int nid);

static int gost_pkey_meths(ENGINE* e, EVP_PKEY_METHOD** pmeth,
                           const int** nids, int nid);

static int gost_pkey_asn1_meths(ENGINE* e, EVP_PKEY_ASN1_METHOD** ameth,
                                const int** nids, int nid);

static EVP_PKEY_METHOD* pmeth_GostR3410_2001 = NULL,
        * pmeth_GostR3410_2001DH = NULL,
        * pmeth_GostR3410_2012_256 = NULL,
        * pmeth_GostR3410_2012_512 = NULL,
        * pmeth_Gost28147_MAC = NULL, * pmeth_Gost28147_MAC_12 = NULL,
        * pmeth_magma_mac = NULL,  * pmeth_grasshopper_mac = NULL,
        * pmeth_magma_mac_acpkm = NULL,  * pmeth_grasshopper_mac_acpkm = NULL;

static EVP_PKEY_ASN1_METHOD* ameth_GostR3410_2001 = NULL,
        * ameth_GostR3410_2001DH = NULL,
        * ameth_GostR3410_2012_256 = NULL,
        * ameth_GostR3410_2012_512 = NULL,
        * ameth_Gost28147_MAC = NULL, * ameth_Gost28147_MAC_12 = NULL,
        * ameth_magma_mac = NULL,  * ameth_grasshopper_mac = NULL,
        * ameth_magma_mac_acpkm = NULL,  * ameth_grasshopper_mac_acpkm = NULL;

GOST_digest *gost_digest_array[] = {
    &GostR3411_94_digest,
    &Gost28147_89_MAC_digest,
    &GostR3411_2012_256_digest,
    &GostR3411_2012_512_digest,
    &Gost28147_89_mac_12_digest,
    &magma_mac_digest,
    &grasshopper_mac_digest,
    &kuznyechik_ctracpkm_omac_digest,
};

GOST_cipher *gost_cipher_array[] = {
    &Gost28147_89_cipher,
    &Gost28147_89_cnt_cipher,
    &Gost28147_89_cnt_12_cipher,
    &Gost28147_89_cbc_cipher,
    &grasshopper_ecb_cipher,
    &grasshopper_cbc_cipher,
    &grasshopper_cfb_cipher,
    &grasshopper_ofb_cipher,
    &grasshopper_ctr_cipher,
    &magma_cbc_cipher,
    &magma_ctr_cipher,
    &magma_ctr_acpkm_cipher,
    &magma_ctr_acpkm_omac_cipher,
    &grasshopper_ctr_acpkm_cipher,
    &grasshopper_ctr_acpkm_omac_cipher,
    &magma_kexp15_cipher,
    &kuznyechik_kexp15_cipher,
};

static struct gost_meth_minfo {
    int nid;
    EVP_PKEY_METHOD **pmeth;
    EVP_PKEY_ASN1_METHOD **ameth;
    const char *pemstr;
    const char *info;
} gost_meth_array[] = {
    {
        NID_id_GostR3410_2001,
        &pmeth_GostR3410_2001,
        &ameth_GostR3410_2001,
        "GOST2001",
        "GOST R 34.10-2001",
    },
    {
        NID_id_GostR3410_2001DH,
        &pmeth_GostR3410_2001DH,
        &ameth_GostR3410_2001DH,
        "GOST2001 DH",
        "GOST R 34.10-2001 DH",
    },
    {
        NID_id_Gost28147_89_MAC,
        &pmeth_Gost28147_MAC,
        &ameth_Gost28147_MAC,
        "GOST-MAC",
        "GOST 28147-89 MAC",
    },
    {
        NID_id_GostR3410_2012_256,
        &pmeth_GostR3410_2012_256,
        &ameth_GostR3410_2012_256,
        "GOST2012_256",
        "GOST R 34.10-2012 with 256 bit key",
    },
    {
        NID_id_GostR3410_2012_512,
        &pmeth_GostR3410_2012_512,
        &ameth_GostR3410_2012_512,
        "GOST2012_512",
        "GOST R 34.10-2012 with 512 bit key",
    },
    {
        NID_gost_mac_12,
        &pmeth_Gost28147_MAC_12,
        &ameth_Gost28147_MAC_12,
        "GOST-MAC-12",
        "GOST 28147-89 MAC with 2012 params",
    },
    {
        NID_magma_mac,
        &pmeth_magma_mac,
        &ameth_magma_mac,
        "MAGMA-MAC",
        "GOST R 34.13-2015 Magma MAC",
    },
    {
        NID_grasshopper_mac,
        &pmeth_grasshopper_mac,
        &ameth_grasshopper_mac,
        "KUZNYECHIK-MAC",
        "GOST R 34.13-2015 Grasshopper MAC",
    },
    {
        NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac,
        &pmeth_magma_mac_acpkm,
        &ameth_magma_mac_acpkm,
        "ID-TC26-CIPHER-GOSTR3412-2015-MAGMA-CTRACPKM-OMAC",
        "GOST R 34.13-2015 Magma MAC ACPKM",
    },
    {
        NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac,
        &pmeth_grasshopper_mac_acpkm,
        &ameth_grasshopper_mac_acpkm,
        "ID-TC26-CIPHER-GOSTR3412-2015-KUZNYECHIK-CTRACPKM-OMAC",
        "GOST R 34.13-2015 Grasshopper MAC ACPKM",
    },
    { 0 },
};

#ifndef OSSL_NELEM
# define OSSL_NELEM(x) (sizeof(x)/sizeof((x)[0]))
#endif

static int known_digest_nids[OSSL_NELEM(gost_digest_array)];
static int known_cipher_nids[OSSL_NELEM(gost_cipher_array)];
/* `- 1' because of terminating zero element */
static int known_meths_nids[OSSL_NELEM(gost_meth_array) - 1];

static int gost_engine_init(ENGINE* e) {
    return 1;
}

static int gost_engine_finish(ENGINE* e) {
    return 1;
}

static int gost_engine_destroy(ENGINE* e) {
    int i;

    for (i = 0; i < OSSL_NELEM(gost_digest_array); i++)
        GOST_deinit_digest(gost_digest_array[i]);
    for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++)
        GOST_deinit_cipher(gost_cipher_array[i]);

    gost_param_free();

    struct gost_meth_minfo *minfo = gost_meth_array;
    for (; minfo->nid; minfo++) {
        *minfo->pmeth = NULL;
        *minfo->ameth = NULL;
    }

    ERR_unload_GOST_strings();

    return 1;
}

static int bind_gost(ENGINE* e, const char* id) {
    int ret = 0;
    if (id != NULL && strcmp(id, engine_gost_id) != 0)
        return 0;
    if (ameth_GostR3410_2001) {
        printf("GOST engine already loaded\n");
        goto end;
    }
    if (!ENGINE_set_id(e, engine_gost_id)) {
        printf("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_gost_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    if (!ENGINE_set_digests(e, gost_digests)) {
        printf("ENGINE_set_digests failed\n");
        goto end;
    }
    if (!ENGINE_set_ciphers(e, gost_ciphers)) {
        printf("ENGINE_set_ciphers failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_meths(e, gost_pkey_meths)) {
        printf("ENGINE_set_pkey_meths failed\n");
        goto end;
    }
    if (!ENGINE_set_pkey_asn1_meths(e, gost_pkey_asn1_meths)) {
        printf("ENGINE_set_pkey_asn1_meths failed\n");
        goto end;
    }
    /* Control function and commands */
    if (!ENGINE_set_cmd_defns(e, gost_cmds)) {
        fprintf(stderr, "ENGINE_set_cmd_defns failed\n");
        goto end;
    }
    if (!ENGINE_set_ctrl_function(e, gost_control_func)) {
        fprintf(stderr, "ENGINE_set_ctrl_func failed\n");
        goto end;
    }
    if (!ENGINE_set_destroy_function(e, gost_engine_destroy)
        || !ENGINE_set_init_function(e, gost_engine_init)
        || !ENGINE_set_finish_function(e, gost_engine_finish)) {
        goto end;
    }

    struct gost_meth_minfo *minfo = gost_meth_array;
    for (; minfo->nid; minfo++) {

        /* This skip looks temporary. */
        if (minfo->nid == NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac)
            continue;

        if (!register_ameth_gost(minfo->nid, minfo->ameth, minfo->pemstr,
                minfo->info))
            goto end;
        if (!register_pmeth_gost(minfo->nid, minfo->pmeth, 0))
            goto end;
    }

    if (!ENGINE_register_ciphers(e)
        || !ENGINE_register_digests(e)
        || !ENGINE_register_pkey_meths(e))
        goto end;

    int i;
    for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++) {
        if (!EVP_add_cipher(GOST_init_cipher(gost_cipher_array[i])))
            goto end;
    }

    for (i = 0; i < OSSL_NELEM(gost_digest_array); i++) {
        if (!EVP_add_digest(GOST_init_digest(gost_digest_array[i])))
            goto end;
    }

    ENGINE_register_all_complete();

    ERR_load_GOST_strings();
    ret = 1;
    end:
    return ret;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_gost)
    IMPLEMENT_DYNAMIC_CHECK_FN()
#endif                          /* ndef OPENSSL_NO_DYNAMIC_ENGINE */

/* ENGINE_DIGESTS_PTR callback installed by ENGINE_set_digests */
static int gost_digests(ENGINE *e, const EVP_MD **digest,
                        const int **nids, int nid)
{
    int i;

    if (!digest) {
        int *n = known_digest_nids;

        *nids = n;
        for (i = 0; i < OSSL_NELEM(gost_digest_array); i++)
            *n++ = gost_digest_array[i]->nid;
        return i;
    }

    for (i = 0; i < OSSL_NELEM(gost_digest_array); i++)
        if (nid == gost_digest_array[i]->nid) {
            *digest = GOST_init_digest(gost_digest_array[i]);
            return 1;
        }
    *digest = NULL;
    return 0;
}

/* ENGINE_CIPHERS_PTR callback installed by ENGINE_set_ciphers */
static int gost_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                        const int **nids, int nid)
{
    int i;

    if (!cipher) {
        int *n = known_cipher_nids;

        *nids = n;
        for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++)
            *n++ = gost_cipher_array[i]->nid;
        return i;
    }

    for (i = 0; i < OSSL_NELEM(gost_cipher_array); i++)
        if (nid == gost_cipher_array[i]->nid) {
            *cipher = GOST_init_cipher(gost_cipher_array[i]);
            return 1;
        }
    *cipher = NULL;
    return 0;
}

static int gost_meth_nids(const int **nids)
{
    struct gost_meth_minfo *info = gost_meth_array;
    int *n = known_meths_nids;

    *nids = n;
    for (; info->nid; info++)
        *n++ = info->nid;
    return OSSL_NELEM(known_meths_nids);
}

/* ENGINE_PKEY_METHS_PTR installed by ENGINE_set_pkey_meths */
static int gost_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    struct gost_meth_minfo *info;

    if (!pmeth)
        return gost_meth_nids(nids);

    for (info = gost_meth_array; info->nid; info++)
        if (nid == info->nid) {
            *pmeth = *info->pmeth;
            return 1;
        }
    *pmeth = NULL;
    return 0;
}

/* ENGINE_PKEY_ASN1_METHS_PTR installed by ENGINE_set_pkey_asn1_meths */
static int gost_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                                const int **nids, int nid)
{
    struct gost_meth_minfo *info;

    if (!ameth)
        return gost_meth_nids(nids);

    for (info = gost_meth_array; info->nid; info++)
        if (nid == info->nid) {
            *ameth = *info->ameth;
            return 1;
        }
    *ameth = NULL;
    return 0;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE

static ENGINE* engine_gost(void) {
    ENGINE* ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_gost(ret, engine_gost_id)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_gost(void) {
    ENGINE* toadd;
    if (pmeth_GostR3410_2001)
        return;
    toadd = engine_gost();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

#endif
/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
