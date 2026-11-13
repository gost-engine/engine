#pragma once

/**********************************************************************
 *                 gost_prov.h - The provider itself                  *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

/* OID constants for GOST algorithms */
#define OID_id_GostR3410_2001        "1.2.643.2.2.19"
#define OID_id_GostR3410_2001DH      "1.2.643.2.2.98"
#define OID_id_GostR3410_2012_256    "1.2.643.7.1.1.1.1"
#define OID_id_GostR3410_2012_512    "1.2.643.7.1.1.1.2"
#define OID_id_GostR3411_94_with_GostR3410_2001 "1.2.643.2.2.3"
#define OID_id_Gost28147_89_MAC      "1.2.643.2.2.22"
#define OID_id_tc26_signwithdigest_gost3410_2012_256   "1.2.643.7.1.1.3.2"
#define OID_id_tc26_signwithdigest_gost3410_2012_512   "1.2.643.7.1.1.3.3"

/* Algorithm name constants for initializing OSSL_ALGORITHM */
#define ALG_NAME_GOST2001      \
    SN_id_GostR3410_2001 ":"   \
    LN_id_GostR3410_2001 ":"   \
    OID_id_GostR3410_2001

#define ALG_NAME_GOST2001DH    \
    SN_id_GostR3410_2001DH ":" \
    LN_id_GostR3410_2001DH ":" \
    OID_id_GostR3410_2001DH

#define ALG_NAME_GOST2012_256  \
    SN_id_GostR3410_2012_256 ":" \
    LN_id_GostR3410_2012_256 ":" \
    OID_id_GostR3410_2012_256

#define ALG_NAME_GOST2012_512  \
    SN_id_GostR3410_2012_512 ":" \
    LN_id_GostR3410_2012_512 ":" \
    OID_id_GostR3410_2012_512

/* Names for GOST MAC keymgmt and signature operations */
#define ALG_NAME_GOST_MAC      \
    SN_id_Gost28147_89_MAC ":" \
    LN_id_Gost28147_89_MAC ":" \
    OID_id_Gost28147_89_MAC

#define ALG_NAME_GOST12_MAC    SN_gost_mac_12
#define ALG_NAME_MAGMA_MAC     SN_magma_mac
#define ALG_NAME_KUZNYECHIK_MAC SN_kuznyechik_mac

/* Utilities for checking and working with bit flags */
#define FLAGS_CONTAIN(flags, subset) (((flags)&(subset)) == (subset))
#define FLAGS_INTERSECT(flags, subset) (((flags)&(subset)) != 0)

OSSL_FUNC_keymgmt_dup_fn keymgmt_dup;
OSSL_FUNC_keymgmt_free_fn keymgmt_free;
OSSL_FUNC_keymgmt_match_fn keymgmt_match;

struct provider_ctx_st {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};
typedef struct provider_ctx_st PROV_CTX;

typedef struct gost_key_data_st
{
    EC_KEY *ec;
    int type;
    int param_nid;
} GOST_KEY_DATA;

/* Secret key data for GOST MAC operations (gost_prov_keymgmt_mac.c) */
struct gost_mac_key_data_st {
    unsigned char key[32];
};
typedef struct gost_mac_key_data_st GOST_MAC_KEY_DATA;

int gost_get_max_keyexch_size(const GOST_KEY_DATA *);
int gost_get_max_signature_size(const GOST_KEY_DATA *);

extern const OSSL_ALGORITHM GOST_prov_ciphers[];
extern const OSSL_ALGORITHM GOST_prov_keymgmt[];
extern const OSSL_ALGORITHM GOST_prov_encoder[];
extern const OSSL_ALGORITHM GOST_prov_signature[];
extern const OSSL_ALGORITHM GOST_prov_decoder[];
extern const OSSL_ALGORITHM GOST_prov_keyexch[];
extern const OSSL_ALGORITHM GOST_prov_asym_cipher[];

/* keymgmt for GOST MAC secret keys (gost_prov_keymgmt_mac.c) */
extern const OSSL_DISPATCH id_gost_mac_keymgmt_mac_functions[];
extern const OSSL_DISPATCH id_gost_mac_12_keymgmt_mac_functions[];
extern const OSSL_DISPATCH id_magma_mac_keymgmt_mac_functions[];
extern const OSSL_DISPATCH id_kuznyechik_mac_keymgmt_mac_functions[];

/* MAC over signature API (gost_prov_signature_mac.c) */
extern const OSSL_DISPATCH id_Gost28147_89_mac_signature_mac_functions[];
extern const OSSL_DISPATCH id_Gost28147_89_mac_12_signature_mac_functions[];
extern const OSSL_DISPATCH id_magma_omac_mac_signature_mac_functions[];
extern const OSSL_DISPATCH id_grasshopper_omac_mac_signature_mac_functions[];

int keymgmt_mac_gen_set_params(void *genctx, const OSSL_PARAM params[]);
