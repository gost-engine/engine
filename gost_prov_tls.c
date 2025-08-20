#include "gost_prov_tls.h"

#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#define OSSL_TLS_GROUP_ID_gc256A           0x0022
#define OSSL_TLS_GROUP_ID_gc256B           0x0023
#define OSSL_TLS_GROUP_ID_gc256C           0x0024
#define OSSL_TLS_GROUP_ID_gc256D           0x0025
#define OSSL_TLS_GROUP_ID_gc512A           0x0026
#define OSSL_TLS_GROUP_ID_gc512B           0x0027
#define OSSL_TLS_GROUP_ID_gc512C           0x0028

typedef struct tls_group_constants_st {
    unsigned int group_id;   /* Group ID */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
} TLS_GROUP_CONSTANTS;

static const TLS_GROUP_CONSTANTS group_list[] = {
    { OSSL_TLS_GROUP_ID_gc256A, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc256B, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc256C, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc256D, 128, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc512A, 256, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc512B, 256, TLS1_3_VERSION, 0, -1, -1 },
    { OSSL_TLS_GROUP_ID_gc512C, 256, TLS1_3_VERSION, 0, -1, -1 },
};

#define TLS_GROUP_ENTRY(group_name, name_internal, alg, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, \
                               group_name, sizeof(group_name)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
                               name_internal, sizeof(name_internal)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, \
                               alg, sizeof(alg)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, \
                        (unsigned int *)&group_list[idx].group_id), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, \
                        (unsigned int *)&group_list[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, \
                       (unsigned int *)&group_list[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, \
                       (unsigned int *)&group_list[idx].maxtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, \
                       (unsigned int *)&group_list[idx].mindtls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, \
                       (unsigned int *)&group_list[idx].maxdtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_group_list[][10] = {
    TLS_GROUP_ENTRY("GC256A", "TCA", SN_id_GostR3410_2012_256, 0),
    TLS_GROUP_ENTRY("GC256B", "TCB", SN_id_GostR3410_2012_256, 1),
    TLS_GROUP_ENTRY("GC256C", "TCC", SN_id_GostR3410_2012_256, 2),
    TLS_GROUP_ENTRY("GC256D", "TCD", SN_id_GostR3410_2012_256, 3),
    TLS_GROUP_ENTRY("GC512A", "A", SN_id_GostR3410_2012_512, 4),
    TLS_GROUP_ENTRY("GC512B", "B", SN_id_GostR3410_2012_512, 5),
    TLS_GROUP_ENTRY("GC512C", "C", SN_id_GostR3410_2012_512, 6),
};

int gost_prov_get_tls_group_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < sizeof(param_group_list) / sizeof(param_group_list[0]); i++)
        if (!cb(param_group_list[i], arg))
            return 0;
    return 1;
}

#define TLS_SIGALG_gostr34102012_256a  0x0709
#define TLS_SIGALG_gostr34102012_256b  0x070A
#define TLS_SIGALG_gostr34102012_256c  0x070B
#define TLS_SIGALG_gostr34102012_256d  0x070C
#define TLS_SIGALG_gostr34102012_512a  0x070D
#define TLS_SIGALG_gostr34102012_512b  0x070E
#define TLS_SIGALG_gostr34102012_512c  0x070F

typedef struct tls_sigalg_constants_st {
    unsigned int code_point; /* SignatureScheme */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} TLS_SIGALG_CONSTANTS;

static const TLS_SIGALG_CONSTANTS gost_sigalg_constants[] = {
    { TLS_SIGALG_gostr34102012_256a, 128, TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS_SIGALG_gostr34102012_256b, 128, TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS_SIGALG_gostr34102012_256c, 128, TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS_SIGALG_gostr34102012_256d, 128, TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS_SIGALG_gostr34102012_512a, 256, TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS_SIGALG_gostr34102012_512b, 256, TLS1_3_VERSION, TLS1_3_VERSION },
    { TLS_SIGALG_gostr34102012_512c, 256, TLS1_3_VERSION, TLS1_3_VERSION },
};

#define TLS_SIGALG_ENTRY(iana_name, sigalg_name, hash_name, idx) \
    { \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, iana_name, sizeof(iana_name)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, \
                        (unsigned int *)&gost_sigalg_constants[idx].code_point), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME, sigalg_name, sizeof(sigalg_name)), \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME, hash_name, sizeof(hash_name)), \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, \
                        (unsigned int *)&gost_sigalg_constants[idx].secbits), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, \
                       (int *)&gost_sigalg_constants[idx].mintls), \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, \
                       (int *)&gost_sigalg_constants[idx].maxtls), \
        OSSL_PARAM_END \
    }

static const OSSL_PARAM param_sigalg_list[][8] = {
    TLS_SIGALG_ENTRY("gostr34102012_256a", SN_id_GostR3410_2012_256,
                     SN_id_GostR3411_2012_256, 0),
    TLS_SIGALG_ENTRY("gostr34102012_256b", SN_id_GostR3410_2012_256,
                     SN_id_GostR3411_2012_256, 1),
    TLS_SIGALG_ENTRY("gostr34102012_256c", SN_id_GostR3410_2012_256,
                     SN_id_GostR3411_2012_256, 2),
    TLS_SIGALG_ENTRY("gostr34102012_256d", SN_id_GostR3410_2012_256,
                     SN_id_GostR3411_2012_256, 3),
    TLS_SIGALG_ENTRY("gostr34102012_512a", SN_id_GostR3410_2012_512,
                     SN_id_GostR3411_2012_512, 4),
    TLS_SIGALG_ENTRY("gostr34102012_512b", SN_id_GostR3410_2012_512,
                     SN_id_GostR3411_2012_512, 5),
    TLS_SIGALG_ENTRY("gostr34102012_512c", SN_id_GostR3410_2012_512,
                     SN_id_GostR3411_2012_512, 6)
};

int gost_prov_get_tls_sigalg_capability(OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    for (i = 0; i < sizeof(param_sigalg_list) / sizeof(param_sigalg_list[0]); i++)
        if (!cb(param_sigalg_list[i], arg))
            return 0;

    return 1;
}
