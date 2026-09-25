/*
 * test_raw_sign_prehash.c
 *
 * Checks the "hash then EVP_PKEY_sign" path (Node.js createSign / SignFinal).
 * Key is generated in-process via the provider API — no external PEM.
 *
 */
#ifdef _MSC_VER
# pragma warning(push, 3)
# include <openssl/applink.c>
# pragma warning(pop)
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* Soft fail: print OpenSSL errors and return, do not abort (avoids
 * ctest "Subprocess aborted" with no diagnostics). */
#define TE(e) \
    do { \
        if (!(e)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #e); \
            ERR_print_errors_fp(stderr); \
            return 1; \
        } \
    } while (0)

static EVP_PKEY *gost2012_256_keygen(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    /* TCA = id-tc26-gost-3410-2012-256-paramSetA (same as test_sign) */
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("paramset", (char *)"TCA", 0),
        OSSL_PARAM_END
    };

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_256", NULL);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name(gost2012_256) failed "
                        "(is gostprov loaded via OPENSSL_CONF?)\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    /* Preferred: OSSL_PARAM. Fallback: ctrl_str("paramset", ...). */
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        ERR_clear_error();
        if (EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "TCA") <= 0) {
            fprintf(stderr, "setting paramset=TCA failed\n");
            ERR_print_errors_fp(stderr);
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0 || pkey == NULL) {
        fprintf(stderr, "EVP_PKEY_keygen failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int main(void)
{
    const unsigned char msg[] = "this is test string";
    size_t mlen = sizeof(msg) - 1;
    unsigned char dgst[64];
    unsigned int dlen = 0;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ret = 1;

    /* Load OPENSSL_CONF from the environment (set by ctest harness). */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    EVP_PKEY *pkey = gost2012_256_keygen();
    TE(pkey != NULL);

    /* --- prehash --- */
    EVP_MD *md = EVP_MD_fetch(NULL, "md_gost12_256", NULL);
    TE(md != NULL);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    TE(mdctx != NULL);
    TE(EVP_DigestInit_ex(mdctx, md, NULL) == 1);
    TE(EVP_DigestUpdate(mdctx, msg, mlen) == 1);
    TE(EVP_DigestFinal_ex(mdctx, dgst, &dlen) == 1);
    TE(dlen == 32); /* Streebog-256 */
    EVP_MD_CTX_free(mdctx);

    /* --- raw sign on digest (Node createSign / SignFinal path) --- */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    TE(pctx != NULL);
    TE(EVP_PKEY_sign_init(pctx) > 0);
    if (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0)
        ERR_clear_error();

    TE(EVP_PKEY_sign(pctx, NULL, &siglen, dgst, dlen) > 0);
    TE((sig = OPENSSL_malloc(siglen)) != NULL);
    TE(EVP_PKEY_sign(pctx, sig, &siglen, dgst, dlen) > 0);
    EVP_PKEY_CTX_free(pctx);

    /* --- verify --- */
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    TE(pctx != NULL);
    TE(EVP_PKEY_verify_init(pctx) > 0);
    if (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0)
        ERR_clear_error();
    TE(EVP_PKEY_verify(pctx, sig, siglen, dgst, dlen) == 1);

    printf("test_raw_sign_prehash: OK (dlen=%u siglen=%zu)\n", dlen, siglen);
    ret = 0;

    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_free(md);
    EVP_PKEY_free(pkey);
    return ret;
}
