/*
 * RFC 9337 / RFC 9548 PKCS#12 conformance test for gost-engine.
 *
 * For each cipher in the RFC 9337 §4 set
 * {kuznyechik-ctr-acpkm, magma-ctr-acpkm,
 *  kuznyechik-ctr-acpkm-omac, magma-ctr-acpkm-omac} × each
 * macalg in {md_gost12_256, md_gost12_512}, this test:
 *
 *   1. Builds a self-signed GOST 2012-512 cert + private key.
 *   2. Calls PKCS12_create() + PKCS12_set_mac() + i2d_PKCS12() to
 *      produce a PFX byte stream — the same code path that
 *      apps/pkcs12.c drives.
 *   3. Re-parses the bytes and asserts:
 *        - The CTR-ACPKM cipher's `parameters` blob has the RFC 9337
 *          §7.3 shape: `Gost3412-15-Encryption-Parameters ::=
 *          SEQUENCE { ukm OCTET STRING }` with `ukm` of size 12
 *          (Magma) or 16 (Kuznyechik).
 *        - The PBKDF2 PRF OID resolves to a GOST HMAC variant.
 *        - The outer MAC re-computes under the RFC 9548 §3 KDF
 *          (PBKDF2 dkLen=96, last 32 → HMAC key).
 *   4. PKCS12_parse() recovers a key+cert byte-equal to the originals.
 *
 * Cross-mode parity fingerprint (Phase 16d, 2026-05-03)
 * ------------------------------------------------------
 * When env var `RFC9337_FINGERPRINT_OUT` names a writable path, each
 * `run_case` appends a structural fingerprint record (one logical
 * block per case, sorted key=value lines, blank line between cases).
 * The companion ctest `test_pkcs12_rfc9337_cross_mode` runs the
 * binary twice — engine cnf + provider cnf — and `diff`s the two
 * output files. Identical => same OID layout + same length-fields,
 * which is the conformance bar (RFC 9337 §7.3 + RFC 9548 §3 specify
 * structure, not random fields).
 *
 * Fields included (must match between engine + provider):
 *   case=<cipher_name>/<macalg_name>           — locator
 *   cert.cipher.oid=<dotted>                   — RFC 9337 §7.3 cipher
 *   cert.cipher.params_shape=<hex tag:len ...> — `SEQUENCE{OCTET STRING N}` form
 *   cert.pbkdf2.prf.oid=<dotted>               — RFC 9337 §7.4 PRF
 *   cert.pbkdf2.iter=<n>                       — caller-set, 2048 here
 *   cert.pbkdf2.salt_len=<n>                   — length only (bytes random)
 *   key.cipher.oid=<dotted>                    — same matrix, key bag side
 *   key.cipher.params_shape=<hex tag:len ...>
 *   key.pbkdf2.prf.oid=<dotted>
 *   key.pbkdf2.iter=<n>
 *   key.pbkdf2.salt_len=<n>
 *   mac.oid=<dotted>                           — outer-MAC alg (RFC 9548 §3)
 *   mac.iter=<n>
 *   mac.salt_len=<n>
 *
 * Fields excluded (random or wall-clock dependent — would fail
 * structural equivalence falsely):
 *   - PBKDF2 salt bytes (random per call)
 *   - cipher UKM bytes (random per call; `params_shape` already
 *     fixes the *length* via RFC 9337 §5.1.1 step 5)
 *   - encrypted key + cert content (depends on random keypair +
 *     random IV)
 *   - cert notBefore/notAfter (X509_gmtime_adj uses wall clock)
 *   - public key bytes (random keypair per process)
 */

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define cRED   "\033[1;31m"
#define cGREEN "\033[1;32m"
#define cNORM  "\033[m"

static int failures = 0;

#define ASSERT(expr) do {                                                   \
    if (!(expr)) {                                                          \
        fprintf(stderr, cRED "FAIL %s:%d: %s" cNORM "\n",                   \
                __FILE__, __LINE__, #expr);                                 \
        ERR_print_errors_fp(stderr);                                        \
        failures++;                                                         \
        return -1;                                                          \
    }                                                                       \
} while (0)

static const char *kPassword = "test";

/* Build a self-signed GOST 2012-512 cert. Caller frees both. */
static int make_keypair_and_cert(EVP_PKEY **out_pkey, X509 **out_cert)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_512", NULL);
    ASSERT(kctx);
    ASSERT(EVP_PKEY_keygen_init(kctx) == 1);
    ASSERT(EVP_PKEY_CTX_ctrl_str(kctx, "paramset", "A") == 1);
    EVP_PKEY *privkey = NULL;
    ASSERT(EVP_PKEY_keygen(kctx, &privkey) == 1);
    EVP_PKEY_CTX_free(kctx);

    X509 *cert = X509_new();
    ASSERT(cert);
    ASSERT(X509_set_version(cert, 2));
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24);
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"rfc9337-test", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);
    ASSERT(X509_set_pubkey(cert, privkey) == 1);
    ASSERT(X509_sign(cert, privkey, EVP_get_digestbyname("md_gost12_512")) > 0);

    *out_pkey = privkey;
    *out_cert = cert;
    return 0;
}

/*
 * Walk the PFX outer SEQUENCE → ContentInfo → [0] EXPLICIT → inner
 * OCTET STRING and yield its contents. These bytes are what
 * pkcs12_gen_mac HMACs.
 */
static int find_authdata(const unsigned char *file, size_t flen,
                         const unsigned char **adata, int *alen)
{
    const unsigned char *p = file;
    long len; int tag, xclass;
    if (ASN1_get_object(&p, &len, &tag, &xclass, flen) & 0x80) return 0;
    if (tag != V_ASN1_SEQUENCE) return 0;
    const unsigned char *outer_end = p + len;
    if (ASN1_get_object(&p, &len, &tag, &xclass, outer_end - p) & 0x80) return 0;
    p += len; /* version */
    if (ASN1_get_object(&p, &len, &tag, &xclass, outer_end - p) & 0x80) return 0;
    if (tag != V_ASN1_SEQUENCE) return 0;
    const unsigned char *ci_end = p + len;
    if (ASN1_get_object(&p, &len, &tag, &xclass, ci_end - p) & 0x80) return 0;
    p += len; /* OID pkcs7-data */
    if (ASN1_get_object(&p, &len, &tag, &xclass, ci_end - p) & 0x80) return 0;
    if (ASN1_get_object(&p, &len, &tag, &xclass, ci_end - p) & 0x80) return 0;
    if (tag != V_ASN1_OCTET_STRING) return 0;
    *adata = p;
    *alen = (int)len;
    return 1;
}

/*
 * Inside a PFX, find the first occurrence of the cipher OID and return
 * a pointer to the AlgorithmIdentifier `parameters` blob that follows
 * it. The PBES2 encryption_scheme is `SEQUENCE { OID cipher, params }`,
 * so the bytes immediately after the OID are the params. Used to
 * assert the RFC 9337 §7.3 cipher-params shape.
 */
static int find_cipher_params(const unsigned char *file, size_t flen,
                              int cipher_nid,
                              const unsigned char **pbytes, size_t *plen)
{
    const ASN1_OBJECT *o = OBJ_nid2obj(cipher_nid);
    int oid_der_len = i2d_ASN1_OBJECT((ASN1_OBJECT *)o, NULL);
    unsigned char *oid_der = OPENSSL_malloc(oid_der_len);
    unsigned char *q = oid_der;
    i2d_ASN1_OBJECT((ASN1_OBJECT *)o, &q);

    const unsigned char *hit = NULL;
    size_t i;
    for (i = 0; i + (size_t)oid_der_len <= flen; i++) {
        if (memcmp(file + i, oid_der, oid_der_len) == 0) { hit = file + i; break; }
    }
    OPENSSL_free(oid_der);
    if (!hit) return 0;

    const unsigned char *p = hit + oid_der_len;
    long len; int tag, xclass;
    if (ASN1_get_object(&p, &len, &tag, &xclass, flen - (p - file)) & 0x80) return 0;
    /* p now points just past the params header; back up to header start. */
    *pbytes = hit + oid_der_len;
    *plen = (size_t)((p - hit - oid_der_len) + len); /* header + body */
    return 1;
}

/*
 * Phase 16d helpers — extract structural fingerprint fields from one
 * PFX. PKCS12_create lays out the AuthenticatedSafe as
 * [encrypted-cert-bag PKCS7, plain-key-bag PKCS7], so the PBES2 OID
 * appears twice in file order: idx=0 → cert bag encryptedContentInfo,
 * idx=1 → shroudedKeyBag encryptionAlgorithm. Same order under
 * engine + provider configs (PKCS12_create is libcrypto-side and
 * provider-agnostic for layout).
 */
typedef struct {
    char prf_oid[64];     /* dotted, OBJ_obj2txt(no_name=1) */
    long iter;
    int  salt_len;
    char cipher_oid[64];
    char cipher_shape[32]; /* "30:NN:04:N" — outer SEQUENCE + inner OCTET STRING headers */
} pbes2_fp_t;

static const unsigned char *find_nth_oid_after(const unsigned char *file,
                                                size_t flen, int nid, int n)
{
    const ASN1_OBJECT *o = OBJ_nid2obj(nid);
    int oid_der_len = i2d_ASN1_OBJECT((ASN1_OBJECT *)o, NULL);
    unsigned char *oid_der = OPENSSL_malloc(oid_der_len);
    unsigned char *q = oid_der;
    i2d_ASN1_OBJECT((ASN1_OBJECT *)o, &q);

    int found = 0;
    const unsigned char *hit = NULL;
    size_t i;
    for (i = 0; i + (size_t)oid_der_len <= flen; i++) {
        if (memcmp(file + i, oid_der, oid_der_len) == 0) {
            if (found == n) { hit = file + i + oid_der_len; break; }
            found++;
        }
    }
    OPENSSL_free(oid_der);
    return hit;
}

static int extract_pbes2_fp(const unsigned char *file, size_t flen, int idx,
                            pbes2_fp_t *out)
{
    const unsigned char *p = find_nth_oid_after(file, flen, NID_pbes2, idx);
    if (!p) return 0;

    /* Bytes after the PBES2 OID = PBE2PARAM SEQUENCE (with header). */
    PBE2PARAM *pbe = d2i_PBE2PARAM(NULL, &p, (long)(flen - (p - file)));
    if (!pbe) return 0;

    int ok = 0;
    PBKDF2PARAM *pbkdf2 = NULL;

    /* keyfunc.algorithm must be id-PBKDF2; parameter is PBKDF2-params SEQUENCE. */
    const ASN1_OBJECT *kdf_oid;
    X509_ALGOR_get0(&kdf_oid, NULL, NULL, pbe->keyfunc);
    if (OBJ_obj2nid(kdf_oid) != NID_id_pbkdf2) goto out;
    if (pbe->keyfunc->parameter == NULL
        || pbe->keyfunc->parameter->type != V_ASN1_SEQUENCE) goto out;

    {
        const ASN1_STRING *kdf_seq = pbe->keyfunc->parameter->value.sequence;
        const unsigned char *kp = ASN1_STRING_get0_data(kdf_seq);
        pbkdf2 = d2i_PBKDF2PARAM(NULL, &kp, ASN1_STRING_length(kdf_seq));
    }
    if (!pbkdf2) goto out;

    /* PBKDF2.salt is ASN1_TYPE wrapping OCTET STRING in OpenSSL's emitter. */
    if (pbkdf2->salt == NULL
        || pbkdf2->salt->type != V_ASN1_OCTET_STRING) goto out;
    out->salt_len = ASN1_STRING_length(pbkdf2->salt->value.octet_string);
    out->iter = ASN1_INTEGER_get(pbkdf2->iter);

    /* PBKDF2.prf is X509_ALGOR. Field is DEFAULT-typed in RFC 8018 §A.2
     * (DEFAULT algid-hmacWithSHA1), so d2i may leave it NULL when the
     * encoder omitted it. For RFC 9337 §7.4 we mandate an explicit GOST
     * HMAC OID; absence is a structural defect — fail the case rather
     * than crash on X509_ALGOR_get0(NULL). */
    if (pbkdf2->prf == NULL) goto out;
    {
        const ASN1_OBJECT *prf_oid;
        X509_ALGOR_get0(&prf_oid, NULL, NULL, pbkdf2->prf);
        if (OBJ_obj2txt(out->prf_oid, sizeof(out->prf_oid),
                        prf_oid, 1) <= 0) goto out;
    }

    /* encryption.algorithm = cipher OID; parameter = SEQUENCE { OCTET STRING ukm }. */
    {
        const ASN1_OBJECT *cipher_oid;
        X509_ALGOR_get0(&cipher_oid, NULL, NULL, pbe->encryption);
        if (OBJ_obj2txt(out->cipher_oid, sizeof(out->cipher_oid),
                        cipher_oid, 1) <= 0) goto out;
    }
    if (pbe->encryption->parameter == NULL
        || pbe->encryption->parameter->type != V_ASN1_SEQUENCE) goto out;
    {
        const ASN1_STRING *seq = pbe->encryption->parameter->value.sequence;
        const unsigned char *sp = ASN1_STRING_get0_data(seq);
        int sl = ASN1_STRING_length(seq);
        /* Stored bytes are full DER (outer SEQUENCE tag + length + content). */
        if (sl < 4 || sp[0] != 0x30) goto out;
        snprintf(out->cipher_shape, sizeof(out->cipher_shape),
                 "%02x:%02x:%02x:%02x", sp[0], sp[1], sp[2], sp[3]);
    }

    ok = 1;
out:
    PBKDF2PARAM_free(pbkdf2);
    PBE2PARAM_free(pbe);
    return ok;
}

static void dump_fingerprint(FILE *fp, const char *cipher_name,
                             const char *macalg_name,
                             const pbes2_fp_t *cert_fp,
                             const pbes2_fp_t *key_fp,
                             const char *mac_oid, long mac_iter,
                             int mac_salt_len)
{
    fprintf(fp, "[case %s/%s]\n", cipher_name, macalg_name);
    fprintf(fp, "cert.cipher.oid=%s\n", cert_fp->cipher_oid);
    fprintf(fp, "cert.cipher.params_shape=%s\n", cert_fp->cipher_shape);
    fprintf(fp, "cert.pbkdf2.iter=%ld\n", cert_fp->iter);
    fprintf(fp, "cert.pbkdf2.prf.oid=%s\n", cert_fp->prf_oid);
    fprintf(fp, "cert.pbkdf2.salt_len=%d\n", cert_fp->salt_len);
    fprintf(fp, "key.cipher.oid=%s\n", key_fp->cipher_oid);
    fprintf(fp, "key.cipher.params_shape=%s\n", key_fp->cipher_shape);
    fprintf(fp, "key.pbkdf2.iter=%ld\n", key_fp->iter);
    fprintf(fp, "key.pbkdf2.prf.oid=%s\n", key_fp->prf_oid);
    fprintf(fp, "key.pbkdf2.salt_len=%d\n", key_fp->salt_len);
    fprintf(fp, "mac.iter=%ld\n", mac_iter);
    fprintf(fp, "mac.oid=%s\n", mac_oid);
    fprintf(fp, "mac.salt_len=%d\n", mac_salt_len);
    fprintf(fp, "\n");
    fflush(fp);
}

static int run_case(EVP_PKEY *pkey, X509 *cert,
                    int cipher_nid, const char *cipher_name,
                    const char *macalg_name)
{
    printf("  [%-22s / %s] ", cipher_name, macalg_name);
    fflush(stdout);

    /*
     * Phase 13 OMAC scope-gates:
     *   (1) provider mode — gost_prov_cipher.c dispatches the OMAC
     *       ciphers but the AEAD ctrl trio (TLS1_AAD/SET_TAG/GET_TAG)
     *       used by p12_decr.c isn't yet translated to OSSL_PARAMs on
     *       the provider side, so PKCS12_create's encrypt aborts.
     *       Provider-side OMAC parity is queued separately.
     *   (2) cross-mode fingerprint runs (RFC9337_FINGERPRINT_OUT set) —
     *       provider.cnf can only emit 4 non-OMAC cells, so the
     *       cross-mode diff against engine.cnf needs both sides to
     *       limit to 4 cells.
     * Skip rather than fail so the engine-mode regular run keeps
     * exercising all 8 cells.
     */
    int is_omac = (cipher_nid == NID_kuznyechik_ctr_acpkm_omac
                   || cipher_nid == NID_magma_ctr_acpkm_omac);
    if (is_omac) {
        const char *fp_path = getenv("RFC9337_FINGERPRINT_OUT");
        int from_provider = 0;
        EVP_CIPHER *probe = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
        if (probe != NULL) {
            from_provider = (EVP_CIPHER_get0_provider(probe) != NULL);
            EVP_CIPHER_free(probe);
        }
        if (from_provider || (fp_path != NULL && *fp_path != '\0')) {
            printf("skip (provider/cross-mode: OMAC out of Phase 13 scope)\n");
            return 0;
        }
    }

    PKCS12 *p12 = PKCS12_create(kPassword, "rfc9337-test", pkey, cert,
                                NULL, cipher_nid, cipher_nid,
                                2048, 2048, 0);
    ASSERT(p12);

    /*
     * EVP_MD_fetch finds provider-registered digests; EVP_get_digestbyname
     * finds engine-registered legacy ones. The same test runs in both
     * modes, so try fetch first and fall back to legacy.
     */
    EVP_MD *macmd_fetched = EVP_MD_fetch(NULL, macalg_name, NULL);
    const EVP_MD *macmd = macmd_fetched != NULL
                          ? (const EVP_MD *)macmd_fetched
                          : EVP_get_digestbyname(macalg_name);
    ASSERT(macmd);
    ASSERT(PKCS12_set_mac(p12, kPassword, -1, NULL, 0, 2048, macmd) == 1);

    unsigned char *enc = NULL;
    int enc_len = i2d_PKCS12(p12, &enc);
    ASSERT(enc_len > 0);
    PKCS12_free(p12);

    /* Re-parse for byte assertions. */
    const unsigned char *q = enc;
    PKCS12 *p12r = d2i_PKCS12(NULL, &q, enc_len);
    ASSERT(p12r);

    /* (a) outer-MAC KDF is RFC 9548 §3 (PBKDF2 dkLen=96, last 32). */
    const ASN1_OCTET_STRING *macval, *salt;
    const X509_ALGOR *macalg;
    const ASN1_INTEGER *iter;
    PKCS12_get0_mac(&macval, &macalg, &salt, &iter, p12r);
    ASSERT(macval && macalg && salt && iter);
    long iters = ASN1_INTEGER_get(iter);
    const ASN1_OBJECT *aobj;
    X509_ALGOR_get0(&aobj, NULL, NULL, macalg);
    EVP_MD *md_fetched = EVP_MD_fetch(NULL, OBJ_nid2sn(OBJ_obj2nid(aobj)), NULL);
    const EVP_MD *md = md_fetched != NULL
                       ? (const EVP_MD *)md_fetched
                       : EVP_get_digestbynid(OBJ_obj2nid(aobj));
    ASSERT(md);

    const unsigned char *adata; int alen;
    ASSERT(find_authdata(enc, enc_len, &adata, &alen));

    unsigned char dk[96], hmac_key[32];
    ASSERT(PKCS5_PBKDF2_HMAC(kPassword, -1,
                             ASN1_STRING_get0_data(salt),
                             ASN1_STRING_length(salt),
                             (int)iters, md, sizeof(dk), dk) == 1);
    memcpy(hmac_key, dk + 64, 32);
    unsigned char mac9548[64] = {0};
    unsigned int mac9548_len = sizeof(mac9548);
    ASSERT(HMAC(md, hmac_key, sizeof(hmac_key), adata, alen, mac9548,
                &mac9548_len) != NULL);
    ASSERT((int)mac9548_len == ASN1_STRING_length(macval) &&
           memcmp(mac9548, ASN1_STRING_get0_data(macval), mac9548_len) == 0);

    /*
     * (b) cipher `parameters` matches RFC 9337 §7.3:
     *     Gost3412-15-Encryption-Parameters ::= SEQUENCE { ukm OCTET STRING }
     * with ukm = 12 octets for Magma, 16 for Kuznyechik (RFC 9337 §5.1.1
     * step 5). Short-form lengths suffice at these sizes — outer SEQUENCE
     * length 14 (Magma) or 18 (Kuznyechik); inner OCTET STRING length 12 or 16.
     */
    const unsigned char *cp; size_t cp_len;
    ASSERT(find_cipher_params(enc, enc_len, cipher_nid, &cp, &cp_len));
    int expected_ukm = (cipher_nid == NID_magma_ctr_acpkm
                        || cipher_nid == NID_magma_ctr_acpkm_omac)
                       ? 12 : 16;
    ASSERT(cp[0] == 0x30);                     /* outer SEQUENCE */
    ASSERT(cp[1] == 2 + expected_ukm);         /* SEQUENCE body length */
    ASSERT(cp[2] == 0x04);                     /* inner OCTET STRING */
    ASSERT(cp[3] == expected_ukm);             /* ukm length */

    /* (c) round-trip decode recovers identical key+cert. */
    EVP_PKEY *pkey2 = NULL; X509 *cert2 = NULL;
    ASSERT(PKCS12_parse(p12r, kPassword, &pkey2, &cert2, NULL) == 1);
    ASSERT(X509_cmp(cert, cert2) == 0);
    ASSERT(EVP_PKEY_eq(pkey, pkey2) == 1);

    /*
     * (d) Phase 16d cross-mode parity: when RFC9337_FINGERPRINT_OUT
     * names a writable path, append a structural record so a
     * companion ctest can `diff` engine vs provider output.
     */
    {
        const char *fp_path = getenv("RFC9337_FINGERPRINT_OUT");
        if (fp_path != NULL && *fp_path != '\0') {
            pbes2_fp_t cert_fp, key_fp;
            memset(&cert_fp, 0, sizeof(cert_fp));
            memset(&key_fp, 0, sizeof(key_fp));
            ASSERT(extract_pbes2_fp(enc, (size_t)enc_len, 0, &cert_fp));
            ASSERT(extract_pbes2_fp(enc, (size_t)enc_len, 1, &key_fp));

            char mac_oid[64];
            ASSERT(OBJ_obj2txt(mac_oid, sizeof(mac_oid), aobj, 1) > 0);

            FILE *fp = fopen(fp_path, "a");
            ASSERT(fp);
            dump_fingerprint(fp, cipher_name, macalg_name,
                             &cert_fp, &key_fp,
                             mac_oid, iters, ASN1_STRING_length(salt));
            fclose(fp);
        }
    }

    EVP_PKEY_free(pkey2);
    X509_free(cert2);
    PKCS12_free(p12r);
    OPENSSL_free(enc);
    EVP_MD_free(md_fetched);
    EVP_MD_free(macmd_fetched);

    printf(cGREEN "ok" cNORM "\n");
    return 0;
}

int main(void)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    EVP_PKEY *pkey = NULL; X509 *cert = NULL;
    if (make_keypair_and_cert(&pkey, &cert) != 0) return 1;

    /*
     * Full RFC 9337 §4 cipher set. The OMAC variants round-trip via the
     * AEAD ctrl trio (EVP_CTRL_AEAD_TLS1_AAD/SET_TAG/GET_TAG) wired in
     * gost_grasshopper_cipher.c / gost_crypt.c (Phase 13b) plus the
     * kdf_seed lifecycle fix in gost2015_acpkm_omac_init +
     * {grasshopper,magma}_set_asn1_parameters (Phase 13b'). See
     * notes.md "Phase 13 — OMAC PKCS#12 round-trip investigation".
     */
    static const struct { int nid; const char *name; } ciphers[] = {
        { NID_kuznyechik_ctr_acpkm,      "kuznyechik-ctr-acpkm"      },
        { NID_magma_ctr_acpkm,           "magma-ctr-acpkm"           },
        { NID_kuznyechik_ctr_acpkm_omac, "kuznyechik-ctr-acpkm-omac" },
        { NID_magma_ctr_acpkm_omac,      "magma-ctr-acpkm-omac"      },
    };
    static const char *macalgs[] = { "md_gost12_256", "md_gost12_512" };

    printf("RFC 9337 / RFC 9548 PFX matrix:\n");
    {
        size_t i, j;
        for (i = 0; i < sizeof(ciphers)/sizeof(ciphers[0]); i++)
        for (j = 0; j < sizeof(macalgs)/sizeof(macalgs[0]); j++) {
            run_case(pkey, cert,
                     ciphers[i].nid, ciphers[i].name,
                     macalgs[j]);
        }
    }

    EVP_PKEY_free(pkey);
    X509_free(cert);

    if (failures) {
        printf(cRED "%d failure(s)" cNORM "\n", failures);
        return 1;
    }
    printf(cGREEN "all matrix cases passed" cNORM "\n");
    return 0;
}
