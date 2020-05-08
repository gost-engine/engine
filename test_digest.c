/*
 * Test GOST 34.11 Digest operation
 *
 * Copyright (C) 2019-2020 Vitaly Chikunov <vt@altlinux.org>. All Rights Reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <stdlib.h>
#if MIPSEL
# include <sys/sysmips.h>
#endif
#ifndef EVP_MD_CTRL_SET_KEY
# include "gost_lcl.h"
#endif

/* Helpers to test OpenSSL API calls. */
#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })
#define TE(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		fprintf(stderr, "Error at %s:%d %s\n", __FILE__, __LINE__, #e); \
		return -1; \
	    } \
        })

#define cRED	"\033[1;31m"
#define cDRED	"\033[0;31m"
#define cGREEN	"\033[1;32m"
#define cDGREEN	"\033[0;32m"
#define cBLUE	"\033[1;34m"
#define cDBLUE	"\033[0;34m"
#define cNORM	"\033[m"
#define TEST_ASSERT(e) {if ((test = (e))) \
		 printf(cRED "  Test FAILED\n" cNORM); \
	     else \
		 printf(cGREEN "  Test passed\n" cNORM);}

/*
 * Test key from both GOST R 34.12-2015 and GOST R 34.13-2015.
 */
static const char K[32] = {
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
};

/*
 * Plaintext from GOST R 34.13-2015 A.1.
 * First 16 bytes is vector (a) from GOST R 34.12-2015 A.1.
 */
static const char P[] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11,
};

/*
 * OMAC1/CMAC test vector from GOST R 34.13-2015 А.1.6
 */
static const char MAC_omac[] = { 0x33,0x6f,0x4d,0x29,0x60,0x59,0xfb,0xe3 };

/*
 * OMAC-ACPKM test vector from R 1323565.1.017-2018 A.4.1
 */
static const char P_omac_acpkm1[] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
};

static const char MAC_omac_acpkm1[] = {
    0xB5,0x36,0x7F,0x47,0xB6,0x2B,0x99,0x5E,0xEB,0x2A,0x64,0x8C,0x58,0x43,0x14,0x5E,
};

/*
 * OMAC-ACPKM test vector from R 1323565.1.017-2018 A.4.2
 */
static const char P_omac_acpkm2[] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xEE,0xFF,0x0A,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xEE,0xFF,0x0A,0x00,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xEE,0xFF,0x0A,0x00,0x11,
    0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xEE,0xFF,0x0A,0x00,0x11,0x22,
};

static const char MAC_omac_acpkm2[] = {
    0xFB,0xB8,0xDC,0xEE,0x45,0xBE,0xA6,0x7C,0x35,0xF5,0x8C,0x57,0x00,0x89,0x8E,0x5D,
};

struct hash_testvec {
    int nid;		   /* OpenSSL algorithm numeric id. */
    const char *name;	   /* Test name and source. */
    const char *plaintext; /* Input (of psize), NULL for synthetic test. */
    const char *digest;	   /* Expected output (of EVP_MD_size or truncate). */
    const char *key;	   /* MAC key.*/
    int psize;		   /* Input (plaintext) size. */
    int mdsize;		   /* Compare to EVP_MD_size() if non-zero. */
    int truncate;	   /* Truncated output (digest) size. */
    int key_size;	   /* MAC key size. */
    int block_size;	   /* Internal block size. */
    int acpkm;		   /* The section size N (the number of bits that are
			      processed with one section key before this key is
			      transformed) (bytes) */
    int acpkm_t;	   /* Master key (change) frequency T* (bytes) */
};

static const struct hash_testvec testvecs[] = {
    {
	.nid = NID_id_GostR3411_2012_512,
	.name = "M1 from RFC 6986 (10.1.1) and GOST R 34.11-2012 (А.1.1)",
	.plaintext =
	    "012345678901234567890123456789012345678901234567890123456789012",
	.psize = 63,
	.digest =
	    "\x1b\x54\xd0\x1a\x4a\xf5\xb9\xd5\xcc\x3d\x86\xd6\x8d\x28\x54\x62"
	    "\xb1\x9a\xbc\x24\x75\x22\x2f\x35\xc0\x85\x12\x2b\xe4\xba\x1f\xfa"
	    "\x00\xad\x30\xf8\x76\x7b\x3a\x82\x38\x4c\x65\x74\xf0\x24\xc3\x11"
	    "\xe2\xa4\x81\x33\x2b\x08\xef\x7f\x41\x79\x78\x91\xc1\x64\x6f\x48",
	.mdsize = 512 / 8,
	.block_size = 512 / 8,
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "M1 from RFC 6986 (10.1.2) and GOST R 34.11-2012 (А.1.2)",
	.plaintext =
	    "012345678901234567890123456789012345678901234567890123456789012",
	.psize = 63,
	.digest =
	    "\x9d\x15\x1e\xef\xd8\x59\x0b\x89\xda\xa6\xba\x6c\xb7\x4a\xf9\x27"
	    "\x5d\xd0\x51\x02\x6b\xb1\x49\xa4\x52\xfd\x84\xe5\xe5\x7b\x55\x00",
	.mdsize = 256 / 8,
	.block_size = 512 / 8,
    },
    {
	.nid = NID_id_GostR3411_2012_512,
	.name = "M2 from RFC 6986 (10.2.1) and GOST R 34.11-2012 (А.2.1)",
	.plaintext =
	    "\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
	    "\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
	    "\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
	    "\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
	    "\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
	.psize = 72,
	.digest =
	    "\x1e\x88\xe6\x22\x26\xbf\xca\x6f\x99\x94\xf1\xf2\xd5\x15\x69\xe0"
	    "\xda\xf8\x47\x5a\x3b\x0f\xe6\x1a\x53\x00\xee\xe4\x6d\x96\x13\x76"
	    "\x03\x5f\xe8\x35\x49\xad\xa2\xb8\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3"
	    "\x3f\x0c\xb9\xdd\xdc\x2b\x64\x60\x14\x3b\x03\xda\xba\xc9\xfb\x28",
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "M2 from RFC 6986 (10.2.2) and GOST R 34.11-2012 (А.2.2)",
	.plaintext =
	    "\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
	    "\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
	    "\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
	    "\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
	    "\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
	.psize = 72,
	.digest =
	    "\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d\xa8\x7f\x53\x97\x6d\x74\x05\xb0"
	    "\xc0\xca\xc6\x28\xfc\x66\x9a\x74\x1d\x50\x06\x3c\x55\x7e\x8f\x50",
    },
    /* OMAC tests */
    {
	.nid = NID_grasshopper_mac,
	.name = "P from GOST R 34.13-2015 (А.1.6)",
	.plaintext = P,
	.psize = sizeof(P),
	.key = K,
	.key_size = sizeof(K),
	.digest = MAC_omac,
	.mdsize = 128 / 8,
	.truncate = sizeof(MAC_omac),
    },
    {
	.nid = NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac,
	.name = "M from R 1323565.1.017-2018 (A.4.1)",
	.plaintext = P_omac_acpkm1,
	.psize = sizeof(P_omac_acpkm1),
	.key = K,
	.key_size = sizeof(K),
	.acpkm = 32,
	.acpkm_t = 768 / 8,
	.digest = MAC_omac_acpkm1,
	.mdsize = sizeof(MAC_omac_acpkm1),
    },
    {
	.nid = NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac,
	.name = "M from R 1323565.1.017-2018 (A.4.2)",
	.plaintext = P_omac_acpkm2,
	.psize = sizeof(P_omac_acpkm2),
	.key = K,
	.key_size = sizeof(K),
	.acpkm = 32,
	.acpkm_t = 768 / 8,
	.digest = MAC_omac_acpkm2,
	.mdsize = sizeof(MAC_omac_acpkm2),
    },
    /* Synthetic tests. */
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "streebog256 synthetic test",
	.mdsize = 32,
	.block_size = 64,
	.digest =
	    "\xa2\xf3\x6d\x9c\x42\xa1\x1e\xad\xe3\xc1\xfe\x99\xf9\x99\xc3\x84"
	    "\xe7\x98\xae\x24\x50\x75\x73\xd7\xfc\x99\x81\xa0\x45\x85\x41\xf6"
    }, {
	.nid = NID_id_GostR3411_2012_512,
	.name = "streebog512 synthetic test",
	.mdsize = 64,
	.block_size = 64,
	.digest =
	    "\x1d\x14\x4d\xd8\xb8\x27\xfb\x55\x1a\x5a\x7d\x03\xbb\xdb\xfa\xcb"
	    "\x43\x6b\x5b\xc5\x77\x59\xfd\x5f\xf2\x3b\x8e\xf9\xc4\xdd\x6f\x79"
	    "\x45\xd8\x16\x59\x9e\xaa\xbc\xf2\xb1\x4f\xd0\xe4\xf6\xad\x46\x60"
	    "\x90\x89\xf7\x2f\x93\xd8\x85\x0c\xb0\x43\xff\x5a\xb6\xe3\x69\xbd"
    },
    { 0 }
};

static void hexdump(const void *ptr, size_t len)
{
    const unsigned char *p = ptr;
    size_t i, j;

    for (i = 0; i < len; i += j) {
	for (j = 0; j < 16 && i + j < len; j++)
	    printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n");
}

static int do_digest(const EVP_MD *type, const char *plaintext,
    unsigned int psize, const char *etalon, int mdsize, int truncate,
    const char *key, unsigned int key_size, int acpkm, int acpkm_t,
    int block_size)
{
    if (mdsize)
	T(EVP_MD_size(type) == mdsize);
    if (truncate)
	mdsize = truncate;
    else
	mdsize = EVP_MD_size(type);

    if (block_size)
	T(EVP_MD_block_size(type) == block_size);
    EVP_MD_CTX *ctx;
    T(ctx = EVP_MD_CTX_new());
    T(EVP_MD_CTX_init(ctx));
    T(EVP_DigestInit_ex(ctx, type, NULL));
    if (key)
	T(EVP_MD_CTX_ctrl(ctx, EVP_MD_CTRL_SET_KEY, key_size, (void *)key));
    if (acpkm)
	T(EVP_MD_CTX_ctrl(ctx,
		EVP_CTRL_KEY_MESH, acpkm, acpkm_t? &acpkm_t : NULL));
    T(EVP_DigestUpdate(ctx, plaintext, psize));

    unsigned int len;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (EVP_MD_flags(EVP_MD_CTX_md(ctx)) & EVP_MD_FLAG_XOF) {
	T(EVP_DigestFinalXOF(ctx, md, mdsize));
	len = mdsize;
    } else {
	T(EVP_MD_CTX_size(ctx) == mdsize);
	T(EVP_DigestFinal_ex(ctx, md, &len));
    }

    EVP_MD_CTX_free(ctx);
    T(len == mdsize);
    if (memcmp(md, etalon, mdsize) != 0) {
	printf(cRED "digest mismatch\n" cNORM);
	return 1;
    }

    return 0;
}

static int do_test(const struct hash_testvec *tv)
{
	int ret = 0;

	const EVP_MD *type;
	T(type = EVP_get_digestbynid(tv->nid));
	const char *name = EVP_MD_name(type);
	printf(cBLUE "Test %s: %s: " cNORM, name, tv->name);
	fflush(stdout);
	ret |= do_digest(type, tv->plaintext, tv->psize, tv->digest,
	    tv->mdsize, tv->truncate, tv->key, tv->key_size, tv->acpkm,
	    tv->acpkm_t, tv->block_size);

	/* Text alignment problems. */
	int shifts = 32;
	int i;
	char *buf;
	T(buf = OPENSSL_malloc(tv->psize + shifts));
	for (i = 0; i < shifts; i++) {
		memcpy(buf + i, tv->plaintext, tv->psize);
		ret |= do_digest(type, buf + i, tv->psize, tv->digest,
		    tv->mdsize, tv->truncate, tv->key, tv->key_size, tv->acpkm,
		    tv->acpkm_t, tv->block_size);
	}
	OPENSSL_free(buf);

	if (!ret)
		printf(cGREEN "success\n" cNORM);
	else
		printf(cRED "fail\n" cNORM);
	return ret;
}

#define SUPER_SIZE 256
/*
 * For 256-byte buffer filled with 256 bytes from 0 to 255;
 * Digest them 256 times from the buffer end with lengths from 0 to 256,
 * and from beginning of the buffer with lengths from 0 to 256;
 * Each produced digest is digested again into final sum.
 */
static int do_synthetic_once(const struct hash_testvec *tv, unsigned int shifts)
{
    unsigned char *ibuf, *md;
    T(ibuf = OPENSSL_zalloc(SUPER_SIZE + shifts));

    /* fill with pattern */
    unsigned int len;
    for (len = 0; len < SUPER_SIZE; len++)
	    ibuf[shifts + len] = len & 0xff;

    const EVP_MD *mdtype;
    T(mdtype = EVP_get_digestbynid(tv->nid));
    OPENSSL_assert(tv->nid == EVP_MD_type(mdtype));
    EVP_MD_CTX *ctx, *ctx2;
    T(ctx  = EVP_MD_CTX_new());
    T(ctx2 = EVP_MD_CTX_new());
    T(EVP_DigestInit(ctx2, mdtype));
    OPENSSL_assert(tv->nid == EVP_MD_CTX_type(ctx2));
    OPENSSL_assert(EVP_MD_block_size(mdtype) == tv->block_size);
    OPENSSL_assert(EVP_MD_CTX_size(ctx2) == tv->mdsize);
    OPENSSL_assert(EVP_MD_CTX_block_size(ctx2) == tv->block_size);

    const unsigned int mdlen = EVP_MD_size(mdtype);
    OPENSSL_assert(mdlen == tv->mdsize);
    T(md = OPENSSL_zalloc(mdlen + shifts));
    md += shifts; /* test for output digest alignment problems */

    /* digest cycles */
    for (len = 0; len < SUPER_SIZE; len++) {
	/* for each len digest len bytes from the end of buf */
	T(EVP_DigestInit(ctx, mdtype));
	T(EVP_DigestUpdate(ctx, ibuf + shifts + SUPER_SIZE - len, len));
	T(EVP_DigestFinal(ctx, md, NULL));
	T(EVP_DigestUpdate(ctx2, md, mdlen));
    }

    for (len = 0; len < SUPER_SIZE; len++) {
	/* for each len digest len bytes from the beginning of buf */
	T(EVP_DigestInit(ctx, mdtype));
	T(EVP_DigestUpdate(ctx, ibuf + shifts, len));
	T(EVP_DigestFinal(ctx, md, NULL));
	T(EVP_DigestUpdate(ctx2, md, mdlen));
    }

    OPENSSL_free(ibuf);
    EVP_MD_CTX_free(ctx);

    T(EVP_DigestFinal(ctx2, md, &len));
    EVP_MD_CTX_free(ctx2);

    if (len != mdlen) {
	printf(cRED "digest output len mismatch %u != %u (expected)\n" cNORM,
	    len, mdlen);
	goto err;
    }

    if (memcmp(md, tv->digest, mdlen) != 0) {
	printf(cRED "digest mismatch\n" cNORM);

	unsigned int i;
	printf("  Expected value is: ");
	for (i = 0; i < mdlen; i++)
	    printf("\\x%02x", md[i]);
	printf("\n");
	goto err;
    }

    OPENSSL_free(md - shifts);
    return 0;
err:
    OPENSSL_free(md - shifts);
    return 1;
}

/* do different block sizes and different memory offsets */
static int do_synthetic_test(const struct hash_testvec *tv)
{
    int ret = 0;

    printf(cBLUE "Synthetic test %s: " cNORM, tv->name);
    fflush(stdout);

    unsigned int shifts;
    for (shifts = 0; shifts < 16 && !ret; shifts++)
	ret |= do_synthetic_once(tv, shifts);

    if (!ret)
	printf(cGREEN "success\n" cNORM);
    else
	printf(cRED "fail\n" cNORM);
    return 0;
}

int main(int argc, char **argv)
{
    int ret = 0;

#if MIPSEL
    /* Trigger SIGBUS for unaligned access. */
    sysmips(MIPS_FIXADE, 0);
#endif
    setenv("OPENSSL_ENGINES", ENGINE_DIR, 0);
    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    ENGINE *eng;
    T(eng = ENGINE_by_id("gost"));
    T(ENGINE_init(eng));
    T(ENGINE_set_default(eng, ENGINE_METHOD_ALL));

    const struct hash_testvec *tv;
    for (tv = testvecs; tv->nid; tv++) {
	if (tv->plaintext)
	    ret |= do_test(tv);
	else
	    ret |= do_synthetic_test(tv);
    }

    ENGINE_finish(eng);
    ENGINE_free(eng);

    if (ret)
	printf(cDRED "= Some tests FAILED!\n" cNORM);
    else
	printf(cDGREEN "= All tests passed!\n" cNORM);
    return ret;
}
