/*
 * Test GOST 34.11 Digest operation
 *
 * Copyright (C) 2019 vt@altlinux.org. All Rights Reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include "e_gost_err.h"
#include "gost_lcl.h"
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

struct hash_testvec {
	int nid;
	const char *name;
	const char *plaintext;
	const char *digest;
	unsigned short psize;
	unsigned short mdsize;
	unsigned short block_size;
};

static const struct hash_testvec testvecs[] = {
	{ /* M1 */
		.nid = NID_id_GostR3411_2012_256,
		.name = "M1",
		.plaintext = "012345678901234567890123456789012345678901234567890123456789012",
		.psize = 63,
		.digest =
			"\x9d\x15\x1e\xef\xd8\x59\x0b\x89"
			"\xda\xa6\xba\x6c\xb7\x4a\xf9\x27"
			"\x5d\xd0\x51\x02\x6b\xb1\x49\xa4"
			"\x52\xfd\x84\xe5\xe5\x7b\x55\x00",
	},
	{ /* M2 */
		.nid = NID_id_GostR3411_2012_256,
		.name = "M2",
		.plaintext =
			"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8"
			"\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
			"\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8"
			"\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
			"\xf1\x20\xec\xee\xf0\xff\x20\xf1"
			"\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
			"\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0"
			"\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
			"\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
		.psize = 72,
		.digest =
			"\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d"
			"\xa8\x7f\x53\x97\x6d\x74\x05\xb0"
			"\xc0\xca\xc6\x28\xfc\x66\x9a\x74"
			"\x1d\x50\x06\x3c\x55\x7e\x8f\x50",
	},
	{ /* M1 */
		.nid = NID_id_GostR3411_2012_512,
		.name = "M1",
		.plaintext = "012345678901234567890123456789012345678901234567890123456789012",
		.psize = 63,
		.digest =
			"\x1b\x54\xd0\x1a\x4a\xf5\xb9\xd5"
			"\xcc\x3d\x86\xd6\x8d\x28\x54\x62"
			"\xb1\x9a\xbc\x24\x75\x22\x2f\x35"
			"\xc0\x85\x12\x2b\xe4\xba\x1f\xfa"
			"\x00\xad\x30\xf8\x76\x7b\x3a\x82"
			"\x38\x4c\x65\x74\xf0\x24\xc3\x11"
			"\xe2\xa4\x81\x33\x2b\x08\xef\x7f"
			"\x41\x79\x78\x91\xc1\x64\x6f\x48",
	},
	{ /* M2 */
		.nid = NID_id_GostR3411_2012_512,
		.name = "M2",
		.plaintext =
			"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8"
			"\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee"
			"\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8"
			"\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20"
			"\xf1\x20\xec\xee\xf0\xff\x20\xf1"
			"\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20"
			"\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0"
			"\xfb\xff\x20\xef\xeb\xfa\xea\xfb"
			"\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
		.psize = 72,
		.digest =
			"\x1e\x88\xe6\x22\x26\xbf\xca\x6f"
			"\x99\x94\xf1\xf2\xd5\x15\x69\xe0"
			"\xda\xf8\x47\x5a\x3b\x0f\xe6\x1a"
			"\x53\x00\xee\xe4\x6d\x96\x13\x76"
			"\x03\x5f\xe8\x35\x49\xad\xa2\xb8"
			"\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3"
			"\x3f\x0c\xb9\xdd\xdc\x2b\x64\x60"
			"\x14\x3b\x03\xda\xba\xc9\xfb\x28",
	},
	{ 0 }
};

/* synthetic test */
static const struct hash_testvec stestvecs[] = {
	{
		.nid = NID_id_GostR3411_2012_256,
		.name = "streebog256",
		.mdsize = 32,
		.block_size = 64,
		.digest =
			"\xa2\xf3\x6d\x9c\x42\xa1\x1e\xad\xe3\xc1\xfe\x99\xf9\x99\xc3\x84"
			"\xe7\x98\xae\x24\x50\x75\x73\xd7\xfc\x99\x81\xa0\x45\x85\x41\xf6"
	}, {
		.nid = NID_id_GostR3411_2012_512,
		.name = "streebog512",
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

static int do_digest(int hash_nid, const char *plaintext, unsigned int psize,
    const char *etalon)
{
	unsigned int mdlen = 0;
	if (hash_nid == NID_id_GostR3411_2012_256)
		mdlen = 256 / 8;
	else if (hash_nid == NID_id_GostR3411_2012_512)
		mdlen = 512 / 8;
	const EVP_MD *mdtype;
	T(mdtype = EVP_get_digestbynid(hash_nid));
	EVP_MD_CTX *ctx;
	T(ctx = EVP_MD_CTX_new());
	T(EVP_DigestInit(ctx, mdtype));
	T(EVP_DigestUpdate(ctx, plaintext, psize));
	unsigned int len;
	unsigned char md[512 / 8];
	T(EVP_DigestFinal(ctx, md, &len));
	EVP_MD_CTX_free(ctx);
	if (len != mdlen) {
		printf(cRED "digest output len mismatch %u != %u (expected)\n" cNORM,
		    len, mdlen);
		return 1;
	}
	if (memcmp(md, etalon, mdlen) != 0) {
		printf(cRED "digest mismatch\n" cNORM);
		return 1;
	}

	return 0;
}

static int do_test(const struct hash_testvec *tv)
{
	int ret = 0;

	const char *mdname = NULL;
	if (tv->nid == NID_id_GostR3411_2012_256)
		mdname = "streebog256";
	else if (tv->nid == NID_id_GostR3411_2012_512)
		mdname = "streebog512";
	printf(cBLUE "Test 1 %s %s: " cNORM, mdname, tv->name);
	fflush(stdout);
	ret |= do_digest(tv->nid, tv->plaintext, tv->psize, tv->digest);

	/* Text alignment problems. */
	int shifts = 32;
	int i;
	char *buf;
	T(buf = OPENSSL_malloc(tv->psize + shifts));
	for (i = 0; i < shifts; i++) {
		memcpy(buf + i, tv->plaintext, tv->psize);
		ret |= do_digest(tv->nid, buf + i, tv->psize, tv->digest);
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
static int do_stest_once(const struct hash_testvec *tv, unsigned int shifts)
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
static int do_stest(const struct hash_testvec *tv)
{
    int ret = 0;

    printf(cBLUE "Test 2 %s: " cNORM, tv->name);
    fflush(stdout);

    unsigned int shifts;
    for (shifts = 0; shifts < 16 && !ret; shifts++)
	ret |= do_stest_once(tv, shifts);

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
    for (tv = testvecs; tv->nid; tv++)
	    ret |= do_test(tv);
    for (tv = stestvecs; tv->nid; tv++)
	    ret |= do_stest(tv);

    ENGINE_finish(eng);
    ENGINE_free(eng);

    if (ret)
	printf(cDRED "= Some tests FAILED!\n" cNORM);
    else
	printf(cDGREEN "= All tests passed!\n" cNORM);
    return ret;
}
