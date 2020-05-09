/*
 * Test GOST 34.11 Digest operation
 *
 * Copyright (C) 2019-2020 Vitaly Chikunov <vt@altlinux.org>. All Rights Reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include <openssl/engine.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#if OPENSSL_VERSION_MAJOR < 3
# include <openssl/hmac.h>
#else
# include <openssl/core_names.h>
#endif
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
 * Test keys from both GOST R 34.12-2015 and GOST R 34.13-2015,
 * for 128-bit cipher (A.1).
 */
static const char K[32] = {
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
};

/*
 * Key for 64-bit cipher (A.2).
 */
static const char Km[32] = {
    0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,
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

/* Plaintext for 64-bit cipher (A.2) */
static const char Pm[] = {
    0x92,0xde,0xf0,0x6b,0x3c,0x13,0x0a,0x59,0xdb,0x54,0xc7,0x04,0xf8,0x18,0x9d,0x20,
    0x4a,0x98,0xfb,0x2e,0x67,0xa8,0x02,0x4c,0x89,0x12,0x40,0x9b,0x17,0xb5,0x7e,0x41,
};

/*
 * Kuznyechik OMAC1/CMAC test vector from GOST R 34.13-2015 А.1.6
 */
static const char MAC_omac[] = { 0x33,0x6f,0x4d,0x29,0x60,0x59,0xfb,0xe3 };

/*
 * Magma OMAC1/CMAC test vector from GOST R 34.13-2015 А.2.6
 */
static const char MAC_magma_omac[] = { 0x15,0x4e,0x72,0x10 };

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

/* Some other test vectors. */
static const char etalon_M4[64] = { 0 };

static const char etalon_M5[] = {
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
};

static const char etalon_M6[] = {
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
    0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x20,0x0a,
};

static const char etalon_carry[] = {
    0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
    0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
    0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
    0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
    0x16,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x16,
};

struct hash_testvec {
    int nid;		   /* OpenSSL algorithm numeric id. */
    const char *name;	   /* Test name and source. */
    const char *plaintext; /* Input (of psize), NULL for synthetic test. */
    const char *digest;	   /* Expected output (of EVP_MD_size or truncate). */
    const char *hmac;	   /* Expected output for HMAC tests. */
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
    { /* Test vectors from standards. */
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
	.nid = NID_magma_mac,
	.name = "P from GOST R 34.13-2015 (А.2.6)",
	.plaintext = Pm,
	.psize = sizeof(Pm),
	.key = Km,
	.key_size = sizeof(Km),
	.digest = MAC_magma_omac,
	.mdsize = 64 / 8,
	.truncate = sizeof(MAC_magma_omac),
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
    { /* HMAC tests. */
	.nid = NID_id_GostR3411_2012_512,
	.name = "HMAC_GOSTR3411_2012_512 from RFC 7836 (B) and R 50.1.113-2016 (A)",
	.plaintext =
	    "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00",
	.psize = 16,
	.key =
	    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
	.key_size = 32,
	.hmac =
	    "\xa5\x9b\xab\x22\xec\xae\x19\xc6\x5f\xbd\xe6\xe5\xf4\xe9\xf5\xd8"
	    "\x54\x9d\x31\xf0\x37\xf9\xdf\x9b\x90\x55\x00\xe1\x71\x92\x3a\x77"
	    "\x3d\x5f\x15\x30\xf2\xed\x7e\x96\x4c\xb2\xee\xdc\x29\xe9\xad\x2f"
	    "\x3a\xfe\x93\xb2\x81\x4f\x79\xf5\x00\x0f\xfc\x03\x66\xc2\x51\xe6",
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "HMAC_GOSTR3411_2012_256 from RFC 7836 (B) and R 50.1.113-2016 (A)",
	.plaintext =
	    "\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00",
	.psize = 16,
	.key =
	    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
	.key_size = 32,
	.hmac =
	    "\xa1\xaa\x5f\x7d\xe4\x02\xd7\xb3\xd3\x23\xf2\x99\x1c\x8d\x45\x34"
	    "\x01\x31\x37\x01\x0a\x83\x75\x4f\xd0\xaf\x6d\x7c\xd4\x92\x2e\xd9",
    },
    /* Other KATs. */
    {
	.nid = NID_id_GostR3411_2012_512,
	.name = "Zero length string (M3)",
	.plaintext = "",
	.psize = 0,
	.digest =
	    "\x8e\x94\x5d\xa2\x09\xaa\x86\x9f\x04\x55\x92\x85\x29\xbc\xae\x46"
	    "\x79\xe9\x87\x3a\xb7\x07\xb5\x53\x15\xf5\x6c\xeb\x98\xbe\xf0\xa7"
	    "\x36\x2f\x71\x55\x28\x35\x6e\xe8\x3c\xda\x5f\x2a\xac\x4c\x6a\xd2"
	    "\xba\x3a\x71\x5c\x1b\xcd\x81\xcb\x8e\x9f\x90\xbf\x4c\x1c\x1a\x8a",
	.mdsize = 512 / 8,
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "Zero length string (M3)",
	.plaintext = "",
	.psize = 0,
	.digest =
	    "\x3f\x53\x9a\x21\x3e\x97\xc8\x02\xcc\x22\x9d\x47\x4c\x6a\xa3\x2a"
	    "\x82\x5a\x36\x0b\x2a\x93\x3a\x94\x9f\xd9\x25\x20\x8d\x9c\xe1\xbb",
	.mdsize = 256 / 8,
    },
    { /* M4 */
	.nid = NID_id_GostR3411_2012_512,
	.name = "64 bytes of zeros (M4)",
	.plaintext = etalon_M4,
	.psize = sizeof(etalon_M4),
	.digest =
	    "\xb0\xfd\x29\xac\x1b\x0d\xf4\x41\x76\x9f\xf3\xfd\xb8\xdc\x56\x4d"
	    "\xf6\x77\x21\xd6\xac\x06\xfb\x28\xce\xff\xb7\xbb\xaa\x79\x48\xc6"
	    "\xc0\x14\xac\x99\x92\x35\xb5\x8c\xb2\x6f\xb6\x0f\xb1\x12\xa1\x45"
	    "\xd7\xb4\xad\xe9\xae\x56\x6b\xf2\x61\x14\x02\xc5\x52\xd2\x0d\xb7"
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "64 bytes of zeros (M4)",
	.plaintext = etalon_M4,
	.psize = sizeof(etalon_M4),
	.digest =
	    "\xdf\x1f\xda\x9c\xe8\x31\x91\x39\x05\x37\x35\x80\x31\xdb\x2e\xca"
	    "\xa6\xaa\x54\xcd\x0e\xda\x24\x1d\xc1\x07\x10\x5e\x13\x63\x6b\x95"
    },
    { /* M5 */
	.nid = NID_id_GostR3411_2012_512,
	.name = "64 bytes of (M5)",
	.plaintext = etalon_M5,
	.psize = sizeof(etalon_M5),
	.digest =
	    "\x36\x3b\x44\x9e\xc8\x1a\xe4\x0b\x3a\x40\x7b\x12\x5c\x3b\x1c\x2b"
	    "\x76\x8b\x50\x49\x6b\xcb\x5f\x69\x0b\x89\xe9\x00\x7b\x06\xe4\x08"
	    "\x41\x82\xed\x45\xd4\x07\x2a\x67\xfe\xc9\xd3\x42\x1d\xab\x01\x3d"
	    "\xa2\xaa\xbc\x1d\x65\x28\xe8\xe7\x75\xae\xc7\xb3\x45\x7a\xc6\x75"
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "64 bytes of (M5)",
	.plaintext = etalon_M5,
	.psize = sizeof(etalon_M5),
	.digest =
	    "\xf0\xa5\x57\xf6\xa0\x4a\x90\xab\x18\x11\xc1\xb6\xe9\xb0\x78\xe4"
	    "\x16\x3b\x74\x03\x7c\x6c\xf5\x9f\x52\x44\x4a\x37\xf4\x8e\x11\xd8"
    },
    { /* M6 */
	.nid = NID_id_GostR3411_2012_512,
	.name = "(M6)",
	.plaintext = etalon_M6,
	.psize = sizeof(etalon_M6),
	.digest =
	    "\x87\x81\xdf\xc8\x1d\x2d\xb6\xa4\x1d\x18\x57\xf3\x23\x0b\x3f\xfe"
	    "\x2b\xda\x57\x42\x73\xea\x19\x47\x18\x9a\xaa\x54\x68\x47\x0d\xf1"
	    "\xc4\xb3\x74\xb1\xa2\xb5\x6e\x59\xd1\x1d\x21\x3f\xea\x57\xe3\x51"
	    "\x45\x43\xb0\xce\xd9\xb2\x0e\x55\x3a\xe6\x64\x25\xec\x90\x9c\xfd"
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "(M6)",
	.plaintext = etalon_M6,
	.psize = sizeof(etalon_M6),
	.digest =
	    "\x2f\x4f\x65\x1f\xe8\x8f\xea\x46\xec\x6f\x22\x23\x72\x8d\x8d\xff"
	    "\x39\x68\x89\x35\x58\xef\x00\xa3\x10\xc2\x3e\x7d\x19\x23\xba\x0c"
    },
    { /* carry */
	.nid = NID_id_GostR3411_2012_512,
	.name = "(carry)",
	.plaintext = etalon_carry,
	.psize = sizeof(etalon_carry),
	.digest =
	    "\x8b\x06\xf4\x1e\x59\x90\x7d\x96\x36\xe8\x92\xca\xf5\x94\x2f\xcd"
	    "\xfb\x71\xfa\x31\x16\x9a\x5e\x70\xf0\xed\xb8\x73\x66\x4d\xf4\x1c"
	    "\x2c\xce\x6e\x06\xdc\x67\x55\xd1\x5a\x61\xcd\xeb\x92\xbd\x60\x7c"
	    "\xc4\xaa\xca\x67\x32\xbf\x35\x68\xa2\x3a\x21\x0d\xd5\x20\xfd\x41"
    },
    {
	.nid = NID_id_GostR3411_2012_256,
	.name = "(carry)",
	.plaintext = etalon_carry,
	.psize = sizeof(etalon_carry),
	.digest =
	    "\x81\xbb\x63\x2f\xa3\x1f\xcc\x38\xb4\xc3\x79\xa6\x62\xdb\xc5\x8b"
	    "\x9b\xed\x83\xf5\x0d\x3a\x1b\x2c\xe7\x27\x1a\xb0\x2d\x25\xba\xbb"
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

#if OPENSSL_VERSION_MAJOR < 3
static int do_hmac(const EVP_MD *type, const char *plaintext,
    unsigned int psize, const char *etalon, int mdsize,
    const char *key, unsigned int key_size)
{
    unsigned int len;
    unsigned char md[EVP_MAX_MD_SIZE];

    HMAC_CTX *ctx;
    T(ctx = HMAC_CTX_new());
    T(HMAC_Init_ex(ctx, key, key_size, type, NULL));
    T(HMAC_Update(ctx, (const unsigned char *)plaintext, psize));
    T(HMAC_Final(ctx, md, &len));
    HMAC_CTX_free(ctx);

    if (mdsize)
	T(len == mdsize);
    if (memcmp(md, etalon, len) != 0) {
	printf(cRED "hmac mismatch\n" cNORM);
	hexdump(etalon, len);
	hexdump(md, len);
	return 1;
    }
    return 0;
}
#else
static int do_hmac(const EVP_MD *type, const char *plaintext,
    unsigned int psize, const char *etalon, int mdsize,
    const char *key, unsigned int key_size)
{
    size_t len;
    unsigned char md[EVP_MAX_MD_SIZE];

    EVP_MAC *hmac;
    T(hmac = EVP_MAC_fetch(NULL, "HMAC", NULL));
    EVP_MAC_CTX *ctx;
    T(ctx = EVP_MAC_CTX_new(hmac));
    OSSL_PARAM params[] = {
	OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST,
	    (char *)EVP_MD_name(type), 0),
	OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, (char *)key, key_size),
	OSSL_PARAM_END
    };
    T(EVP_MAC_CTX_set_params(ctx, params));
    T(EVP_MAC_init(ctx));
    T(EVP_MAC_update(ctx, (unsigned char *)plaintext, psize));
    T(EVP_MAC_final(ctx, md, &len, EVP_MAX_MD_SIZE));
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(hmac);

    if (mdsize)
	T(len == mdsize);
    if (memcmp(md, etalon, len) != 0) {
	printf(cRED "hmac mismatch\n" cNORM);
	hexdump(etalon, len);
	hexdump(md, len);
	return 1;
    }
    return 0;
}
#endif

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
	hexdump(etalon, mdsize);
	hexdump(md, mdsize);
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
    printf(cBLUE "%s Test %s: %s: " cNORM, tv->hmac? "HMAC" : "MD",
	name, tv->name);
    fflush(stdout);
    if (tv->hmac)
	ret |= do_hmac(type, tv->plaintext, tv->psize, tv->hmac,
	    tv->mdsize, tv->key, tv->key_size);
    else
	ret |= do_digest(type, tv->plaintext, tv->psize, tv->digest,
	    tv->mdsize, tv->truncate, tv->key, tv->key_size, tv->acpkm,
	    tv->acpkm_t, tv->block_size);

    /* Test alignment problems. */
    int shifts = 32;
    int i;
    char *buf;
    T(buf = OPENSSL_malloc(tv->psize + shifts));
    for (i = 0; i < shifts; i++) {
	memcpy(buf + i, tv->plaintext, tv->psize);
	if (tv->hmac)
	    ret |= do_hmac(type, buf + i, tv->psize, tv->hmac,
		tv->mdsize, tv->key, tv->key_size);
	else
	    ret |= do_digest(type, buf + i, tv->psize, tv->digest,
		tv->mdsize, tv->truncate, tv->key, tv->key_size,
		tv->acpkm, tv->acpkm_t, tv->block_size);
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

    printf(cBLUE "MD Test %s: " cNORM, tv->name);
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
