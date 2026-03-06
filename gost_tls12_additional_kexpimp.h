#pragma once

#include <stddef.h>

/* KExp/KImp */
int gost_kexp15(const unsigned char *shared_key, const int shared_len,
                int cipher_nid, const unsigned char *cipher_key,
                int mac_nid, unsigned char *mac_key,
                const unsigned char *iv, const size_t ivlen,
                unsigned char *out, int *out_len);
int gost_kimp15(const unsigned char *expkey, const size_t expkeylen,
                int cipher_nid, const unsigned char *cipher_key,
                int mac_nid, unsigned char *mac_key,
                const unsigned char *iv, const size_t ivlen,
                unsigned char *shared_key);
