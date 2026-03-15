#pragma once

#include <openssl/evp.h>
#include "gost_digest.h"

typedef int (digest_ctrl_fn)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);

typedef struct gost_eng_digest_st GOST_eng_digest;
struct gost_eng_digest_st {
    GOST_digest *digest;
    EVP_MD *md;
    digest_ctrl_fn *ctrl;
};

EVP_MD *GOST_eng_digest_init(GOST_eng_digest *d);
void GOST_eng_digest_deinit(GOST_eng_digest *d);
int GOST_eng_digest_nid(const GOST_eng_digest *d);

#define STRCAT_IMPL(prefix, suffix) prefix##suffix
#define STRCAT(prefix, suffix) STRCAT_IMPL(prefix, suffix)
#define ENG_DIGEST_NAME(GOST_DIGEST_NAME) STRCAT(GOST_DIGEST_NAME, _eng_digest)

extern GOST_eng_digest ENG_DIGEST_NAME(GostR3411_94_digest);
extern GOST_eng_digest ENG_DIGEST_NAME(GostR3411_2012_256_digest);
extern GOST_eng_digest ENG_DIGEST_NAME(GostR3411_2012_512_digest);
extern GOST_eng_digest ENG_DIGEST_NAME(Gost28147_89_mac);
extern GOST_eng_digest ENG_DIGEST_NAME(Gost28147_89_mac_12);
extern GOST_eng_digest ENG_DIGEST_NAME(magma_omac_mac);
extern GOST_eng_digest ENG_DIGEST_NAME(grasshopper_omac_mac);
extern GOST_eng_digest ENG_DIGEST_NAME(magma_ctracpkm_mac);
extern GOST_eng_digest ENG_DIGEST_NAME(grasshopper_ctracpkm_mac);
