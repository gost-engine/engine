#pragma once

#include <openssl/evp.h>
#include "gost_lcl.h"

struct gost_eng_cipher_st;
typedef struct gost_eng_cipher_st GOST_eng_cipher;

EVP_CIPHER *GOST_eng_cipher_init(GOST_eng_cipher *c);
void GOST_eng_cipher_deinit(GOST_eng_cipher *c);
int GOST_eng_cipher_nid(const GOST_eng_cipher *c);

#define STRCAT_IMPL(prefix, suffix) prefix##suffix
#define STRCAT(prefix, suffix) STRCAT_IMPL(prefix, suffix)
#define ENG_CIPHER_NAME(GOST_CIPHER_NAME) STRCAT(GOST_CIPHER_NAME, _eng_cipher)

extern GOST_eng_cipher ENG_CIPHER_NAME(Gost28147_89_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(Gost28147_89_cbc_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(Gost28147_89_cnt_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(Gost28147_89_cnt_12_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(magma_ctr_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(magma_ctr_acpkm_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(magma_ctr_acpkm_omac_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(magma_ecb_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(magma_cbc_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(magma_mgm_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_ecb_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_cbc_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_cfb_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_ofb_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_ctr_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_mgm_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_ctr_acpkm_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(grasshopper_ctr_acpkm_omac_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(magma_kexp15_cipher);
extern GOST_eng_cipher ENG_CIPHER_NAME(kuznyechik_kexp15_cipher);

