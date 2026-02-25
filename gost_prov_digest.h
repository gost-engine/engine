#pragma once

#include <openssl/types.h>

void GOST_prov_init_digests(void);
void GOST_prov_deinit_digests(void);

extern const OSSL_ALGORITHM GOST_prov_digests[];
