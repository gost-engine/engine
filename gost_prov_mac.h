#pragma once

#include <openssl/types.h>

void GOST_prov_init_macs(void);
void GOST_prov_deinit_macs(void);

extern const OSSL_ALGORITHM GOST_prov_macs[];
