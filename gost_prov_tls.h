#pragma once

#include <openssl/core.h>

int gost_prov_get_tls_group_capability(OSSL_CALLBACK *cb, void *arg);
int gost_prov_get_tls_sigalg_capability(OSSL_CALLBACK *cb, void *arg);