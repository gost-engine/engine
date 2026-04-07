#pragma once

#include <openssl/evp.h>

int register_pmeth_gost(int id, EVP_PKEY_METHOD **pmeth, int flags);
