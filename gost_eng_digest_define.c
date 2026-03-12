#include "gost_eng_digest.h"
#include "gost_lcl.h"

#define GOST_DIGEST_NAME GostR3411_94_digest
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME GostR3411_2012_256_digest
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME GostR3411_2012_512_digest
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME Gost28147_89_mac
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME Gost28147_89_mac_12
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME magma_omac_mac
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME grasshopper_omac_mac
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME magma_ctracpkm_mac
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME

#define GOST_DIGEST_NAME grasshopper_ctracpkm_mac
#include "gost_eng_digest_define.h"
#undef GOST_DIGEST_NAME
