#ifndef GOST_PROV_H
#define GOST_PROV_H

#define GOST_PROV_VERSION_STR "3.0.0"
#define GOST_PROV_FULL_VERSION_STR "3.0.0"
#define GOST_PROV_NAME "GOST Provider"
/* Basic definitions */
typedef void (*funcptr_t)(void);

/* Digest */
extern OSSL_DISPATCH streebog256_funcs[];
/* extern OSSL_DISPATCH streebog512_funcs[]; */

#endif
