#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/params.h>

#include "gost_prov.h"
#include "gosthash2012.h"

const char micalg_256[] = "gostr3411-2012-256";
const char micalg_512[] = "gostr3411-2012-512";

/* Context management */
static void *STREEBOG256_newctx(void *provctx);
static void STREEBOG_freectx(void *dctx);
static void *STREEBOG_dupctx(void *dctx);

/* Digest generation */
static int STREEBOG256_digest_init(void *dctx);
static int STREEBOG_digest_update(void *dctx, const unsigned char *in, size_t inl);
static int STREEBOG_digest_final(void *dctx, unsigned char *out, size_t *outl,
                    size_t outsz);

/* Digest parameter descriptors */
static const OSSL_PARAM *STREEBOG_gettable_params(void);
static int STREEBOG256_digest_get_params(OSSL_PARAM params[]);

OSSL_DISPATCH streebog256_funcs[] = {
	{ OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)STREEBOG256_newctx },
	{ OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)STREEBOG_freectx },
	{ OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)STREEBOG_dupctx },

	{ OSSL_FUNC_DIGEST_INIT, (funcptr_t)STREEBOG256_digest_init },
	{ OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)STREEBOG_digest_update },
	{ OSSL_FUNC_DIGEST_FINAL, (funcptr_t)STREEBOG_digest_final },

	{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)STREEBOG_gettable_params },
	{ OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)STREEBOG256_digest_get_params },

	{ 0, NULL },
};

static void *STREEBOG256_newctx(void *provctx)
{
	gost2012_hash_ctx *pctx = OPENSSL_zalloc(sizeof(gost2012_hash_ctx));
	return pctx;
}

static void STREEBOG_freectx(void *dctx)
{
	OPENSSL_free(dctx);
}

static void *STREEBOG_dupctx(void *dctx) 
{
	gost2012_hash_ctx *pctx = OPENSSL_zalloc(sizeof(gost2012_hash_ctx));
	if (pctx == NULL)
		return NULL;
	
	if (pctx)
		memcpy(pctx, dctx, sizeof(gost2012_hash_ctx));
	
	return pctx;
}

static int STREEBOG256_digest_init(void *dctx)
{
	init_gost2012_hash_ctx((gost2012_hash_ctx *)dctx, 256);
	return 1;
}

static int STREEBOG_digest_update(void *dctx, const unsigned char *in, size_t inl)
{
    gost2012_hash_block((gost2012_hash_ctx *)dctx, in, inl);
    return 1;
}

static int STREEBOG_digest_final(void *dctx, unsigned char *out, size_t *outl,
                    size_t outsz)
{
	gost2012_hash_ctx *pctx = (gost2012_hash_ctx *)dctx;

	if (pctx->digest_size/8 > outsz)
		return 0;

	gost2012_finish_hash(pctx, out);
	*outl = pctx->digest_size/8;
	return 1;
}

static const OSSL_PARAM *STREEBOG_gettable_params(void)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t("blocksize", NULL),
        OSSL_PARAM_size_t("size", NULL),
  /*      OSSL_PARAM_utf8_ptr("micalg", NULL, strlen(micalg_256)+1), */
        OSSL_PARAM_END
    };

    return table;
}

static int STREEBOG256_digest_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "blocksize")) != NULL)
        if (!OSSL_PARAM_set_size_t(p, 64))
            return 0;
    if ((p = OSSL_PARAM_locate(params, "size")) != NULL)
        if (!OSSL_PARAM_set_size_t(p, 32))
            return 0;
/*    if ((p = OSSL_PARAM_locate(params, "micalg")) != NULL)
        if (!OSSL_PARAM_set_utf8_ptr(p, micalg_256))
            return 0; */
    return 1;
}
