/**********************************************************************
 *      gost_prov_key.c - Key managmenent and encoding/decoding       *
 *                                                                    *
 *      Copyright (c) 2025 Victor Wagner <vitus@wagner.pp.ru>         *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *         OpenSSL provider interface to GOST cipher functions        *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "gost_prov.h"
#include "gost_lcl.h"

static OSSL_FUNC_keymgmt_new_fn gost2012_256_ctx_new;
static OSSL_FUNC_keymgmt_new_fn gost2012_512_ctx_new;
static OSSL_FUNC_keymgmt_free_fn gost2012_free;
static OSSL_FUNC_keymgmt_gen_init_fn gost2012_256_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn gost2012_512_gen_init;
static OSSL_FUNC_keymgmt_gen_cleanup_fn gost2012_ctx_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn gost2012_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn gost2012_settable_params;
static OSSL_FUNC_keymgmt_gen_set_template_fn gost2012_set_template;
static OSSL_FUNC_keymgmt_gen_fn gost2012_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn gost2012_cleanup;
static OSSL_FUNC_keymgmt_has_fn gost2012_has;
static OSSL_FUNC_keymgmt_validate_fn gost2012_validate;
static OSSL_FUNC_keymgmt_match_fn gost2012_match;
static OSSL_FUNC_keymgmt_query_operation_name_fn gost2012_256_query_operation;
static OSSL_FUNC_keymgmt_query_operation_name_fn gost2012_512_query_operation;
static OSSL_FUNC_keymgmt_get_params_fn gost2012_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn gost2012_gettable_params;
struct gost2012_keygen_ctx {
	int algorithm;
	int params;
};

typedef void (*fptr_t)(void);

static OSSL_DISPATCH gost2012_256_km_functions[]={
{OSSL_FUNC_KEYMGMT_NEW,(fptr_t) gost2012_256_ctx_new},
{OSSL_FUNC_KEYMGMT_FREE,(fptr_t) gost2012_free},
{OSSL_FUNC_KEYMGMT_GEN_INIT,(fptr_t)gost2012_256_gen_init},
{OSSL_FUNC_KEYMGMT_GEN_CLEANUP,(fptr_t) gost2012_ctx_cleanup},
{OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,(fptr_t)gost2012_settable_params},
{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,(fptr_t)gost2012_set_params},
{OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,(fptr_t)gost2012_set_template},
{OSSL_FUNC_KEYMGMT_GEN,(fptr_t)gost2012_gen},
{OSSL_FUNC_KEYMGMT_HAS,(fptr_t)gost2012_has},
{OSSL_FUNC_KEYMGMT_VALIDATE,(fptr_t)gost2012_validate},
{OSSL_FUNC_KEYMGMT_MATCH,(fptr_t) gost2012_match},
{OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,(fptr_t) gost2012_256_query_operation},
{OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,(fptr_t) gost2012_gettable_params},
{OSSL_FUNC_KEYMGMT_GET_PARAMS,(fptr_t) gost2012_get_params},
{0,NULL}
};
static OSSL_DISPATCH gost2012_512_km_functions[]={
{OSSL_FUNC_KEYMGMT_NEW,(fptr_t)gost2012_512_ctx_new},
{OSSL_FUNC_KEYMGMT_FREE,(fptr_t)gost2012_free},
{OSSL_FUNC_KEYMGMT_GEN_INIT,(fptr_t)gost2012_512_gen_init},
{OSSL_FUNC_KEYMGMT_GEN_CLEANUP,(fptr_t) gost2012_ctx_cleanup},
{OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,(fptr_t)gost2012_settable_params},
{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,(fptr_t)gost2012_set_params},
{OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,(fptr_t)gost2012_set_template},
{OSSL_FUNC_KEYMGMT_GEN,(fptr_t)gost2012_gen},
{OSSL_FUNC_KEYMGMT_HAS,(fptr_t)gost2012_has},
{OSSL_FUNC_KEYMGMT_VALIDATE,(fptr_t)gost2012_validate},
{OSSL_FUNC_KEYMGMT_MATCH,(fptr_t)gost2012_match},
{OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,(fptr_t) gost2012_512_query_operation},
{OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,(fptr_t) gost2012_gettable_params},
{OSSL_FUNC_KEYMGMT_GET_PARAMS,(fptr_t) gost2012_get_params},
{0,NULL}
};



const OSSL_ALGORITHM GOST_prov_keymgmt[] = {
   { SN_id_GostR3410_2012_256 ":1.643.7.1.1.1.1","provider=gost",gost2012_256_km_functions},
   { SN_id_GostR3410_2012_512 ":1.643.7.1.1.1.2","provider=gost",gost2012_512_km_functions},
   {NULL,NULL,NULL}
};

static struct gost2012_keygen_ctx *gost2012_new(int alg) 
{
	struct gost2012_keygen_ctx *newkey = calloc(1,sizeof(struct gost2012_keygen_ctx));
	newkey->algorithm = alg;
	return newkey;
}


static void *gost2012_256_ctx_new(void *provctx)
{
  return gost2012_new(NID_id_GostR3410_2012_256);
}

static void *gost2012_512_ctx_new(void *provctx)
{
  return gost2012_new(NID_id_GostR3410_2012_512);
}

static void gost2012_ctx_cleanup(void *genctx)
{
	struct gost2012_keygen_ctx *k=genctx;
	free(k);
}

static void gost2012_key_free(void *keydata) 
{
	EC_KEY_free((EC_KEY *)keydata);
}

static struct gost2012_keygen_ctx *gost2012_gen_init(int algorithm,
              int selection, const OSSL_PARAM params[])
{
	struct gost2012_keygen_ctx *newctx = gost2012_new(algorithm);
	/* FIXME There we should deal with selection param */
	if (!gost2012_set_params(newctx, params)) {
		gost2012_ctx_cleanup(newctx);
		return NULL;
	}
	return newctx;

}

static void* gost2012_256_gen_init(void *provctx, int selection,
                                   const OSSL_PARAM params[])
{
	return gost2012_gen_init(NID_id_GostR3410_2012_256,selection,params);
}
static void* gost2012_512_gen_init(void *provctx, int selection,
                                   const OSSL_PARAM params[])
{
	return gost2012_gen_init(NID_id_GostR3410_2012_512,selection,params);
}

static int gost2012_set_template(void *genctx, void *template)
{
   struct gost2012_keygen_ctx *k=genctx;
   EC_KEY *t=template;
   const EC_GROUP *group = EC_KEY_get0_group(t);
   int bits = EC_GROUP_order_bits(group);
   if ((k->algorithm == NID_id_GostR3410_2012_512 && bits != 512)
       || (k->algorithm == NID_id_GostR3410_2012_256 && bits != 256)) {
   	   /* Error key size mismatch*/
	   return 0;
   }
   k->params = EC_GROUP_get_curve_name(group);
   /* Error template parameter is not initalized */
   return 0;
}

struct paramset_lookup {
	int algorithm;
	int paramset;
	char name;
};
static struct paramset_lookup paramset_table[]={
{NID_id_GostR3410_2012_256,NID_id_tc26_gost_3410_2012_256_paramSetA,'A'},
{NID_id_GostR3410_2012_256,NID_id_tc26_gost_3410_2012_256_paramSetB,'B'},
{NID_id_GostR3410_2012_256,NID_id_tc26_gost_3410_2012_256_paramSetC,'C'},
{NID_id_GostR3410_2012_256,NID_id_tc26_gost_3410_2012_256_paramSetD,'D'},
{NID_id_GostR3410_2012_256,NID_id_tc26_gost_3410_2012_512_paramSetA,'A'},
{NID_id_GostR3410_2012_256,NID_id_tc26_gost_3410_2012_512_paramSetB,'B'},
{NID_id_GostR3410_2012_256,NID_id_tc26_gost_3410_2012_512_paramSetC,'C'},
{NID_undef,NID_undef,0}
};

static int gost2012_paramset_nid(int algorithm, const char *paramset)
{
	struct paramset_lookup *p;
	for(p = paramset_table; p->name; p++) 
	{
		if (p->algorithm == algorithm && p->name == *paramset)
			return p->paramset;
	}
	return NID_undef;
}
static int gost2012_set_params(void *genctx, const OSSL_PARAM params[])
{	
	struct gost2012_keygen_ctx *k = genctx;
	const OSSL_PARAM *p;
	if (! params[0].key)
		return 1; /* Ok not to set anything */
    p = OSSL_PARAM_locate_const(params,"paramset");
	if (p) {
		const char *paramset;
	    OSSL_PARAM_get_utf8_string_ptr(p,&paramset);
		k->params = gost2012_paramset_nid(k->algorithm, paramset);
		if (k->params != NID_undef)
			return 1;
	}
	return 0;
}

static const OSSL_PARAM *gost2012_settable_params(void *provctx, void *genctx) 
{
	static const OSSL_PARAM settable_params[]={
	OSSL_PARAM_utf8_string("paramset",NULL,0),
	OSSL_PARAM_END
	};
	return settable_params;
}

static void *gost2012_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg) 
{
	struct gost2012_keygen_ctx *k=genctx;
	EC_KEY *newkey;
	if (k->params == 0) {
		/* Error - parameters are not initialized */
		return NULL;
	}
	newkey = EC_KEY_new_by_curve_name(k->params);
	if (newkey == NULL) 
		return NULL;
	EC_KEY_generate_key(newkey);
	return newkey;
}

static int gost2012_has(const void *keydata, int selection)
{
	const EC_KEY* key= keydata;
	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (EC_KEY_get0_private_key(key) == NULL)
			return 0;
    }
	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
		if (EC_KEY_get0_public_key(key) == NULL)
			return 0;
	}
	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
		if (EC_KEY_get0_group(key) == NULL)
			return 0;
	}
	return 1;
}

static void gost2012_free(void *keydata)
{
	EC_KEY_free((EC_KEY *)keydata);
}

int gost2012_validate(const void *keydata, int selection, int checktype)
{
	const EC_KEY *key=keydata;
	if (!gost2012_has(keydata, selection) )
		return 0;
	/* Validation of domain parameters - ensure that curve is listed
	 * in the paramset table
	 */
	if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) 
	{
		const EC_GROUP *group = EC_KEY_get0_group(key);
		int algorithm,params;
		struct paramset_lookup *p;
		if  (EC_GROUP_order_bits(group) == 512)
			algorithm = NID_id_GostR3410_2012_512;
		else
			algorithm = NID_id_GostR3410_2012_256;
		params = EC_GROUP_get_curve_name(group);
		for(p=paramset_table; p->algorithm !=0; p++) 
		{
			if (p->algorithm == algorithm && p->paramset == params) 
			 	break;
		}
		if (p->algorithm == NID_undef)
			return 0;
	}
	if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR) 
	{
		return EC_KEY_check_key(key);
	}
	return 1;
}

static int gost2012_match(const void* keydata1, const void *keydata2, int selection)
{
	const EC_KEY *ec1 = keydata1;
	const EC_KEY *ec2 = keydata2;

	const EC_GROUP *group1 = EC_KEY_get0_group(ec1);
	BN_CTX *ctx = NULL;
	int ok = 1;
 	if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) !=0)
	  	ok = ok && EC_GROUP_get_curve_name(group1) == 
		EC_GROUP_get_curve_name(EC_KEY_get0_group(ec2));
	if ((selection && OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
		int key_checked = 0;
		if ((selection && OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
		{
		   const EC_POINT *p1 = EC_KEY_get0_public_key(ec1);
		   const EC_POINT *p2 = EC_KEY_get0_public_key(ec2);
		   if (p1 != NULL && p2 !=NULL) {
	   	   ctx = BN_CTX_new();
		       ok= ok && EC_POINT_cmp(group1, p1, p2, ctx) == 0;
			   key_checked =1;
		   }
		}
		if (! key_checked &&
		    (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
			const BIGNUM *p1 = EC_KEY_get0_private_key(ec1);
			const BIGNUM *p2 = EC_KEY_get0_private_key(ec2);
			if (p1 != NULL && p2 != NULL) {
			     ok = ok && BN_cmp(p1, p2) == 0;
			}
		}
	}
	if (ctx) BN_CTX_free(ctx);
	return ok;
}

int gost2012_get_params(void *keydata, OSSL_PARAM params[]) 
{
    EC_KEY *key = keydata;
    int paramset = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
    int bits = EC_GROUP_order_bits(EC_KEY_get0_group(key));
	OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, "paramset"))!=NULL) {
		int algorithm;
		struct paramset_lookup *q;
		char strval[2] = {0,0};
		if  (bits == 512)
			algorithm = NID_id_GostR3410_2012_512;
		else
			algorithm = NID_id_GostR3410_2012_256;
		for (q = paramset_table; q->algorithm; q++) {
			if (q->algorithm == algorithm && q->paramset == paramset) 
				break;
		}
		if (q->algorithm == 0) 
			return 0;
		strval[0] = q->name;
		OSSL_PARAM_set_utf8_string(p, strval);
	}
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
	    OSSL_PARAM_set_int(p, bits);
	}
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE))!=NULL) {
		OSSL_PARAM_set_int(p, ECDSA_size(key));
	}
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS))!=NULL) {
		OSSL_PARAM_set_int(p, bits/2);
	}
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST))!=NULL) {
		OSSL_PARAM_set_utf8_string(p,bits==512?SN_id_GostR3411_2012_512:
		                           SN_id_GostR3411_2012_256);
	}
	return 1;
}


static const OSSL_PARAM *gost2012_gettable_params(void *provctx) 
{

	static const OSSL_PARAM gettable_params[]={
	OSSL_PARAM_utf8_string("paramset",NULL,0),
	OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS,0),
	OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE,0),
	OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS,0),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST,NULL,0),
	OSSL_PARAM_END
	};
	return gettable_params;
}

const char *gost2012_256_query_operation(int operation_id) {
	return SN_id_GostR3410_2012_256;
}
const char *gost2012_512_query_operation(int operation_id) {
	return SN_id_GostR3410_2012_512;
}
