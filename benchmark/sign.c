/**********************************************************************
 *             Copyright (c) 2018 Cryptocom LTD                       *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

static EVP_PKEY *create_key(char *algname, char *param)
{
	EVP_PKEY *key1 = EVP_PKEY_new(), *newkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	if(EVP_PKEY_set_type_str(key1, algname, strlen(algname)) <= 0)
	{
		goto err;
	}
	if(!(ctx = EVP_PKEY_CTX_new(key1, NULL)))
	{
		goto err;
	}
	EVP_PKEY_keygen_init(ctx);
	if(ERR_peek_last_error())
	{
		goto err;
	}
	if(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", param) <= 0)
	{
		goto err;
	}
	if(EVP_PKEY_keygen(ctx, &newkey) <= 0)
	{
		goto err;
	}
err:
	if(ctx)
		EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key1);
	return newkey;
}

void usage(char *name)
{
	fprintf(stderr, "usage: %s [-l data_len] [-c cycles]\n", name);
	exit(1);
}

int main(int argc, char **argv)
{
	unsigned char *data;
	const EVP_MD *mdtype;
	EVP_MD_CTX md_ctx;
	int siglen;
	unsigned char *sigbuf;
	EVP_PKEY *pkey;
	unsigned int compter;
	time_t debut, fin;
	unsigned int data_len = 1024;
	unsigned int cycles = 8000;
	int option;
	opterr = 0;
	while((option = getopt(argc, argv, "l:c:")) >= 0)
	{
		if(option == ':') option = optopt;
		if(optarg && (optarg[0] == '-')) { optind--; optarg = NULL; }
		switch (option)
		{
			case 'l':
				data_len = atoi(optarg);
				break;
			case 'c':
				cycles = atoi(optarg);
				break;
			default:
				usage(argv[0]);
				break;
		}
	}
	if (optind < argc) usage(argv[0]);
	OPENSSL_config(NULL);
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	mdtype = EVP_get_digestbyname("md_gost12_256");
	pkey = create_key("gost2012_256", "A");
	data = (unsigned char *) malloc(data_len);
	printf("wait"); fflush(stdout);
	siglen = EVP_PKEY_size(pkey);
	sigbuf = malloc(siglen);
	debut = time(NULL);
	for(compter = 0; compter < cycles; compter++)
	{
		EVP_SignInit(&md_ctx, mdtype);
		EVP_SignUpdate(&md_ctx, data, data_len);
		EVP_SignFinal(&md_ctx, sigbuf, (unsigned int *) &siglen, pkey);
		EVP_MD_CTX_cleanup(&md_ctx);
	}
	fin = time(NULL);
	printf("\b\b\b\b");
	if ((fin - debut) < 3) { printf("cycles too low\n"); exit(1); }
	printf("sign: %d/s\n", compter / (unsigned int)(fin - debut));
	EVP_PKEY_free(pkey);
	free(sigbuf);
	free(data);
	exit(0);
}
