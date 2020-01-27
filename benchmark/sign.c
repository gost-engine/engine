/**********************************************************************
 *             Simple benchmarking for gost-engine                    *
 *                                                                    *
 *             Copyright (c) 2018 Cryptocom LTD                       *
 *             Copyright (c) 2018 <vt@altlinux.org>.                  *
 *       This file is distributed under the same license as OpenSSL   *
 **********************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "../ansi_terminal.h"
#include "platform.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#ifdef _MSC_VER
#include "../getopt.h"
#else
#include <getopt.h>
#endif

const char *tests[] = {
    "md_gost12_256", "gost2012_256", "A",
    "md_gost12_256", "gost2012_256", "B",
    "md_gost12_256", "gost2012_256", "C",
    "md_gost12_256", "gost2012_256", "TCA",
    "md_gost12_256", "gost2012_256", "TCB",
    "md_gost12_256", "gost2012_256", "TCC",
    "md_gost12_256", "gost2012_256", "TCD",
    "md_gost12_512", "gost2012_512", "A",
    "md_gost12_512", "gost2012_512", "B",
    "md_gost12_512", "gost2012_512", "C",
    NULL,
};
const int tests_line_size = 3; 

static EVP_PKEY *create_key(const char *algname, const char *param)
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
    if(1!=EVP_PKEY_keygen_init(ctx))
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
    unsigned int data_len = 1;
    unsigned int cycles = 100;
    int name_length=0;
    int line_length;
    int option;
#ifndef _MSC_VER
    clockid_t option_clock_type = CLOCK_MONOTONIC;
#else
    #define     option_clock_type   void(0)
#endif
    int test, test_count = 0;
    
    opterr = 0;
    while((option = getopt(argc, argv, "l:c:C")) >= 0)
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
#ifndef _MSC_VER
            case 'C':
                option_clock_type = CLOCK_PROCESS_CPUTIME_ID;
                break;
#endif
            default:
                usage(argv[0]);
                break;
        }
    }
    if (optind < argc) usage(argv[0]);
    if (cycles < 100) { printf("cycles too low\n"); exit(1); }

    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    
    
    for (test = 0; tests[test]; test += tests_line_size) {
        line_length = strlen(tests[test+1]) + strlen(tests[test+2]);
        if(line_length>name_length){
            name_length = line_length;
        }
    }
    setupConsole();
    printf("%*soperations per sec\n",name_length,"");
    printf("%*s            sign      verify\n",name_length,"");
    
    for (test = 0; tests[test]; test += tests_line_size) {
        TIMER_INIT_EX(option_clock_type);
        int error_flag = 0;
        double diff[2]; /* sign, verify */
        const char *digest = tests[test];
        const char *algo   = tests[test + 1];
        const char *param  = tests[test + 2];
        const EVP_MD *mdtype;
        EVP_MD_CTX *md_ctx;
        unsigned int siglen;
        unsigned char *sigbuf;
        EVP_PKEY *pkey;
        unsigned char *data;
        int pass;

        md_ctx = EVP_MD_CTX_new();
        mdtype = EVP_get_digestbyname(digest);
        if (!mdtype)
            continue;
        
        pkey = create_key(algo, param);
        data = (unsigned char *) malloc(data_len);
        if (!pkey)
            continue;
        
        
        printf("wait...");
        fflush(stdout);
        siglen = EVP_PKEY_size(pkey);
        sigbuf = malloc(siglen * cycles);
        if (!sigbuf) {
            fprintf(stderr, cRED "No tests were run, malloc failure.\n");
            restoreConsole();
            exit(1);
        }

        for (pass = 0; pass < 2; pass++) {
            int err;
            
            unsigned int i;
            TIMER_START;

            if (pass == 0) { /* sign */
                for (i = 0; i < cycles; i++) {
                    EVP_SignInit(md_ctx, mdtype);
                    EVP_SignUpdate(md_ctx, data, data_len);
                    err = EVP_SignFinal(md_ctx, &sigbuf[siglen * i],
                        (unsigned int *)&siglen, pkey);
                    if (err != 1){
                        error_flag=1;
                        test_count++;
                    }
                    EVP_MD_CTX_reset(md_ctx);
                }
            } else { /* verify */
                for (i = 0; i < cycles; i++) {
                    EVP_VerifyInit(md_ctx, mdtype);
                    EVP_VerifyUpdate(md_ctx, data, data_len);
                    err = EVP_VerifyFinal(md_ctx, &sigbuf[siglen * i],
                        siglen, pkey);
                    EVP_MD_CTX_reset(md_ctx);
                    if (err != 1){
                        error_flag=1;
                        test_count++;
                    }
                }
            }

            TIMER_STOP;
            diff[pass] = elapsedTime;
        }
        /* pad length */
        line_length = name_length - strlen(algo) - strlen(param);
        
        printf(cNORM"\r%s %s%*s %s " cNORM "%10.1f  %10.1f\n", algo, param, line_length, "", (error_flag==1)?cRED"ERR":"   ",
        (double)cycles * 1000000 / diff[0], (double)cycles * 1000000 / diff[1]);
        EVP_PKEY_free(pkey);
        free(sigbuf);
        free(data);
    }
    restoreConsole();
    if (test_count) {
        fprintf(stderr, cRED "No tests were run,%i tests are failed .\n", test_count);
        exit(1);
    }
    exit(0);
    
}
