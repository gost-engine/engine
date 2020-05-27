/* SPDX-License-Identifier: Apache-2.0
 *
 * Sign benchmarker.
 *
 * Copyright (C) 2020 Vitaly Chikunov <vt@altlinux.org>.
 */

#define _GNU_SOURCE
#include <asm/unistd.h>
#include <assert.h>
#include <getopt.h>
#include <linux/perf_event.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

static int keygen_once = 1;     /* single private key */
static int data_once = 1;       /* same data to sign */
static int use_perf = -1;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
}

static EVP_PKEY *keygen(const char *algo, const char *param)
{
    char *stmp = NULL, *vtmp = NULL;
    static EVP_PKEY *key = NULL;

    if (keygen_once && key)
        return key;

    int pkey_id = OBJ_txt2nid(algo);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(pkey_id, NULL);
    if (!EVP_PKEY_keygen_init(ctx))
        goto err;

    if (param) {
        stmp = strdup(param);
        OPENSSL_assert(stmp);
        vtmp = strchr(stmp, ':');
        if (vtmp) {
            *vtmp = 0;
            vtmp++;
        }
    }

    if (param && !EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp)) {
        fprintf(stderr, "set parameter [%s] error\n", param);
        goto err;
    }

    if (!EVP_PKEY_keygen(ctx, &key)) {
        fprintf(stderr, "keygen(%s) error\n", OBJ_nid2sn(pkey_id));
        goto err;
    }

    EVP_PKEY_CTX_free(ctx);
    free(stmp);
    return key;
err:
    ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    free(stmp);
    exit(1);
}

static int cmptimeval(const void *a, const void *b)
{
    return timercmp((struct timeval *)a, (struct timeval *)b, >);
}

static long get_switches()
{
    struct rusage ru;

    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_nvcsw + ru.ru_nivcsw + ru.ru_minflt + ru.ru_majflt + ru.ru_nswap;
}

static int rand_bytes(unsigned char *buf, int num)
{
    unsigned char val = 1;

    while (--num >= 0)
        *buf++ = val++;
    return 1;
}

static int rand_status(void)
{
    return 1;
}

static RAND_METHOD rand_method = {
    NULL,
    rand_bytes,
    NULL,
    NULL,
    rand_bytes,
    rand_status
};

int main(int argc, char **argv)
{
    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    ENGINE *eng;
    if (!(eng = ENGINE_by_id("gost"))
        || !ENGINE_init(eng)
        || !ENGINE_set_default(eng, ENGINE_METHOD_ALL)) {
        goto out;
    }

    const char *algo = "gost2012_256";
    const char *param = NULL;
    const char *kfile = NULL;
    int cycles = 222, drop = -1;
    int raw = 0;
    int rdtsc = 0;
    int opt;
    while ((opt = getopt(argc, argv, "a:p:c:m:K:kdrtP:R")) != -1) {
        switch (opt) {
        case 'a':
            /* Signing algo to use. */
            algo = optarg;
            break;
        case 'p':
            param = optarg;
            break;
        case 'c':
            /* That much measurements */
            cycles = atoi(optarg);
            break;
        case 'm':
            /* Drop that much outliers */
            drop = atoi(optarg);
            break;
        case 'K':
            /* Read/write to file */
            kfile = optarg;
            break;
        case 'k':
            /* New key each time */
            keygen_once = 0;
            break;
        case 'd':
            /* New data each time. */
            data_once = 0;
            break;
        case 'r':
            /* Raw output instead of histogram. */
            raw = 1;
            break;
        case 'R':
            /* RAND determinism. */
            RAND_set_rand_method(&rand_method);
            break;
        case 't':
            /* Use RDTSC to measure CPU cycles instead of time. */
            rdtsc = 1;
            break;
        case 'P':
            /* Use perf_events, see perf_event.h */
            use_perf = atoi(optarg);
            break;
        }
    }

    if (!param && strncmp(algo, "gost", 4) == 0)
        param = "paramset:A";

    if (drop < 0)
        drop = cycles / 33; /* drop 3% of outliers */

    EVP_PKEY *key = NULL;
    if (kfile) {
        BIO *in;
        if ((in = BIO_new_file(kfile, "r"))) {
            fprintf(stderr, "Reading key from %s\n", kfile);
            OPENSSL_assert(PEM_read_bio_PrivateKey(in, &key, NULL, NULL));
            BIO_free(in);
            kfile = NULL;    /* disable writing */
        }
    }
    if (!key) {
        fprintf(stderr, "Using %s %s\n", algo, param? param : "");
        OPENSSL_assert(key = keygen(algo, param));
    }
    if (kfile && key) {
        BIO *out;
        if ((out = BIO_new_file(kfile, "w"))) {
            fprintf(stderr, "Writing key to %s\n", kfile);
            OPENSSL_assert(PEM_write_bio_PrivateKey(out, key, NULL, NULL, 0, NULL, NULL));
            BIO_free(out);
        }
    }

    struct perf_event_attr pe = {};
    long long events;
    int fd = -1;
    if (use_perf >= 0) {
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(struct perf_event_attr);
        pe.config = use_perf;
        pe.disabled = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;
        fd = perf_event_open(&pe, 0, -1, -1, 0);
        assert(fd);
    }

    unsigned char *sig;
    size_t siglen;
    assert(sig = OPENSSL_malloc(EVP_PKEY_size(key)));

    static unsigned char hash[64];

    EVP_PKEY_CTX *ctx = NULL;
    OPENSSL_assert(ctx = EVP_PKEY_CTX_new(key, NULL));

    struct timeval *mes = NULL;
    mes = malloc(sizeof(struct timeval) * cycles);

    mlockall(MCL_CURRENT|MCL_FUTURE);

    /* Measurement cycle. */
    long retry = 0;
    int i;
    for (i = 0; i < cycles; i++) {
        if (!keygen_once)
            OPENSSL_assert(key = keygen(algo, param));

        if (!data_once)
            RAND_bytes(hash, sizeof(hash));

        OPENSSL_assert(EVP_PKEY_sign_init(ctx));

        long switches;
        while (1) {
            switches = get_switches();

            struct timespec ts = {};
            struct timeval start, fin, delta;
            if (use_perf >= 0) {
                ioctl(fd, PERF_EVENT_IOC_RESET, 0);
                ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
                start.tv_usec = 0;
            } else if (rdtsc)
                start.tv_usec = __rdtsc();
            else {
                clock_gettime(CLOCK_MONOTONIC, &ts);
                TIMESPEC_TO_TIMEVAL(&start, &ts);
            }

            /* Measured work. */
            OPENSSL_assert(EVP_PKEY_sign(ctx, sig, &siglen, hash, sizeof(hash)));

            if (use_perf >= 0) {
                ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
                read(fd, &events, sizeof(long long));
                fin.tv_usec = events;
            } else if (rdtsc)
                fin.tv_usec = __rdtsc();
            else {
                clock_gettime(CLOCK_MONOTONIC, &ts);
                TIMESPEC_TO_TIMEVAL(&fin, &ts);
            }
            timersub(&fin, &start, &mes[i]);

            if (switches == get_switches())
                break;
            retry++;
            /* Retry if context was switched. */
        }
    }

    qsort(mes, cycles, sizeof(struct timeval), cmptimeval);
    int count = cycles - drop;
    unsigned long min = mes[0].tv_usec;
    unsigned long max = mes[count - 1].tv_usec;

    if (raw) {
        /* Raw data for plotting. */
        for (i = 0; i < (cycles - drop); i++)
            printf("%ld.%06ld\n", mes[i].tv_sec, mes[i].tv_usec);
        goto skip_hist;
    }

    /* Histogram to quick view over console. */
    int bins = 22; /* this isn't precise number */
    if (max - min < bins)
        bins = max - min;
    int width = (max - min) / bins;

    printf("min %lu max %lu (%s)\n", min, max,
           use_perf? "perf_events" :
           rdtsc? "cycles" : "microseconds");
    i = 0;
    int b;
    for (b = 0; i < count; b++) {
        unsigned long base = b * width;
        int n = 0;

        printf("%6lu:", min + base);
        while (i < count && mes[i].tv_usec < min + base + width) {
            n++;
            i++;
        }
        printf("%5d: ", n);

        /* draw line */
        int t;
        const int max_width = 80;
        int nn = n / (count / bins / (max_width / 2) + 1);
        if (n >= max_width)
            nn = max_width;
        for (t = 0; t < nn; t++)
            putchar('#');
        if (nn == max_width)
            printf("...");

        printf("\n");
    }
skip_hist:

    EVP_PKEY_CTX_free(ctx);
    free(sig);
    free(mes);
    EVP_PKEY_free(key);

out:
    ERR_print_errors_fp(stderr);
    ENGINE_finish(eng);
    ENGINE_free(eng);

    return 0;
}
/* vim: set expandtab cinoptions=\:0,l1,t0,g0,(0 sw=4 : */
