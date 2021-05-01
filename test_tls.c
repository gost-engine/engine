/*
 * Simple Client/Server connection test
 *
 * Based on OpenSSL example code.
 * Copyright (C) 2019 vt@altlinux.org. All Rights Reserved.
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 */

#include "e_gost_err.h"
#include "gost_lcl.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* For X509_NAME_add_entry_by_txt */
#pragma GCC diagnostic ignored "-Wpointer-sign"

#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })
#define TE(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		fprintf(stderr, "Error at %s:%d %s\n", __FILE__, __LINE__, #e); \
		return -1; \
	    } \
        })

#define cRED	"\033[1;31m"
#define cDRED	"\033[0;31m"
#define cGREEN	"\033[1;32m"
#define cDGREEN	"\033[0;32m"
#define cBLUE	"\033[1;34m"
#define cDBLUE	"\033[0;34m"
#define cNORM	"\033[m"
#define TEST_ASSERT(e) {if ((test = (e))) \
		 printf(cRED "  Test FAILED\n" cNORM); \
	     else \
		 printf(cGREEN "  Test passed\n" cNORM);}

struct certkey {
    EVP_PKEY *pkey;
    X509 *cert;
};

static int verbose;
static const char *cipher_list;

/* How much K to transfer between client and server. */
#define KTRANSFER (1 * 1024)

static void err(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf(": %s\n", strerror(errno));
    exit(eval);
}

/*
 * Simple TLS Server code is based on
 * https://wiki.openssl.org/index.php/Simple_TLS_Server
 */
static int s_server(EVP_PKEY *pkey, X509 *cert, int client)
{
    SSL_CTX *ctx;
    T(ctx = SSL_CTX_new(TLS_server_method()));
    T(SSL_CTX_use_certificate(ctx, cert));
    T(SSL_CTX_use_PrivateKey(ctx, pkey));
    T(SSL_CTX_check_private_key(ctx));

    SSL *ssl;
    T(ssl = SSL_new(ctx));
    T(SSL_set_fd(ssl, client));
    if (cipher_list)
	T(SSL_set_cipher_list(ssl, cipher_list));
    T(SSL_accept(ssl) == 1);

    /* Receive data from client */
    char buf[1024];
    int i;
    for (i = 0; i < KTRANSFER; i++) {
	int k;

	T(SSL_read(ssl, buf, sizeof(buf)) == sizeof(buf));
	for (k = 0; k < sizeof(buf); k++)
	    if (buf[k] != 'c')
		err(1, "corruption from client");
    }
    /* Send data to client. */
    memset(buf, 's', sizeof(buf));
    for (i = 0; i < KTRANSFER; i++) {
	T(SSL_write(ssl, buf, sizeof(buf)) == sizeof(buf));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);

    SSL_CTX_free(ctx);
    return 0;
}

/*
 * Simple TLC Client code is based on man BIO_f_ssl and
 * https://wiki.openssl.org/index.php/SSL/TLS_Client
 */
static int s_client(int server)
{
    SSL_CTX *ctx;
    T(ctx = SSL_CTX_new(TLS_client_method()));

    BIO *sbio;
    T(sbio = BIO_new_ssl_connect(ctx));
    SSL *ssl;
    T(BIO_get_ssl(sbio, &ssl));
    T(SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY));
    if (cipher_list)
	T(SSL_set_cipher_list(ssl, cipher_list));
#if 0
    /* Does not work with reneg. */
    BIO_set_ssl_renegotiate_bytes(sbio, 100 * 1024);
#endif
    T(SSL_set_fd(ssl, server));
    T(BIO_do_handshake(sbio) == 1);

    printf("Protocol: %s\n", SSL_get_version(ssl));
    printf("Cipher:   %s\n", SSL_get_cipher_name(ssl));
    if (verbose) {
	SSL_SESSION *sess = SSL_get0_session(ssl);
	SSL_SESSION_print_fp(stdout, sess);
    }

    X509 *cert;
    T(cert = SSL_get_peer_certificate(ssl));
    X509_free(cert);
    int verify = SSL_get_verify_result(ssl);
    printf("Verify:   %s\n", X509_verify_cert_error_string(verify));
    if (verify != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	err(1, "invalid SSL_get_verify_result");

    /* Send data to server. */
    char buf[1024];
    int i;
    memset(buf, 'c', sizeof(buf));
    for (i = 0; i < KTRANSFER; i++) {
	T(BIO_write(sbio, buf, sizeof(buf)) == sizeof(buf));
    }
    (void)BIO_shutdown_wr(sbio);

    /* Receive data from server. */
    for (i = 0; i < KTRANSFER; i++) {
	int k;
	int n = BIO_read(sbio, buf, sizeof(buf));

	if (n != sizeof(buf)) {
	    printf("i:%d BIO_read:%d SSL_get_error:%d\n", i, n,
		SSL_get_error(ssl, n));
	    ERR_print_errors_fp(stderr);
	    err(1, "BIO_read");
	}

	for (k = 0; k < sizeof(buf); k++)
	    if (buf[k] != 's')
		err(1, "corruption from server");
    }

    i = BIO_get_num_renegotiates(sbio);
    if (i)
	printf("Renegs:   %d\n", i);
    BIO_free_all(sbio);
    SSL_CTX_free(ctx);

    return 0;
}

/* Generate simple cert+key pair. Based on req.c */
static struct certkey certgen(const char *algname, const char *paramset)
{
    /* Keygen. */
    EVP_PKEY *tkey;
    T(tkey = EVP_PKEY_new());
    T(EVP_PKEY_set_type_str(tkey, algname, strlen(algname)));
    EVP_PKEY_CTX *ctx;
    T(ctx = EVP_PKEY_CTX_new(tkey, NULL));
    T(EVP_PKEY_keygen_init(ctx));
    if (paramset)
	T(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", paramset));
    EVP_PKEY *pkey = NULL;
    T((EVP_PKEY_keygen(ctx, &pkey)) == 1);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(tkey);

    /* REQ. */
    X509_REQ *req = NULL;
    T(req = X509_REQ_new());
    T(X509_REQ_set_version(req, 0L));
    X509_NAME *name;
    T(name = X509_NAME_new());
    T(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "Test CA", -1, -1, 0));
    T(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Test Key", -1, -1, 0));
    T(X509_REQ_set_subject_name(req, name));
    T(X509_REQ_set_pubkey(req, pkey));
    X509_NAME_free(name);

    /* Cert. */
    X509 *x509ss = NULL;
    T(x509ss = X509_new());
    T(X509_set_version(x509ss, 2));
    BIGNUM *brnd = BN_new();
    T(BN_rand(brnd, 20 * 8 - 1, -1, 0));
    T(BN_to_ASN1_INTEGER(brnd, X509_get_serialNumber(x509ss)));
    T(X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req)));
    T(X509_gmtime_adj(X509_getm_notBefore(x509ss), 0));
    T(X509_time_adj_ex(X509_getm_notAfter(x509ss), 1, 0, NULL));
    T(X509_set_subject_name(x509ss, X509_REQ_get_subject_name(req)));
    T(X509_set_pubkey(x509ss, X509_REQ_get0_pubkey(req)));
    X509_REQ_free(req);
    BN_free(brnd);

    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, x509ss, x509ss, NULL, NULL, 0);
    X509_EXTENSION *ext;
    T(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints, "critical,CA:TRUE"));
    T(X509_add_ext(x509ss, ext, 0));
    X509_EXTENSION_free(ext);
    T(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash"));
    T(X509_add_ext(x509ss, ext, 1));
    X509_EXTENSION_free(ext);
    T(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_authority_key_identifier, "keyid:always,issuer"));
    T(X509_add_ext(x509ss, ext, 2));
    X509_EXTENSION_free(ext);

    EVP_MD_CTX *mctx;
    T(mctx = EVP_MD_CTX_new());
    T(EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey));
    T(X509_sign_ctx(x509ss, mctx));
    EVP_MD_CTX_free(mctx);
#if 0
    /* Print cert in text format. */
    X509_print_fp(stdout, x509ss);
#endif
#if 0
    /* Print cert in PEM format. */
    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    PEM_write_bio_X509(out, x509ss);
    BIO_free_all(out);
#endif
    return (struct certkey){ .pkey = pkey, .cert = x509ss };
}

int test(const char *algname, const char *paramset)
{
    int ret = 0;

    printf(cBLUE "Test %s", algname);
    if (paramset)
	printf(cBLUE ":%s", paramset);
    printf(cNORM "\n");

    struct certkey ck;
    ck = certgen(algname, paramset);

    int sockfd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == -1)
	err(1, "socketpair");

    setpgid(0, 0);

    /* Run server in separate process. */
    pid_t server_pid = fork();
    if (server_pid < 0)
	err(1, "fork server");
    if (server_pid == 0) {
	ret = s_server(ck.pkey, ck.cert, sockfd[1]);
	X509_free(ck.cert);
	EVP_PKEY_free(ck.pkey);
	exit(ret);
    }

    /* Run client in separate process. */
    pid_t client_pid = fork();
    if (client_pid < 0)
	err(1, "fork client");
    if (client_pid == 0) {
	ret = s_client(sockfd[0]);
	X509_free(ck.cert);
	EVP_PKEY_free(ck.pkey);
	exit(ret);
    }

    /* Wait for first child to exit. */
    int status;
    pid_t exited_pid = wait(&status);
    ret = (WIFEXITED(status) && WEXITSTATUS(status)) ||
	(WIFSIGNALED(status) && WTERMSIG(status));
    if (ret) {
	fprintf(stderr, cRED "%s child %s with %d %s" cNORM,
	    exited_pid == server_pid? "server" : "client",
	    WIFSIGNALED(status)? "killed" : "exited",
	    WIFSIGNALED(status)? WTERMSIG(status) : WEXITSTATUS(status),
	    WIFSIGNALED(status)? strsignal(WTERMSIG(status)) : "");

	/* If first child exited with error, kill other. */
	fprintf(stderr, "terminating %s by force",
	    exited_pid == server_pid? "client" : "server");
	kill(exited_pid == server_pid? client_pid : server_pid, SIGTERM);
    }

    exited_pid = wait(&status);
    /* Report error unless we killed it. */
    if (!ret && (!WIFEXITED(status) || WEXITSTATUS(status)))
	fprintf(stderr, cRED "%s child %s with %d %s" cNORM,
	    exited_pid == server_pid? "server" : "client",
	    WIFSIGNALED(status)? "killed" : "exited",
	    WIFSIGNALED(status)? WTERMSIG(status) : WEXITSTATUS(status),
	    WIFSIGNALED(status)? strsignal(WTERMSIG(status)) : "");
    ret |= (WIFEXITED(status) && WEXITSTATUS(status)) ||
	(WIFSIGNALED(status) && WTERMSIG(status));

    /* Every responsible process should free this. */
    X509_free(ck.cert);
    EVP_PKEY_free(ck.pkey);
#ifdef __SANITIZE_ADDRESS__
    /* Abort on the first (hopefully) ASan error. */
    if (ret)
	_exit(ret);
#endif
    return ret;
}

int main(int argc, char **argv)
{
    int ret = 0;

    OPENSSL_add_all_algorithms_conf();

    char *p;
    if ((p = getenv("VERBOSE")))
	verbose = atoi(p);

    ret |= test("rsa", NULL);
    cipher_list = "LEGACY-GOST2012-GOST8912-GOST8912";
    ret |= test("gost2012_256", "A");
    ret |= test("gost2012_256", "B");
    ret |= test("gost2012_256", "C");
    ret |= test("gost2012_256", "TCA");
    ret |= test("gost2012_512", "A");
    ret |= test("gost2012_512", "B");
    ret |= test("gost2012_512", "C");

    if (ret)
	printf(cDRED "= Some tests FAILED!\n" cNORM);
    else
	printf(cDGREEN "= All tests passed!\n" cNORM);
    return ret;
}
