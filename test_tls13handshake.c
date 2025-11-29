#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

static const char test_cert_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBbTCCARgCFCwPZ2ufyPD4w6L9+gIW0bxgc9VKMAwGCCqFAwcBAQMCBQAwNDES\n"
    "MBAGA1UEAwwJbG9jYWxob3N0MQ0wCwYDVQQKDARUZXN0MQ8wDQYDVQQLDAZUTFMx\n"
    "LjMwHhcNMjUwNDE0MTUxNDIzWhcNMjYwNDE0MTUxNDIzWjA0MRIwEAYDVQQDDAls\n"
    "b2NhbGhvc3QxDTALBgNVBAoMBFRlc3QxDzANBgNVBAsMBlRMUzEuMzBmMB8GCCqF\n"
    "AwcBAQEBMBMGByqFAwICIwEGCCqFAwcBAQICA0MABEBmhmqMH3rbH6kjPLR7iUwo\n"
    "uJqFtsP52CSDz8gJVp1PyW6dzV8EbClmFlI0aJdyyEQ55SlAAGrOOwfSV3aDQjul\n"
    "MAwGCCqFAwcBAQMCBQADQQBlxklUm4GF2/ReRw+H9HfJrTFn2lw6Ohv2+WMQKCUl\n"
    "JAxWHymeIDaow5oF8Sv2iCO/dUrkab4LYgxRZFrge4mD\n"
    "-----END CERTIFICATE-----";

static const char test_key_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MEYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEIIouOKJ+r8nY\n"
    "nBM5uRJ3opU7kclTm2FzsexlIt6BPpbq\n"
    "-----END PRIVATE KEY-----";

int load_cert_and_key_from_strings(SSL_CTX *ctx,
                                   const char *cert_pem,
                                   const char *key_pem)
{
    BIO *cert_bio = NULL, *key_bio = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    cert_bio = BIO_new_mem_buf(cert_pem, -1);
    key_bio  = BIO_new_mem_buf(key_pem, -1);
    if (!cert_bio || !key_bio) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        goto end;
    }

    cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    pkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
    if (!cert || !pkey) {
        fprintf(stderr, "PEM_read_bio_X509/PrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        fprintf(stderr, "SSL_CTX_use_certificate failed\n");
        goto end;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        fprintf(stderr, "SSL_CTX_use_PrivateKey failed\n");
        goto end;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "SSL_CTX_check_private_key failed\n");
        goto end;
    }

    ret = 1; /* success */

end:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    BIO_free(cert_bio);
    BIO_free(key_bio);
    return ret;
}

static int create_ctx_pair(SSL_CTX **server_ctx, SSL_CTX **client_ctx)
{
    *server_ctx = SSL_CTX_new(TLS_server_method());
    *client_ctx = SSL_CTX_new(TLS_client_method());
    if (*server_ctx == NULL || *client_ctx == NULL) {
        fprintf(stderr, "Failed to create SSL_CTX\n");
        return 0;
    }

    SSL_CTX_set_min_proto_version(*server_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(*server_ctx, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(*client_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(*client_ctx, TLS1_3_VERSION);

    SSL_CTX_set_cipher_list(*server_ctx, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L");
    SSL_CTX_set_cipher_list(*client_ctx, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L");

    SSL_CTX_set_num_tickets(*server_ctx, 1);

    if (!load_cert_and_key_from_strings(*server_ctx, test_cert_pem, test_key_pem))
        return 0;

    SSL_CTX_set_verify(*client_ctx, SSL_VERIFY_NONE, NULL);

    /* Early data */
    SSL_CTX_set_max_early_data(*server_ctx, 0xffffffff);

    return 1;
}

static int create_ssl_connection(SSL *sssl, SSL *cssl)
{
    int s_ret, c_ret;
    int max_iterations = 100;
    int iterations = 0;
    int s_err, c_err;
    unsigned char tmpbuf[10];

    if (!sssl || !cssl)
        return 0;

    do {
        s_ret = SSL_accept(sssl);
        c_ret = SSL_connect(cssl);

        s_err = SSL_get_error(sssl, s_ret);
        c_err = SSL_get_error(cssl, c_ret);

        if (s_ret <= 0 && s_err != SSL_ERROR_WANT_READ && s_err != SSL_ERROR_WANT_WRITE) {
            fprintf(stderr, "Server handshake error: %d\n", s_err);
            ERR_print_errors_fp(stderr);
            return 0;
        }

        if (c_ret <= 0 && c_err != SSL_ERROR_WANT_READ && c_err != SSL_ERROR_WANT_WRITE) {
            fprintf(stderr, "Client handshake error: %d\n", c_err);
            ERR_print_errors_fp(stderr);
            return 0;
        }

        iterations++;
        if (iterations > max_iterations) {
            fprintf(stderr, "Too many iterations in handshake\n");
            return 0;
        }

    } while ((s_ret <= 0 && (s_err == SSL_ERROR_WANT_READ || s_err == SSL_ERROR_WANT_WRITE)) ||
             (c_ret <= 0 && (c_err == SSL_ERROR_WANT_READ || c_err == SSL_ERROR_WANT_WRITE)));

    iterations = 0;
    do {
        s_ret = SSL_write(sssl, "mTest", strlen("mTest"));
        c_ret = SSL_read(cssl, tmpbuf, sizeof(tmpbuf));

        s_err = SSL_get_error(sssl, s_ret);
        c_err = SSL_get_error(cssl, c_ret);

        iterations++;
        if (iterations > max_iterations) {
            fprintf(stderr, "Too many iterations reading post-handshake data\n");
            return 0;
        }

    } while ((s_err == SSL_ERROR_WANT_READ || s_err == SSL_ERROR_WANT_WRITE) ||
             (c_err == SSL_ERROR_WANT_READ || c_err == SSL_ERROR_WANT_WRITE));

    if (s_err != SSL_ERROR_NONE) {
        fprintf(stderr, "Server post-handshake write error: %d\n", s_err);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (c_err != SSL_ERROR_NONE) {
        fprintf(stderr, "Client post-handshake read error: %d\n", c_err);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}

static int create_ssl_pair(SSL_CTX *server_ctx, SSL_CTX *client_ctx,
                           SSL **server_ssl, SSL **client_ssl)
{
    SSL *s = NULL, *c = NULL;
    BIO *srv_bio = NULL, *cli_bio = NULL;
    int rv;

    s = SSL_new(server_ctx);
    c = SSL_new(client_ctx);
    if (s == NULL || c == NULL) {
        fprintf(stderr, "SSL_new failed\n");
        goto err;
    }

    rv = BIO_new_bio_pair(&cli_bio, 64 * 1024, &srv_bio, 64 * 1024);
    if (rv != 1 || cli_bio == NULL || srv_bio == NULL) {
        fprintf(stderr, "BIO_new_bio_pair failed\n");
        goto err;
    }

    SSL_set_bio(c, cli_bio, cli_bio);
    SSL_set_bio(s, srv_bio, srv_bio);

    *server_ssl = s;
    *client_ssl = c;
    return 1;

err:
    if (s)
        SSL_free(s);
    if (c)
        SSL_free(c);
    return 0;
}

int main(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_SESSION *sess = NULL;
    const char msg[] = "Hello early data!";
    char buf[256];
    size_t written = 0, readbytes = 0;
    int ret = 1;

    SSL_library_init();
    SSL_load_error_strings();

    if (!create_ctx_pair(&sctx, &cctx))
        goto err;

    if (!create_ssl_pair(sctx, cctx, &sssl, &cssl))
        goto err;

    if (!create_ssl_connection(sssl, cssl))
        goto err;

    sess = SSL_get1_session(cssl);
    if (!sess) {
        fprintf(stderr, "No session established\n");
        goto err;
    }

    SSL_shutdown(cssl);
    SSL_shutdown(sssl);
    SSL_free(cssl);
    SSL_free(sssl);
    cssl = sssl = NULL;

    if (!create_ssl_pair(sctx, cctx, &sssl, &cssl))
        goto err;

    if (!SSL_set_session(cssl, sess)) {
        fprintf(stderr, "SSL_set_session failed\n");
        goto err;
    }

    if (!SSL_write_early_data(cssl, msg, strlen(msg), &written)) {
        fprintf(stderr, "SSL_write_early_data failed\n");
        goto err;
    }

    if (SSL_read_early_data(sssl, buf, sizeof(buf) - 1, &readbytes)
        != SSL_READ_EARLY_DATA_SUCCESS) {
        fprintf(stderr, "SSL_read_early_data failed\n");
        goto err;
    }

    buf[readbytes] = '\0';
    printf("Server received early data: '%s'\n", buf);

    ret = 0;

err:
    if (ret != 0)
        ERR_print_errors_fp(stderr);

    SSL_SESSION_free(sess);
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
}
