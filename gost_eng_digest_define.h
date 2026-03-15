#define STRCAT_IMPL(prefix, suffix) prefix##suffix
#define STRCAT(prefix, suffix) STRCAT_IMPL(prefix, suffix)

int STRCAT(GOST_DIGEST_NAME,_eng_ctrl)(EVP_MD_CTX *c, int cmd, int p1, void *p2) {
    GOST_digest_ctx *ctx = c ? (GOST_digest_ctx*)EVP_MD_CTX_md_data(c) : NULL;
    GOST_digest_ctx *new_ctx = NULL;
    int r = 0;

    if (!ctx) {
        new_ctx = GOST_digest_ctx_new();
        ctx = new_ctx;
    }

    if (!GOST_digest_ctx_digest(ctx) && !GOST_digest_ctx_init(ctx, &GOST_DIGEST_NAME)) {
        goto exit;
    }

    r = GOST_digest_ctx_ctrl(ctx, cmd, p1, p2);

exit:
    GOST_digest_ctx_free(new_ctx);
    return r;
}

GOST_eng_digest ENG_DIGEST_NAME(GOST_DIGEST_NAME) = {
    .digest = &GOST_DIGEST_NAME,
    .ctrl = STRCAT(GOST_DIGEST_NAME,_eng_ctrl)
};

#undef STRCAT_IMPL
#undef STRCAT
