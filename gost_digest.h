#pragma once

#include <stddef.h>
#include <stdint.h>

struct gost_digest_st;
typedef struct gost_digest_st GOST_digest;

struct gost_digest_ctx_st;
typedef struct gost_digest_ctx_st GOST_digest_ctx;

extern size_t GOST_digest_ctx_size;

// No GOST_digest instance may be used before GOST_digest_init call
const GOST_digest* GOST_digest_init(GOST_digest* digest);
void GOST_digest_deinit(GOST_digest* d);
unsigned long GOST_digest_flags(const GOST_digest* d);
int GOST_digest_type(const GOST_digest* d);
int GOST_digest_block_size(const GOST_digest* d);
int GOST_digest_size(const GOST_digest* d);
int (*GOST_digest_meth_get_init(const GOST_digest *md))(GOST_digest_ctx *ctx);

GOST_digest_ctx* GOST_digest_ctx_new();
void GOST_digest_ctx_free(GOST_digest_ctx *ctx);

int GOST_digest_ctx_init(GOST_digest_ctx *ctx, const GOST_digest *cls);
int GOST_digest_ctx_update(GOST_digest_ctx *ctx, const void *data, size_t count);
int GOST_digest_ctx_final(GOST_digest_ctx *ctx, unsigned char *md);
int GOST_digest_ctx_copy(GOST_digest_ctx *to, const GOST_digest_ctx *from);
int GOST_digest_ctx_cleanup(GOST_digest_ctx *ctx);
int GOST_digest_ctx_ctrl(GOST_digest_ctx *ctx, int cmd, int p1, void *p2);

const GOST_digest* GOST_digest_ctx_digest(GOST_digest_ctx *ctx);
void* GOST_digest_ctx_data(const GOST_digest_ctx* ctx);
void GOST_digest_ctx_set_flags(GOST_digest_ctx *ctx, unsigned long flags);
void GOST_digest_ctx_reset_flags(GOST_digest_ctx *ctx, unsigned long flags);
int GOST_digest_ctx_test_flags(const GOST_digest_ctx *ctx, unsigned long flags);
