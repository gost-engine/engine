#include "gost_digest.h"

void* GOST_digest_ctx_data(const GOST_digest_ctx* ctx) {
	return ctx->algctx;
}
