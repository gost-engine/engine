#pragma once

#include <openssl/engine.h>

extern const ENGINE_CMD_DEFN gost_cmds[];

int gost_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void));
