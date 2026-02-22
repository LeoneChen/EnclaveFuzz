#pragma once

#include "SGXSanRTConfig.h"

extern int asan_inited;

#if defined(__cplusplus)
extern "C" {
#endif
void dump_sancov();
#if defined(__cplusplus)
}
#endif
