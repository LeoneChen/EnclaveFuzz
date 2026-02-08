#pragma once

#include "SGXSanRTConfig.h"
#include <cstddef>

extern int asan_inited;

#if defined(__cplusplus)
extern "C" {
#endif
void AsanInitFromRtl();
void __asan_init();
#if defined(__cplusplus)
}
#endif

#ifndef ENSURE_ASAN_INITED
#define ENSURE_ASAN_INITED()                                                   \
  do {                                                                         \
    if (UNLIKELY(!asan_inited)) {                                              \
      AsanInitFromRtl();                                                       \
    }                                                                          \
  } while (0)
#endif
