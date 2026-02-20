#pragma once

#include "SGXSanRTConfig.h"
#include <stddef.h>

// use our malloc series (which use dlmalloc as backend), and override original
// dlmalloc and tcmalloc libraries
#define MALLOC malloc
#define BACKEND_MALLOC dlmalloc
#define FREE free
#define BACKEND_FREE dlfree
#define CALLOC calloc
#define BACKEND_CALLOC dlcalloc
#define REALLOC realloc
#define BACKEND_REALLOC dlrealloc
#define MALLOC_USABLE_SZIE malloc_usable_size
#define BACKEND_MALLOC_USABLE_SZIE dlmalloc_usable_size

// rz_log represent 2^(rz_log+4)
static inline uptr ComputeRZLog(uptr user_requested_size) {
  u32 rz_log = user_requested_size <= 64 - 16            ? 0
               : user_requested_size <= 128 - 32         ? 1
               : user_requested_size <= 512 - 64         ? 2
               : user_requested_size <= 4096 - 128       ? 3
               : user_requested_size <= (1 << 14) - 256  ? 4
               : user_requested_size <= (1 << 15) - 512  ? 5
               : user_requested_size <= (1 << 16) - 1024 ? 6
                                                         : 7;

  return rz_log;
}

static inline u32 RZLog2Size(u32 rz_log) {
  sgxsan_assert(rz_log < 8);
  return 16 << rz_log;
}

static inline uptr ComputeRZSize(uptr size) { return 16 << ComputeRZLog(size); }

#if defined(__cplusplus)
extern "C" {
#endif
void update_heap_usage(void *ptr, size_t (*malloc_usable_size_func)(void *mem),
                       bool true_add_false_minus = true);
size_t malloc_usable_size(void *mem);
#if defined(__cplusplus)
}
#endif
