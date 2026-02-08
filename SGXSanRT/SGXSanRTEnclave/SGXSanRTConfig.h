#pragma once

#include <stdint.h>
#include <stdlib.h>

#define USED_LOG_LEVEL LOG_LEVEL_WARNING

/* Page assumption */
#define PAGE_SIZE 0x1000
#define PAGE_SIZE_SHIFT 12

/* Shadow basic settings */
#define SHADOW_OFFSET 0x7fff8000
#define X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS 47
#define SHADOW_SCALE 3
#define ADDR_SPACE_BITS X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS
#define SHADOW_GRANULARITY (1UL << SHADOW_SCALE)
#define SHADOW_SIZE (1UL << (ADDR_SPACE_BITS - SHADOW_SCALE))

#define MEM_TO_SHADOW(mem) (((uptr)(mem) >> SHADOW_SCALE) + SHADOW_OFFSET)

/* Memory layout */
#define kLowMemBeg 0
#define kLowMemEnd (SHADOW_OFFSET - 1)

#define kLowShadowBeg SHADOW_OFFSET
#define kLowShadowEnd (MEM_TO_SHADOW(kLowShadowBeg) - 1)

#define kHighMemBeg (kLowShadowBeg + SHADOW_SIZE)
#define kHighMemEnd ((1UL << ADDR_SPACE_BITS) - 1)

#define kHighShadowBeg MEM_TO_SHADOW(kHighMemBeg)
#define kHighShadowEnd (kHighMemBeg - 1)

#define kShadowGapBeg (kLowShadowEnd + 1)
#define kShadowGapEnd (kHighShadowBeg - 1)

#define kLowShadowGuardBeg (kLowShadowBeg - PAGE_SIZE)
#define kLowShadowGuardEnd (kLowShadowBeg - 1)

#define kHighShadowGuardBeg (kHighShadowEnd + 1)
#define kHighShadowGuardEnd (kHighShadowEnd + PAGE_SIZE)

/* Log util */
enum log_level {
  LOG_LEVEL_NONE,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_WARNING,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_TRACE,
};

#define log_always(...) sgxsan_log(LOG_LEVEL_NONE, true, __VA_ARGS__)
#define log_error(...) sgxsan_log(LOG_LEVEL_ERROR, true, __VA_ARGS__)
#define log_warning(...) sgxsan_log(LOG_LEVEL_WARNING, true, __VA_ARGS__)
#define log_debug(...) sgxsan_log(LOG_LEVEL_DEBUG, true, __VA_ARGS__)
#define log_trace(...) sgxsan_log(LOG_LEVEL_TRACE, true, __VA_ARGS__)

// no prefix
#define log_always_np(...) sgxsan_log(LOG_LEVEL_NONE, false, __VA_ARGS__)
#define log_error_np(...) sgxsan_log(LOG_LEVEL_ERROR, false, __VA_ARGS__)
#define log_warning_np(...) sgxsan_log(LOG_LEVEL_WARNING, false, __VA_ARGS__)
#define log_debug_np(...) sgxsan_log(LOG_LEVEL_DEBUG, false, __VA_ARGS__)
#define log_trace_np(...) sgxsan_log(LOG_LEVEL_TRACE, false, __VA_ARGS__)

#if defined(__cplusplus)
extern "C" {
#endif

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

/* Stack trace */
#if defined(__cplusplus)
extern "C" {
#endif

void sgxsan_backtrace(log_level ll = LOG_LEVEL_ERROR);

#if defined(__cplusplus)
}
#endif

/* Int define */
typedef unsigned long uptr;
typedef signed long sptr;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

/* Some define */
#define NOINLINE __attribute__((noinline))
#define INTERFACE_ATTRIBUTE __attribute__((visibility("default")))
#define NORETURN __attribute__((noreturn))

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#define GET_CALLER_PC_BP_SP                                                    \
  uptr bp = (uptr)__builtin_frame_address(0);                                  \
  uptr pc = (uptr)__builtin_return_address(0);                                 \
  uptr local_stack;                                                            \
  uptr sp = (uptr) & local_stack

/* Check util */
#define sgxsan_error(cond, ...)                                                \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_error(__VA_ARGS__);                                                  \
      sgxsan_backtrace();                                                      \
      abort();                                                                 \
    }                                                                          \
  } while (0);

#define sgxsan_assert(cond) sgxsan_error(!(cond), "Assert Fail: " #cond "\n");

/* Alignment util */
static inline bool IsAligned(uptr a, uptr alignment) {
  return (a & (alignment - 1)) == 0;
}

static inline bool AddrIsAlignedByGranularity(uptr addr) {
  return IsAligned(addr, SHADOW_GRANULARITY);
}

static inline bool IsPowerOfTwo(uptr x) { return (x & (x - 1)) == 0; }

static inline uptr RoundUpTo(uptr size, uptr boundary) {
  sgxsan_assert(IsPowerOfTwo(boundary));
  return (size + boundary - 1) & ~(boundary - 1);
}

static inline uptr RoundDownTo(uptr x, uptr boundary) {
  return x & ~(boundary - 1);
}

static inline uptr RoundUpDiv(uptr x, uptr boundary) {
  return (x + boundary - 1) / boundary;
}

/* Memory tools */
static inline bool AddrIsInLowMem(uptr a) {
  return kLowMemBeg <= a && a <= kLowMemEnd;
}

static inline bool AddrIsInHighMem(uptr a) {
  return kHighMemBeg <= a && a <= kHighMemEnd;
}

static inline bool AddrIsInMem(uptr a) {
  return AddrIsInLowMem(a) or AddrIsInHighMem(a);
}

static inline bool AddrIsInLowShadow(uptr a) {
  return kLowShadowBeg <= a && a <= kLowShadowEnd;
}

static inline bool AddrIsInHighShadow(uptr a) {
  return kHighShadowBeg <= a && a <= kHighShadowEnd;
}

static inline bool AddrIsInShadow(uptr a) {
  return AddrIsInLowShadow(a) or AddrIsInHighShadow(a);
}

static inline uptr MemToShadow(uptr addr) {
  sgxsan_assert(AddrIsInMem(addr));
  return MEM_TO_SHADOW(addr);
}

extern uint64_t g_enclave_base, g_enclave_size;
