#pragma once

#include "SGXSanRTConfig.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <vector>

/* Page assumption */
#define PAGE_SIZE 0x1000
#define PAGE_SIZE_SHIFT 12

/// Shadow basic settings
#ifndef SHADOW_OFFSET
#define SHADOW_OFFSET 0x7fff8000
#endif
#define X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS 47
#define SHADOW_SCALE 3
#define ADDR_SPACE_BITS X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS
#define SHADOW_GRANULARITY (1UL << SHADOW_SCALE)
#define SHADOW_SIZE (1UL << (ADDR_SPACE_BITS - SHADOW_SCALE))

#define MEM_TO_SHADOW(mem) (((uptr)(mem) >> SHADOW_SCALE) + SHADOW_OFFSET)

/// Some
typedef unsigned long uptr;
typedef signed long sptr;

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#define SANITIZER_INTERFACE_ATTRIBUTE __attribute__((visibility("default")))
#define NORETURN __attribute__((noreturn))

#define GET_CALLER_PC_BP_SP                                                    \
  uptr pc = (uptr)__builtin_return_address(0);                                 \
  uptr bp = (uptr)__builtin_frame_address(0);                                  \
  uptr local_stack;                                                            \
  uptr sp = (uptr) & local_stack

/// mem layout
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
/// Init util
extern bool asan_inited;
extern "C" void SGXSanInit();

/// Logging utils
enum log_level {
  LOG_LEVEL_ALWAYS,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_WARNING,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_TRACE,
};

#ifndef USED_LOG_LEVEL
#define USED_LOG_LEVEL LOG_LEVEL_WARNING
#endif

#if defined(__cplusplus)
extern "C" {
#endif
void register_sgxsan_sigaction();
int hook_enclave();

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...);
void SGXSanLogEnter(const char *str);
#if defined(__cplusplus)
}
#endif

/// have prefix in output
#define log_always(...) sgxsan_log(LOG_LEVEL_ALWAYS, true, __VA_ARGS__)
#define log_error(...) sgxsan_log(LOG_LEVEL_ERROR, true, __VA_ARGS__)
#define log_warning(...) sgxsan_log(LOG_LEVEL_WARNING, true, __VA_ARGS__)
#define log_debug(...) sgxsan_log(LOG_LEVEL_DEBUG, true, __VA_ARGS__)
#define log_trace(...) sgxsan_log(LOG_LEVEL_TRACE, true, __VA_ARGS__)

/// no prefix in output
#define log_always_np(...) sgxsan_log(LOG_LEVEL_ALWAYS, false, __VA_ARGS__)
#define log_error_np(...) sgxsan_log(LOG_LEVEL_ERROR, false, __VA_ARGS__)
#define log_warning_np(...) sgxsan_log(LOG_LEVEL_WARNING, false, __VA_ARGS__)
#define log_debug_np(...) sgxsan_log(LOG_LEVEL_DEBUG, false, __VA_ARGS__)
#define log_trace_np(...) sgxsan_log(LOG_LEVEL_TRACE, false, __VA_ARGS__)

struct MallocFreeBTTy {
  size_t malloc_bt_cnt, free_bt_cnt;
  uptr malloc_bt[30], free_bt[30];
};

extern "C" {
void sgxsan_dump_bt_buf(void **array, size_t size);
void sgxsan_backtrace(log_level ll = LOG_LEVEL_ERROR);

void ReportError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                 uptr access_size, const char *msg, ...);
void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal = true,
                        const char *msg = "Out of bound", ...);
void ReportUseAfterFree(uptr pc, uptr bp, uptr sp, uptr addr);
void ReportDoubleFree(uptr pc, uptr bp, uptr sp, uptr addr);
}

#define sgxsan_error(cond, ...)                                                \
  do {                                                                         \
    if (UNLIKELY(!!(cond))) {                                                  \
      log_error(__VA_ARGS__);                                                  \
      sgxsan_backtrace();                                                      \
      abort();                                                                 \
    }                                                                          \
  } while (0);

#define sgxsan_assert(cond) sgxsan_error(!(cond), #cond "\n");

#define sgxsan_warning(cond, ...)                                              \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_warning(__VA_ARGS__);                                                \
      sgxsan_backtrace(LOG_LEVEL_WARNING);                                     \
    }                                                                          \
  } while (0);

/// Interceptor
#define SGXSAN(sym) sgxsan_##sym

/// mem tools
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
  sgxsan_error(not AddrIsInMem(addr), "Address not in valid memory\n");
  return MEM_TO_SHADOW(addr);
}

/// Alignment
static inline bool IsAligned(uptr a, uptr alignment) {
  return (a & (alignment - 1)) == 0;
}

static inline bool IsPowerOfTwo(uptr x) { return (x & (x - 1)) == 0; }

static inline uptr RoundUpTo(uptr size, uptr boundary) {
  sgxsan_error(not IsPowerOfTwo(boundary), "Boundary is not power of two\n");
  return (size + boundary - 1) & ~(boundary - 1);
}

static inline uptr RoundDownTo(uptr x, uptr boundary) {
  sgxsan_error(not IsPowerOfTwo(boundary), "Boundary is not power of two\n");
  return x & ~(boundary - 1);
}

static inline uptr RoundUpDiv(uptr a, uptr b) {
  sgxsan_error(not IsPowerOfTwo(b), "Boundary is not power of two\n");
  return (a + b - 1) / b;
}

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2) {
  return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}

static inline uptr ExtendInt8(uint8_t _8bit) {
  uptr result = 0;
  for (size_t i = 0; i < sizeof(uptr); i++) {
    result = (result << 8) + _8bit;
  }
  return result;
}

static inline int getArraySum(int *array, int size) {
  int sum = 0;
  for (int i = 0; i < size; i++) {
    sum += array[i];
  }
  return sum;
}

/* addr2line & backtrace Util */
std::string addr2fname_try(void *addr);
std::string addr2fname(void *addr);

/// Cipher detect
enum EncryptStatus { Unknown, Plaintext, Ciphertext };

extern pthread_rwlock_t output_history_rwlock;
extern std::unordered_map<void * /* callsite addr */,
                          std::vector<EncryptStatus> /* output type history */>
    output_history;

static inline int getBucketNum(size_t size) {
  return size >= 0x800   ? 0x100
         : size >= 0x100 ? 0x40
         : size >= 0x10  ? 0x4
         : size >= 0x2   ? 0x2
                         : 0x1;
}

__attribute__((always_inline)) static inline EncryptStatus
isCiphertext(uint64_t addr, uint64_t size, void *caller_addr) {
  if (size < 0x100)
    return Unknown;

  int bucket_num = getBucketNum(size);

  int map[256 /* 2^8 */] = {0};

  // collect byte map
  for (uint64_t i = 0; i < size; i++) {
    unsigned char byte = *(unsigned char *)(addr + i);
    map[byte]++;
  }

  double CountPerBacket = (int)size / (double)bucket_num;
  if (size >= 0x100)
    CountPerBacket = (int)(size - map[0] /* maybe 0-padding in ciphertext */) /
                     (double)(bucket_num - 1);

  bool is_cipher = true;
  int step = 0x100 / bucket_num;
  log_trace("[Cipher Detect] CountPerBacket = %f \n", CountPerBacket);

  for (int i = 0; i < 256; i += step) {
    int sum = getArraySum(map + i, step);
    if ((sum > CountPerBacket * 1.5 || sum < CountPerBacket / 2) and
        (size >= 0x100 ? i != 0 : true)) {
      is_cipher = false;
      break;
    }
  }

  if (!is_cipher) {
    std::string fname = addr2fname(caller_addr);
    log_warning("[%s] Plaintext transfering...\n", fname.c_str());
  }
  return is_cipher ? Ciphertext : Plaintext;
}

__attribute__((always_inline)) static inline void
check_output_hybrid(uint64_t addr, uint64_t size) {
  pthread_rwlock_wrlock(&output_history_rwlock);

  // get history of callsite
  int depth = 2;
  void *bt_array[depth];
  if (backtrace(bt_array, depth) != depth)
    return;

  std::vector<EncryptStatus> &history =
      output_history[(void *)((uptr)bt_array[depth - 1] - 1)];

  EncryptStatus status = isCiphertext(addr, size, bt_array[depth - 1]);
  if (history.size() == 0) {
    history.emplace_back(status);
  } else {
    EncryptStatus last_known_status = Unknown;
    for (auto it = history.rbegin(); it != history.rend(); it++) {
      if (*it != Unknown) {
        last_known_status = *it;
        break;
      }
    }
    history.emplace_back(status);

    sgxsan_warning(last_known_status != Unknown && status != Unknown &&
                       last_known_status != status,
                   "Output is plaintext ciphertext hybridization\n");
  }
  pthread_rwlock_unlock(&output_history_rwlock);
}

void ClearSGXSanRT();
void ClearStackPoison();
