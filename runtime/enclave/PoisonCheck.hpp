#pragma once

#include "SGXSanRTEnclave.hpp"
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif
uptr sgxsan_region_is_poisoned(uptr beg, uptr size, bool ret_adddr = false);
#if defined(__cplusplus)
}
#endif

static inline bool AddressIsPoisoned(uptr a) {
  const uptr kAccessSize = 1;
  u8 *shadow_address = (u8 *)MEM_TO_SHADOW(a);
  // situation of shadow_value >= SHADOW_GRANULARITY (max positive integer for
  // shadow byte is 0x7f) is that sgxsan's shallow poison usage
  s8 shadow_value = *shadow_address;
  if (shadow_value) {
    // last_accessed_byte should <= SHADOW_GRANULARITY - 1 (e.g. 0x7)
    u8 last_accessed_byte = (a & (SHADOW_GRANULARITY - 1)) + kAccessSize - 1;
    return shadow_value >= (s8)SHADOW_GRANULARITY ||
           ((s8)last_accessed_byte) >=
               shadow_value /* shadow_value is 0x1-0x7 or < 0x0 */;
  }
  return false;
}

// Return true if we can quickly decide that the region is unpoisoned.
// We assume that a redzone is at least 16 bytes.
static inline bool QuickCheckForUnpoisonedRegion(uptr beg, uptr size) {
  if (size == 0)
    return true;
  if (size <= 32)
    return !AddressIsPoisoned(beg) && !AddressIsPoisoned(beg + size - 1) &&
           !AddressIsPoisoned(beg + size / 2);
  if (size <= 64)
    return !AddressIsPoisoned(beg) && !AddressIsPoisoned(beg + size / 4) &&
           !AddressIsPoisoned(beg + size - 1) &&
           !AddressIsPoisoned(beg + 3 * size / 4) &&
           !AddressIsPoisoned(beg + size / 2);
  return false;
}

static inline bool mem_is_zero(uint8_t *beg, uptr size) {
  if (size == 0)
    return true;
  sgxsan_assert(size <= 1ULL << 40); // Sanity check.
  uint8_t *end = beg + size;         // offset by 1
  uptr *aligned_beg = (uptr *)RoundUpTo((uptr)beg, sizeof(uptr));
  uptr *aligned_end =
      (uptr *)RoundDownTo((uptr)end, sizeof(uptr)); // offset by 1
  uptr all = 0;
  // Prologue.
  for (uint8_t *mem = beg; mem < (uint8_t *)aligned_beg && mem < end; mem++)
    all |= *mem;
  // Aligned loop.
  for (; aligned_beg < aligned_end; aligned_beg++)
    all |= *aligned_beg;
  // Epilogue.
  if ((uint8_t *)aligned_end >= beg) {
    for (uint8_t *mem = (uint8_t *)aligned_end; mem < end; mem++)
      all |= *mem;
  }
  return all == 0;
}

// Leave overlapping memory access to ELRANGE guard page to check
#define SGXSAN_ELRANGE_CHECK_BEG(start, size)                                  \
  do {                                                                         \
    uptr _start = (uptr)start;                                                 \
    uptr _end = _start + size - 1;                                             \
    uptr _enclave_end = g_enclave_base + g_enclave_size - 1;                   \
    if (g_enclave_base <= _start && _end <= _enclave_end) {

#define SGXSAN_ELRANGE_CHECK_MID                                               \
  }                                                                            \
  else if (_end < g_enclave_base || _enclave_end < _start) {

#define SGXSAN_ELRANGE_CHECK_END                                               \
  }                                                                            \
  }                                                                            \
  while (0)

// Behavior of functions like "memcpy" or "strcpy" is undefined
// if memory intervals overlap. We report error in this case.
// Macro is used to avoid creation of new frames.
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2) {
  return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}

// We implement ACCESS_MEMORY_RANGE, ASAN_READ_RANGE,
// and ASAN_WRITE_RANGE as macro instead of function so
// that no extra frames are created, and stack trace contains
// relevant information only.
// We check all shadow bytes.
#define ACCESS_MEMORY_RANGE(offset, size, isWrite)                             \
  do {                                                                         \
    uptr __offset = (uptr)(offset);                                            \
    uptr __size = (uptr)(size);                                                \
    uptr __bad = 0;                                                            \
    sgxsan_error(__offset > __offset + __size,                                 \
                 "[%s:%d] 0x%lx:%lu size overflow\n", __FILE__, __LINE__,      \
                 __offset, __size);                                            \
    if (!QuickCheckForUnpoisonedRegion(__offset, __size) &&                    \
        (__bad = sgxsan_region_is_poisoned(__offset, __size, true))) {         \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, __bad, isWrite, __size, true);            \
    }                                                                          \
  } while (0)

#define ASAN_READ_RANGE(offset, size) ACCESS_MEMORY_RANGE(offset, size, false)
#define ASAN_WRITE_RANGE(offset, size) ACCESS_MEMORY_RANGE(offset, size, true)
