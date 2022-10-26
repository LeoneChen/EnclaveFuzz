#pragma once

#include "SGXSanRTCom.h"
#include <algorithm>
#include <cstdint>
#include <stddef.h>

// These magic values are written to shadow for better error reporting.
const int kAsanHeapLeftRedzoneMagic = 0xfa;
const int kAsanHeapFreeMagic = 0xfd;
const int kAsanStackLeftRedzoneMagic = 0xf1;
const int kAsanStackMidRedzoneMagic = 0xf2;
const int kAsanStackRightRedzoneMagic = 0xf3;
const int kAsanStackAfterReturnMagic = 0xf5;
const int kAsanInitializationOrderMagic = 0xf6;
const int kAsanUserPoisonedMemoryMagic = 0xf7;
const int kAsanContiguousContainerOOBMagic = 0xfc;
const int kAsanStackUseAfterScopeMagic = 0xf8;
const int kAsanGlobalRedzoneMagic = 0xf9;
const int kAsanInternalHeapMagic = 0xfe;
const int kAsanArrayCookieMagic = 0xac;
const int kAsanIntraObjectRedzone = 0xbb;
const int kAsanAllocaLeftMagic = 0xca;
const int kAsanAllocaRightMagic = 0xcb;
// Mark sensitive area
const int kSGXSanSensitiveLayout = 0x10;
const int kSGXSanSensitiveObjData = 0x20;

/* Level 1 Poison - Reflect whether memory is valid to access or not */
#define kL1Filter 0x8F
#define kL1Mask ((uint8_t)(~kL1Filter))
#define L1F(ShadowValue) (ShadowValue & kL1Filter)
#define L1M(ShadowValue) (ShadowValue & kL1Mask)

static inline void FastPoisonShadow(uptr alignedAddr, size_t alignedSize,
                                    uint8_t value) {
  sgxsan_assert(AddrIsAlignedByGranularity(alignedAddr) and
                (alignedSize % SHADOW_GRANULARITY == 0) and
                (value == 0 or value >= 0x80));
  memset((uint8_t *)MEM_TO_SHADOW(alignedAddr), value,
         alignedSize / SHADOW_GRANULARITY);
}

/// @brief Poison valid memory with right redzone
/// @param alignedAddr
/// @param size
/// @param alignedSizeWithRZ
/// @param RZValue
static inline void FastPoisonShadowPartialRightRedzone(uptr alignedAddr,
                                                       size_t size,
                                                       size_t alignedSizeWithRZ,
                                                       uint8_t RZValue) {
  sgxsan_assert(AddrIsAlignedByGranularity(alignedAddr) and RZValue >= 0x80);
  uint8_t *shadowBeg = (uint8_t *)MEM_TO_SHADOW(alignedAddr);
  for (uptr i = 0; i < alignedSizeWithRZ; i += SHADOW_GRANULARITY) {
    shadowBeg[i / SHADOW_GRANULARITY] = (i + SHADOW_GRANULARITY <= size) ? 0
                                        : i >= size ? RZValue
                                                    : size - i;
  }
}

static inline void PoisonShadow(uptr addr, size_t size, uint8_t value) {
  if (size == 0)
    return;
  // If addr do not aligned at granularity, start posioning from
  // RoundUpTo(addr, granularity)
  if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY))) {
    uptr aligned_addr = RoundUpTo(addr, SHADOW_GRANULARITY);
    if (size <= aligned_addr - addr) {
      return;
    }
    size -= (aligned_addr - addr);
    addr = aligned_addr;
  }

  uint8_t remained = size & (SHADOW_GRANULARITY - 1);
  FastPoisonShadow(addr, size - remained, value);

  if (remained) {
    uint8_t *shadowEnd = (uint8_t *)MEM_TO_SHADOW(addr + size - remained);
    int8_t origValue = L1F(*shadowEnd);
    if (value >= 0x80) {
      // If possible, mark all the bytes mapping to last shadow byte as
      // unaddressable.
      if (0 < origValue && origValue <= (int8_t)remained) {
        *shadowEnd = value;
      }
    } else if (value == 0) {
      // If necessary, mark few first bytes mapping to last shadow byte
      // as addressable
      *shadowEnd = std::max(origValue, (int8_t)remained);
    } else {
      abort();
    }
  }
}

static inline void UnPoisonShadow(uptr addr, size_t size) {
  if (size == 0)
    return;
  // If addr do not aligned at granularity, start posioning from
  // RoundUpTo(addr, granularity)
  if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY))) {
    uptr aligned_addr = RoundUpTo(addr, SHADOW_GRANULARITY);
    if (size <= aligned_addr - addr) {
      return;
    }
    size -= (aligned_addr - addr);
    addr = aligned_addr;
  }

  uint8_t remained = size & (SHADOW_GRANULARITY - 1);
  FastPoisonShadow(addr, size - remained, 0);

  if (remained) {
    uint8_t *shadowEnd = (uint8_t *)MEM_TO_SHADOW(addr + size - remained);
    int8_t origValue = L1F(*shadowEnd);
    *shadowEnd = origValue == 0 ? 0 : std::max(origValue, (int8_t)remained);
  }
}

/* Level 2 Poison - Reflect extra information */
#define kL2Filter 0x30
#define kL2Mask ((uint8_t)(~kL2Filter))
#define L2F(ShadowValue) (ShadowValue & kL2Filter)
#define L2M(ShadowValue) (ShadowValue & kL2Mask)

#ifdef __cplusplus
extern "C" {
#endif
void ShallowPoisonShadow(uptr addr, uptr size, uint8_t value);
void ShallowUnPoisonShadow(uptr addr, uptr size);
void sgxsan_shallow_shadow_copy_on_mem_transfer(uptr dst_addr, uptr src_addr,
                                                uptr dst_size, uptr copy_cnt);
#ifdef __cplusplus
}
#endif
