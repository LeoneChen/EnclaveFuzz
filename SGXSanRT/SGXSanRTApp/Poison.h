#pragma once

#include "SGXSanRTApp.h"
#include <stdint.h>

extern bool __thread RunInEnclave;

/// These magic values are written to shadow for better error reporting.
const int kAsanNotPoisonedMagic = 0x00;
const int kAsanStackLeftRedzoneMagic = 0x81 /* 0xf1 */;
const int kAsanStackMidRedzoneMagic = 0x82 /* 0xf2 */;
const int kAsanStackRightRedzoneMagic = 0x83 /* 0xf3 */;
const int kAsanStackAfterReturnMagic = 0x85 /* 0xf5 */;
const int kAsanAllocaLeftMagic = 0x86; /* 0xca */
const int kAsanAllocaRightMagic = 0x87 /* 0xcb */;
const int kAsanStackUseAfterScopeMagic = 0x88 /* 0xf8 */;
const int kAsanGlobalRedzoneMagic = 0x89 /* 0xf9 */;
const int kAsanHeapLeftRedzoneMagic = 0x8a /* 0xfa */;
const int kAsanHeapFreeMagic = 0x8d /* 0xfd */;
const int kAsanInternalHeapMagic = 0x8e /* 0xfe */;
/// Indicate memory byte is of Enclave or not
const int kSGXSanInEnclaveMagic = 0x40;

#if defined(__cplusplus)
extern "C" {
#endif

/// Level 0 Poison
///
/// Only reflect whether memory is in Enclave or not
/// Filter
#define kL0Filter kSGXSanInEnclaveMagic
#define L0F(ShadowValue) (ShadowValue & kL0Filter)
/// Poison
#define L0P(PoisonValue)                                                       \
  (RunInEnclave ? (PoisonValue) | kSGXSanInEnclaveMagic : (PoisonValue))

/// Level 1 Poison
///
/// Only reflect whether memory is valid to access or not
/// Filter
#define kL1Filter 0x8F
#define L1F(ShadowValue) (ShadowValue & kL1Filter)
/// Poison
void FastPoisonShadow(uptr aligned_addr, uptr aligned_size, uint8_t value,
                      bool returnBackToNormal = false);
void FastPoisonShadowPartialRightRedzone(uptr aligned_addr, uptr size,
                                         uptr aligned_size_with_rz,
                                         uint8_t rz_value);
void PoisonShadow(uptr addr, uptr size, uint8_t value,
                  bool returnBackToNormal = false);

#if defined(__cplusplus)
}
#endif
