#ifndef SGXSAN_COMMON_POISON_HPP
#define SGXSAN_COMMON_POISON_HPP
#include <cstring>
#include "SGXSanInt.h"
#include "SGXSanCheck.h"
#include "SGXSanAlignment.h"
#include "SGXSanManifest.h"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanDefs.h"

// These magic values are written to shadow for better error reporting.
const int kAsanHeapLeftRedzoneMagic = 0xfa;
const int kAsanHeapRightRedzoneMagic = 0xfb;
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
// Used to populate the shadow gap for systems without memory
// protection there (i.e. Myriad).
const int kAsanShadowGap = 0xcc;
// mark sensitive area
const int kSGXSanShadowSensitive = 0x10;

#ifndef SHADOW_GRANULARITY
#define SHADOW_GRANULARITY 8
#endif

// assume all are aligned to SHADOW_GRANULARITY
static inline void FastPoisonShadow(uptr addr, uptr size, u8 value)
{
    CHECK(IsAligned(addr, SHADOW_GRANULARITY));
    CHECK(!(size % SHADOW_GRANULARITY));
    size_t poison_size = size / SHADOW_GRANULARITY;
    // printf("[0x%lx,0x%lx]: 0x%x\n", addr, addr + size - 1, value);
    memset(reinterpret_cast<void *>(MEM_TO_SHADOW(addr)), value, poison_size);
}

static inline void PoisonShadow(uptr addr, uptr size, u8 value)
{
    // If addr do not aligned at granularity, start posioning from RoundUpTo(addr, granularity)
    if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY)))
    {
        uptr aligned_addr = RoundUpTo(addr, SHADOW_GRANULARITY);
        size -= aligned_addr - addr;
        addr = aligned_addr;
    }

    uptr remained = size & (SHADOW_GRANULARITY - 1);
    FastPoisonShadow(addr, size - remained, value);

    if (remained)
    {
        *(reinterpret_cast<u8 *>(MEM_TO_SHADOW(addr + size - remained))) = value ? value : (u8)remained;
    }
}

#endif // SGXSAN_COMMON_POISON_HPP