#include "Poison.hpp"
#include "PoisonCheck.hpp"
#include <sgx_trts.h>
#include <string.h>

static const u64 kAllocaRedzoneSize = 32UL;
static const u64 kAllocaRedzoneMask = 31UL;

extern "C" {
/* Callbacks of ASan pass */
// Used by static allocas
void __asan_set_shadow_00(uptr addr, uptr size) {
  memset((void *)addr, 0, size);
}

void __asan_set_shadow_f1(uptr addr, uptr size) {
  memset((void *)addr, 0xf1, size);
}

void __asan_set_shadow_f2(uptr addr, uptr size) {
  memset((void *)addr, 0xf2, size);
}

void __asan_set_shadow_f3(uptr addr, uptr size) {
  memset((void *)addr, 0xf3, size);
}

void __asan_set_shadow_f5(uptr addr, uptr size) {
  memset((void *)addr, 0xf5, size);
}

void __asan_set_shadow_f8(uptr addr, uptr size) {
  memset((void *)addr, 0xf8, size);
}

void __asan_set_shadow_fe(uptr addr, uptr size) {
  memset((void *)addr, 0xfe, size);
}

// Used by dynamic allocas
// lifetime.start/end
void __asan_poison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanStackUseAfterScopeMagic);
}

void __asan_unpoison_stack_memory(uptr addr, uptr size) {
  UnPoisonShadow(addr, size);
}

// Init time
void __asan_alloca_poison(uptr addr, uptr size) {
  sgxsan_assert(addr && AddrIsAlignedByGranularity(addr));
  uptr LeftRedzoneAddr = addr - kAllocaRedzoneSize;
  uptr PartialRzAddr = addr + size;
  uptr RightRzAddr = (PartialRzAddr + kAllocaRedzoneMask) & ~kAllocaRedzoneMask;
  uptr PartialRzAligned = PartialRzAddr & ~(SHADOW_GRANULARITY - 1);
  FastPoisonShadow(LeftRedzoneAddr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
  FastPoisonShadowPartialRightRedzone(
      PartialRzAligned, PartialRzAddr % SHADOW_GRANULARITY,
      RightRzAddr - PartialRzAligned, kAsanAllocaRightMagic);
  FastPoisonShadow(RightRzAddr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
}

void __asan_allocas_unpoison(uptr top, uptr bottom) {
  if ((!top) || (top > bottom))
    return;
  memset(reinterpret_cast<void *>(MemToShadow(top)), 0,
         (bottom - top) / SHADOW_GRANULARITY);
}
}
