#include "Poison.h"
#include "SGXSanRTApp.h"
#include <algorithm>
#include <pthread.h>
#include <string.h>
#include <vector>

/// Callback for SGXSan Pass
/// Used by static allocas
/// Already applied InEnclave flag in PASS before call these
#define ASAN_SET_SHADOW(shadowValue)                                           \
  extern "C" void __asan_set_shadow_##shadowValue(uptr addr, uptr size) {      \
    memset((void *)addr, L1F(0x##shadowValue), size);                          \
  }

ASAN_SET_SHADOW(00)
ASAN_SET_SHADOW(f1)
ASAN_SET_SHADOW(f2)
ASAN_SET_SHADOW(f3)
ASAN_SET_SHADOW(f5)
ASAN_SET_SHADOW(f8)
ASAN_SET_SHADOW(fe)

/// Used by dynamic allocas
extern "C" void __asan_poison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanStackUseAfterScopeMagic);
}

extern "C" void __asan_unpoison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanNotPoisonedMagic, true);
}

static const uint64_t kAllocaRedzoneSize = 32UL;

extern "C" void __asan_alloca_poison(uptr addr, uptr size) {
  /// LeftRedzoneAddr < addr < PartialRzAligned <= PartialRzAddr <= RightRzAddr
  uptr LeftRedzoneAddr = addr - kAllocaRedzoneSize;
  uptr PartialRzAddr = addr + size;
  uptr RightRzAddr = RoundUpTo(PartialRzAddr, kAllocaRedzoneSize);
  uptr PartialRzAligned = RoundDownTo(PartialRzAddr, SHADOW_GRANULARITY);

  FastPoisonShadow(LeftRedzoneAddr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
  FastPoisonShadow(addr, PartialRzAligned - addr, kAsanNotPoisonedMagic);
  FastPoisonShadowPartialRightRedzone(
      PartialRzAligned, PartialRzAddr % SHADOW_GRANULARITY,
      RightRzAddr - PartialRzAligned, kAsanAllocaRightMagic);
  FastPoisonShadow(RightRzAddr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
}

extern "C" void __asan_allocas_unpoison(uptr top, uptr bottom) {
  if ((!top) || (top > bottom))
    return;
  memset((void *)MemToShadow(top), kAsanNotPoisonedMagic,
         (bottom - top) / SHADOW_GRANULARITY);
}

/// Level 1 API
void FastPoisonShadow(uptr aligned_addr, uptr aligned_size, uint8_t value,
                      bool returnBackToNormal) {
  memset((void *)MEM_TO_SHADOW(aligned_addr),
         returnBackToNormal ? value : L0P(value),
         aligned_size / SHADOW_GRANULARITY);
}

/// Poison valid memory with right redzone
void FastPoisonShadowPartialRightRedzone(uptr aligned_addr, uptr size,
                                         uptr aligned_size_with_rz,
                                         uint8_t rz_value) {
  uint8_t *shadow = (uint8_t *)MEM_TO_SHADOW(aligned_addr);
  for (uptr i = 0; i < aligned_size_with_rz; i += SHADOW_GRANULARITY) {
    shadow[i / SHADOW_GRANULARITY] =
        L0P(i + SHADOW_GRANULARITY <= size ? kAsanNotPoisonedMagic
            : i >= size                    ? rz_value
                                           : size - i);
  }
}

void PoisonShadow(uptr addr, uptr size, uint8_t value,
                  bool returnBackToNormal) {
  // If addr do not aligned at granularity, start posioning from
  // RoundUpTo(addr, granularity)
  if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY))) {
    uptr aligned_addr = RoundUpTo(addr, SHADOW_GRANULARITY);
    if (size <= aligned_addr - addr) {
      return;
    }
    size -= aligned_addr - addr;
    addr = aligned_addr;
  }

  uint8_t remained = size & (SHADOW_GRANULARITY - 1);
  FastPoisonShadow(addr, size - remained, value, returnBackToNormal);

  if (remained) {
    uint8_t *shadowEnd = (uint8_t *)MEM_TO_SHADOW(addr + size - remained);
    int8_t origValue = L1F(*shadowEnd);
    if (value >= 0x80) {
      if (0 < origValue && origValue <= (int8_t)remained)
        *shadowEnd = L0P(value);
    } else if (value == kAsanNotPoisonedMagic) {
      uint8_t poisonVal = std::max(origValue, (int8_t)remained);
      *shadowEnd = returnBackToNormal ? poisonVal : L0P(poisonVal);
    } else {
      abort();
    }
  }
}

// This structure is used to describe the source location of a place where
// global was defined.
struct __asan_global_source_location {
  const char *filename;
  int line_no;
  int column_no;
};

// This structure describes an instrumented global variable.
struct SGXSanGlobal {
  uptr beg;                // The address of the global.
  uptr size;               // The original size of the global.
  uptr size_with_redzone;  // The size with the redzone.
  const char *name;        // Name as a C string.
  const char *module_name; // Module name as a C string. This pointer is a
                           // unique identifier of a module.
  uptr has_dynamic_init;   // Non-zero if the global has dynamic initializer.
  __asan_global_source_location *location; // Source location of a global,
                                           // or NULL if it is unknown.
  uptr odr_indicator; // The address of the ODR indicator symbol.
};

struct DynInitGlobal {
  SGXSanGlobal g;
  bool initialized;
};

static pthread_mutex_t mu_for_globals = PTHREAD_MUTEX_INITIALIZER;
static std::vector<DynInitGlobal> dynamic_init_globals;

static void PoisonRedZones(const SGXSanGlobal &g) {
  uptr aligned_size = RoundUpTo(g.size, SHADOW_GRANULARITY);
  FastPoisonShadow(g.beg + aligned_size, g.size_with_redzone - aligned_size,
                   kAsanGlobalRedzoneMagic);
  if (g.size != aligned_size) {
    FastPoisonShadowPartialRightRedzone(
        g.beg + RoundDownTo(g.size, SHADOW_GRANULARITY),
        g.size % SHADOW_GRANULARITY, SHADOW_GRANULARITY,
        kAsanGlobalRedzoneMagic);
  }
}

static void PoisonShadowForGlobal(const SGXSanGlobal *g, uint8_t value) {
  FastPoisonShadow(g->beg, g->size_with_redzone, value);
}

// Register a global variable.
// This function may be called more than once for every global
// so we store the globals in a map.
static void RegisterGlobal(const SGXSanGlobal *g) {
  sgxsan_assert(asan_inited and AddrIsInMem(g->beg));
  sgxsan_error(!IsAligned(g->beg, SHADOW_GRANULARITY),
               "The following global variable is not properly aligned.\n"
               "This may happen if another global with the same name\n"
               "resides in another non-instrumented module.\n"
               "Or the global comes from a C file built w/o -fno-common.\n"
               "In either case this is likely an ODR violation bug,\n"
               "but AddressSanitizer can not provide more details.\n");
  sgxsan_assert(IsAligned(g->size_with_redzone, SHADOW_GRANULARITY));

  uptr aligned_size = RoundUpTo(g->size, SHADOW_GRANULARITY);
  sgxsan_assert(g->size_with_redzone > aligned_size);
  FastPoisonShadow(g->beg, aligned_size, kAsanNotPoisonedMagic);
  PoisonRedZones(*g);

  if (g->has_dynamic_init) {
    DynInitGlobal dyn_global = {*g, false};
    dynamic_init_globals.push_back(dyn_global);
  }
}

// Register an array of globals.
extern "C" void __asan_register_globals(SGXSanGlobal *globals, uptr n) {
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0; i < n; i++) {
    RegisterGlobal(&globals[i]);
  }

  // Poison the metadata. It should not be accessible to user code.
  PoisonShadow((uptr)globals, n * sizeof(SGXSanGlobal),
               kAsanGlobalRedzoneMagic);
  pthread_mutex_unlock(&mu_for_globals);
}

static void UnregisterGlobal(const SGXSanGlobal *g) {
  sgxsan_assert(asan_inited and AddrIsInMem(g->beg) and
                IsAligned(g->beg, SHADOW_GRANULARITY) and
                IsAligned(g->size_with_redzone, SHADOW_GRANULARITY));

  FastPoisonShadow(g->beg, g->size_with_redzone, kAsanNotPoisonedMagic, true);
}

// Unregister an array of globals.
// We must do this when a shared objects gets dlclosed.
extern "C" void __asan_unregister_globals(SGXSanGlobal *globals, uptr n) {
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0; i < n; i++) {
    UnregisterGlobal(&globals[i]);
  }

  // Remove corresponding dynamic-init entries.
  dynamic_init_globals.erase(std::remove_if(dynamic_init_globals.begin(),
                                            dynamic_init_globals.end(),
                                            [&](const DynInitGlobal &dg) {
                                              for (uptr i = 0; i < n; i++)
                                                if (dg.g.beg == globals[i].beg)
                                                  return true;
                                              return false;
                                            }),
                             dynamic_init_globals.end());

  // Unpoison the metadata.
  PoisonShadow((uptr)globals, n * sizeof(SGXSanGlobal), kAsanNotPoisonedMagic,
               true);
  pthread_mutex_unlock(&mu_for_globals);
}

extern "C" void __asan_before_dynamic_init(const char *module_name) {
  if (!asan_inited || dynamic_init_globals.empty())
    return;
  pthread_mutex_lock(&mu_for_globals);
  for (auto &dyn_g : dynamic_init_globals) {
    if (dyn_g.initialized)
      continue;
    if (dyn_g.g.module_name != module_name)
      PoisonShadowForGlobal(&dyn_g.g, kAsanInitializationOrderMagic);
    else
      dyn_g.initialized = true;
  }
  pthread_mutex_unlock(&mu_for_globals);
}

extern "C" void
__sanitizer_annotate_contiguous_container(const void *beg_p, const void *end_p,
                                          const void *old_mid_p,
                                          const void *new_mid_p) {
  uptr beg = reinterpret_cast<uptr>(beg_p);
  uptr end = reinterpret_cast<uptr>(end_p);
  uptr old_mid = reinterpret_cast<uptr>(old_mid_p);
  uptr new_mid = reinterpret_cast<uptr>(new_mid_p);
  uptr granularity = SHADOW_GRANULARITY;

  sgxsan_error(!(beg <= old_mid && beg <= new_mid && old_mid <= end &&
                 new_mid <= end && IsAligned(beg, granularity)),
               "__sanitizer_annotate_contiguous_container: Invalid parameters\n"
               "beg=%p, end=%p, old_mid=%p, new_mid=%p\n",
               beg_p, end_p, old_mid_p, new_mid_p);

  uptr a = RoundDownTo(std::min(old_mid, new_mid), granularity);
  uptr c = RoundUpTo(std::max(old_mid, new_mid), granularity);
  uptr b1 = RoundDownTo(new_mid, granularity);
  uptr b2 = RoundUpTo(new_mid, granularity);

  PoisonShadow(a, b1 - a, 0);
  PoisonShadow(b2, c - b2, kAsanContiguousContainerOOBMagic);

  if (b1 != b2) {
    uint8_t *shadow_b1 = (uint8_t *)MEM_TO_SHADOW(b1);
    *shadow_b1 = L0P(static_cast<uint8_t>(new_mid - b1));
  }
}

extern "C" void __asan_after_dynamic_init() {
  if (!asan_inited || dynamic_init_globals.empty())
    return;
  pthread_mutex_lock(&mu_for_globals);
  for (auto &dyn_g : dynamic_init_globals) {
    if (!dyn_g.initialized) {
      PoisonShadowForGlobal(&dyn_g.g, kAsanNotPoisonedMagic);
      PoisonRedZones(dyn_g.g);
    }
  }
  pthread_mutex_unlock(&mu_for_globals);
}
