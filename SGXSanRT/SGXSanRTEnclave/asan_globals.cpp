#include "asan_globals.hpp"
#include "Poison.hpp"

typedef __asan_global Global;

#define Report log_warning

#define CHECK sgxsan_assert

inline void PoisonRedZones(const Global &g) {
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

// Register a global variable.
// This function may be called more than once for every global
// so we store the globals in a map.
static void RegisterGlobal(const Global *g) {
  CHECK(asan_inited);
  CHECK(AddrIsInMem(g->beg));
  if (!AddrIsAlignedByGranularity(g->beg)) {
    Report("The following global variable is not properly aligned.\n");
    Report("This may happen if another global with the same name\n");
    Report("resides in another non-instrumented module.\n");
    Report("Or the global comes from a C file built w/o -fno-common.\n");
    Report("In either case this is likely an ODR violation bug,\n");
    Report("but AddressSanitizer can not provide more details.\n");
    CHECK(AddrIsAlignedByGranularity(g->beg));
  }
  CHECK(AddrIsAlignedByGranularity(g->size_with_redzone));

  PoisonRedZones(*g);
}

extern "C" {
// Register an array of globals.
void __asan_register_globals(__asan_global *globals, uptr n) {
  for (uptr i = 0; i < n; i++) {
    RegisterGlobal(&globals[i]);
  }

  // Poison the metadata. It should not be accessible to user code.
  PoisonShadow(reinterpret_cast<uptr>(globals), n * sizeof(__asan_global),
               kAsanGlobalRedzoneMagic);
}

static inline void PoisonShadowForGlobal(const Global *g, u8 value) {
  FastPoisonShadow(g->beg, g->size_with_redzone, value);
}

static void UnregisterGlobal(const Global *g) {
  CHECK(asan_inited);
  CHECK(AddrIsInMem(g->beg));
  CHECK(AddrIsAlignedByGranularity(g->beg));
  CHECK(AddrIsAlignedByGranularity(g->size_with_redzone));

  PoisonShadowForGlobal(g, 0);
}

// Unregister an array of globals.
// We must do this when a shared objects gets dlclosed.
void __asan_unregister_globals(__asan_global *globals, uptr n) {
  for (uptr i = 0; i < n; i++) {
    UnregisterGlobal(&globals[i]);
  }

  // Unpoison the metadata.
  UnPoisonShadow(reinterpret_cast<uptr>(globals), n * sizeof(__asan_global));
}
}