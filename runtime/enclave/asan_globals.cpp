#include "asan_globals.hpp"
#include "InternalDlmalloc.hpp"
#include "Poison.hpp"
#include <pthread.h>

typedef __asan_global Global;

#define Report log_warning

#define CHECK sgxsan_assert

static pthread_mutex_t mu_for_globals = PTHREAD_MUTEX_INITIALIZER;

struct DynInitGlobal {
  Global g;
  bool initialized;
};

// Lazily initialized; tracks globals that have dynamic initializers.
// Implemented as a manually grown array backed by dlmalloc to avoid
// SGX SDK STL limitations and malloc re-entry issues.
static DynInitGlobal *dynamic_init_globals = nullptr;
static uptr dynamic_init_globals_size = 0;
static uptr dynamic_init_globals_capacity = 0;

static void push_dyn_global(const DynInitGlobal &dg) {
  if (dynamic_init_globals_size >= dynamic_init_globals_capacity) {
    uptr new_cap = dynamic_init_globals_capacity == 0
                       ? 64
                       : dynamic_init_globals_capacity * 2;
    dynamic_init_globals = (DynInitGlobal *)dlrealloc(
        dynamic_init_globals, new_cap * sizeof(DynInitGlobal));
    dynamic_init_globals_capacity = new_cap;
  }
  dynamic_init_globals[dynamic_init_globals_size++] = dg;
}

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

  // Track globals that need dynamic-init-order checking.
  if (g->has_dynamic_init) {
    DynInitGlobal dyn_global = {*g, false};
    push_dyn_global(dyn_global);
  }
}

extern "C" {
// Register an array of globals.
void __asan_register_globals(__asan_global *globals, uptr n) {
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0; i < n; i++) {
    RegisterGlobal(&globals[i]);
  }

  // Poison the metadata. It should not be accessible to user code.
  PoisonShadow(reinterpret_cast<uptr>(globals), n * sizeof(__asan_global),
               kAsanGlobalRedzoneMagic);
  pthread_mutex_unlock(&mu_for_globals);
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
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0; i < n; i++) {
    UnregisterGlobal(&globals[i]);
  }

  // Unpoison the metadata.
  UnPoisonShadow(reinterpret_cast<uptr>(globals), n * sizeof(__asan_global));
  pthread_mutex_unlock(&mu_for_globals);
}

// Runs immediately BEFORE dynamic initialization of each TU.
//
// Strategy: poison every dynamic global that belongs to a *different* TU so
// that any cross-TU access during initialization is caught.  Globals that
// belong to the current TU (identified by pointer-equality of module_name)
// are left unpoisoned and marked initialized so they are skipped in future
// calls.
void __asan_before_dynamic_init(const char *module_name) {
  if (!asan_inited || !dynamic_init_globals)
    return;
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0, n = dynamic_init_globals_size; i < n; ++i) {
    DynInitGlobal &dyn_g = dynamic_init_globals[i];
    const Global *g = &dyn_g.g;
    if (dyn_g.initialized)
      continue; // already confirmed initialized, skip
    if (g->module_name != module_name)
      // Different TU: poison the global body to trap premature accesses.
      PoisonShadowForGlobal(g, kAsanInitializationOrderMagic);
    else
      // Same TU: about to be initialized, mark it so future iterations skip it.
      dyn_g.initialized = true;
  }
  pthread_mutex_unlock(&mu_for_globals);
}

// Runs immediately AFTER dynamic initialization of each TU.
//
// Unpoisons every global that was temporarily poisoned by before_dynamic_init,
// then restores its redzones so normal out-of-bounds detection still works.
void __asan_after_dynamic_init() {
  if (!asan_inited || !dynamic_init_globals)
    return;
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0, n = dynamic_init_globals_size; i < n; ++i) {
    DynInitGlobal &dyn_g = dynamic_init_globals[i];
    const Global *g = &dyn_g.g;
    if (!dyn_g.initialized) {
      // Unpoison the whole global body.
      PoisonShadowForGlobal(g, 0);
      // Re-poison redzones for normal OOB detection.
      PoisonRedZones(*g);
    }
  }
  pthread_mutex_unlock(&mu_for_globals);
}
}