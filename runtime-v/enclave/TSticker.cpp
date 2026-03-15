#include "Poison.h"
#include "SGXSanRTApp.h"
#include "Sticker.h"
#include "rts_cmd.h"
#include "rts_sim.h"
#include "sgx_eid.h"
#include "trts_internal_types.h"
#include <assert.h>
#include <new>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/// Birdge Sticker
typedef sgx_status_t (*ecall_func_t)(void *ms);
extern const ecall_table_t g_ecall_table;
extern entry_table_t g_dyn_entry_table;
secs_t g_secs;

static void SGXInitInternal() {
  // Prepare necessary Enclave's state
  g_global_data_sim.secs_ptr = &g_secs;
  PoisonShadow((uptr)&g_secs, sizeof(g_secs), kAsanNotPoisonedMagic);
}

extern "C" sgx_status_t tsticker_ecall(const sgx_enclave_id_t eid,
                                       const int index, const void *ocall_table,
                                       void *ms) {
  sgx_status_t result = SGX_ERROR_UNEXPECTED;
  if (index == ECMD_INIT_ENCLAVE) {
    SGXInitInternal();
    result = SGX_SUCCESS;
  } else {
    assert(index < (int)g_ecall_table.nr_ecall);
    result = ((ecall_func_t)g_ecall_table.ecall_table[index].ecall_addr)(ms);
  }
  return result;
}

/// @brief Must called before SanitizerCoverage's ctors, since in this function
/// I hook callbacks in these ctors.
extern "C" void __asan_init() {
  // gAlreadyAsanInited should reside in Enclave image, since we should set it
  // to false whenever we load Enclave image and call __asan_init
  static bool gAlreadyAsanInited = false;
  if (gAlreadyAsanInited == false) {
    register_sgxsan_sigaction();
    gEnclaveInfo.PoisonEnclaveDSOCode();
    gAlreadyAsanInited = true;
  }
}

extern "C" bool check_ecall(ECallCheckType ty, uint32_t targetECallIdx,
                            unsigned int curOCallIdx) {
  switch (ty) {
  case CHECK_ECALL_PRIVATE: {
    return g_ecall_table.ecall_table[targetECallIdx].is_priv;
  }
  case CHECK_ECALL_ALLOWED: {
    sgxsan_assert(curOCallIdx < g_dyn_entry_table.nr_ocall);
    return g_dyn_entry_table
        .entry_table[curOCallIdx * g_ecall_table.nr_ecall + targetECallIdx];
  }
  default: {
    abort();
  }
  }
}

extern "C" {
void *sgxsan_malloc_raw(size_t size, uptr alignment);
void sgxsan_free_raw(void *ptr, uptr alignment, uptr expected_size);

void *sgxsan_malloc(size_t size);
void *malloc(size_t size) { return sgxsan_malloc(size); }

void sgxsan_free(void *ptr);
void free(void *ptr) { sgxsan_free(ptr); }

void *sgxsan_calloc(size_t n_elements, size_t elem_size);
void *calloc(size_t n_elements, size_t elem_size) {
  return sgxsan_calloc(n_elements, elem_size);
}

void *sgxsan_realloc(void *oldmem, size_t bytes);
void *realloc(void *oldmem, size_t bytes) {
  return sgxsan_realloc(oldmem, bytes);
}

size_t sgxsan_malloc_usable_size(void *mem);
size_t malloc_usable_size(void *mem) { return sgxsan_malloc_usable_size(mem); }

// Intercept enclave DSO's sancov registrations via protected visibility.
// Within this DSO, all calls bind to these definitions instead of libfuzzer's.
__attribute__((visibility("protected"))) void
__sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop) {
  SGXSanSaveEnclaveCntrsRange(Start, Stop);
}

__attribute__((visibility("protected"))) void
__sanitizer_cov_pcs_init(const uintptr_t *Start, const uintptr_t *Stop) {
  SGXSanSaveEnclavePCsRange(Start, Stop);
}
}

void *operator new(size_t size) {
  void *ptr = sgxsan_malloc(size);
  if (!ptr)
    throw std::bad_alloc();
  return ptr;
}
void *operator new[](size_t size) { return operator new(size); }
void operator delete(void *ptr) noexcept { sgxsan_free(ptr); }
void operator delete[](void *ptr) noexcept { sgxsan_free(ptr); }

void *operator new(size_t size, const std::nothrow_t &) noexcept {
  return sgxsan_malloc(size);
}
void *operator new[](size_t size, const std::nothrow_t &) noexcept {
  return sgxsan_malloc(size);
}
void operator delete(void *ptr, const std::nothrow_t &) noexcept {
  sgxsan_free(ptr);
}
void operator delete[](void *ptr, const std::nothrow_t &) noexcept {
  sgxsan_free(ptr);
}

#ifdef __cpp_sized_deallocation
void operator delete(void *ptr, size_t size) noexcept {
  sgxsan_free_raw(ptr, SHADOW_GRANULARITY, size);
}
void operator delete[](void *ptr, size_t size) noexcept {
  operator delete(ptr, size);
}
#endif

#ifdef __cpp_aligned_new
void *operator new(size_t size, std::align_val_t align) {
  size_t alignment = static_cast<size_t>(align);
  void *ptr = sgxsan_malloc_raw(size, alignment);
  if (!ptr)
    throw std::bad_alloc();
  return ptr;
}

void operator delete(void *ptr, size_t size, std::align_val_t align) noexcept {
  if (!ptr)
    return;
  size_t alignment = static_cast<size_t>(align);
  sgxsan_free_raw(ptr, alignment, size);
}

void operator delete(void *ptr, std::align_val_t align) noexcept {
  operator delete(ptr, 0, align);
}

void *operator new[](size_t size, std::align_val_t align) {
  return operator new(size, align);
}
void operator delete[](void *ptr, std::align_val_t align) noexcept {
  operator delete(ptr, align);
}

void operator delete[](void *ptr, size_t size,
                       std::align_val_t align) noexcept {
  operator delete(ptr, size, align);
}

void *operator new(size_t size, std::align_val_t align,
                   const std::nothrow_t &) noexcept {
  try {
    return operator new(size, align);
  } catch (...) {
    return nullptr;
  }
}

void *operator new[](size_t size, std::align_val_t align,
                     const std::nothrow_t &) noexcept {
  try {
    return operator new[](size, align);
  } catch (...) {
    return nullptr;
  }
}

void operator delete(void *ptr, std::align_val_t align,
                     const std::nothrow_t &) noexcept {
  operator delete(ptr, align);
}

void operator delete[](void *ptr, std::align_val_t align,
                       const std::nothrow_t &) noexcept {
  operator delete[](ptr, align);
}
#endif
