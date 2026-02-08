#include "SGXSanRTEnclave.hpp"
#include "Poison.hpp"
#include "SGXSanRTTBridge.hpp"
#include "trts_util.h"
#include <assert.h>
#include <pthread.h>
#include <sgx_trts_exception.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static pthread_mutex_t sgxsan_init_mutex = PTHREAD_MUTEX_INITIALIZER;

int asan_inited = 0;

/* Internal exception handler */
// #PF etc. need platform (e.g. SGXv2 CPU) support conditonal exception handling
int sgxsan_exception_handler(sgx_exception_info_t *info) {
  (void)info;
  sgxsan_backtrace();
  return EXCEPTION_CONTINUE_SEARCH;
}

/* Initialize */
static void init_shadow_memory_out_enclave() {
  sgxsan_assert(SGX_SUCCESS == sgxsan_ocall_init_shadow_memory(g_enclave_base,
                                                               g_enclave_size));
  // Poison shadow map of Enclave heap
  uptr enclaveHeapBase = (uptr)get_heap_base();
  size_t enclaveHeapSize = get_heap_size();
  sgxsan_assert(enclaveHeapSize % SHADOW_GRANULARITY == 0);
  memset((void *)MEM_TO_SHADOW(enclaveHeapBase), kAsanHeapLeftRedzoneMagic,
         enclaveHeapSize / SHADOW_GRANULARITY);
}

static void AsanInitInternal() {
  if (LIKELY(asan_inited))
    return;

  init_shadow_memory_out_enclave();

  asan_inited = 1;

  sgxsan_assert(sgx_register_exception_handler(1, sgxsan_exception_handler) !=
                nullptr);
}

void AsanInitFromRtl() {
  pthread_mutex_lock(&sgxsan_init_mutex);
  AsanInitInternal();
  pthread_mutex_unlock(&sgxsan_init_mutex);
}

void __asan_init() {
  // sgxsdk already ensure each ctor only run once
  AsanInitInternal();
}
