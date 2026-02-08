#include "SGXSanRTEnclave.hpp"
#include "Poison.hpp"
#include "SGXSanRTConfig.h"
#include "SGXSanRTTBridge.hpp"
#include "mbusafecrt.h"
#include "trts_util.h"
#include <assert.h>
#include <cstdint>
#include <pthread.h>
#include <sgx_trts_exception.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t sgxsan_init_mutex = PTHREAD_MUTEX_INITIALIZER;
enum log_level g_log_level = LOG_LEVEL_WARNING;
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

extern "C" {
uint8_t *g_sancov_cntrs_start = nullptr, *g_sancov_cntrs_end = nullptr;
uintptr_t *g_sancov_pcs_start = nullptr, *g_sancov_pcs_end = nullptr;

void sgxsan_ecall_dump_sancov(uint64_t cntrs_start, uint64_t cntrs_end,
                              uint64_t pcs_start, uint64_t pcs_end) {
  memcpy_s((void *)cntrs_start, cntrs_end - cntrs_start, g_sancov_cntrs_start,
           g_sancov_cntrs_end - g_sancov_cntrs_start);
  memcpy_s((void *)pcs_start, pcs_end - pcs_start, g_sancov_pcs_start,
           (g_sancov_pcs_end - g_sancov_pcs_start) * 8);
}

void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop) {
  g_sancov_cntrs_start = Start;
  g_sancov_cntrs_end = Stop;
}

void __sanitizer_cov_pcs_init(uintptr_t *pcs_beg, uintptr_t *pcs_end) {
  g_sancov_pcs_start = pcs_beg;
  g_sancov_pcs_end = pcs_end;
}
}