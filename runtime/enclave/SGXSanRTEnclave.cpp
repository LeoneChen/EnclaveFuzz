#include "SGXSanRTEnclave.hpp"
#include "Poison.hpp"
#include "SGXSanRTConfig.h"
#include "SGXSanRTTBridge.hpp"
#include "mbusafecrt.h"
#include "thread_data.h"
#include "trts_util.h"
#include <assert.h>
#include <cstdint>
#include <pthread.h>
#include <sgx_trts_exception.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum log_level g_log_level = LOG_LEVEL_WARNING;
int asan_inited = 0;
uint8_t *g_sancov_cntrs_start = nullptr, *g_sancov_cntrs_end = nullptr;
uintptr_t *g_sancov_pcs_start = nullptr, *g_sancov_pcs_end = nullptr;
uint8_t *g_sancov_copy_cntrs_start = nullptr,
        *g_sancov_copy_cntrs_end = nullptr;
uintptr_t *g_sancov_copy_pcs_start = nullptr, *g_sancov_copy_pcs_end = nullptr;

/* Internal exception handler */
// #PF etc. need platform (e.g. SGXv2 CPU) support conditonal exception handling
int sgxsan_exception_handler(sgx_exception_info_t *info) {
  // SGX_EXCEPTION_VECTOR_PF == 14 (#PF)
  if (info->exception_vector == SGX_EXCEPTION_VECTOR_PF) {
    uptr fault_addr = (uptr)info->exinfo.faulting_address;
    uptr pc = (uptr)info->cpu_context.rip;
    // In enclave AEX context the faulting address is always valid (no SI_KERNEL
    // ambiguity), so we can classify it directly.
    log_error("#PF Addr %p at pc %p => ", (void *)fault_addr, (void *)pc);
    if (fault_addr < PAGE_SIZE) {
      log_error_np("Null-Pointer dereference\n");
    } else if (((g_enclave_base - PAGE_SIZE) <= fault_addr &&
                fault_addr < g_enclave_base) ||
               ((g_enclave_base + g_enclave_size) <= fault_addr &&
                fault_addr <=
                    (g_enclave_base + g_enclave_size - 1 + PAGE_SIZE))) {
      log_error_np("Pointer dereference overflows enclave boundary "
                   "(Overlapping memory access)\n");
    } else if ((g_enclave_base + g_enclave_size - 0x1000) <= fault_addr &&
               fault_addr < (g_enclave_base + g_enclave_size)) {
      log_error_np(
          "Infer pointer dereference overflows enclave boundary, as "
          "mprotect's effort is page-granularity and faulting_address only "
          "gives page-granularity address\n");
    } else if ((kLowShadowGuardBeg <= fault_addr &&
                fault_addr < kLowShadowBeg) ||
               (kHighShadowEnd < fault_addr &&
                fault_addr <= kHighShadowGuardEnd)) {
      log_error_np("Pointer dereference overflows shadow map boundary "
                   "(Overlapping memory access)\n");
    } else if ((kHighShadowEnd + 1 - 0x1000) <= fault_addr &&
               fault_addr <= kHighShadowEnd) {
      log_error_np(
          "Infer pointer dereference overflows shadow map boundary, as "
          "mprotect's effort is page-granularity and faulting_address only "
          "gives page-granularity address\n");
    } else {
      log_error_np("Unknown page fault\n");
    }
  }
  dump_sancov();
  sgxsan_backtrace();
  return EXCEPTION_CONTINUE_SEARCH;
}

/* Initialize */
static void init_shadow_memory_out_enclave() {
  sgxsan_assert(SGX_SUCCESS == sgxsan_ocall_init_shadow_memory(
                                   g_enclave_base, g_enclave_size,
                                   (uptr *)&g_sancov_copy_cntrs_start,
                                   (uptr *)&g_sancov_copy_cntrs_end,
                                   (uptr *)&g_sancov_copy_pcs_start,
                                   (uptr *)&g_sancov_copy_pcs_end));
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

extern "C" {

void sgxsan_abort() { __builtin_trap(); }

void __asan_init() {
  // sgxsdk already ensure each ctor only run once
  AsanInitInternal();
}

void __asan_version_mismatch_check_v8() {
  // Do nothing.
}

void UnpoisonStack(uptr bottom, uptr top, const char *type) {
  static const uptr kMaxExpectedCleanupSize = 64 << 20; // 64M
  if (top - bottom > kMaxExpectedCleanupSize) {
    static bool reported_warning = false;
    if (reported_warning)
      return;
    reported_warning = true;
    log_warning("ASan is ignoring requested __asan_handle_no_return: "
                "stack type: %s top: %p; bottom %p; size: %p (%zd)\n"
                "False positive error reports may follow\n"
                "For details see "
                "https://github.com/google/sanitizers/issues/189\n",
                type, top, bottom, top - bottom, top - bottom);
    return;
  }
  PoisonShadow(bottom, RoundUpTo(top - bottom, SHADOW_GRANULARITY), 0);
}

void __asan_handle_no_return() {
  thread_data_t *td = get_thread_data();
  uintptr_t bottom = td->stack_limit_addr; // 低地址
  uintptr_t top = td->stack_base_addr;     // 高地址
  UnpoisonStack(bottom, top, "default");
}

__attribute__((destructor)) void dump_sancov() {
  log_debug("dump_sancov\n");
  memcpy_s((void *)g_sancov_copy_cntrs_start,
           g_sancov_copy_cntrs_end - g_sancov_copy_cntrs_start,
           g_sancov_cntrs_start, g_sancov_cntrs_end - g_sancov_cntrs_start);
  memcpy_s((void *)g_sancov_copy_pcs_start,
           (g_sancov_copy_pcs_end - g_sancov_copy_pcs_start) * 8,
           g_sancov_pcs_start, (g_sancov_pcs_end - g_sancov_pcs_start) * 8);
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