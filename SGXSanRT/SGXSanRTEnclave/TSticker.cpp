#include "Poison.h"
#include "SGXSanRTApp.h"
#include "Sticker.h"
#include "arch.h"
#include "rts_cmd.h"
#include "rts_sim.h"
#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_key.h"
#include "trts_internal_types.h"
#include <assert.h>
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
    // We already initialized shadow memory in host ctor
    if (hook_enclave() != 0) {
      abort();
    }
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

extern "C" __attribute__((weak)) int __llvm_profile_write_file(void);
extern "C" void TSticker__llvm_profile_write_file() {
  if (__llvm_profile_write_file)
    __llvm_profile_write_file();
}
