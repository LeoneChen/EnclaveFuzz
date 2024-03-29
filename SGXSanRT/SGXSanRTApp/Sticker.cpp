#include "Sticker.h"
#include "ArgShadow.h"
#include "HostASanRT.h"
#include "Malloc.h"
#include "MemAccessMgr.h"
#include "Poison.h"
#include "SGXSanRTApp.h"
#include "arch.h"
#include "cpuid.h"
#include "plthook.h"
#include "routine.h"
#include "rts_cmd.h"
#include "sgx_edger8r.h"
#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_thread.h"
#include "sgx_urts.h"
#include "trts_internal.h"
#include <algorithm>
#include <errno.h>
#include <filesystem>
#include <fstream>
#include <link.h>
#include <map>
#include <pthread.h>
#include <regex>
#include <set>
#include <stack>
#include <thread_data.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

EnclaveInfo gEnclaveInfo;

/// Birdge Sticker
typedef sgx_status_t (*bridge_fn_t)(const void *);

__thread sgx_ocall_table_t *g_enclave_ocall_table = nullptr;
__thread bool RunInEnclave = false;
__thread bool AlreadyFirstECall = false;
__thread TrustThread sgxsan_thread;
thread_local std::vector<unsigned int> ocallHistory;

/// Thread Data
extern "C" thread_data_t *get_thread_data() { return &sgxsan_thread.m_td; }

sgx_status_t (*tsticker_ecall)(const sgx_enclave_id_t eid, const int index,
                               const void *ocall_table, void *ms);
bool (*check_ecall)(ECallCheckType ty, uint32_t targetECallIdx,
                    unsigned int curOCallIdx);

extern "C" sgx_status_t sgx_ecall(const sgx_enclave_id_t eid, const int index,
                                  const void *ocall_table, void *ms) {
  (void)eid;
  sgx_status_t result = SGX_ERROR_UNEXPECTED;
  RunInEnclave = true;

  bool curIsFirstECall = false;
  if (AlreadyFirstECall == false) {
    // Current is fisrt ecall
    if (index >= 0 and check_ecall(CHECK_ECALL_PRIVATE, index, 0)) {
      result = SGX_ERROR_ECALL_NOT_ALLOWED;
      goto exit;
    }
    AlreadyFirstECall = true;
    curIsFirstECall = true;
  } else {
    // Current is OCall, but only allowed ECalls can be called,
    // thus to check it
    if (index >= 0 and
        not check_ecall(CHECK_ECALL_ALLOWED, index, ocallHistory.back())) {
      result = SGX_ERROR_ECALL_NOT_ALLOWED;
      goto exit;
    }
  }

  g_enclave_ocall_table = (sgx_ocall_table_t *)ocall_table;
  get_thread_data()->last_error = errno;
  sgxsan_assert(tsticker_ecall);
  result = tsticker_ecall(eid, index, nullptr, ms);
  if (curIsFirstECall) {
    AlreadyFirstECall = false;
  }
exit:
  RunInEnclave = false;
  return result;
}
extern "C" sgx_status_t sgx_ecall_switchless(const sgx_enclave_id_t eid,
                                             const int index,
                                             const void *ocall_table, void *ms)
    __attribute__((alias("sgx_ecall")));

extern "C" sgx_status_t sgx_ocall(const unsigned int index, void *ms) {
  RunInEnclave = false;
  sgxsan_assert(index < g_enclave_ocall_table->count);
  ocallHistory.push_back(index);
  auto result = ((bridge_fn_t)g_enclave_ocall_table->ocall[index])(ms);
  sgxsan_assert(ocallHistory.size() > 0 and ocallHistory.back() == index);
  ocallHistory.pop_back();
  RunInEnclave = true;
  return result;
}

extern "C" sgx_status_t sgx_ocall_switchless(const unsigned int index, void *ms)
    __attribute__((alias("sgx_ocall")));

// OCAllocStack
thread_local std::stack<std::vector<void *>> OCAllocStack;

extern "C" void PushOCAllocStack() {
  OCAllocStack.emplace(std::vector<void *>{});
}
extern "C" void PopOCAllocStack() { OCAllocStack.pop(); }

extern "C" void *sgx_ocalloc(size_t size) {
  auto &top = OCAllocStack.top();
  void *ocallocAddr = malloc(size);
  sgxsan_assert(ocallocAddr);
  top.push_back(ocallocAddr);
  return ocallocAddr;
}

extern "C" void sgx_ocfree() {
  auto &top = OCAllocStack.top();
  for (auto ocallocAddr : top) {
    free(ocallocAddr);
  }
}

extern "C" void ClearOCAllocStack() {
  while (OCAllocStack.size() > 0) {
    auto &top = OCAllocStack.top();
    for (auto ocallocAddr : top) {
      free(ocallocAddr);
    }
    top.clear();
    OCAllocStack.pop();
  }
}

// replace libsgx_tstdc with normal glibc and additional API
extern "C" {

int *__errno(void) { return &errno; }

void *__memset(void *dst, int c, size_t n) { return memset(dst, c, n); }

typedef error_t errno_t;
extern "C" errno_t memcpy_s(void *dst, size_t sizeInBytes, const void *src,
                            size_t count) {
  auto res = memcpy(dst, src, std::min(sizeInBytes, count));
  if (res != dst) {
    return -1;
  }
  return 0;
}

extern "C" errno_t memmove_s(void *dst, size_t sizeInBytes, const void *src,
                             size_t count) {
  auto res = memmove(dst, src, std::min(sizeInBytes, count));
  if (res != dst) {
    return -1;
  }
  return 0;
}

extern "C" errno_t memset_s(void *s, size_t smax, int c, size_t n) {
  auto res = memset(s, c, std::min(smax, n));
  if (res != s) {
    return -1;
  }
  return 0;
}

int heap_init(void *_heap_base, size_t _heap_size, size_t _heap_min_size,
              int _is_edmm_supported) {
  return SGX_SUCCESS;
}

int rsrv_mem_init(void *_rsrv_mem_base, size_t _rsrv_mem_size,
                  size_t _rsrv_mem_min_size) {
  return SGX_SUCCESS;
}

int sgx_init_string_lib(uint64_t cpu_feature_indicator) {
  (void)cpu_feature_indicator;
  return 0;
}

#ifdef alloca
#undef alloca
#endif
void *alloca(size_t __size) { return __builtin_alloca(__size); }

sgx_status_t sgx_cpuidex(int cpuinfo[4], int leaf, int subleaf) {
  if (cpuinfo == NULL)
    return SGX_ERROR_INVALID_PARAMETER;

  __cpuidex(cpuinfo, leaf, subleaf);
  return SGX_SUCCESS;
}

sgx_status_t sgx_cpuid(int cpuinfo[4], int leaf) {
  return sgx_cpuidex(cpuinfo, leaf, 0);
}
}

/// life time management
int dlItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size, void *data) {
  return gEnclaveInfo.DLItCBGetEnclaveDSO(info, size, data);
}

extern "C" __attribute__((weak)) void *GetOCallTableAddr();
extern "C" sgx_status_t __sgx_create_enclave_ex(
    const char *file_name, const int debug, sgx_launch_token_t *launch_token,
    int *launch_token_updated, sgx_enclave_id_t *enclave_id,
    sgx_misc_attribute_t *misc_attr, const uint32_t ex_features,
    const void *ex_features_p[32]) {
  std::string file_abs_path = fs::absolute(fs::path(file_name));
  sgxsan_assert(fs::exists(file_abs_path));
  gEnclaveInfo.SetEnclaveFileName(file_abs_path);
  if (GetOCallTableAddr) {
    g_enclave_ocall_table = (sgx_ocall_table_t *)GetOCallTableAddr();
  }
  RunInEnclave = true;
  auto EnclaveHandler =
      (struct link_map *)dlopen(file_abs_path.c_str(), RTLD_LAZY);
  RunInEnclave = false;
  sgxsan_error(EnclaveHandler == nullptr, "%s\n", dlerror());
  gEnclaveInfo.SetHandler(EnclaveHandler);

  sgxsan_assert(tsticker_ecall = (decltype(tsticker_ecall))dlsym(
                    EnclaveHandler, "tsticker_ecall"));
  sgxsan_assert(check_ecall = (decltype(check_ecall))dlsym(EnclaveHandler,
                                                           "check_ecall"));
  RunInEnclave = true;
  tsticker_ecall(0, ECMD_INIT_ENCLAVE, nullptr, nullptr);
  RunInEnclave = false;
  return SGX_SUCCESS;
}

extern "C" sgx_status_t sgx_create_enclave(const char *file_name,
                                           const int debug,
                                           sgx_launch_token_t *launch_token,
                                           int *launch_token_updated,
                                           sgx_enclave_id_t *enclave_id,
                                           sgx_misc_attribute_t *misc_attr) {
  return __sgx_create_enclave_ex(file_name, debug, launch_token,
                                 launch_token_updated, enclave_id, misc_attr, 0,
                                 NULL);
}

extern "C" sgx_status_t sgx_create_enclave_ex(
    const char *file_name, const int debug, sgx_launch_token_t *launch_token,
    int *launch_token_updated, sgx_enclave_id_t *enclave_id,
    sgx_misc_attribute_t *misc_attr, const uint32_t ex_features,
    const void *ex_features_p[32]) {
  return __sgx_create_enclave_ex(file_name, debug, launch_token,
                                 launch_token_updated, enclave_id, misc_attr,
                                 ex_features, ex_features_p);
}

#ifndef KAFL_FUZZER
extern "C" __attribute__((weak)) void
__sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop);
extern "C" __attribute__((weak)) void
__sanitizer_cov_8bit_counters_unregister(uint8_t *Start);
extern "C" __attribute__((weak)) void
__sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end);
extern "C" __attribute__((weak)) void
__sanitizer_cov_pcs_unregister(const uintptr_t *pcs_beg);

class SanCovMapRepeater {

  struct PCTableEntry {
    uintptr_t PC, PCFlags;
  };

public:
  void RegisterSanCov8Bit(uint8_t *Start, uint8_t *Stop) {
    if (!__sanitizer_cov_8bit_counters_init or
        !__sanitizer_cov_8bit_counters_unregister)
      return;
    if (m8BitStart2Stop.count(Start) != 0) {
      // Already registered
      sgxsan_assert(m8BitStart2Stop[Start] == Stop);
      return;
    }
    m8BitStart2Stop[Start] = Stop;
    __sanitizer_cov_8bit_counters_init(Start, Stop);
    if (mShowed8BitCntrs.count(Start) == 0) {
      log_always("Enclave __sanitizer_cov_8bit_counters_init, %ld inline "
                 "8-bit counts [%p, %p)\n",
                 (uptr)Stop - (uptr)Start, Start, Stop);
      mShowed8BitCntrs.emplace(Start);
    }
  }

  void RegisterSanCovPCs(const uintptr_t *pcs_beg, const uintptr_t *pcs_end) {
    if (!__sanitizer_cov_pcs_init or !__sanitizer_cov_pcs_unregister)
      return;
    if (mPCsBeg2End.count(pcs_beg) != 0) {
      // Already registered
      sgxsan_assert(mPCsBeg2End[pcs_beg] == pcs_end);
      return;
    }
    mPCsBeg2End[pcs_beg] = pcs_end;
    __sanitizer_cov_pcs_init(pcs_beg, pcs_end);
    if (mShowedPCs.count(pcs_beg) == 0) {
      log_always("Enclave __sanitizer_cov_pcs_init, %ld PCs [%p, %p)\n",
                 (PCTableEntry *)pcs_end - (PCTableEntry *)pcs_beg, pcs_beg,
                 pcs_end);
      mShowedPCs.emplace(pcs_beg);
    }
  }

  void UnregisterSanCov8Bit() {
    if (!__sanitizer_cov_8bit_counters_unregister)
      return;
    for (auto &pair : m8BitStart2Stop) {
      __sanitizer_cov_8bit_counters_unregister(pair.first);
    }
    m8BitStart2Stop.clear();
  }

  void UnregisterSanCovPCs() {
    if (!__sanitizer_cov_pcs_unregister)
      return;
    for (auto &pair : mPCsBeg2End) {
      __sanitizer_cov_pcs_unregister(pair.first);
    }
    mPCsBeg2End.clear();
  }

private:
  std::map<uint8_t *, uint8_t *> m8BitStart2Stop;
  std::map<const uintptr_t *, const uintptr_t *> mPCsBeg2End;
  std::set<uint8_t *> mShowed8BitCntrs;
  std::set<const uintptr_t *> mShowedPCs;
};

SanCovMapRepeater gRepeater;

extern "C" void SGXSAN(__sanitizer_cov_8bit_counters_init)(uint8_t *Start,
                                                           uint8_t *Stop) {
  gRepeater.RegisterSanCov8Bit(Start, Stop);
}

extern "C" void SGXSAN(__sanitizer_cov_pcs_init)(const uintptr_t *pcs_beg,
                                                 const uintptr_t *pcs_end) {
  gRepeater.RegisterSanCovPCs(pcs_beg, pcs_end);
}
#endif

void ClearSticker() {
  g_enclave_ocall_table = nullptr;
  RunInEnclave = false;
  AlreadyFirstECall = false;
  ocallHistory.clear();
  ClearOCAllocStack();
  gEnclaveInfo.Clear();
}

sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id) {
#ifndef KAFL_FUZZER
  gRepeater.UnregisterSanCov8Bit();
  gRepeater.UnregisterSanCovPCs();
#endif

  // Since we will access object belong to Enclave, so set RunInEnclave to true
  RunInEnclave = true;
  sgxsan_assert(dlclose(gEnclaveInfo.GetHandler()) == 0);
  RunInEnclave = false;

  // Clear SGXSanRT's global status belong to Enclave
  ClearSGXSanRT();
  MemAccessMgrClear();
  ClearArgShadowStack();
  ClearSticker();
  if (not gHostASanInited) {
    ClearStackPoison();
  }
  ClearHeapObject();
  return SGX_SUCCESS;
}

#ifndef KAFL_FUZZER
extern "C" __attribute__((weak)) int __llvm_profile_write_file(void);
void (*TSticker__llvm_profile_write_file)(void);
extern "C" void libFuzzerCrashCallback() {
  // Maybe enclave is destoryed
  if (gEnclaveInfo.GetHandler()) {
    TSticker__llvm_profile_write_file =
        (decltype(TSticker__llvm_profile_write_file))dlsym(
            gEnclaveInfo.GetHandler(), "TSticker__llvm_profile_write_file");
    if (TSticker__llvm_profile_write_file)
      TSticker__llvm_profile_write_file();
  }
  if (__llvm_profile_write_file)
    __llvm_profile_write_file();
}
#endif

extern "C" void GetEnclaveDSORange(uptr *start, uptr *end) {
  gEnclaveInfo.GetEnclaveDSORange(start, end);
}

uintptr_t GetOffsetIfEnclave(uintptr_t pc) {
  uintptr_t start = 0, end = 0;
  gEnclaveInfo.GetEnclaveDSORange(&start, &end);
  if (start and end and start < end and start <= pc and pc < end) {
    pc -= start;
  }
  return pc;
}
