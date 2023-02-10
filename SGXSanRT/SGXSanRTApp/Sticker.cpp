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

/// TCS Manager

TrustThreadPool _g_thread_pool;
TrustThreadPool *g_thread_pool = &_g_thread_pool;

/// Birdge Sticker
typedef sgx_status_t (*bridge_fn_t)(const void *);

__thread sgx_ocall_table_t *g_enclave_ocall_table = nullptr;
__thread bool RunInEnclave = false;
__thread bool AlreadyFirstECall = false;
__thread TrustThread *sgxsan_thread = nullptr;
thread_local std::vector<unsigned int> ocallHistory;

/// Thread Data
extern "C" thread_data_t *get_thread_data() { return &sgxsan_thread->m_td; }

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
    sgxsan_thread = g_thread_pool->alloc(gettid());
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
    g_thread_pool->free(sgxsan_thread);
    sgxsan_thread = nullptr;
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
static void *gEnclaveHandler = nullptr;
static std::map<uptr, uptr, std::less<uptr>,
                ContainerAllocator<std::pair<const uptr, uptr>>>
    EnclaveDSOStart2End;

bool isInEnclaveDSORange(uptr addr, size_t len) {
  for (auto pair : EnclaveDSOStart2End) {
    // Shouldn't overlap different segments
    if (pair.first <= addr and (addr + len) < pair.second) {
      return true;
    }
  }
  return false;
}

static int dlItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size,
                               void *data) {
  auto EnclaveDSOStart = *(uptr *)data;
  if (EnclaveDSOStart == info->dlpi_addr) {
    // Found interesting DSO
    for (int i = 0; i < info->dlpi_phnum; i++) {
      const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
      if (phdr->p_type == PT_LOAD) {
        // Found loadable segment
        uptr beg = RoundDownTo(EnclaveDSOStart + phdr->p_vaddr, phdr->p_align);
        uptr end = RoundUpTo(
            EnclaveDSOStart + phdr->p_vaddr + phdr->p_memsz - 1, phdr->p_align);

        // Poison Enclave DSO
        sgxsan_assert(EnclaveDSOStart2End.count(beg) == 0);
        EnclaveDSOStart2End[beg] = end;
      }
    }
    return 1;
  } else {
    return 0;
  }
}

void _PoisonEnclaveDSOCodeSegment() {
  for (auto pair : EnclaveDSOStart2End) {
    uptr beg = pair.first, end = pair.second;
    bool origInEnclave = false;
    if (RunInEnclave == false)
      RunInEnclave = true;
    else
      origInEnclave = true;
    PoisonShadow(beg, end - beg, kAsanNotPoisonedMagic);
    RunInEnclave = origInEnclave;
  }
}

void PoisonEnclaveDSOCodeSegment() {
  // Currently, called from __asan_init, we still in dlopen, so we can't get
  // dlopen-ed handler, and we also have to call this func before poisoning
  // global, since we directly write shadow byte of globals to map
  std::string enclaveFileName = getEnclaveFileName();
  sgxsan_assert(enclaveFileName != "");

  // Current Enclave is in dlopen-ing, and should already have been mmap-ed
  // We get start address of current Enclave
  auto handler = (struct link_map *)dlopen(enclaveFileName.c_str(),
                                           RTLD_LAZY | RTLD_NOLOAD);
  sgxsan_assert(handler);
  uptr EnclaveStartAddr = handler->l_addr;
  sgxsan_assert(dlclose(handler) == 0);

  // To find Enclave DSO and poison it with InEnclave flag
  sgxsan_assert(EnclaveDSOStart2End.size() == 0);
  dl_iterate_phdr(dlItCBGetEnclaveDSO, &EnclaveStartAddr);
  _PoisonEnclaveDSOCodeSegment();
}

extern "C" __attribute__((weak)) void *GetOCallTableAddr();
extern "C" sgx_status_t __sgx_create_enclave_ex(
    const char *file_name, const int debug, sgx_launch_token_t *launch_token,
    int *launch_token_updated, sgx_enclave_id_t *enclave_id,
    sgx_misc_attribute_t *misc_attr, const uint32_t ex_features,
    const void *ex_features_p[32]) {
  std::string file_abs_path = fs::absolute(fs::path(file_name));
  sgxsan_assert(fs::exists(file_abs_path));
  setEnclaveFileName(file_abs_path);
  if (GetOCallTableAddr) {
    g_enclave_ocall_table = (sgx_ocall_table_t *)GetOCallTableAddr();
  }
  RunInEnclave = true;
  gEnclaveHandler = dlopen(file_abs_path.c_str(), RTLD_LAZY);
  RunInEnclave = false;
  sgxsan_error(gEnclaveHandler == nullptr, "%s\n", dlerror());

  sgxsan_assert(tsticker_ecall = (decltype(tsticker_ecall))dlsym(
                    gEnclaveHandler, "tsticker_ecall"));
  sgxsan_assert(check_ecall = (decltype(check_ecall))dlsym(gEnclaveHandler,
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

void ClearSticker() {
  g_enclave_ocall_table = nullptr;
  RunInEnclave = false;
  AlreadyFirstECall = false;
  sgxsan_thread = nullptr;
  ocallHistory.clear();
  g_thread_pool->clear();
  ClearOCAllocStack();
  EnclaveDSOStart2End.clear();
}

sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id) {
  gRepeater.UnregisterSanCov8Bit();
  gRepeater.UnregisterSanCovPCs();

  // Since we will access object belong to Enclave, so set RunInEnclave to true
  RunInEnclave = true;
  sgxsan_assert(dlclose(gEnclaveHandler) == 0);
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
  gEnclaveHandler = nullptr;
  return SGX_SUCCESS;
}

extern "C" __attribute__((weak)) int __llvm_profile_write_file(void);
void (*TSticker__llvm_profile_write_file)(void);
extern "C" void libFuzzerCrashCallback() {
  TSticker__llvm_profile_write_file =
      (decltype(TSticker__llvm_profile_write_file))dlsym(
          gEnclaveHandler, "TSticker__llvm_profile_write_file");
  if (TSticker__llvm_profile_write_file)
    TSticker__llvm_profile_write_file();
  if (__llvm_profile_write_file)
    __llvm_profile_write_file();
}
