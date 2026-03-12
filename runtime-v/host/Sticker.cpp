#include "Sticker.h"
#include "Malloc.h"
#include "MemAccessMgr.h"
#include "Poison.h"
#include "SGXSanRTApp.h"
#include "arch.h"
#include "cpuid.h"
#include "routine.h"
#include "rts_cmd.h"
#include "sgx_edger8r.h"
#include "sgx_rsrv_mem_mngr.h"
#include "sgx_urts.h"
#include "trts_internal.h"
#include <algorithm>
#include <errno.h>
#include <filesystem>
#include <link.h>
#include <pthread.h>
#include <stack>
#include <sys/mman.h>
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
extern "C" {
thread_data_t *get_thread_data() { return &sgxsan_thread.m_td; }

sgx_status_t (*tsticker_ecall)(const sgx_enclave_id_t eid, const int index,
                               const void *ocall_table, void *ms);
bool (*check_ecall)(ECallCheckType ty, uint32_t targetECallIdx,
                    unsigned int curOCallIdx);

sgx_status_t sgx_ecall(const sgx_enclave_id_t eid, const int index,
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
sgx_status_t sgx_ecall_switchless(const sgx_enclave_id_t eid, const int index,
                                  const void *ocall_table, void *ms)
    __attribute__((alias("sgx_ecall")));

sgx_status_t sgx_ocall(const unsigned int index, void *ms) {
  RunInEnclave = false;
  sgxsan_assert(index < g_enclave_ocall_table->count);
  ocallHistory.push_back(index);
  auto result = ((bridge_fn_t)g_enclave_ocall_table->ocall[index])(ms);
  sgxsan_assert(ocallHistory.size() > 0 and ocallHistory.back() == index);
  ocallHistory.pop_back();
  RunInEnclave = true;
  return result;
}

sgx_status_t sgx_ocall_switchless(const unsigned int index, void *ms)
    __attribute__((alias("sgx_ocall")));

// OCAllocStack
thread_local std::stack<std::vector<void *>> OCAllocStack;

void *sgx_ocalloc(size_t size) {
  auto &top = OCAllocStack.top();
  void *ocallocAddr = sgxsan_malloc(size);
  sgxsan_assert(ocallocAddr);
  top.push_back(ocallocAddr);
  return ocallocAddr;
}

void sgx_ocfree() {
  auto &top = OCAllocStack.top();
  for (auto ocallocAddr : top) {
    sgxsan_free(ocallocAddr);
  }
}

void ClearOCAllocStack() {
  while (OCAllocStack.size() > 0) {
    auto &top = OCAllocStack.top();
    for (auto ocallocAddr : top) {
      sgxsan_free(ocallocAddr);
    }
    top.clear();
    OCAllocStack.pop();
  }
}

// replace libsgx_tstdc with normal glibc and additional API
int *__errno(void) { return &errno; }

void *__memset(void *dst, int c, size_t n) { return memset(dst, c, n); }

typedef error_t errno_t;
errno_t memcpy_s(void *dst, size_t sizeInBytes, const void *src, size_t count) {
  auto res = memcpy(dst, src, std::min(sizeInBytes, count));
  if (res != dst) {
    return -1;
  }
  return 0;
}

errno_t memmove_s(void *dst, size_t sizeInBytes, const void *src,
                  size_t count) {
  auto res = memmove(dst, src, std::min(sizeInBytes, count));
  if (res != dst) {
    return -1;
  }
  return 0;
}

errno_t memset_s(void *s, size_t smax, int c, size_t n) {
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

/// life time management
int dlItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size, void *data) {
  return gEnclaveInfo.DLItCBGetEnclaveDSO(info, size, data);
}

__attribute__((weak)) void *GetOCallTableAddr();
sgx_status_t __sgx_create_enclave_ex(const char *file_name, const int debug,
                                     sgx_launch_token_t *launch_token,
                                     int *launch_token_updated,
                                     sgx_enclave_id_t *enclave_id,
                                     sgx_misc_attribute_t *misc_attr,
                                     const uint32_t ex_features,
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
  PoisonShadow((uptr)&sgxsan_thread, sizeof(sgxsan_thread),
               kAsanNotPoisonedMagic);
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

sgx_status_t sgx_create_enclave(const char *file_name, const int debug,
                                sgx_launch_token_t *launch_token,
                                int *launch_token_updated,
                                sgx_enclave_id_t *enclave_id,
                                sgx_misc_attribute_t *misc_attr) {
  return __sgx_create_enclave_ex(file_name, debug, launch_token,
                                 launch_token_updated, enclave_id, misc_attr, 0,
                                 NULL);
}

sgx_status_t sgx_create_enclave_ex(const char *file_name, const int debug,
                                   sgx_launch_token_t *launch_token,
                                   int *launch_token_updated,
                                   sgx_enclave_id_t *enclave_id,
                                   sgx_misc_attribute_t *misc_attr,
                                   const uint32_t ex_features,
                                   const void *ex_features_p[32]) {
  return __sgx_create_enclave_ex(file_name, debug, launch_token,
                                 launch_token_updated, enclave_id, misc_attr,
                                 ex_features, ex_features_p);
}

void ClearSticker() {
  g_enclave_ocall_table = nullptr;
  RunInEnclave = false;
  AlreadyFirstECall = false;
  ocallHistory.clear();
  ClearOCAllocStack();
  gEnclaveInfo.Clear();
}

sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id) {
  auto handle = gEnclaveInfo.GetHandler();
  if (handle) {
    // Since we will access object belong to Enclave, so set RunInEnclave to
    // true
    RunInEnclave = true;
    sgxsan_assert(dlclose(handle) == 0);
    RunInEnclave = false;

    // Clear SGXSanRT's global status belong to Enclave
    ClearSGXSanRT();
    MemAccessMgrClear();
    ClearSticker();
    ClearStackPoison();
    ClearHeapObject();
  }
  return SGX_SUCCESS;
}

void GetEnclaveDSORange(uptr *start, uptr *end) {
  gEnclaveInfo.GetEnclaveDSORange(start, end);
}

void *sgx_alloc_rsrv_mem_ex(void *desired_addr, size_t length) {
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if (desired_addr != NULL) {
    flags |= MAP_FIXED;
  }
  void *ptr = mmap(desired_addr, length, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (ptr == MAP_FAILED) {
    errno = ENOMEM;
    return NULL;
  }
  return ptr;
}

void *sgx_alloc_rsrv_mem(size_t length) {
  return sgx_alloc_rsrv_mem_ex(0, length);
}

int sgx_free_rsrv_mem(void *addr, size_t length) {
  if (munmap(addr, length) != 0) {
    return -1;
  }
  return 0;
}

sgx_status_t sgx_tprotect_rsrv_mem(void *addr, size_t len, int prot) {
  int sys_prot = 0;
  if (prot & SGX_PROT_READ)
    sys_prot |= PROT_READ;
  if (prot & SGX_PROT_WRITE)
    sys_prot |= PROT_WRITE;
  if (prot & SGX_PROT_EXEC)
    sys_prot |= PROT_EXEC;
  if (mprotect(addr, len, sys_prot) != 0) {
    return SGX_ERROR_UNEXPECTED;
  }
  return SGX_SUCCESS;
}

#if 0
sgx_status_t sgx_get_rsrv_mem_info(void **start_addr, size_t *max_size) {
  static void *my_rsrv_mem_base = nullptr;
  const size_t my_rsrv_mem_size = 1 << 30;
  if (start_addr == NULL && max_size == NULL) {
    return SGX_ERROR_INVALID_PARAMETER;
  }

  if (my_rsrv_mem_base == nullptr) {
    my_rsrv_mem_base = mmap(nullptr, my_rsrv_mem_size, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (my_rsrv_mem_base == MAP_FAILED) {
      my_rsrv_mem_base = (void *)0x100000000ULL;
    }
  }

  if (start_addr != NULL)
    *start_addr = my_rsrv_mem_base;
  if (max_size != NULL)
    *max_size = my_rsrv_mem_size;

  return SGX_SUCCESS;
}
#endif
}

void EnclaveInfo::PoisonEnclaveDSOCode() {
  // Current Enclave is in dlopen-ing, and should already have been mmap-ed
  // We get start address of current Enclave
  sgxsan_assert(mEnclaveFileName != "");
  auto handler = (struct link_map *)dlopen(mEnclaveFileName.c_str(),
                                           RTLD_LAZY | RTLD_NOLOAD);
  sgxsan_assert(handler);
  mEnclaveStartAddr = handler->l_addr;
  sgxsan_assert(dlclose(handler) == 0);
  mEnclaveDSOStart2End.clear();
  dl_iterate_phdr(dlItCBGetEnclaveDSO, &mEnclaveStartAddr);

  for (auto pair : mEnclaveDSOStart2End) {
    uptr beg = pair.first, end = pair.second;
    bool origInEnclave = false;
    sgxsan_assert(RunInEnclave);
    if (RunInEnclave == false)
      RunInEnclave = true;
    else
      origInEnclave = true;
    PoisonShadow(beg, end - beg, kAsanNotPoisonedMagic);
    RunInEnclave = origInEnclave;
  }
}
