/// Sticker.cpp — Enclave 模拟层（SGX SDK 桩替换）
///
/// runtime-v 以 dlopen 方式将 Enclave SO 作为普通共享库加载，
/// 本文件替换 SGX SDK 的 urts 层，提供：
///   - sgx_ecall / sgx_ocall：ECall/OCall 路由与权限检查
///   - sgx_create_enclave / sgx_destroy_enclave：Enclave 生命周期管理
///   - sgx_ocalloc / sgx_ocfree：OCall 内 Host 端临时内存分配
///   - libc 替身（heap_init、memcpy_s 等）：替代 libsgx_tstdc，对接 glibc

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

/// 全局 Enclave 信息（文件路径、DSO 段范围、dlopen handler）
EnclaveInfo gEnclaveInfo;

/// ECall 桥接函数类型（tsticker_ecall 调用约定）
typedef sgx_status_t (*bridge_fn_t)(const void *);

/// 当前线程的 OCall 表指针（由 sgx_ecall 在调用前设置）
__thread sgx_ocall_table_t *g_enclave_ocall_table = nullptr;

/// 当前线程是否处于 Enclave 上下文（ECall 内为 true，OCall 期间为 false）
__thread bool RunInEnclave = false;

/// 当前线程是否已进入 ECall 上下文（区分根 ECall 和 OCall 内触发的 ECall）
__thread bool g_in_ecall_ctx = false;

/// 模拟 Enclave 线程数据结构（对应 SDK 的 thread_data_t）
__thread TrustThread sgxsan_thread;

/// 当前线程的 OCall 调用历史栈（用于校验嵌套 ECall 权限）
thread_local std::vector<unsigned int> ocallHistory;

// ── 线程数据 ──────────────────────────────────────────────────────────────
extern "C" {
/// 返回当前线程的 Enclave 线程数据，替代 SDK 的 get_thread_data()
thread_data_t *get_thread_data() { return &sgxsan_thread.m_td; }

/// 可信侧 ECall 桥接函数指针（dlsym 从 Enclave SO 中解析）
sgx_status_t (*tsticker_ecall)(const sgx_enclave_id_t eid, const int index,
                               const void *ocall_table, void *ms);

/// ECall 权限检查函数指针（dlsym 从 Enclave SO 中解析）
bool (*check_ecall)(ECallCheck ty, uint32_t targetECallIdx,
                    unsigned int curOCallIdx);

/// sgx_ecall — 模拟 ECall 调度
///
/// 流程：
///   1. 权限检查：根 ECall 不能是 private；OCall 内的 ECall 必须在 allowed 列表
///   2. 设置 RunInEnclave=true，进入 Enclave 上下文
///   3. 调用 tsticker_ecall 执行 Enclave 内目标函数
///   4. 返回后恢复 RunInEnclave=false
sgx_status_t sgx_ecall(const sgx_enclave_id_t eid, const int index,
                       const void *ocall_table, void *ms) {
  (void)eid;
  RunInEnclave = true;

  bool isRootECall = false;
  if (g_in_ecall_ctx == false) {
    // 当前为根 ECall（非 OCall 内触发）
    if (index >= 0 and check_ecall(CHECK_ECALL_PRIVATE, index, 0)) {
      RunInEnclave = false;
      return SGX_ERROR_ECALL_NOT_ALLOWED;
    }
    g_in_ecall_ctx = true;
    isRootECall = true;
  } else {
    // 当前在 OCall 内被触发的 ECall，需检查是否在 allowed 列表中
    if (index >= 0 and
        not check_ecall(CHECK_ECALL_ALLOWED, index, ocallHistory.back())) {
      RunInEnclave = false;
      return SGX_ERROR_ECALL_NOT_ALLOWED;
    }
  }

  g_enclave_ocall_table = (sgx_ocall_table_t *)ocall_table;
  get_thread_data()->last_error = errno;
  sgxsan_assert(tsticker_ecall);
  sgx_status_t result = tsticker_ecall(eid, index, nullptr, ms);
  if (isRootECall) {
    g_in_ecall_ctx = false;
  }
  RunInEnclave = false;
  return result;
}
sgx_status_t sgx_ecall_switchless(const sgx_enclave_id_t eid, const int index,
                                  const void *ocall_table, void *ms)
    __attribute__((alias("sgx_ecall")));

/// sgx_ocall — 模拟 OCall 调度
/// 切换 RunInEnclave=false，调用 Host 侧 OCall 处理函数，返回后恢复
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

/// OCAllocStack：每层 OCall 对应一个临时分配列表，OCall 返回时统一释放
thread_local std::stack<std::vector<void *>> OCAllocStack;

/// OCall 内临时内存分配（由 Enclave 侧 edger8r 生成的 sgx_ocalloc 调用）
void *sgx_ocalloc(size_t size) {
  auto &top = OCAllocStack.top();
  void *ocallocAddr = sgxsan_malloc(size);
  sgxsan_assert(ocallocAddr);
  top.push_back(ocallocAddr);
  return ocallocAddr;
}

/// OCall 临时内存释放（与 sgx_ocalloc 配对）
void sgx_ocfree() {
  auto &top = OCAllocStack.top();
  for (auto ocallocAddr : top) {
    sgxsan_free(ocallocAddr);
  }
}

/// 强制清空所有 OCAlloc 栈帧及其分配的内存（enclave 销毁时调用）
void ClearOCAllocStack() {
  while (!OCAllocStack.empty()) {
    auto &top = OCAllocStack.top();
    for (auto ocallocAddr : top) {
      sgxsan_free(ocallocAddr);
    }
    top.clear();
    OCAllocStack.pop();
  }
}

// ── libc 替身（替代 libsgx_tstdc，直接对接 glibc）─────────────────────────

int *__errno(void) { return &errno; }

void *__memset(void *dst, int c, size_t n) { return memset(dst, c, n); }

typedef error_t errno_t;
errno_t memcpy_s(void *dst, size_t sizeInBytes, const void *src, size_t count) {
  memcpy(dst, src, std::min(sizeInBytes, count));
  return 0;
}

errno_t memmove_s(void *dst, size_t sizeInBytes, const void *src,
                  size_t count) {
  memmove(dst, src, std::min(sizeInBytes, count));
  return 0;
}

errno_t memset_s(void *s, size_t smax, int c, size_t n) {
  memset(s, c, std::min(smax, n));
  return 0;
}

/// Enclave 堆/保留内存初始化桩（模拟模式下由 glibc 堆接管，直接返回成功）
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

// ── Enclave 生命周期管理 ───────────────────────────────────────────────────

/// dl_iterate_phdr 回调：查找 Enclave DSO 并记录其 PT_LOAD 段范围
int dlItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size, void *data) {
  return gEnclaveInfo.DLItCBGetEnclaveDSO(info, size, data);
}

/// GetOCallTableAddr：弱符号，由具体目标程序提供 OCall 表地址（可选）
__attribute__((weak)) void *GetOCallTableAddr();

/// __sgx_create_enclave_ex — 加载 Enclave SO 并完成初始化
///
/// 流程：
///   1. dlopen 加载 Enclave SO（RunInEnclave=true 以正确标记影子内存）
///   2. 初始化 sgxsan_thread 的影子内存
///   3. dlsym 解析 tsticker_ecall 和 check_ecall 函数指针
///   4. 调用 ECMD_INIT_ENCLAVE 完成 Enclave 内部初始化
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
  // 将线程数据结构标记为可访问（Enclave 侧会直接访问）
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

/// 清除当前线程的 Sticker 状态（Enclave 销毁时调用）
void ClearSticker() {
  g_enclave_ocall_table = nullptr;
  RunInEnclave = false;
  g_in_ecall_ctx = false;
  ocallHistory.clear();
  ClearOCAllocStack();
  gEnclaveInfo.Clear();
}

/// sgx_destroy_enclave — 卸载 Enclave SO 并清理全部运行时状态
///
/// 流程：
///   1. 调用 DumpSancov 将 Enclave 覆盖率计数器同步到代理缓冲区
///   2. dlclose 卸载 Enclave SO
///   3. 依次清除 SGXSanRT、MemAccessMgr、Sticker、HeapObject 状态
sgx_status_t SGXAPI sgx_destroy_enclave(const sgx_enclave_id_t enclave_id) {
  auto handle = gEnclaveInfo.GetHandler();
  if (handle) {
    // 在 dlclose 前将 Enclave sancov 计数器/PC 表同步到代理缓冲区
    DumpSancov();

    // dlclose 时需访问 Enclave 内的对象，临时设置 RunInEnclave=true
    RunInEnclave = true;
    sgxsan_assert(dlclose(handle) == 0);
    RunInEnclave = false;

    // 清除所有与本次 Enclave 相关的运行时全局状态
    ClearSGXSanRT();
    MemAccessMgrClear();
    ClearSticker();
  }
  return SGX_SUCCESS;
}

/// 获取 Enclave DSO 在内存中的地址范围（用于 sancov PC 归一化）
void GetEnclaveDSORange(uptr *start, uptr *end) {
  gEnclaveInfo.GetEnclaveDSORange(start, end);
}

// ── 保留内存（rsrv mem）管理桩 ────────────────────────────────────────────
// 模拟模式下用 mmap 实现，替代 SDK 的 EPC 保留内存机制

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
}

/// 对 Enclave DSO 的所有可加载段写影子内存（标记为可访问）
/// 在 dlopen 加载完成后、Enclave 初始化前调用，确保 Enclave 代码段
/// 在影子内存中有正确的 NotPoisoned + InEnclave 标记
void EnclaveInfo::PoisonEnclaveDSOCode() {
  // Enclave 正在 dlopen 中，已完成 mmap，先获取其起始地址
  sgxsan_assert(m_filename != "");
  auto handler =
      (struct link_map *)dlopen(m_filename.c_str(), RTLD_LAZY | RTLD_NOLOAD);
  sgxsan_assert(handler);
  m_start_addr = handler->l_addr;
  sgxsan_assert(dlclose(handler) == 0);
  m_dso_ranges.clear();
  dl_iterate_phdr(dlItCBGetEnclaveDSO, &m_start_addr);

  for (auto pair : m_dso_ranges) {
    uptr beg = pair.first, end = pair.second;
    sgxsan_assert(RunInEnclave);
    // 将 Enclave DSO 段影子标记为可访问（附带 InEnclave 标志位）
    PoisonShadow(beg, end - beg, kAsanNotPoisonedMagic);
  }
}
