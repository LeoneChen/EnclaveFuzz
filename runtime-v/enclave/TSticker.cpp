/// TSticker.cpp — Enclave 侧桩实现
///
/// 本文件在 Enclave SO 内部提供：
///   - tsticker_ecall：Enclave 侧 ECall 分发入口（由 host 的 sgx_ecall 调用）
///   - check_ecall：ECall 权限检查（private / allowed 列表）
///   - __asan_init：ASan/SanitizerCoverage 初始化钩子
///   - malloc/free/new/delete 拦截：将 Enclave 内分配路由到 SGXSan 堆分配器

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

/// ECall 函数指针类型（edger8r 生成的 Enclave 侧桩函数）
typedef sgx_status_t (*ecall_func_t)(void *ms);
extern const ecall_table_t g_ecall_table;
extern entry_table_t g_dyn_entry_table;
/// Enclave SECS（安全飞地控制结构）模拟对象
secs_t g_secs;

/// Enclave 内部初始化：将 g_secs 注册到 global_data_sim 并标记影子内存可访问
static void SGXInitInternal() {
  g_global_data_sim.secs_ptr = &g_secs;
  PoisonShadow((uptr)&g_secs, sizeof(g_secs), kAsanNotPoisonedMagic);
}

/// tsticker_ecall — Enclave 侧 ECall 分发
/// ECMD_INIT_ENCLAVE 时执行初始化；其他 index 直接查表调用对应 ECall 函数
extern "C" sgx_status_t tsticker_ecall(const sgx_enclave_id_t eid,
                                       const int index, const void *ocall_table,
                                       void *ms) {
  if (index == ECMD_INIT_ENCLAVE) {
    SGXInitInternal();
    return SGX_SUCCESS;
  }
  assert(index < (int)g_ecall_table.nr_ecall);
  return ((ecall_func_t)g_ecall_table.ecall_table[index].ecall_addr)(ms);
}

/// __asan_init — ASan 初始化钩子（必须在 SanitizerCoverage 构造函数之前执行）
/// 在此注册信号处理器并对 Enclave DSO 代码段写影子内存标记。
/// gAlreadyAsanInited 驻留在 Enclave 镜像中，每次 dlopen 加载后重置为 false。
extern "C" void __asan_init() {
  static bool gAlreadyAsanInited = false;
  if (!gAlreadyAsanInited) {
    register_sgxsan_sigaction();
    gEnclaveInfo.PoisonEnclaveDSOCode();
    gAlreadyAsanInited = true;
  }
}

/// check_ecall — ECall 权限检查
///   CHECK_ECALL_PRIVATE：目标 ECall 是否为 private（不允许根调用）
///   CHECK_ECALL_ALLOWED：当前 OCall 的 allowed_ecall 表中是否包含目标 ECall
extern "C" bool check_ecall(ECallCheck ty, uint32_t targetECallIdx,
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

// ── malloc/free 拦截 ──────────────────────────────────────────────────────
// 将 Enclave 内的 libc 分配函数路由到 SGXSan 堆分配器（带影子内存标记）

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

/// sancov 拦截：通过 protected 可见性将 Enclave DSO 内的 sancov 注册
/// 绑定到本文件的实现，转发给 host 侧代理缓冲区，而非直接注册给 libfuzzer
__attribute__((visibility("protected"))) void
__sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop) {
  SGXSanSaveEnclaveCntrsRange(Start, Stop);
}

__attribute__((visibility("protected"))) void
__sanitizer_cov_pcs_init(const uintptr_t *Start, const uintptr_t *Stop) {
  SGXSanSaveEnclavePCsRange(Start, Stop);
}
}

// ── C++ new/delete 拦截 ───────────────────────────────────────────────────

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
