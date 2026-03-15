/// Poison.cpp — 影子内存毒化实现
///
/// 实现两类 API：
///   1. ASan 插桩回调（__asan_set_shadow_*、__asan_alloca_*、全局变量注册等）
///   2. SGXSan 内部毒化函数（FastPoisonShadow、PoisonShadow）

#include "Poison.h"
#include "SGXSanRTApp.h"
#include <algorithm>
#include <pthread.h>
#include <string.h>
#include <vector>

/// ── ASan 静态插桩回调 ───────────────────────────────────────────────────
///
/// __asan_set_shadow_XX 由 ASan Pass 在编译期插入，用于对静态 alloca 写影子。
/// Enclave Pass 已在调用前设置好 InEnclave 标志，故此处只写 L1 位。
#define ASAN_SET_SHADOW(shadowValue)                                           \
  extern "C" void __asan_set_shadow_##shadowValue(uptr addr, uptr size) {      \
    memset((void *)addr, L1F(0x##shadowValue), size);                          \
  }

ASAN_SET_SHADOW(00)
ASAN_SET_SHADOW(f1)
ASAN_SET_SHADOW(f2)
ASAN_SET_SHADOW(f3)
ASAN_SET_SHADOW(f5)
ASAN_SET_SHADOW(f8)
ASAN_SET_SHADOW(fe)

/// 动态 alloca 的毒化/取消毒化回调
extern "C" void __asan_poison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanStackUseAfterScopeMagic);
}

/// skipInEnclaveTag=true：还原栈影子内存时不叠加 InEnclave 位
extern "C" void __asan_unpoison_stack_memory(uptr addr, uptr size) {
  PoisonShadow(addr, size, kAsanNotPoisonedMagic, true);
}

/// alloca 红区大小固定为 32 字节
static constexpr uptr kAllocaRedzoneSize = 32;

/// 对 VLA（动态栈数组）两侧红区进行毒化
/// 布局：[LeftRedzone | 用户数据 | PartialRz | RightRedzone]
extern "C" void __asan_alloca_poison(uptr addr, uptr size) {
  uptr left_rz_addr = addr - kAllocaRedzoneSize;
  uptr partial_rz_addr = addr + size;
  uptr right_rz_addr = RoundUpTo(partial_rz_addr, kAllocaRedzoneSize);
  uptr partial_rz_aligned = RoundDownTo(partial_rz_addr, SHADOW_GRANULARITY);

  FastPoisonShadow(left_rz_addr, kAllocaRedzoneSize, kAsanAllocaLeftMagic);
  FastPoisonShadow(addr, partial_rz_aligned - addr, kAsanNotPoisonedMagic);
  FastPoisonShadowPartialRightRedzone(
      partial_rz_aligned, partial_rz_addr % SHADOW_GRANULARITY,
      right_rz_addr - partial_rz_aligned, kAsanAllocaRightMagic);
  FastPoisonShadow(right_rz_addr, kAllocaRedzoneSize, kAsanAllocaRightMagic);
}

/// 清除 [top, bottom) 范围内所有 VLA 的影子毒化（函数返回时批量还原）
extern "C" void __asan_allocas_unpoison(uptr top, uptr bottom) {
  if (!top || top > bottom)
    return;
  memset((void *)MemToShadow(top), kAsanNotPoisonedMagic,
         (bottom - top) / SHADOW_GRANULARITY);
}

/// ── L1 层毒化实现 ───────────────────────────────────────────────────────

/// 批量写入对齐影子内存
/// skipInEnclaveTag=true：直接写入 value，不叠加 L0 InEnclave 标志位
void FastPoisonShadow(uptr aligned_addr, uptr aligned_size, uint8_t value,
                      bool skipInEnclaveTag) {
  memset((void *)MEM_TO_SHADOW(aligned_addr),
         skipInEnclaveTag ? value : L0P(value),
         aligned_size / SHADOW_GRANULARITY);
}

/// 处理内存块右侧部分未对齐的影子粒度（right partial redzone）
void FastPoisonShadowPartialRightRedzone(uptr aligned_addr, uptr size,
                                         uptr aligned_size_with_rz,
                                         uint8_t rz_value) {
  uint8_t *shadow = (uint8_t *)MEM_TO_SHADOW(aligned_addr);
  for (uptr i = 0; i < aligned_size_with_rz; i += SHADOW_GRANULARITY) {
    shadow[i / SHADOW_GRANULARITY] =
        L0P(i + SHADOW_GRANULARITY <= size ? kAsanNotPoisonedMagic
            : i >= size                    ? rz_value
                                           : size - i);
  }
}

/// 对任意起始地址 / 任意大小的内存区域写影子
/// 若 addr 未对齐，先跳过前缀不足一个粒度的部分，再批量处理中间对齐段，
/// 最后单独处理末尾不足一个粒度的残余字节
void PoisonShadow(uptr addr, uptr size, uint8_t value, bool skipInEnclaveTag) {
  // 若起始地址未对齐，从下一个对齐边界开始
  if (UNLIKELY(!IsAligned(addr, SHADOW_GRANULARITY))) {
    uptr aligned_addr = RoundUpTo(addr, SHADOW_GRANULARITY);
    if (size <= aligned_addr - addr) {
      return;
    }
    size -= aligned_addr - addr;
    addr = aligned_addr;
  }

  // 处理末尾残余字节（不足一个 SHADOW_GRANULARITY 的部分）
  uint8_t remained = size & (SHADOW_GRANULARITY - 1);
  FastPoisonShadow(addr, size - remained, value, skipInEnclaveTag);

  if (remained) {
    uint8_t *shadowEnd = (uint8_t *)MEM_TO_SHADOW(addr + size - remained);
    int8_t origValue = L1F(*shadowEnd);
    if (value >= 0x80) {
      // 红区/释放魔数：仅当残余字节覆盖范围内有有效字节时才写入
      if (0 < origValue && origValue <= (int8_t)remained)
        *shadowEnd = L0P(value);
    } else if (value == kAsanNotPoisonedMagic) {
      // 取消毒化：保留原有可访问边界（取最大值），确保部分可访问状态正确
      uint8_t poisonVal = std::max(origValue, (int8_t)remained);
      *shadowEnd = skipInEnclaveTag ? poisonVal : L0P(poisonVal);
    } else {
      sgxsan_error(
          true, "PoisonShadow: unexpected value 0x%02x for partial granule\n",
          value);
    }
  }
}

/// ── 全局变量毒化（__asan_register/unregister_globals）───────────────────

// ASan 全局变量源码位置描述符
struct __asan_global_source_location {
  const char *filename;
  int line_no;
  int column_no;
};

// ASan 插桩的全局变量描述符
struct __asan_global {
  uptr beg;                                // 全局变量起始地址
  uptr size;                               // 原始大小
  uptr size_with_redzone;                  // 含右红区的总大小
  const char *name;                        // 变量名（C 字符串）
  const char *module_name;                 // 所属模块名（作为模块唯一标识）
  uptr has_dynamic_init;                   // 非零表示有动态初始化器
  __asan_global_source_location *location; // 源码位置，未知则为 NULL
  uptr odr_indicator;                      // ODR 指示符地址
};

// 带初始化状态的动态全局变量包装
struct DynInitGlobal {
  __asan_global g;
  bool initialized;
};

static pthread_mutex_t mu_for_globals = PTHREAD_MUTEX_INITIALIZER;
static std::vector<DynInitGlobal> dynamic_init_globals;

/// 对全局变量的右红区写毒化标记
static void PoisonRedZones(const __asan_global &g) {
  uptr aligned_size = RoundUpTo(g.size, SHADOW_GRANULARITY);
  FastPoisonShadow(g.beg + aligned_size, g.size_with_redzone - aligned_size,
                   kAsanGlobalRedzoneMagic);
  if (g.size != aligned_size) {
    FastPoisonShadowPartialRightRedzone(
        g.beg + RoundDownTo(g.size, SHADOW_GRANULARITY),
        g.size % SHADOW_GRANULARITY, SHADOW_GRANULARITY,
        kAsanGlobalRedzoneMagic);
  }
}

/// 对整个全局变量（含红区）写指定毒化值
static void PoisonShadowForGlobal(const __asan_global *g, uint8_t value) {
  FastPoisonShadow(g->beg, g->size_with_redzone, value);
}

/// 注册单个全局变量：将用户区域标记为可访问，红区标记为毒化
/// 同一全局变量可能被多次注册（如模板实例化），需幂等处理
static void RegisterGlobal(const __asan_global *g) {
  sgxsan_assert(asan_inited and AddrIsInMem(g->beg));
  sgxsan_error(!IsAligned(g->beg, SHADOW_GRANULARITY),
               "The following global variable is not properly aligned.\n"
               "This may happen if another global with the same name\n"
               "resides in another non-instrumented module.\n"
               "Or the global comes from a C file built w/o -fno-common.\n"
               "In either case this is likely an ODR violation bug,\n"
               "but AddressSanitizer can not provide more details.\n");
  sgxsan_assert(IsAligned(g->size_with_redzone, SHADOW_GRANULARITY));

  uptr aligned_size = RoundUpTo(g->size, SHADOW_GRANULARITY);
  sgxsan_assert(g->size_with_redzone > aligned_size);
  FastPoisonShadow(g->beg, aligned_size, kAsanNotPoisonedMagic);
  PoisonRedZones(*g);

  if (g->has_dynamic_init) {
    DynInitGlobal dyn_global = {*g, false};
    dynamic_init_globals.push_back(dyn_global);
  }
}

/// 批量注册全局变量数组（由编译器生成的 __asan_register_globals 调用）
extern "C" void __asan_register_globals(__asan_global *globals, uptr n) {
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0; i < n; i++) {
    RegisterGlobal(&globals[i]);
  }
  // 对描述符元数据本身也毒化，防止用户代码意外访问
  PoisonShadow((uptr)globals, n * sizeof(__asan_global),
               kAsanGlobalRedzoneMagic);
  pthread_mutex_unlock(&mu_for_globals);
}

/// 注销单个全局变量：skipInEnclaveTag=true，直接还原为 0，不带 InEnclave 位
static void UnregisterGlobal(const __asan_global *g) {
  sgxsan_assert(asan_inited and AddrIsInMem(g->beg) and
                IsAligned(g->beg, SHADOW_GRANULARITY) and
                IsAligned(g->size_with_redzone, SHADOW_GRANULARITY));

  FastPoisonShadow(g->beg, g->size_with_redzone, kAsanNotPoisonedMagic, true);
}

/// 批量注销全局变量（DSO 被 dlclose 时调用）
extern "C" void __asan_unregister_globals(__asan_global *globals, uptr n) {
  pthread_mutex_lock(&mu_for_globals);
  for (uptr i = 0; i < n; i++) {
    UnregisterGlobal(&globals[i]);
  }
  // 同步删除对应的动态初始化条目
  dynamic_init_globals.erase(std::remove_if(dynamic_init_globals.begin(),
                                            dynamic_init_globals.end(),
                                            [&](const DynInitGlobal &dg) {
                                              for (uptr i = 0; i < n; i++)
                                                if (dg.g.beg == globals[i].beg)
                                                  return true;
                                              return false;
                                            }),
                             dynamic_init_globals.end());
  // 还原描述符元数据的影子内存
  PoisonShadow((uptr)globals, n * sizeof(__asan_global), kAsanNotPoisonedMagic,
               true);
  pthread_mutex_unlock(&mu_for_globals);
}

/// 动态初始化开始前：对其他模块的全局变量写初始化顺序毒化，
/// 防止当前模块提前访问尚未初始化的跨模块全局变量
extern "C" void __asan_before_dynamic_init(const char *module_name) {
  if (!asan_inited || dynamic_init_globals.empty())
    return;
  pthread_mutex_lock(&mu_for_globals);
  for (auto &dyn_g : dynamic_init_globals) {
    if (dyn_g.initialized)
      continue;
    // ASan 用指针相等（而非 strcmp）判断模块名：同一编译单元的字符串字面量
    // 地址相同，跨编译单元则不同，与 ASan 上游行为一致
    if (dyn_g.g.module_name != module_name)
      PoisonShadowForGlobal(&dyn_g.g, kAsanInitializationOrderMagic);
    else
      dyn_g.initialized = true;
  }
  pthread_mutex_unlock(&mu_for_globals);
}

/// std::vector 等容器的容量注解回调（标记 [old_mid, new_mid) 的可访问性变化）
extern "C" void
__sanitizer_annotate_contiguous_container(const void *beg_p, const void *end_p,
                                          const void *old_mid_p,
                                          const void *new_mid_p) {
  uptr beg = reinterpret_cast<uptr>(beg_p);
  uptr end = reinterpret_cast<uptr>(end_p);
  uptr old_mid = reinterpret_cast<uptr>(old_mid_p);
  uptr new_mid = reinterpret_cast<uptr>(new_mid_p);

  sgxsan_error(!(beg <= old_mid && beg <= new_mid && old_mid <= end &&
                 new_mid <= end && IsAligned(beg, SHADOW_GRANULARITY)),
               "__sanitizer_annotate_contiguous_container: Invalid parameters\n"
               "beg=%p, end=%p, old_mid=%p, new_mid=%p\n",
               beg_p, end_p, old_mid_p, new_mid_p);

  uptr a = RoundDownTo(std::min(old_mid, new_mid), SHADOW_GRANULARITY);
  uptr c = RoundUpTo(std::max(old_mid, new_mid), SHADOW_GRANULARITY);
  uptr b1 = RoundDownTo(new_mid, SHADOW_GRANULARITY);
  uptr b2 = RoundUpTo(new_mid, SHADOW_GRANULARITY);

  PoisonShadow(a, b1 - a, kAsanNotPoisonedMagic);
  PoisonShadow(b2, c - b2, kAsanContiguousContainerOOBMagic);

  if (b1 != b2) {
    uint8_t *shadow_b1 = (uint8_t *)MEM_TO_SHADOW(b1);
    *shadow_b1 = L0P(static_cast<uint8_t>(new_mid - b1));
  }
}

/// 动态初始化完成后：将未完成初始化的全局变量影子还原为正常可访问状态
extern "C" void __asan_after_dynamic_init() {
  if (!asan_inited || dynamic_init_globals.empty())
    return;
  pthread_mutex_lock(&mu_for_globals);
  for (auto &dyn_g : dynamic_init_globals) {
    if (!dyn_g.initialized) {
      PoisonShadowForGlobal(&dyn_g.g, kAsanNotPoisonedMagic);
      PoisonRedZones(dyn_g.g);
    }
  }
  pthread_mutex_unlock(&mu_for_globals);
}
