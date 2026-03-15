#pragma once

/// SGXSanRTApp.h — SGXSan runtime-v 宿主侧运行时基础定义
///
/// 提供以下内容：
///   - 影子内存布局常量（地址空间划分）
///   - 基础类型别名（uptr/sptr）与工具宏
///   - 日志宏（log_error / log_debug / ...）
///   - 内存地址工具函数（AddrIsInMem、RoundUpTo 等）
///   - SGXSanInit / Die / sgxsan_backtrace 声明
///   - sancov 代理接口声明

#include "SGXSanRTConfig.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <vector>

// ── 页大小假设 ───────────────────────────────────────────────────────────
#define PAGE_SIZE 0x1000
#define PAGE_SIZE_SHIFT 12

// ── 影子内存参数 ──────────────────────────────────────────────────────────
/// 影子基址偏移（默认 0x7fff8000，与 ASan 64-bit 布局对齐）
#ifndef SHADOW_OFFSET
#define SHADOW_OFFSET 0x7fff8000
#endif
/// x86-64 四级页表可用地址位数
#define X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS 47
/// 每个影子字节覆盖 2^3 = 8 个应用字节
#define SHADOW_SCALE 3
#define ADDR_SPACE_BITS X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS
#define SHADOW_GRANULARITY (1UL << SHADOW_SCALE)
#define SHADOW_SIZE (1UL << (ADDR_SPACE_BITS - SHADOW_SCALE))

/// 应用地址 → 影子地址转换
#define MEM_TO_SHADOW(mem) (((uptr)(mem) >> SHADOW_SCALE) + SHADOW_OFFSET)

// ── 基础类型 ──────────────────────────────────────────────────────────────
typedef unsigned long uptr;
typedef signed long sptr;

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#define SANITIZER_INTERFACE_ATTRIBUTE __attribute__((visibility("default")))
#define NORETURN __attribute__((noreturn))

/// 快速获取调用点的 PC / 帧指针 / 栈指针（必须是宏，不能封装为函数）
#define GET_CALLER_PC_BP_SP                                                    \
  uptr pc = (uptr)__builtin_return_address(0);                                 \
  uptr bp = (uptr)__builtin_frame_address(0);                                  \
  uptr local_stack;                                                            \
  uptr sp = (uptr) & local_stack

// ── 影子内存地址空间布局 ──────────────────────────────────────────────────
/// 布局（低地址 → 高地址）：
///   LowMem | LowShadowGuard | LowShadow | ShadowGap | HighShadow |
///   HighShadowGuard | HighMem
#define kLowMemBeg 0
#define kLowMemEnd (SHADOW_OFFSET - 1)
#define kLowShadowBeg SHADOW_OFFSET
#define kLowShadowEnd (MEM_TO_SHADOW(kLowShadowBeg) - 1)
#define kHighMemBeg (kLowShadowBeg + SHADOW_SIZE)
#define kHighMemEnd ((1UL << ADDR_SPACE_BITS) - 1)
#define kHighShadowBeg MEM_TO_SHADOW(kHighMemBeg)
#define kHighShadowEnd (kHighMemBeg - 1)
/// Shadow Gap：影子映射的中间空洞，访问此区域触发 SIGSEGV
#define kShadowGapBeg (kLowShadowEnd + 1)
#define kShadowGapEnd (kHighShadowBeg - 1)
/// 影子内存两端各一页 Guard Page，越界访问触发 SIGSEGV
#define kLowShadowGuardBeg (kLowShadowBeg - PAGE_SIZE)
#define kLowShadowGuardEnd (kLowShadowBeg - 1)
#define kHighShadowGuardBeg (kHighShadowEnd + 1)
#define kHighShadowGuardEnd (kHighShadowEnd + PAGE_SIZE)

// ── 初始化 ────────────────────────────────────────────────────────────────
/// asan_inited：运行时是否已完成初始化（影子内存 mmap 完成后置 true）
extern bool asan_inited;
/// SGXSanInit：运行时构造函数，在 main 前由 __attribute__((constructor))
/// 自动调用
extern "C" void SGXSanInit();

// ── 日志系统 ──────────────────────────────────────────────────────────────
enum log_level {
  LOG_LEVEL_ALWAYS,  // 始终输出
  LOG_LEVEL_ERROR,   // 错误（默认上报级别）
  LOG_LEVEL_WARNING, // 警告
  LOG_LEVEL_DEBUG,   // 调试
  LOG_LEVEL_TRACE,   // 追踪（最详细）
};

/// 编译期控制日志输出级别（默认只输出 WARNING 及以上）
#ifndef USED_LOG_LEVEL
#define USED_LOG_LEVEL LOG_LEVEL_WARNING
#endif

#if defined(__cplusplus)
extern "C" {
#endif
void register_sgxsan_sigaction();
/// DFEnableCollectStack：弱符号，若目标程序提供则开启 double-fetch 调用栈收集
__attribute__((weak)) bool DFEnableCollectStack();

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...);
/// SGXSanLogEnter：在函数入口打印 "Enter <name>" 日志（调试用）
void SGXSanLogEnter(const char *str);

// ── sancov 代理接口（Symbolizer.cpp 实现）────────────────────────────────
/// SancovInit：在 Enclave 加载后初始化 sancov 代理缓冲区并注册给 libfuzzer
void SancovInit();
/// DumpSancov：在 dlclose 前将 Enclave 计数器/PC 同步到代理缓冲区
void DumpSancov();
/// 由 Enclave 侧 sancov 钩子调用，记录计数器/PC 段地址
void SGXSanSaveEnclaveCntrsRange(uint8_t *Start, uint8_t *Stop);
void SGXSanSaveEnclavePCsRange(const uintptr_t *Start, const uintptr_t *Stop);

#if defined(__cplusplus)
}
#endif

// ── 日志便捷宏（带前缀）──────────────────────────────────────────────────
#define log_always(...) sgxsan_log(LOG_LEVEL_ALWAYS, true, __VA_ARGS__)
#define log_error(...) sgxsan_log(LOG_LEVEL_ERROR, true, __VA_ARGS__)
#define log_warning(...) sgxsan_log(LOG_LEVEL_WARNING, true, __VA_ARGS__)
#define log_debug(...) sgxsan_log(LOG_LEVEL_DEBUG, true, __VA_ARGS__)
#define log_trace(...) sgxsan_log(LOG_LEVEL_TRACE, true, __VA_ARGS__)

// ── 日志便捷宏（不带前缀，用于续行输出）─────────────────────────────────
#define log_always_np(...) sgxsan_log(LOG_LEVEL_ALWAYS, false, __VA_ARGS__)
#define log_error_np(...) sgxsan_log(LOG_LEVEL_ERROR, false, __VA_ARGS__)
#define log_warning_np(...) sgxsan_log(LOG_LEVEL_WARNING, false, __VA_ARGS__)
#define log_debug_np(...) sgxsan_log(LOG_LEVEL_DEBUG, false, __VA_ARGS__)
#define log_trace_np(...) sgxsan_log(LOG_LEVEL_TRACE, false, __VA_ARGS__)

// ── 堆回溯信息结构 ────────────────────────────────────────────────────────
/// MallocFreeBT：记录一次堆分配/释放的调用栈，用于 UAF/double-free 报告
struct MallocFreeBT {
  size_t malloc_bt_cnt, free_bt_cnt;
  uptr malloc_bt[30], free_bt[30];
};

extern "C" {
/// sgxsan_dump_bt_buf：将 void* 数组逐帧符号化后输出
void sgxsan_dump_bt_buf(void **array, size_t size);
/// sgxsan_backtrace：采集并打印当前调用栈（ll 低于 USED_LOG_LEVEL 时跳过）
void sgxsan_backtrace(log_level ll = LOG_LEVEL_ERROR);
}

// ── 断言与错误宏 ──────────────────────────────────────────────────────────
/// sgxsan_error：条件成立时打印日志 + 回溯 + abort
#define sgxsan_error(cond, ...)                                                \
  do {                                                                         \
    if (UNLIKELY(!!(cond))) {                                                  \
      log_error(__VA_ARGS__);                                                  \
      sgxsan_backtrace();                                                      \
      abort();                                                                 \
    }                                                                          \
  } while (0);

/// sgxsan_assert：断言，失败时打印条件字符串并 abort
#define sgxsan_assert(cond) sgxsan_error(!(cond), #cond "\n");

/// sgxsan_warning：条件成立时打印警告级回溯（不 abort）
#define sgxsan_warning(cond, ...)                                              \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_warning(__VA_ARGS__);                                                \
      sgxsan_backtrace(LOG_LEVEL_WARNING);                                     \
    }                                                                          \
  } while (0);

/// SGXSAN(sym)：将符号名转换为 sgxsan_ 前缀版本（Interceptor 命名惯例）
#define SGXSAN(sym) sgxsan_##sym

// ── 地址空间工具函数 ──────────────────────────────────────────────────────
static inline bool AddrIsInLowMem(uptr a) {
  return kLowMemBeg <= a && a <= kLowMemEnd;
}

static inline bool AddrIsInHighMem(uptr a) {
  return kHighMemBeg <= a && a <= kHighMemEnd;
}

/// 判断地址是否在合法应用内存范围内（低内存或高内存）
static inline bool AddrIsInMem(uptr a) {
  return AddrIsInLowMem(a) or AddrIsInHighMem(a);
}

static inline bool AddrIsInLowShadow(uptr a) {
  return kLowShadowBeg <= a && a <= kLowShadowEnd;
}

static inline bool AddrIsInHighShadow(uptr a) {
  return kHighShadowBeg <= a && a <= kHighShadowEnd;
}

static inline bool AddrIsInShadow(uptr a) {
  return AddrIsInLowShadow(a) or AddrIsInHighShadow(a);
}

/// MemToShadow：带合法性检查的应用地址 → 影子地址转换
static inline uptr MemToShadow(uptr addr) {
  sgxsan_error(not AddrIsInMem(addr), "Address not in valid memory\n");
  return MEM_TO_SHADOW(addr);
}

// ── 对齐工具函数 ──────────────────────────────────────────────────────────
static inline bool IsAligned(uptr a, uptr alignment) {
  return (a & (alignment - 1)) == 0;
}

static inline bool IsPowerOfTwo(uptr x) { return (x & (x - 1)) == 0; }

/// 向上对齐到 boundary（boundary 必须是 2 的幂）
static inline uptr RoundUpTo(uptr size, uptr boundary) {
  sgxsan_error(not IsPowerOfTwo(boundary), "Boundary is not power of two\n");
  return (size + boundary - 1) & ~(boundary - 1);
}

/// 向下对齐到 boundary
static inline uptr RoundDownTo(uptr x, uptr boundary) {
  sgxsan_error(not IsPowerOfTwo(boundary), "Boundary is not power of two\n");
  return x & ~(boundary - 1);
}

static inline uptr RoundUpDiv(uptr a, uptr b) {
  sgxsan_error(not IsPowerOfTwo(b), "Boundary is not power of two\n");
  return (a + b - 1) / b;
}

/// 判断两个内存区间是否重叠（用于 double-fetch 重叠检测）
static inline bool RangesOverlap(const char *offset1, uptr length1,
                                 const char *offset2, uptr length2) {
  return !((offset1 + length1 <= offset2) || (offset2 + length2 <= offset1));
}

/// 将 8-bit 值复制填充到 uptr 宽度（用于批量比较影子内存）
static inline uptr ExtendInt8(uint8_t _8bit) {
  uptr result = 0;
  for (size_t i = 0; i < sizeof(uptr); i++) {
    result = (result << 8) + _8bit;
  }
  return result;
}

/// ClearSGXSanRT：断言当前无嵌套 ECall，重置运行时状态（Enclave 销毁时调用）
void ClearSGXSanRT();

/// Die：不可恢复错误终止点（同步 sancov 后退出，退出码 77）
void NORETURN Die();
