#pragma once

/// Poison.h — 影子内存毒化层（Shadow Poison Layer）
///
/// SGXSan 的影子内存采用两级位域设计：
///   L0（bit6，0x40）：标记该内存粒度是否属于 Enclave 地址空间
///   L1（bits[3:0] + bit7，0x8F）：标记 ASan 层的边界/释放/红区状态
///
/// 写影子时通过 L0P() 叠加 InEnclave 标志位；
/// 读影子时通过 L0F() / L1F() 分别提取两层信息。

#include "SGXSanRTApp.h"
#include <stdint.h>

/// 标记当前线程是否处于 Enclave 上下文（由 sgx_ecall/sgx_ocall 切换）
extern bool __thread RunInEnclave;

/// 影子内存魔数（写入影子字节的标记值）
/// 与原始 ASan 相比，高位用 0x8X 代替 0xfX，
/// 并额外预留 0x4X 范围表示 Enclave 内存
// clang-format off
const int kAsanNotPoisonedMagic            = 0x00;
const int kAsanStackLeftRedzoneMagic       = 0x81 /* 0xf1 */;
const int kAsanStackMidRedzoneMagic        = 0x82 /* 0xf2 */;
const int kAsanStackRightRedzoneMagic      = 0x83 /* 0xf3 */;
const int kAsanAllocaLeftMagic             = 0x84 /* 0xca */;
const int kAsanStackAfterReturnMagic       = 0x85 /* 0xf5 */;
const int kAsanInitializationOrderMagic    = 0x86 /* 0xf6 */;
const int kAsanAllocaRightMagic            = 0x87 /* 0xcb */;
const int kAsanStackUseAfterScopeMagic     = 0x88 /* 0xf8 */;
const int kAsanGlobalRedzoneMagic          = 0x89 /* 0xf9 */;
const int kAsanHeapLeftRedzoneMagic        = 0x8a /* 0xfa */;
const int kAsanHeapRightRedzoneMagic       = 0x8b /* 0xfb */;
const int kAsanContiguousContainerOOBMagic = 0x8c /* 0xfc */;
const int kAsanHeapFreeMagic               = 0x8d /* 0xfd */;
const int kAsanInternalHeapMagic           = 0x8e /* 0xfe */;
/// L0 位：标记对应内存粒度是否属于 Enclave（bit6 = 0x40）
const int kSGXSanInEnclaveMagic            = 0x40;
// clang-format on

#if defined(__cplusplus)
extern "C" {
#endif

/// ── L0 层：Enclave/Host 标志位 ──────────────────────────────────────
///
/// kL0Filter / L0F：提取影子字节中的 Enclave 标志位
/// L0P：写影子时，若当前在 Enclave 上下文则叠加 InEnclave 位
#define kL0Filter kSGXSanInEnclaveMagic
#define L0F(ShadowValue) (ShadowValue & kL0Filter)
#define L0P(PoisonValue)                                                       \
  (RunInEnclave ? (PoisonValue) | kSGXSanInEnclaveMagic : (PoisonValue))

/// ── L1 层：ASan 边界/释放/红区状态位 ────────────────────────────────
///
/// kL1Filter / L1F：提取影子字节中的 ASan 毒化状态位（去掉 L0 位后的部分）
#define kL1Filter 0x8F
#define L1F(ShadowValue) (ShadowValue & kL1Filter)

/// 批量写入对齐地址的影子内存（addr 和 size 均须按 SHADOW_GRANULARITY 对齐）
/// skipInEnclaveTag=true 时，直接写入 value 而不叠加 L0 InEnclave 标志位，
/// 用于注销全局变量或清理栈时将影子内存还原至原始值
void FastPoisonShadow(uptr aligned_addr, uptr aligned_size, uint8_t value,
                      bool skipInEnclaveTag = false);

/// 处理内存块右侧未完整对齐的影子粒度（partial right redzone）
void FastPoisonShadowPartialRightRedzone(uptr aligned_addr, uptr size,
                                         uptr aligned_size_with_rz,
                                         uint8_t rz_value);

/// 对任意地址/大小的内存区域写影子（内部处理非对齐起始地址）
/// skipInEnclaveTag 语义同 FastPoisonShadow
void PoisonShadow(uptr addr, uptr size, uint8_t value,
                  bool skipInEnclaveTag = false);

#if defined(__cplusplus)
}
#endif
