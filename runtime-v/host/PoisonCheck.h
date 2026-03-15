#pragma once

/// PoisonCheck.h — 影子内存状态查询接口
///
/// 提供两类 API：
///   1. 地址/区间的 InOutEnclave 状态判断：区分访问是 Enclave 侧还是 Host 侧
///   2. 毒化状态判断：是否访问了越界/已释放内存
///
/// 这两类状态组合使用，是 SGXSan 检测
///   - Enclave 越界访问（堆/栈/全局变量溢出）
///   - Host 越界访问
///   - 跨 Enclave/Host 边界的混合访问（RangeMixedInOutEnclave）
/// 的核心逻辑。
///
/// RANGE_CHECK 宏封装了完整的区间检查 + 错误上报流程，
/// 供 InstrumentedLibc.cpp 中的内存函数包装器调用。

#include "ErrorReport.h"
#include "Poison.h"
#include "SGXSanRTApp.h"
#include <stdint.h>
#include <utility>

/// EnclaveStatus：内存地址/区间相对于 Enclave 边界的位置状态
enum EnclaveStatus {
  UnknownEnclaveStatus = -1,  // 大小为 0 等无法判断的情况
  OutEnclave = 0,             // 完全在 Host 侧
  InEnclave = 1,              // 完全在 Enclave 侧
  RangeMixedInOutEnclave = 2, // 区间跨越了 Enclave/Host 边界（提示 OOB）
  RangeOverflow = 3,          // beg + size 整数溢出
  RangeInvalid = 4,           // 地址不在合法内存范围内
};

/// PoisonStatus：地址/区间的影子内存毒化状态
enum PoisonStatus {
  UnknownPoisonStatus = -1, // 无法判断（混合区间等）
  NotPoisoned = 0,          // 可安全访问
  IsPoisoned = 1,           // 已毒化（越界/已释放）
};

/// 检查单个地址对应的影子字节，输出其 InOutEnclave 状态和毒化状态
/// 不会递归调用其他检查函数
void QueryAddr(uptr addr, EnclaveStatus &status, PoisonStatus &poison);

/// 检查影子内存区间 [beg, beg+size) 中所有字节的状态
/// "Strict"：只要有一个字节毒化，整个区间即判定为 IsPoisoned
/// 适用于 SHADOW_GRANULARITY 对齐的区间（由 QueryRegion 内部调用）
void QueryShadowRegion(uint8_t *beg, uptr size, EnclaveStatus &status,
                       PoisonStatus &poison);

/// 检查应用内存区间 [beg, beg+size) 的完整状态
/// 先检查首尾字节，再检查中间对齐段，综合得出区间状态
void QueryRegion(uptr beg, uptr size, EnclaveStatus &status,
                 PoisonStatus &poison);

/// 同上，但额外返回第一个被毒化的地址（用于精确的错误报告）
void FindFirstPoisoned(uptr beg, uptr size, EnclaveStatus &status,
                       uptr &first_poisoned);

#if defined(__cplusplus)
extern "C" {
#endif
/// sgx_is_within_enclave / sgx_is_outside_enclave：替代 SDK 同名函数
/// 通过影子内存判断地址区间是否完全在 Enclave 内/外
int sgx_is_within_enclave(const void *addr, size_t size);
int sgx_is_outside_enclave(const void *addr, size_t size);
#if defined(__cplusplus)
}
#endif

/// RANGE_CHECK：对内存区间执行完整检查并上报错误
/// 必须是宏（GET_CALLER_PC_BP_SP 展开时需要在调用帧内执行，不能封装进函数）
/// size 不能为 0
#define RANGE_CHECK(beg, size, status, first_poisoned, IsWrite)                \
  do {                                                                         \
    FindFirstPoisoned((uptr)beg, size, status, first_poisoned);                \
    if (status == InEnclave) {                                                 \
      MemAccessMgrInEnclaveAccess();                                           \
      if (first_poisoned) {                                                    \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, first_poisoned, IsWrite, size,          \
                           "Enclave out of bound");                            \
      }                                                                        \
    } else if (status == OutEnclave) {                                         \
      MemAccessMgrOutEnclaveAccess(beg, size, IsWrite);                        \
      if (first_poisoned) {                                                    \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, first_poisoned, IsWrite, size,          \
                           "Host out of bound");                               \
      }                                                                        \
    } else if (status == RangeMixedInOutEnclave) {                             \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, first_poisoned, IsWrite, size,            \
                         "RangeMixedInOutEnclave hint OOB");                   \
    } else {                                                                   \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, (uptr)beg, IsWrite, size,                 \
                         "regionInOutEnclaveStatus: %d", status);              \
    }                                                                          \
  } while (0);
