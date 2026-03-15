/// PoisonCheck.cpp — ASan 内存访问插桩回调与影子内存状态查询实现
///
/// ASAN_MEMORY_ACCESS_CALLBACK 宏展开为 __asan_load{1,2,4,8,16} /
/// __asan_store{1,2,4,8,16} 函数，由 ASan Pass 在每次内存访问前插入调用。
/// 每个函数：
///   1. 检查地址合法性
///   2. 读取对应影子字节
///   3. 根据 L0 位判断是 Enclave / Host 访问，通知 MemAccessMgr
///   4. 根据 L1 位判断是否越界，越界则上报错误

#include "PoisonCheck.h"
#include "MemAccessMgr.h"
#include "Poison.h"
#include "SGXSanRTApp.h"

// ── ASan 定长内存访问插桩回调 ─────────────────────────────────────────────

/// ASAN_MEMORY_ACCESS_CALLBACK：为每个访问大小生成一个插桩函数
/// is_control_fetch=true 表示本次访问的值将用于条件比较（double-fetch
/// 检测的"控制流读取"）
#define ASAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                      \
  extern "C" __attribute__((noinline)) void __asan_##type##size(               \
      uptr addr, bool is_control_fetch) {                                      \
    if (UNLIKELY(not AddrIsInMem(addr))) {                                     \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, "Invalid address"); \
    }                                                                          \
    uptr shadow_addr = MEM_TO_SHADOW(addr), shadow_byte, enclave_flag;         \
    /* 对于 size <= 8，读一个影子字节；>8 读两个（uint16_t） */                \
    if (size <= SHADOW_GRANULARITY) {                                          \
      shadow_byte = *(uint8_t *)shadow_addr;                                   \
      enclave_flag = kSGXSanInEnclaveMagic;                                    \
    } else {                                                                   \
      shadow_byte = *(uint16_t *)shadow_addr;                                  \
      enclave_flag = (kSGXSanInEnclaveMagic << 8) + kSGXSanInEnclaveMagic;     \
    }                                                                          \
    /* 快速路径：影子字节完全等于 InEnclave 魔数或 0 */                        \
    if (shadow_byte == enclave_flag) {                                         \
      MemAccessMgrInEnclaveAccess();                                           \
    } else if (shadow_byte == 0) {                                             \
      MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write,               \
                                   is_control_fetch);                          \
    } else {                                                                   \
      /* 慢速路径：提取 L0 位判断 Enclave/Host 侧，再检查 L1 越界位 */         \
      uptr is_in_enclave = shadow_byte & enclave_flag;                         \
      if (is_in_enclave == enclave_flag) {                                     \
        MemAccessMgrInEnclaveAccess();                                         \
      } else if (is_in_enclave == 0) {                                         \
        MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write,             \
                                     is_control_fetch);                        \
      } else {                                                                 \
        /* L0 位混合：部分字节在 Enclave、部分在 Host，提示跨边界 OOB */       \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, "Mixed Access");  \
      }                                                                        \
      /* 提取 L1 越界位 */                                                     \
      uptr l1_mask = size <= SHADOW_GRANULARITY                                \
                         ? kL1Filter                                           \
                         : ((kL1Filter << 8) + kL1Filter);                     \
      shadow_byte &= l1_mask;                                                  \
      if (UNLIKELY(shadow_byte)) {                                             \
        /* 判断访问是否触及已毒化字节 */                                       \
        if (UNLIKELY(size >= SHADOW_GRANULARITY ||                             \
                     (int8_t)((addr & (SHADOW_GRANULARITY - 1)) + size - 1) >= \
                         (int8_t)shadow_byte)) {                               \
          GET_CALLER_PC_BP_SP;                                                 \
          ReportGenericError(pc, bp, sp, addr, is_write, size,                 \
                             is_in_enclave == enclave_flag                     \
                                 ? "Enclave out of bound"                      \
                                 : "Host out of bound");                       \
        }                                                                      \
      }                                                                        \
    }                                                                          \
  }

ASAN_MEMORY_ACCESS_CALLBACK(load, false, 1)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 2)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 4)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 8)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 16)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 1)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 2)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 4)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 8)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 16)

// ── ASan 变长内存访问插桩回调 ─────────────────────────────────────────────

/// ASAN_MEMORY_ACCESS_CALLBACK_N：处理任意大小的内存访问（memcpy 等）
/// 使用 QueryRegion 做完整区间检查
#define ASAN_MEMORY_ACCESS_CALLBACK_N(type, is_write)                          \
  extern "C" __attribute__((noinline)) void __asan_##type##N(                  \
      uptr addr, uptr size, bool is_control_fetch) {                           \
    if (UNLIKELY(not AddrIsInMem(addr))) {                                     \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, "Invalid address"); \
    }                                                                          \
    EnclaveStatus addrEnclaveStatus;                                           \
    PoisonStatus addrPoisonStatus;                                             \
    QueryRegion(addr, size, addrEnclaveStatus, addrPoisonStatus);              \
    if (addrEnclaveStatus == InEnclave) {                                      \
      MemAccessMgrInEnclaveAccess();                                           \
      if (addrPoisonStatus != NotPoisoned) {                                   \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size,                   \
                           "Enclave out of bound");                            \
      }                                                                        \
    } else if (addrEnclaveStatus == OutEnclave) {                              \
      MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write,               \
                                   is_control_fetch);                          \
      if (addrPoisonStatus != NotPoisoned) {                                   \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size,                   \
                           "Host out of bound");                               \
      }                                                                        \
    } else if (addrEnclaveStatus == RangeMixedInOutEnclave) {                  \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size,                     \
                         "RangeMixedInOutEnclave hint OOB");                   \
    } else {                                                                   \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size,                     \
                         "addrEnclaveStatus: %d", addrEnclaveStatus);          \
    }                                                                          \
  }

ASAN_MEMORY_ACCESS_CALLBACK_N(load, false)
ASAN_MEMORY_ACCESS_CALLBACK_N(store, true)

// ── 影子内存状态查询实现 ──────────────────────────────────────────────────

/// 查询单个地址的 InOutEnclave 状态和毒化状态
/// 先处理两个快速路径（纯 InEnclave 魔数 / 纯 0），再处理混合情况
void QueryAddr(uptr addr, EnclaveStatus &status, PoisonStatus &poison) {
  int8_t shadow_value = *(int8_t *)MEM_TO_SHADOW(addr);
  if (shadow_value == kSGXSanInEnclaveMagic) {
    // 快速路径：完整 InEnclave，无需检查 L1 位
    status = InEnclave;
    poison = NotPoisoned;
  } else if (shadow_value == 0) {
    status = OutEnclave;
    poison = NotPoisoned;
  } else {
    // 通用路径：分别提取 L0 和 L1 位
    status = L0F(shadow_value) ? InEnclave : OutEnclave;

    shadow_value &= kL1Filter;
    if (LIKELY(shadow_value == 0)) {
      poison = NotPoisoned;
    } else {
      int8_t accessible_bytes = shadow_value;
      // accessible_bytes：该粒度内前 N 字节可访问，其余已毒化
      uint8_t granule_offset = addr & (SHADOW_GRANULARITY - 1);
      poison = granule_offset >= accessible_bytes ? IsPoisoned : NotPoisoned;
    }
  }
}

/// 检查影子内存区间 [beg, beg+size) 中所有字节的状态
/// 通过位运算批量检测：allBitOr 有任一置位则可能毒化，L0F 混合则跨边界
void QueryShadowRegion(uint8_t *beg, uptr size, EnclaveStatus &status,
                       PoisonStatus &poison) {
  if (size == 0) {
    status = UnknownEnclaveStatus;
    poison = UnknownPoisonStatus;
  } else if (size > (1ULL << 40)) {
    // 合理性检查：超过 1TB 的影子区间视为溢出
    status = RangeOverflow;
    poison = UnknownPoisonStatus;
  } else {
    uint8_t *end = beg + size;
    uint8_t all_or = 0, all_and = ~0;
    for (uint8_t *mem = beg; mem < end; mem++) {
      all_or |= *mem;
      all_and &= *mem;
    }
    if (L0F(all_or) != L0F(all_and)) {
      // L0 位不一致：区间内混合了 Enclave 和 Host 内存
      status = RangeMixedInOutEnclave;
      poison = UnknownPoisonStatus;
    } else if (all_or == kSGXSanInEnclaveMagic) {
      status = InEnclave;
      poison = NotPoisoned;
    } else if (all_or == 0) {
      status = OutEnclave;
      poison = NotPoisoned;
    } else {
      if (L0F(all_or) == 0) {
        status = OutEnclave;
      } else if (L0F(all_or) == kSGXSanInEnclaveMagic) {
        status = InEnclave;
      } else {
        sgxsan_error(true, "Ranged mixed?");
      }
      // L1 位有置位则说明区间内存在毒化字节
      poison = L1F(all_or) ? IsPoisoned : NotPoisoned;
    }
  }
}

/// 检查应用内存区间 [beg, beg+size) 的完整状态
/// 策略：先单独检查首尾字节，再对中间对齐段调用 Shadow 版本
void QueryRegion(uptr beg, uptr size, EnclaveStatus &status,
                 PoisonStatus &poison) {
  if (beg == 0) {
    // 空指针视为 Host 侧已毒化
    status = OutEnclave;
    poison = IsPoisoned;
  } else if (size == 0) {
    status = UnknownEnclaveStatus;
    poison = UnknownPoisonStatus;
  } else {
    uptr end = beg + size; // 半开区间 [beg, end)，end 指向最后一个字节的下一位
    if (beg > end) {
      status = RangeOverflow;
      poison = UnknownPoisonStatus;
    } else if (not(AddrIsInMem(beg) and AddrIsInMem(end - 1))) {
      status = RangeInvalid;
      poison = UnknownPoisonStatus;
    } else {
      EnclaveStatus beg_status, end_status, mid_status;
      PoisonStatus beg_poison, end_poison, mid_poison;

      // 对齐边界：[aligned_b, aligned_e] 是中间完整粒度段的应用地址范围
      uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
      uptr aligned_e = RoundDownTo(end - 1, SHADOW_GRANULARITY);
      uptr shadow_beg = MemToShadow(aligned_b);
      uptr shadow_end = MemToShadow(aligned_e);

      // 检查首尾字节（可能位于粒度内部的非对齐位置）
      QueryAddr(beg, beg_status, beg_poison);
      QueryAddr(end - 1, end_status, end_poison);
      // 首尾必须在同一侧，否则判定为跨边界访问
      if (beg_status != end_status) {
        status = RangeMixedInOutEnclave;
        poison = UnknownPoisonStatus;
      } else {
        if (shadow_end <= shadow_beg) {
          // 区间过小，首尾已覆盖所有影子字节，无需检查中间段
          status = beg_status;
          poison = (beg_poison or end_poison) ? IsPoisoned : NotPoisoned;
        } else {
          // 检查中间对齐段
          QueryShadowRegion((uint8_t *)shadow_beg, shadow_end - shadow_beg,
                            mid_status, mid_poison);
          if (beg_status != mid_status) {
            if (mid_status == InEnclave or mid_status == OutEnclave or
                mid_status == RangeMixedInOutEnclave) {
              status = RangeMixedInOutEnclave;
            } else {
              status = mid_status;
            }
            poison = UnknownPoisonStatus;
          } else {
            status = beg_status;
            poison = (beg_poison or end_poison or mid_poison) ? IsPoisoned
                                                              : NotPoisoned;
          }
        }
      }
    }
  }
}

/// 在 QueryRegion 基础上，
/// 进一步逐字节扫描定位第一个被毒化的地址
void FindFirstPoisoned(uptr beg, uptr size, EnclaveStatus &status,
                       uptr &first_poisoned) {
  PoisonStatus poison;
  QueryRegion(beg, size, status, poison);
  first_poisoned = poison; // 初始值：0=未毒化，1=已毒化（未定位具体地址）

  uptr end = beg + size;
  if (((status == InEnclave or status == OutEnclave) and
       poison == IsPoisoned) or
      status == RangeMixedInOutEnclave) {
    // 快速检查确认有毒化，逐字节扫描找到第一个毒化地址
    for (; beg < end; beg++) {
      EnclaveStatus unused;
      QueryAddr(beg, unused, poison);
      if (poison == IsPoisoned) {
        first_poisoned = beg;
        return;
      }
    }
    sgxsan_error(true, "there must be a poisoned byte\n");
  }
}

// ── sgx_is_within_enclave / sgx_is_outside_enclave ───────────────────────

/// 替代 SGX SDK 同名函数，通过影子内存判断地址是否完全在 Enclave 内
/// size=0 时检查 1 字节（与 SDK 行为一致）
static EnclaveStatus getRegionStatus(const void *addr, size_t size) {
  if (size == 0)
    size = 1;
  EnclaveStatus status;
  PoisonStatus poison;
  QueryRegion((uptr)addr, size, status, poison);
  return status;
}

int sgx_is_within_enclave(const void *addr, size_t size) {
  return getRegionStatus(addr, size) == InEnclave ? 1 : 0;
}

int sgx_is_outside_enclave(const void *addr, size_t size) {
  return getRegionStatus(addr, size) == OutEnclave ? 1 : 0;
}
