#include "ErrorReport.hpp"
#include "MemAccessMgr.hpp"
#include "Poison.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanRTConfig.h"

#define ASAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                      \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_##type##size(            \
      uptr addr, bool used_to_cmp) {                                           \
    if (UNLIKELY(not AddrIsInMem(addr))) {                                     \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, true,               \
                         "Invalid address");                                   \
    }                                                                          \
    uptr smp = MEM_TO_SHADOW(addr);                                            \
    uptr s = size <= SHADOW_GRANULARITY ? (*reinterpret_cast<u8 *>(smp))       \
                                        : (*reinterpret_cast<u16 *>(smp));     \
    if (UNLIKELY(s)) {                                                         \
      if (UNLIKELY(size >= SHADOW_GRANULARITY ||                               \
                   ((s8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >=     \
                       (s8)s)) {                                               \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true);            \
      }                                                                        \
    }                                                                          \
    SGXSAN_ELRANGE_CHECK_BEG(addr, size)                                       \
    MemAccessMgrInEnclaveAccess();                                             \
    SGXSAN_ELRANGE_CHECK_MID                                                   \
    MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write, used_to_cmp);   \
    SGXSAN_ELRANGE_CHECK_END;                                                  \
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

#define ASAN_MEMORY_ACCESS_CALLBACK_N(type, is_write)                          \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_##type##N(               \
      uptr addr, uptr size, bool used_to_cmp) {                                \
    if (UNLIKELY(not AddrIsInMem(addr))) {                                     \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, true,               \
                         "Invalid address");                                   \
    }                                                                          \
    if (sgxsan_region_is_poisoned(addr, size)) {                               \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, true);              \
    }                                                                          \
    SGXSAN_ELRANGE_CHECK_BEG(addr, size)                                       \
    MemAccessMgrInEnclaveAccess();                                             \
    SGXSAN_ELRANGE_CHECK_MID                                                   \
    MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write, used_to_cmp);   \
    SGXSAN_ELRANGE_CHECK_END;                                                  \
  }

ASAN_MEMORY_ACCESS_CALLBACK_N(load, false)
ASAN_MEMORY_ACCESS_CALLBACK_N(store, true)
