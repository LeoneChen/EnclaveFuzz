#pragma once

#include "Poison.h"
#include "SGXSanRTApp.h"
#include <stdint.h>
#include <utility>

enum InOutEnclaveStatus {
  UnknownInOutEnclaveStatus = -1,
  OutEnclave = 0,
  InEnclave = 1,
  RangeMixedInOutEnclave = 2,
  RangeOverflow = 3,
  RangeInvalid = 4,
};
enum PoisonStatus { UnknownPoisonStatus = -1, NotPoisoned = 0, IsPoisoned = 1 };

/// @brief Check only one shadow byte, this function don't call other check.
/// @param addr Address used to check shadow byte
/// @param[out] addrInOutEnclaveStatus Returns InEnclave or OutEnclave.
/// @param[out] addrPoisonStatus Return NotPoisoned or IsPoisoned
/// @param filter Tell which bits in one byte is interesting
void AddressInOutEnclaveStatusAndPoisonStatus(
    uptr addr, InOutEnclaveStatus &addrInOutEnclaveStatus,
    PoisonStatus &addrPoisonStatus);

/// @brief Tell us whether region is poisoned, even if it's partial poisoned
/// (what 'Strict' means), this function don't call other check.
/// @param beg Begin of shadow region
/// @param size Size of shadow region
/// @param[out] regionInOutEnclaveStatus Return UnknownInOutEnclaveStatus if
/// size is 0. Return RangeOverflow if size > 2^40. Return
/// RangeMixedInOutEnclave if partial shadow bytes indicate InEnclave while
/// others indicate OutEnclave. Otherwise return InEnclave or OutEnclave
/// @param[out] regionPoisonStatus
/// If InEnclave or OutEnclave, return IsPoisoned or NotPoisoned, otherwise
/// return UnknownPoisonStatus.
/// @param filter Tell which bits in one byte is interesting
void ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
    uint8_t *beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus);

/// @brief Tell us whether region is poisoned, partial poisoned will be checked
/// @param beg Begin of region
/// @param size Size of region
/// @param[out] regionInOutEnclaveStatus Return RangeOverflow when (beg + size)
/// cause int overflow. Return RangeInvalid if region isn't in valid memory.
/// Return RangeMixedInOutEnclave if partial shadow bytes indicate InEnclave
/// while others indicate OutEnclave. Otherwise return InEnclave or OutEnclave.
/// @param[out] regionPoisonStatus If InEnclave or OutEnclave, return
/// NotPoisoned or IsPoisoned
/// @param filter Tell which bits in one byte is interesting
void RegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus);

/// @brief Tell us whether region is poisoned and the first address are
/// poisoned, partial poisoned will be checked
/// @param beg Begin of region
/// @param size Size of region
/// @param[out] regionInOutEnclaveStatus Return RangeOverflow when (beg + size)
/// cause int overflow. Return RangeInvalid if region isn't in valid memory.
/// Return RangeMixedInOutEnclave if partial shadow bytes indicate InEnclave
/// while others indicate OutEnclave. Otherwise return InEnclave or OutEnclave.
/// @param[out] regionFirstPoisonedAddr If InEnclave or OutEnclave, return first
/// poisoned address
/// @param filter Tell which bits in one byte is interesting
void RegionInOutEnclaveStatusAndPoisonedAddr(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    uptr &regionFirstPoisonedAddr);

#if defined(__cplusplus)
extern "C" {
#endif
int sgx_is_within_enclave(const void *addr, size_t size);
int sgx_is_outside_enclave(const void *addr, size_t size);
#if defined(__cplusplus)
}
#endif

/// \param size should not be 0, RANGE_CHECK must be a macro since
/// GET_CALLER_PC_BP_SP shouldn't called in sub-function
#define RANGE_CHECK(beg, size, regionInOutEnclaveStatus, PoisonedAddr,         \
                    IsWrite)                                                   \
  do {                                                                         \
    RegionInOutEnclaveStatusAndPoisonedAddr(                                   \
        (uptr)beg, size, regionInOutEnclaveStatus, PoisonedAddr);              \
    if (regionInOutEnclaveStatus == InEnclave) {                               \
      MemAccessMgrInEnclaveAccess();                                           \
      if (PoisonedAddr) {                                                      \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, PoisonedAddr, IsWrite, size, true,      \
                           "Enclave out of bound");                            \
      }                                                                        \
    } else if (regionInOutEnclaveStatus == OutEnclave) {                       \
      MemAccessMgrOutEnclaveAccess(beg, size, IsWrite);                        \
      if (PoisonedAddr) {                                                      \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, PoisonedAddr, IsWrite, size, true,      \
                           "Host out of bound");                               \
      }                                                                        \
    } else if (regionInOutEnclaveStatus == RangeMixedInOutEnclave) {           \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, PoisonedAddr, IsWrite, size, true,        \
                         "RangeMixedInOutEnclave hint OOB");                   \
    } else {                                                                   \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, (uptr)beg, IsWrite, size, true,           \
                         "regionInOutEnclaveStatus: %d",                       \
                         regionInOutEnclaveStatus);                            \
    }                                                                          \
  } while (0);
