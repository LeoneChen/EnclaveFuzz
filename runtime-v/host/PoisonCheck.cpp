#include "PoisonCheck.h"
#include "MemAccessMgr.h"
#include "Poison.h"
#include "SGXSanRTApp.h"
#include "Sticker.h"
#include <algorithm>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <tuple>

// -------------------------- Run-time entry ------------------- {{{1
// exported functions
// memory access callback
#define ASAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                      \
  extern "C" __attribute__((noinline)) void __asan_##type##size(uptr addr,     \
                                                                bool toCmp) {  \
    if (UNLIKELY(not AddrIsInMem(addr))) {                                     \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, true,               \
                         "Invalid address");                                   \
    }                                                                          \
    uptr shadowMapPtr = MEM_TO_SHADOW(addr), shadowByte, inEnclaveFlag;        \
    if (size <= SHADOW_GRANULARITY) {                                          \
      shadowByte = *(uint8_t *)shadowMapPtr;                                   \
      inEnclaveFlag = kSGXSanInEnclaveMagic;                                   \
    } else {                                                                   \
      shadowByte = *(uint16_t *)shadowMapPtr;                                  \
      inEnclaveFlag = (kSGXSanInEnclaveMagic << 8) + kSGXSanInEnclaveMagic;    \
    }                                                                          \
    if (shadowByte == inEnclaveFlag) {                                         \
      MemAccessMgrInEnclaveAccess();                                           \
    } else if (shadowByte == 0) {                                              \
      MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write, toCmp);       \
    } else {                                                                   \
      uptr IsInEnclave = shadowByte & inEnclaveFlag;                           \
      if (IsInEnclave == inEnclaveFlag) {                                      \
        MemAccessMgrInEnclaveAccess();                                         \
      } else if (IsInEnclave == 0) {                                           \
        MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write, toCmp);     \
      } else {                                                                 \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true,             \
                           "Mixed Access");                                    \
      }                                                                        \
      uptr filter = size <= SHADOW_GRANULARITY                                 \
                        ? kL1Filter                                            \
                        : ((kL1Filter << 8) + kL1Filter);                      \
      shadowByte &= filter;                                                    \
      if (UNLIKELY(shadowByte)) {                                              \
        if (UNLIKELY(size >= SHADOW_GRANULARITY ||                             \
                     (int8_t)((addr & (SHADOW_GRANULARITY - 1)) + size - 1) >= \
                         (int8_t)shadowByte)) {                                \
          GET_CALLER_PC_BP_SP;                                                 \
          ReportGenericError(pc, bp, sp, addr, is_write, size, true,           \
                             IsInEnclave == inEnclaveFlag                      \
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

#define ASAN_MEMORY_ACCESS_CALLBACK_N(type, is_write)                          \
  extern "C" __attribute__((noinline)) void __asan_##type##N(                  \
      uptr addr, uptr size, bool toCmp) {                                      \
    if (UNLIKELY(not AddrIsInMem(addr))) {                                     \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, true,               \
                         "Invalid address");                                   \
    }                                                                          \
    InOutEnclaveStatus addrInOutEnclaveStatus;                                 \
    PoisonStatus addrPoisonStatus;                                             \
    RegionInOutEnclaveStatusAndPoisonStatus(                                   \
        addr, size, addrInOutEnclaveStatus, addrPoisonStatus);                 \
    if (addrInOutEnclaveStatus == InEnclave) {                                 \
      MemAccessMgrInEnclaveAccess();                                           \
      if (addrPoisonStatus != NotPoisoned) {                                   \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true,             \
                           "Enclave out of bound");                            \
      }                                                                        \
    } else if (addrInOutEnclaveStatus == OutEnclave) {                         \
      MemAccessMgrOutEnclaveAccess((void *)addr, size, is_write, toCmp);       \
      if (addrPoisonStatus != NotPoisoned) {                                   \
        GET_CALLER_PC_BP_SP;                                                   \
        ReportGenericError(pc, bp, sp, addr, is_write, size, true,             \
                           "Host out of bound");                               \
      }                                                                        \
    } else if (addrInOutEnclaveStatus == RangeMixedInOutEnclave) {             \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportGenericError(pc, bp, sp, addr, is_write, size, true,               \
                         "RangeMixedInOutEnclave hint OOB");                   \
    } else {                                                                   \
      GET_CALLER_PC_BP_SP;                                                     \
      ReportError(pc, bp, sp, addr, is_write, size,                            \
                  "addrInOutEnclaveStatus: %d", addrInOutEnclaveStatus);       \
    }                                                                          \
  }

ASAN_MEMORY_ACCESS_CALLBACK_N(load, false)
ASAN_MEMORY_ACCESS_CALLBACK_N(store, true)

void AddressInOutEnclaveStatusAndPoisonStatus(
    uptr addr, InOutEnclaveStatus &addrInOutEnclaveStatus,
    PoisonStatus &addrPoisonStatus) {
  int8_t shadow_value = *(int8_t *)MEM_TO_SHADOW(addr);
  if (shadow_value == kSGXSanInEnclaveMagic) {
    // early found just in Enclave, filter is needn't to use
    addrInOutEnclaveStatus = InEnclave;
    addrPoisonStatus = NotPoisoned;
  } else if (shadow_value == 0) {
    addrInOutEnclaveStatus = OutEnclave;
    addrPoisonStatus = NotPoisoned;
  } else {
    addrInOutEnclaveStatus = L0F(shadow_value) ? InEnclave : OutEnclave;

    shadow_value &= kL1Filter;
    if (LIKELY(shadow_value == 0)) {
      addrPoisonStatus = NotPoisoned;
    } else {
      int8_t L1Bits = L1F(shadow_value);
      // last_accessed_byte should <= SHADOW_GRANULARITY - 1 (i.e. 0x7)
      uint8_t last_accessed_byte = addr & (SHADOW_GRANULARITY - 1);
      addrPoisonStatus =
          last_accessed_byte >= L1Bits ? IsPoisoned : NotPoisoned;
    }
  }
}

void ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
    uint8_t *beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus) {
  // beg is nullptr when ShadowMap start from 0?
  if (size == 0) {
    regionInOutEnclaveStatus = UnknownInOutEnclaveStatus;
    regionPoisonStatus = UnknownPoisonStatus;
  } else if (size > (1ULL << 40)) {
    // Sanity check
    regionInOutEnclaveStatus = RangeOverflow;
    regionPoisonStatus = UnknownPoisonStatus;
  } else {
    uint8_t *end = beg + size; // offset by 1
    uint8_t allBitOr = 0, allBitAnd = ~0;
    for (uint8_t *mem = beg; mem < end; mem++) {
      allBitOr |= *mem;
      allBitAnd &= *mem;
    }
    if (L0F(allBitOr) != L0F(allBitAnd)) {
      regionInOutEnclaveStatus = RangeMixedInOutEnclave;
      regionPoisonStatus = UnknownPoisonStatus;
    } else if (allBitOr == kSGXSanInEnclaveMagic) {
      regionInOutEnclaveStatus = InEnclave;
      regionPoisonStatus = NotPoisoned;
    } else if (allBitOr == 0) {
      regionInOutEnclaveStatus = OutEnclave;
      regionPoisonStatus = NotPoisoned;
    } else {
      if (L0F(allBitOr) == 0) {
        regionInOutEnclaveStatus = OutEnclave;
      } else if (L0F(allBitOr) == kSGXSanInEnclaveMagic) {
        regionInOutEnclaveStatus = InEnclave;
      } else {
        sgxsan_error(true, "Ranged mixed?");
      }
      regionPoisonStatus = L1F(allBitOr) ? IsPoisoned : NotPoisoned;
    }
  }
}

void RegionInOutEnclaveStatusAndPoisonStatus(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    PoisonStatus &regionPoisonStatus) {
  // Early error
  if (beg == 0) {
    regionInOutEnclaveStatus = OutEnclave;
    regionPoisonStatus = IsPoisoned;
  } else if (size == 0) {
    regionInOutEnclaveStatus = UnknownInOutEnclaveStatus;
    regionPoisonStatus = UnknownPoisonStatus;
  } else {
    uptr end =
        beg + size; // Offset by one. A offset-by-one bug in original ASan?
    if (beg > end) {
      regionInOutEnclaveStatus = RangeOverflow;
      regionPoisonStatus = UnknownPoisonStatus;
    } else if (not(AddrIsInMem(beg) and AddrIsInMem(end - 1))) {
      regionInOutEnclaveStatus = RangeInvalid;
      regionPoisonStatus = UnknownPoisonStatus;
    } else {
      InOutEnclaveStatus begInOutEnclaveStatus, endInOutEnclaveStatus,
          alignedRegionInOutEnclaveStatus;
      PoisonStatus begPoisonStatus, endPoisonStatus, alignedRegionPoisonStatus;

      /// Full check
      uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
      uptr aligned_e = RoundDownTo(end - 1, SHADOW_GRANULARITY);
      uptr shadow_beg = MemToShadow(aligned_b);
      uptr shadow_end = MemToShadow(aligned_e);

      // First check the first and the last application bytes,
      // then check the SHADOW_GRANULARITY-aligned region
      AddressInOutEnclaveStatusAndPoisonStatus(beg, begInOutEnclaveStatus,
                                               begPoisonStatus);
      AddressInOutEnclaveStatusAndPoisonStatus(end - 1, endInOutEnclaveStatus,
                                               endPoisonStatus);
      // make sure all bytes at same side
      if (begInOutEnclaveStatus != endInOutEnclaveStatus) {
        regionInOutEnclaveStatus = RangeMixedInOutEnclave;
        regionPoisonStatus = UnknownPoisonStatus;
      } else {
        if (shadow_end <= shadow_beg) {
          // already check each ShadowByte
          regionInOutEnclaveStatus = begInOutEnclaveStatus;
          regionPoisonStatus =
              (begPoisonStatus or endPoisonStatus) ? IsPoisoned : NotPoisoned;
        } else {
          // need to check granuality-aligned shadow value
          ShadowRegionInOutEnclaveStatusAndStrictPoisonStatus(
              (uint8_t *)shadow_beg, shadow_end - shadow_beg,
              alignedRegionInOutEnclaveStatus, alignedRegionPoisonStatus);
          // make sure all bytes at same side
          if (begInOutEnclaveStatus != alignedRegionInOutEnclaveStatus) {
            if (alignedRegionInOutEnclaveStatus == InEnclave or
                alignedRegionInOutEnclaveStatus == OutEnclave or
                alignedRegionInOutEnclaveStatus == RangeMixedInOutEnclave) {
              regionInOutEnclaveStatus = RangeMixedInOutEnclave;
            } else {
              regionInOutEnclaveStatus = alignedRegionInOutEnclaveStatus;
            }
            regionPoisonStatus = UnknownPoisonStatus;
          } else {
            regionInOutEnclaveStatus = begInOutEnclaveStatus;
            regionPoisonStatus = (begPoisonStatus or endPoisonStatus or
                                  alignedRegionPoisonStatus)
                                     ? IsPoisoned
                                     : NotPoisoned;
          }
        }
      }
    }
  }
}

void RegionInOutEnclaveStatusAndPoisonedAddr(
    uptr beg, uptr size, InOutEnclaveStatus &regionInOutEnclaveStatus,
    uptr &regionFirstPoisonedAddr) {
  InOutEnclaveStatus pos;
  PoisonStatus poison;
  RegionInOutEnclaveStatusAndPoisonStatus(beg, size, regionInOutEnclaveStatus,
                                          poison);
  regionFirstPoisonedAddr = poison;

  uptr end = beg + size;
  if (((regionInOutEnclaveStatus == InEnclave or
        regionInOutEnclaveStatus == OutEnclave) and
       poison == IsPoisoned) or
      regionInOutEnclaveStatus == RangeMixedInOutEnclave) {
    // must be poisoned
    // The fast check failed, so we have a poisoned byte somewhere.
    // Find it slowly.
    for (; beg < end; beg++) {
      AddressInOutEnclaveStatusAndPoisonStatus(beg, pos, poison);
      if (poison == IsPoisoned) {
        regionFirstPoisonedAddr = beg;
        return;
      }
    }
    sgxsan_error(true, "there must be a poisoned byte\n");
  }
}

int sgx_is_within_enclave(const void *addr, size_t size) {
  if (size == 0) {
    // Note: If size is zero, check one byte
    size = 1;
  }
  InOutEnclaveStatus addrInOutEnclaveStatus;
  PoisonStatus addrPoisonStatus;
  RegionInOutEnclaveStatusAndPoisonStatus(
      (uptr)addr, size, addrInOutEnclaveStatus, addrPoisonStatus);
  if (addrInOutEnclaveStatus == InEnclave)
    return 1;
  else
    return 0;
}

int sgx_is_outside_enclave(const void *addr, size_t size) {
  if (size == 0) {
    // Note: If size is zero, check one byte
    size = 1;
  }
  InOutEnclaveStatus addrInOutEnclaveStatus;
  PoisonStatus addrPoisonStatus;
  RegionInOutEnclaveStatusAndPoisonStatus(
      (uptr)addr, size, addrInOutEnclaveStatus, addrPoisonStatus);
  if (addrInOutEnclaveStatus == OutEnclave)
    return 1;
  else
    return 0;
}

extern "C" {
/// Memory Intrinsics Callback
void *__asan_memcpy(void *dst, const void *src, uptr size) {
  if (size == 0)
    return dst;
  if (LIKELY(asan_inited)) {
    if (dst != src) {
      if (RangesOverlap((const char *)dst, size, (const char *)src, size)) {
        GET_CALLER_PC_BP_SP;
        sgxsan_error(
            true,
            "%p:%lu overlap with %p:%lu at pc %p (bp = 0x%lx sp = 0x%lx)\n",
            dst, size, src, size, (void *)pc, bp, sp);
      }
    }
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, size, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, size, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return memcpy(dst, src, size);
}

void *__asan_memset(void *dst, int c, uptr size) {
  if (size == 0)
    return dst;
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, size, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return memset(dst, c, size);
}

void *__asan_memmove(void *dst, const void *src, uptr size) {
  if (size == 0)
    return dst;
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, size, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, size, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return memmove(dst, src, size);
}

typedef error_t errno_t;
extern errno_t memcpy_s(void *dst, size_t sizeInBytes, const void *src,
                        size_t count);
extern errno_t memmove_s(void *dst, size_t sizeInBytes, const void *src,
                         size_t count);
extern errno_t memset_s(void *s, size_t smax, int c, size_t n);
extern errno_t strcpy_s(char *dst, size_t dstSize, const char *src);
extern errno_t strncpy_s(char *dst, size_t dstSize, const char *src,
                         size_t count);
extern errno_t strcat_s(char *dst, size_t dstSize, const char *src);
extern errno_t strncat_s(char *dst, size_t dstSize, const char *src,
                         size_t count);
extern size_t strlcpy(char *dst, const char *src, size_t dsize);

errno_t __sgxsan_memcpy_s(void *dst, size_t dstSize, const void *src,
                          size_t count) {
  if (dstSize == 0 or count == 0)
    return 0;
  if (LIKELY(asan_inited)) {
    if (dst != src) {
      if (RangesOverlap((const char *)dst, dstSize, (const char *)src, count)) {
        GET_CALLER_PC_BP_SP;
        sgxsan_error(true,
                     "[%s] %p:%lu overlap with %p:%lu at pc %p (bp = 0x%lx sp "
                     "= 0x%lx)\n",
                     "memcpy_s", dst, dstSize, src, count, (void *)pc, bp, sp);
      }
    }
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, count, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, dstSize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return memcpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_memset_s(void *dst, size_t dstSize, int c, size_t n) {
  if (dstSize == 0 or n == 0)
    return 0;
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, std::max(dstSize, n), dstInOutEnclaveStatus,
                dstPoisonedAddr, true);
  }
  return memset_s(dst, dstSize, c, n);
}

errno_t __sgxsan_memmove_s(void *dst, size_t dstSize, const void *src,
                           size_t count) {
  if (dstSize == 0 or count == 0)
    return 0;
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, count, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, dstSize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return memmove_s(dst, dstSize, src, count);
}

//==============================================================================
// 3. Fixed-Size Memory and String Operations
//==============================================================================

int __sgxsan_memcmp(const void *s1, const void *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus s1InOutEnclaveStatus, s2InOutEnclaveStatus;
    uptr s1PoisonedAddr, s2PoisonedAddr;
    RANGE_CHECK(s1, n, s1InOutEnclaveStatus, s1PoisonedAddr, false);
    RANGE_CHECK(s2, n, s2InOutEnclaveStatus, s2PoisonedAddr, false);
  }
  return memcmp(s1, s2, n);
}

void *__sgxsan_memchr(const void *s, int c, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus sInOutEnclaveStatus;
    uptr sPoisonedAddr;
    RANGE_CHECK(s, n, sInOutEnclaveStatus, sPoisonedAddr, false);
  }
  return (void *)memchr(s, c, n);
}

int __sgxsan_bcmp(const void *s1, const void *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus s1InOutEnclaveStatus, s2InOutEnclaveStatus;
    uptr s1PoisonedAddr, s2PoisonedAddr;
    RANGE_CHECK(s1, n, s1InOutEnclaveStatus, s1PoisonedAddr, false);
    RANGE_CHECK(s2, n, s2InOutEnclaveStatus, s2PoisonedAddr, false);
  }
  return bcmp(s1, s2, n);
}

char *__sgxsan_strncpy(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, n, dstInOutEnclaveStatus, dstPoisonedAddr, true);
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, src_read, srcInOutEnclaveStatus, srcPoisonedAddr, false);
  }
  return strncpy(dst, src, n);
}

char *__sgxsan_stpncpy(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, n, dstInOutEnclaveStatus, dstPoisonedAddr, true);
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, src_read, srcInOutEnclaveStatus, srcPoisonedAddr, false);
  }
  return stpncpy(dst, src, n);
}

int __sgxsan_strncmp(const char *s1, const char *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    size_t len1 = strnlen(s1, n);
    size_t read1 = len1 < n ? len1 + 1 : n;
    InOutEnclaveStatus s1InOutEnclaveStatus;
    uptr s1PoisonedAddr;
    RANGE_CHECK(s1, read1, s1InOutEnclaveStatus, s1PoisonedAddr, false);
    size_t len2 = strnlen(s2, n);
    size_t read2 = len2 < n ? len2 + 1 : n;
    InOutEnclaveStatus s2InOutEnclaveStatus;
    uptr s2PoisonedAddr;
    RANGE_CHECK(s2, read2, s2InOutEnclaveStatus, s2PoisonedAddr, false);
  }
  return strncmp(s1, s2, n);
}

size_t __sgxsan_strnlen(const char *s, size_t maxlen) {
  size_t result = strnlen(s, maxlen);
  if (maxlen != 0 && LIKELY(asan_inited)) {
    size_t read_size = result < maxlen ? result + 1 : maxlen;
    InOutEnclaveStatus sInOutEnclaveStatus;
    uptr sPoisonedAddr;
    RANGE_CHECK(s, read_size, sInOutEnclaveStatus, sPoisonedAddr, false);
  }
  return result;
}

char *__sgxsan_strncat(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    size_t dst_len = strlen(dst);
    InOutEnclaveStatus dstReadInOutEnclaveStatus;
    uptr dstReadPoisonedAddr;
    RANGE_CHECK(dst, dst_len + 1, dstReadInOutEnclaveStatus,
                dstReadPoisonedAddr, false);
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, src_read, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    InOutEnclaveStatus dstWriteInOutEnclaveStatus;
    uptr dstWritePoisonedAddr;
    RANGE_CHECK(dst, dst_len + n + 1, dstWriteInOutEnclaveStatus,
                dstWritePoisonedAddr, true);
  }
  return strncat(dst, src, n);
}

char *__sgxsan_strndup(const char *s, size_t n) {
  size_t len = strnlen(s, n);
  size_t read_size = len < n ? len + 1 : n;
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus sInOutEnclaveStatus;
    uptr sPoisonedAddr;
    RANGE_CHECK(s, read_size, sInOutEnclaveStatus, sPoisonedAddr, false);
  }
  return strndup(s, n);
}

size_t __sgxsan_strlcpy(char *dst, const char *src, size_t dsize) {
  if (dsize != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, dsize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  size_t result = strlcpy(dst, src, dsize);
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, result + 1, srcInOutEnclaveStatus, srcPoisonedAddr, false);
  }
  return result;
}

void __sgxsan_bzero(void *s, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus sInOutEnclaveStatus;
    uptr sPoisonedAddr;
    RANGE_CHECK(s, n, sInOutEnclaveStatus, sPoisonedAddr, true);
  }
  bzero(s, n);
}

void __sgxsan_bcopy(const void *src, void *dst, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, n, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, n, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  bcopy(src, dst, n);
}

void *__sgxsan_mempcpy(void *dst, const void *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    if (dst != src) {
      if (RangesOverlap((const char *)dst, n, (const char *)src, n)) {
        GET_CALLER_PC_BP_SP;
        sgxsan_error(true,
                     "[%s] %p:%lu overlap with %p:%lu at pc %p (bp = 0x%lx sp "
                     "= 0x%lx)\n",
                     "mempcpy", dst, n, src, n, (void *)pc, bp, sp);
      }
    }
    InOutEnclaveStatus srcInOutEnclaveStatus, dstInOutEnclaveStatus;
    uptr srcPoisonedAddr, dstPoisonedAddr;
    RANGE_CHECK(src, n, srcInOutEnclaveStatus, srcPoisonedAddr, false);
    RANGE_CHECK(dst, n, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  return mempcpy(dst, src, n);
}

//==============================================================================
// 4. Safe String Functions (_s variants)
//==============================================================================

errno_t __sgxsan_strcpy_s(char *dst, size_t dstSize, const char *src) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, dstSize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  size_t src_len = strlen(src);
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, src_len + 1, srcInOutEnclaveStatus, srcPoisonedAddr,
                false);
  }
  return strcpy_s(dst, dstSize, src);
}

errno_t __sgxsan_strncpy_s(char *dst, size_t dstSize, const char *src,
                           size_t count) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus dstInOutEnclaveStatus;
    uptr dstPoisonedAddr;
    RANGE_CHECK(dst, dstSize, dstInOutEnclaveStatus, dstPoisonedAddr, true);
  }
  if (count != 0 && LIKELY(asan_inited)) {
    size_t src_len = strnlen(src, count);
    size_t src_read = src_len < count ? src_len + 1 : count;
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, src_read, srcInOutEnclaveStatus, srcPoisonedAddr, false);
  }
  return strncpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_strcat_s(char *dst, size_t dstSize, const char *src) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    size_t dst_len = strlen(dst);
    InOutEnclaveStatus dstReadInOutEnclaveStatus;
    uptr dstReadPoisonedAddr;
    RANGE_CHECK(dst, dst_len + 1, dstReadInOutEnclaveStatus,
                dstReadPoisonedAddr, false);
    InOutEnclaveStatus dstWriteInOutEnclaveStatus;
    uptr dstWritePoisonedAddr;
    RANGE_CHECK(dst, dstSize, dstWriteInOutEnclaveStatus, dstWritePoisonedAddr,
                true);
  }
  size_t src_len = strlen(src);
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, src_len + 1, srcInOutEnclaveStatus, srcPoisonedAddr,
                false);
  }
  return strcat_s(dst, dstSize, src);
}

errno_t __sgxsan_strncat_s(char *dst, size_t dstSize, const char *src,
                           size_t count) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    size_t dst_len = strlen(dst);
    InOutEnclaveStatus dstReadInOutEnclaveStatus;
    uptr dstReadPoisonedAddr;
    RANGE_CHECK(dst, dst_len + 1, dstReadInOutEnclaveStatus,
                dstReadPoisonedAddr, false);
    InOutEnclaveStatus dstWriteInOutEnclaveStatus;
    uptr dstWritePoisonedAddr;
    RANGE_CHECK(dst, dstSize, dstWriteInOutEnclaveStatus, dstWritePoisonedAddr,
                true);
  }
  if (count != 0 && LIKELY(asan_inited)) {
    size_t src_len = strnlen(src, count);
    size_t src_read = src_len < count ? src_len + 1 : count;
    InOutEnclaveStatus srcInOutEnclaveStatus;
    uptr srcPoisonedAddr;
    RANGE_CHECK(src, src_read, srcInOutEnclaveStatus, srcPoisonedAddr, false);
  }
  return strncat_s(dst, dstSize, src, count);
}

//==============================================================================
// 5. Formatting Functions
//==============================================================================

int __sgxsan_snprintf(char *str, size_t n, const char *fmt, ...) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus strInOutEnclaveStatus;
    uptr strPoisonedAddr;
    RANGE_CHECK(str, n, strInOutEnclaveStatus, strPoisonedAddr, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(str, n, fmt, ap);
  va_end(ap);
  return ret;
}

int __sgxsan_vsnprintf(char *str, size_t n, const char *fmt, va_list ap) {
  if (n != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus strInOutEnclaveStatus;
    uptr strPoisonedAddr;
    RANGE_CHECK(str, n, strInOutEnclaveStatus, strPoisonedAddr, true);
  }
  return vsnprintf(str, n, fmt, ap);
}

int __sgxsan_sprintf_s(char *str, size_t sizeInBytes, const char *fmt, ...) {
  if (sizeInBytes != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus strInOutEnclaveStatus;
    uptr strPoisonedAddr;
    RANGE_CHECK(str, sizeInBytes, strInOutEnclaveStatus, strPoisonedAddr, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(str, sizeInBytes, fmt, ap);
  va_end(ap);
  return ret;
}

int __sgxsan__snprintf_s(char *str, size_t sizeInBytes, size_t count,
                         const char *fmt, ...) {
  if (sizeInBytes != 0 && LIKELY(asan_inited)) {
    InOutEnclaveStatus strInOutEnclaveStatus;
    uptr strPoisonedAddr;
    RANGE_CHECK(str, sizeInBytes, strInOutEnclaveStatus, strPoisonedAddr, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(str, std::min(sizeInBytes, count + 1), fmt, ap);
  va_end(ap);
  return ret;
}

//==============================================================================
// 6. NUL-Terminated String Operations
//==============================================================================

size_t __sgxsan_strlen(const char *s) {
  size_t result = strlen(s);
  if (LIKELY(asan_inited)) {
    InOutEnclaveStatus sInOutEnclaveStatus;
    uptr sPoisonedAddr;
    RANGE_CHECK(s, result + 1, sInOutEnclaveStatus, sPoisonedAddr, false);
  }
  return result;
}

int __sgxsan_strcmp(const char *s1, const char *s2) {
  int result = strcmp(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    InOutEnclaveStatus s1InOutEnclaveStatus, s2InOutEnclaveStatus;
    uptr s1PoisonedAddr, s2PoisonedAddr;
    RANGE_CHECK(s1, len1 + 1, s1InOutEnclaveStatus, s1PoisonedAddr, false);
    RANGE_CHECK(s2, len2 + 1, s2InOutEnclaveStatus, s2PoisonedAddr, false);
  }
  return result;
}

char *__sgxsan_strchr(const char *s, int c) {
  char *result = (char *)strchr(s, c);
  if (LIKELY(asan_inited)) {
    size_t len = result ? (size_t)(result - s + 1) : strlen(s) + 1;
    InOutEnclaveStatus sInOutEnclaveStatus;
    uptr sPoisonedAddr;
    RANGE_CHECK(s, len, sInOutEnclaveStatus, sPoisonedAddr, false);
  }
  return result;
}

char *__sgxsan_strrchr(const char *s, int c) {
  char *result = (char *)strrchr(s, c);
  if (LIKELY(asan_inited)) {
    size_t len = strlen(s) + 1;
    InOutEnclaveStatus sInOutEnclaveStatus;
    uptr sPoisonedAddr;
    RANGE_CHECK(s, len, sInOutEnclaveStatus, sPoisonedAddr, false);
  }
  return result;
}

char *__sgxsan_strstr(const char *s, const char *find) {
  char *result = (char *)strstr(s, find);
  if (LIKELY(asan_inited)) {
    size_t slen = strlen(s) + 1;
    size_t flen = strlen(find) + 1;
    InOutEnclaveStatus sInOutEnclaveStatus, findInOutEnclaveStatus;
    uptr sPoisonedAddr, findPoisonedAddr;
    RANGE_CHECK(s, slen, sInOutEnclaveStatus, sPoisonedAddr, false);
    RANGE_CHECK(find, flen, findInOutEnclaveStatus, findPoisonedAddr, false);
  }
  return result;
}

size_t __sgxsan_strspn(const char *s1, const char *s2) {
  size_t result = strspn(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    InOutEnclaveStatus s1InOutEnclaveStatus, s2InOutEnclaveStatus;
    uptr s1PoisonedAddr, s2PoisonedAddr;
    RANGE_CHECK(s1, len1, s1InOutEnclaveStatus, s1PoisonedAddr, false);
    RANGE_CHECK(s2, len2, s2InOutEnclaveStatus, s2PoisonedAddr, false);
  }
  return result;
}

size_t __sgxsan_strcspn(const char *s1, const char *s2) {
  size_t result = strcspn(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    InOutEnclaveStatus s1InOutEnclaveStatus, s2InOutEnclaveStatus;
    uptr s1PoisonedAddr, s2PoisonedAddr;
    RANGE_CHECK(s1, len1, s1InOutEnclaveStatus, s1PoisonedAddr, false);
    RANGE_CHECK(s2, len2, s2InOutEnclaveStatus, s2PoisonedAddr, false);
  }
  return result;
}

char *__sgxsan_strpbrk(const char *s1, const char *s2) {
  char *result = (char *)strpbrk(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    InOutEnclaveStatus s1InOutEnclaveStatus, s2InOutEnclaveStatus;
    uptr s1PoisonedAddr, s2PoisonedAddr;
    RANGE_CHECK(s1, len1, s1InOutEnclaveStatus, s1PoisonedAddr, false);
    RANGE_CHECK(s2, len2, s2InOutEnclaveStatus, s2PoisonedAddr, false);
  }
  return result;
}
}
