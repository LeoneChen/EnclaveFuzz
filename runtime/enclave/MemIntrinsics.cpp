#include "ErrorReport.hpp"
#include "MemAccessMgr.hpp"
#include "Poison.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanRTEnclave.hpp"
#include <assert.h>
#include <cstdlib>
#include <mbusafecrt.h>
#include <stddef.h>
#include <string.h>

// In order to check safe memory operations:
// If we do not instrument sgxsdk, we should replace memcpy used in memcpy_s
// with __asan_memcpy(weak symbol) by hand. (Current) Or replace memcpy_s with
// __sgxsan_memcpy_s If we need to instrument sgxsdk, we needn't extra check, as
// memcpy will be replaced with __asan_memcpy by llvm pass

#define RANGE_CHECK(beg, size, is_write)                                       \
  do {                                                                         \
    SGXSAN_ELRANGE_CHECK_BEG(beg, size)                                        \
    MemAccessMgrInEnclaveAccess();                                             \
    SGXSAN_ELRANGE_CHECK_MID                                                   \
    MemAccessMgrOutEnclaveAccess(beg, size, is_write, false);                  \
    SGXSAN_ELRANGE_CHECK_END;                                                  \
  } while (0);

extern "C" {
void *__asan_memcpy(void *dst, const void *src, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    if (dst != src) {
      sgxsan_error(
          RangesOverlap((const char *)dst, size, (const char *)src, size),
          "[%s] %p:%lu overlap with %p:%lu\n", "memcpy", dst, size, src, size);
    }

    ASAN_READ_RANGE(src, size);
    RANGE_CHECK(src, size, false);

    ASAN_WRITE_RANGE(dst, size);
    RANGE_CHECK(dst, size, true);
  }
  return memcpy(dst, src, size);
}

void *__asan_memset(void *dst, int c, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(dst, size);
    RANGE_CHECK(dst, size, true);
  }
  return memset(dst, c, size);
}

void *__asan_memmove(void *dst, const void *src, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    ASAN_READ_RANGE(src, size);
    RANGE_CHECK(src, size, false);

    ASAN_WRITE_RANGE(dst, size);
    RANGE_CHECK(dst, size, true);
  }
  return memmove(dst, src, size);
}

errno_t __sgxsan_memcpy_s(void *dst, size_t dstSize, const void *src,
                          size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    if (dst != src) {
      sgxsan_error(
          RangesOverlap((const char *)dst, dstSize, (const char *)src, count),
          "[%s] %p:%lu overlap with %p:%lu\n", "memcpy_s", dst, dstSize, src,
          count);
    }

    ASAN_READ_RANGE(src, count);
    RANGE_CHECK(src, count, false);

    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true);
  }
  return memcpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_memset_s(void *dst, size_t dstSize, int c, size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(dst, std::max(dstSize, count));
    RANGE_CHECK(dst, std::max(dstSize, count), true);
  }
  return memset_s(dst, dstSize, c, count);
}

int __sgxsan_memmove_s(void *dst, size_t dstSize, const void *src,
                       size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    ASAN_READ_RANGE(src, count);
    RANGE_CHECK(src, count, false);

    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true);
  }
  return memmove_s(dst, dstSize, src, count);
}
}