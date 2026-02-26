#include "ErrorReport.hpp"
#include "MemAccessMgr.hpp"
#include "Poison.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanRTEnclave.hpp"
#include <assert.h>
#include <cstdlib>
#include <mbusafecrt.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

//==============================================================================
// Memory Intrinsics Sanitizer Wrappers
//==============================================================================
// This file provides sanitized wrappers for memory and string operations.
// These wrappers intercept standard library functions to perform:
//   1. AddressSanitizer checks (shadow memory validation)
//   2. Memory access tracking (enclave boundary monitoring)
//   3. Overlap detection for memory operations
//
// Function Organization:
//   - ASAN Interceptors (memcpy, memset, memmove)
//   - Safe Function Wrappers (_s variants: memcpy_s, memset_s, etc.)
//   - Fixed-size Operations (memcmp, memchr, strncpy, strncmp, etc.)
//   - NUL-terminated Operations (strlen, strcmp, strchr, strstr, etc.)
//   - BSD/Legacy Functions (bzero, bcopy, bcmp)
//   - Formatting Functions (snprintf, sprintf_s, etc.)
//==============================================================================

// Range check macro: performs both in-enclave and out-of-enclave memory checks
#define RANGE_CHECK(beg, size, is_write)                                       \
  do {                                                                         \
    SGXSAN_ELRANGE_CHECK_BEG(beg, size)                                        \
    MemAccessMgrInEnclaveAccess();                                             \
    SGXSAN_ELRANGE_CHECK_MID                                                   \
    MemAccessMgrOutEnclaveAccess(beg, size, is_write, false);                  \
    SGXSAN_ELRANGE_CHECK_END;                                                  \
  } while (0);

extern "C" {

//==============================================================================
// 1. ASAN Memory Operation Interceptors
//==============================================================================
// These functions are directly called by LLVM AddressSanitizer instrumentation
// to replace standard memcpy/memset/memmove operations.
//==============================================================================

// __asan_memcpy: Sanitizer wrapper for memcpy
// - Checks for overlapping regions (undefined behavior for memcpy)
// - Validates source (read) and destination (write) memory ranges
void *__asan_memcpy(void *dst, const void *src, uptr size) {
  if (size == 0) {
    return dst;
  }
  if (LIKELY(asan_inited)) {
    // Verify no overlap between src and dst
    if (dst != src) {
      sgxsan_error(
          RangesOverlap((const char *)dst, size, (const char *)src, size),
          "[%s] %p:%lu overlap with %p:%lu\n", "memcpy", dst, size, src, size);
    }
    // Check source is readable
    ASAN_READ_RANGE(src, size);
    RANGE_CHECK(src, size, false);
    // Check destination is writable
    ASAN_WRITE_RANGE(dst, size);
    RANGE_CHECK(dst, size, true);
  }
  return memcpy(dst, src, size);
}

// __asan_memset: Sanitizer wrapper for memset
// - Validates destination (write) memory range
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

// __asan_memmove: Sanitizer wrapper for memmove
// - Allows overlapping regions (safe for memmove)
// - Validates source (read) and destination (write) memory ranges
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

//==============================================================================
// 2. Safe Memory Functions (_s variants from Microsoft/Intel SafeCRT)
//==============================================================================
// These wrappers provide bounds-checked versions of memory operations.
// The "_s" suffix indicates "secure" variants with explicit size parameters.
//==============================================================================

// __sgxsan_memcpy_s: Safe memcpy with destination size check
errno_t __sgxsan_memcpy_s(void *dst, size_t dstSize, const void *src,
                          size_t count) {
  if (dstSize == 0 or count == 0) {
    return 0;
  }
  if (LIKELY(asan_inited)) {
    // Verify no overlap between src and dst
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

// __sgxsan_memset_s: Safe memset with destination size check
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

// __sgxsan_memmove_s: Safe memmove with destination size check
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

//==============================================================================
// 3. Fixed-Size Memory and String Operations
//==============================================================================
// Functions that operate on known-size buffers. Size is always checked upfront.
//==============================================================================

// Memory comparison and search
int __sgxsan_memcmp(const void *s1, const void *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_READ_RANGE(s1, n);
    RANGE_CHECK(s1, n, false);
    ASAN_READ_RANGE(s2, n);
    RANGE_CHECK(s2, n, false);
  }
  return memcmp(s1, s2, n);
}

void *__sgxsan_memchr(const void *s, int c, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_READ_RANGE(s, n);
    RANGE_CHECK(s, n, false);
  }
  return (void *)memchr(s, c, n);
}

int __sgxsan_bcmp(const void *s1, const void *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_READ_RANGE(s1, n);
    RANGE_CHECK(s1, n, false);
    ASAN_READ_RANGE(s2, n);
    RANGE_CHECK(s2, n, false);
  }
  return bcmp(s1, s2, n);
}

// Fixed-size string operations
char *__sgxsan_strncpy(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(dst, n);
    RANGE_CHECK(dst, n, true);
    // strncpy reads until NUL or n bytes, whichever comes first
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    ASAN_READ_RANGE(src, src_read);
    RANGE_CHECK(src, src_read, false);
  }
  return strncpy(dst, src, n);
}

char *__sgxsan_stpncpy(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(dst, n);
    RANGE_CHECK(dst, n, true);
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    ASAN_READ_RANGE(src, src_read);
    RANGE_CHECK(src, src_read, false);
  }
  return stpncpy(dst, src, n);
}

int __sgxsan_strncmp(const char *s1, const char *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    size_t len1 = strnlen(s1, n);
    size_t read1 = len1 < n ? len1 + 1 : n;
    ASAN_READ_RANGE(s1, read1);
    RANGE_CHECK(s1, read1, false);
    size_t len2 = strnlen(s2, n);
    size_t read2 = len2 < n ? len2 + 1 : n;
    ASAN_READ_RANGE(s2, read2);
    RANGE_CHECK(s2, read2, false);
  }
  return strncmp(s1, s2, n);
}

size_t __sgxsan_strnlen(const char *s, size_t maxlen) {
  size_t result = strnlen(s, maxlen);
  if (maxlen != 0 && LIKELY(asan_inited)) {
    size_t read_size = result < maxlen ? result + 1 : maxlen;
    ASAN_READ_RANGE(s, read_size);
    RANGE_CHECK(s, read_size, false);
  }
  return result;
}

char *__sgxsan_strncat(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    size_t dst_len = strlen(dst);
    // strncat needs to read the existing dst string first
    ASAN_READ_RANGE(dst, dst_len + 1);
    RANGE_CHECK(dst, dst_len + 1, false);

    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    ASAN_READ_RANGE(src, src_read);
    RANGE_CHECK(src, src_read, false);

    ASAN_WRITE_RANGE(dst, dst_len + n + 1);
    RANGE_CHECK(dst, dst_len + n + 1, true);
  }
  return strncat(dst, src, n);
}

char *__sgxsan_strndup(const char *s, size_t n) {
  size_t len = strnlen(s, n);
  size_t read_size = len < n ? len + 1 : n;
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_READ_RANGE(s, read_size);
    RANGE_CHECK(s, read_size, false);
  }
  return strndup(s, n);
  // Note: Allocated memory will be unpoisoned by malloc interceptor
}

size_t __sgxsan_strlcpy(char *dst, const char *src, size_t dsize) {
  if (dsize != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(dst, dsize);
    RANGE_CHECK(dst, dsize, true);
  }
  size_t result = strlcpy(dst, src, dsize);
  if (LIKELY(asan_inited)) {
    ASAN_READ_RANGE(src, result + 1);
    RANGE_CHECK(src, result + 1, false);
  }
  return result;
}

// BSD/Legacy memory operations
void __sgxsan_bzero(void *s, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(s, n);
    RANGE_CHECK(s, n, true);
  }
  bzero(s, n);
}

void __sgxsan_bcopy(const void *src, void *dst, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_READ_RANGE(src, n);
    RANGE_CHECK(src, n, false);
    ASAN_WRITE_RANGE(dst, n);
    RANGE_CHECK(dst, n, true);
  }
  bcopy(src, dst, n);
}

void *__sgxsan_mempcpy(void *dst, const void *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    if (dst != src) {
      sgxsan_error(RangesOverlap((const char *)dst, n, (const char *)src, n),
                   "[%s] %p:%lu overlap with %p:%lu\n", "mempcpy", dst, n, src,
                   n);
    }
    ASAN_READ_RANGE(src, n);
    RANGE_CHECK(src, n, false);
    ASAN_WRITE_RANGE(dst, n);
    RANGE_CHECK(dst, n, true);
  }
  return mempcpy(dst, src, n);
}

//==============================================================================
// 4. Safe String Functions (_s variants)
//==============================================================================

errno_t __sgxsan_strcpy_s(char *dst, size_t dstSize, const char *src) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true);
  }
  size_t src_len = strlen(src);
  if (LIKELY(asan_inited)) {
    ASAN_READ_RANGE(src, src_len + 1);
    RANGE_CHECK(src, src_len + 1, false);
  }
  return strcpy_s(dst, dstSize, src);
}

errno_t __sgxsan_strncpy_s(char *dst, size_t dstSize, const char *src,
                           size_t count) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true);
  }
  if (count != 0 && LIKELY(asan_inited)) {
    size_t src_len = strnlen(src, count);
    size_t src_read = src_len < count ? src_len + 1 : count;
    ASAN_READ_RANGE(src, src_read);
    RANGE_CHECK(src, src_read, false);
  }
  return strncpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_strcat_s(char *dst, size_t dstSize, const char *src) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    // strcat_s needs to read the existing dst string first
    size_t dst_len = strlen(dst);
    ASAN_READ_RANGE(dst, dst_len + 1);
    RANGE_CHECK(dst, dst_len + 1, false);

    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true);
  }
  size_t src_len = strlen(src);
  if (LIKELY(asan_inited)) {
    ASAN_READ_RANGE(src, src_len + 1);
    RANGE_CHECK(src, src_len + 1, false);
  }
  return strcat_s(dst, dstSize, src);
}

errno_t __sgxsan_strncat_s(char *dst, size_t dstSize, const char *src,
                           size_t count) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    // strncat_s needs to read the existing dst string first
    size_t dst_len = strlen(dst);
    ASAN_READ_RANGE(dst, dst_len + 1);
    RANGE_CHECK(dst, dst_len + 1, false);

    ASAN_WRITE_RANGE(dst, dstSize);
    RANGE_CHECK(dst, dstSize, true);
  }
  if (count != 0 && LIKELY(asan_inited)) {
    size_t src_len = strnlen(src, count);
    size_t src_read = src_len < count ? src_len + 1 : count;
    ASAN_READ_RANGE(src, src_read);
    RANGE_CHECK(src, src_read, false);
  }
  return strncat_s(dst, dstSize, src, count);
}

//==============================================================================
// 5. Formatting Functions
//==============================================================================

int __sgxsan_snprintf(char *str, size_t n, const char *fmt, ...) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(str, n);
    RANGE_CHECK(str, n, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(str, n, fmt, ap);
  va_end(ap);
  return ret;
}

int __sgxsan_vsnprintf(char *str, size_t n, const char *fmt, va_list ap) {
  if (n != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(str, n);
    RANGE_CHECK(str, n, true);
  }
  return vsnprintf(str, n, fmt, ap);
}

int __sgxsan_sprintf_s(char *str, size_t sizeInBytes, const char *fmt, ...) {
  if (sizeInBytes != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(str, sizeInBytes);
    RANGE_CHECK(str, sizeInBytes, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = _vsprintf_s(str, sizeInBytes, fmt, ap);
  va_end(ap);
  return ret;
}

int __sgxsan__snprintf_s(char *str, size_t sizeInBytes, size_t count,
                        const char *fmt, ...) {
  if (sizeInBytes != 0 && LIKELY(asan_inited)) {
    ASAN_WRITE_RANGE(str, sizeInBytes);
    RANGE_CHECK(str, sizeInBytes, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = _vsnprintf_s(str, sizeInBytes, count, fmt, ap);
  va_end(ap);
  return ret;
}

//==============================================================================
// 6. NUL-Terminated String Operations
//==============================================================================
// These functions call the original function first to determine string length,
// then validate the actual memory access after the fact.
//==============================================================================

size_t __sgxsan_strlen(const char *s) {
  size_t result = strlen(s);
  if (LIKELY(asan_inited)) {
    ASAN_READ_RANGE(s, result + 1);
    RANGE_CHECK(s, result + 1, false);
  }
  return result;
}

int __sgxsan_strcmp(const char *s1, const char *s2) {
  int result = strcmp(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    ASAN_READ_RANGE(s1, len1 + 1);
    RANGE_CHECK(s1, len1 + 1, false);
    ASAN_READ_RANGE(s2, len2 + 1);
    RANGE_CHECK(s2, len2 + 1, false);
  }
  return result;
}

char *__sgxsan_strchr(const char *s, int c) {
  char *result = (char *)strchr(s, c);
  if (LIKELY(asan_inited)) {
    size_t len = result ? (size_t)(result - s + 1) : strlen(s) + 1;
    ASAN_READ_RANGE(s, len);
    RANGE_CHECK(s, len, false);
  }
  return result;
}

char *__sgxsan_strrchr(const char *s, int c) {
  char *result = (char *)strrchr(s, c);
  if (LIKELY(asan_inited)) {
    size_t len = strlen(s) + 1;
    ASAN_READ_RANGE(s, len);
    RANGE_CHECK(s, len, false);
  }
  return result;
}

char *__sgxsan_strstr(const char *s, const char *find) {
  char *result = (char *)strstr(s, find);
  if (LIKELY(asan_inited)) {
    size_t slen = strlen(s) + 1;
    size_t flen = strlen(find) + 1;
    ASAN_READ_RANGE(s, slen);
    RANGE_CHECK(s, slen, false);
    ASAN_READ_RANGE(find, flen);
    RANGE_CHECK(find, flen, false);
  }
  return result;
}

size_t __sgxsan_strspn(const char *s1, const char *s2) {
  size_t result = strspn(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    ASAN_READ_RANGE(s1, len1);
    RANGE_CHECK(s1, len1, false);
    ASAN_READ_RANGE(s2, len2);
    RANGE_CHECK(s2, len2, false);
  }
  return result;
}

size_t __sgxsan_strcspn(const char *s1, const char *s2) {
  size_t result = strcspn(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    ASAN_READ_RANGE(s1, len1);
    RANGE_CHECK(s1, len1, false);
    ASAN_READ_RANGE(s2, len2);
    RANGE_CHECK(s2, len2, false);
  }
  return result;
}

char *__sgxsan_strpbrk(const char *s1, const char *s2) {
  char *result = (char *)strpbrk(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    ASAN_READ_RANGE(s1, len1);
    RANGE_CHECK(s1, len1, false);
    ASAN_READ_RANGE(s2, len2);
    RANGE_CHECK(s2, len2, false);
  }
  return result;
}

} // extern "C"