/// InstrumentedLibc.cpp
/// Instrumented wrappers for memory and string operations.
/// Called by code compiled with the SGXSan LLVM pass.

#include "MemAccessMgr.h"
#include "PoisonCheck.h"
#include "SGXSanRTApp.h"
#include <algorithm>
#include <stdarg.h>
#include <string.h>
#include <tuple>

typedef error_t errno_t;
extern "C" {
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
}

extern "C" {

//==============================================================================
// 1. Core memory operations
//==============================================================================

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
    EnclaveStatus src_status, dst_status;
    uptr src_first, dst_first;
    RANGE_CHECK(src, size, src_status, src_first, false);
    RANGE_CHECK(dst, size, dst_status, dst_first, true);
  }
  return memcpy(dst, src, size);
}

void *__asan_memset(void *dst, int c, uptr size) {
  if (size == 0)
    return dst;
  if (LIKELY(asan_inited)) {
    EnclaveStatus dst_status;
    uptr dst_first;
    RANGE_CHECK(dst, size, dst_status, dst_first, true);
  }
  return memset(dst, c, size);
}

void *__asan_memmove(void *dst, const void *src, uptr size) {
  if (size == 0)
    return dst;
  if (LIKELY(asan_inited)) {
    EnclaveStatus src_status, dst_status;
    uptr src_first, dst_first;
    RANGE_CHECK(src, size, src_status, src_first, false);
    RANGE_CHECK(dst, size, dst_status, dst_first, true);
  }
  return memmove(dst, src, size);
}

//==============================================================================
// 2. Safe memory operations (_s variants)
//==============================================================================

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
    EnclaveStatus src_status, dst_status;
    uptr src_first, dst_first;
    RANGE_CHECK(src, count, src_status, src_first, false);
    RANGE_CHECK(dst, dstSize, dst_status, dst_first, true);
  }
  return memcpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_memset_s(void *dst, size_t dstSize, int c, size_t n) {
  if (dstSize == 0 or n == 0)
    return 0;
  if (LIKELY(asan_inited)) {
    EnclaveStatus dst_status;
    uptr dst_first;
    RANGE_CHECK(dst, std::max(dstSize, n), dst_status, dst_first, true);
  }
  return memset_s(dst, dstSize, c, n);
}

errno_t __sgxsan_memmove_s(void *dst, size_t dstSize, const void *src,
                           size_t count) {
  if (dstSize == 0 or count == 0)
    return 0;
  if (LIKELY(asan_inited)) {
    EnclaveStatus src_status, dst_status;
    uptr src_first, dst_first;
    RANGE_CHECK(src, count, src_status, src_first, false);
    RANGE_CHECK(dst, dstSize, dst_status, dst_first, true);
  }
  return memmove_s(dst, dstSize, src, count);
}

//==============================================================================
// 3. Fixed-size memory and string operations
//==============================================================================

int __sgxsan_memcmp(const void *s1, const void *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus s1_status, s2_status;
    uptr s1_first, s2_first;
    RANGE_CHECK(s1, n, s1_status, s1_first, false);
    RANGE_CHECK(s2, n, s2_status, s2_first, false);
  }
  return memcmp(s1, s2, n);
}

void *__sgxsan_memchr(const void *s, int c, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus s_status;
    uptr s_first;
    RANGE_CHECK(s, n, s_status, s_first, false);
  }
  return (void *)memchr(s, c, n);
}

int __sgxsan_bcmp(const void *s1, const void *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus s1_status, s2_status;
    uptr s1_first, s2_first;
    RANGE_CHECK(s1, n, s1_status, s1_first, false);
    RANGE_CHECK(s2, n, s2_status, s2_first, false);
  }
  return bcmp(s1, s2, n);
}

char *__sgxsan_strncpy(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus dst_status;
    uptr dst_first;
    RANGE_CHECK(dst, n, dst_status, dst_first, true);
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, src_read, src_status, src_first, false);
  }
  return strncpy(dst, src, n);
}

char *__sgxsan_stpncpy(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus dst_status;
    uptr dst_first;
    RANGE_CHECK(dst, n, dst_status, dst_first, true);
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, src_read, src_status, src_first, false);
  }
  return stpncpy(dst, src, n);
}

int __sgxsan_strncmp(const char *s1, const char *s2, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    size_t len1 = strnlen(s1, n);
    size_t read1 = len1 < n ? len1 + 1 : n;
    EnclaveStatus s1_status;
    uptr s1_first;
    RANGE_CHECK(s1, read1, s1_status, s1_first, false);
    size_t len2 = strnlen(s2, n);
    size_t read2 = len2 < n ? len2 + 1 : n;
    EnclaveStatus s2_status;
    uptr s2_first;
    RANGE_CHECK(s2, read2, s2_status, s2_first, false);
  }
  return strncmp(s1, s2, n);
}

size_t __sgxsan_strnlen(const char *s, size_t maxlen) {
  size_t result = strnlen(s, maxlen);
  if (maxlen != 0 && LIKELY(asan_inited)) {
    size_t read_size = result < maxlen ? result + 1 : maxlen;
    EnclaveStatus s_status;
    uptr s_first;
    RANGE_CHECK(s, read_size, s_status, s_first, false);
  }
  return result;
}

char *__sgxsan_strncat(char *dst, const char *src, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    size_t dst_len = strlen(dst);
    EnclaveStatus dst_read_status;
    uptr dst_read_first;
    RANGE_CHECK(dst, dst_len + 1, dst_read_status, dst_read_first, false);
    size_t src_len = strnlen(src, n);
    size_t src_read = src_len < n ? src_len + 1 : n;
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, src_read, src_status, src_first, false);
    EnclaveStatus dst_write_status;
    uptr dst_write_first;
    RANGE_CHECK(dst, dst_len + n + 1, dst_write_status, dst_write_first, true);
  }
  return strncat(dst, src, n);
}

char *__sgxsan_strndup(const char *s, size_t n) {
  size_t len = strnlen(s, n);
  size_t read_size = len < n ? len + 1 : n;
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus s_status;
    uptr s_first;
    RANGE_CHECK(s, read_size, s_status, s_first, false);
  }
  return strndup(s, n);
}

size_t __sgxsan_strlcpy(char *dst, const char *src, size_t dsize) {
  if (dsize != 0 && LIKELY(asan_inited)) {
    EnclaveStatus dst_status;
    uptr dst_first;
    RANGE_CHECK(dst, dsize, dst_status, dst_first, true);
  }
  size_t result = strlcpy(dst, src, dsize);
  if (LIKELY(asan_inited)) {
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, result + 1, src_status, src_first, false);
  }
  return result;
}

void __sgxsan_bzero(void *s, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus s_status;
    uptr s_first;
    RANGE_CHECK(s, n, s_status, s_first, true);
  }
  bzero(s, n);
}

void __sgxsan_bcopy(const void *src, void *dst, size_t n) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus src_status, dst_status;
    uptr src_first, dst_first;
    RANGE_CHECK(src, n, src_status, src_first, false);
    RANGE_CHECK(dst, n, dst_status, dst_first, true);
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
    EnclaveStatus src_status, dst_status;
    uptr src_first, dst_first;
    RANGE_CHECK(src, n, src_status, src_first, false);
    RANGE_CHECK(dst, n, dst_status, dst_first, true);
  }
  return mempcpy(dst, src, n);
}

//==============================================================================
// 4. Safe string functions (_s variants)
//==============================================================================

errno_t __sgxsan_strcpy_s(char *dst, size_t dstSize, const char *src) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    EnclaveStatus dst_status;
    uptr dst_first;
    RANGE_CHECK(dst, dstSize, dst_status, dst_first, true);
  }
  size_t src_len = strlen(src);
  if (LIKELY(asan_inited)) {
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, src_len + 1, src_status, src_first, false);
  }
  return strcpy_s(dst, dstSize, src);
}

errno_t __sgxsan_strncpy_s(char *dst, size_t dstSize, const char *src,
                           size_t count) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    EnclaveStatus dst_status;
    uptr dst_first;
    RANGE_CHECK(dst, dstSize, dst_status, dst_first, true);
  }
  if (count != 0 && LIKELY(asan_inited)) {
    size_t src_len = strnlen(src, count);
    size_t src_read = src_len < count ? src_len + 1 : count;
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, src_read, src_status, src_first, false);
  }
  return strncpy_s(dst, dstSize, src, count);
}

errno_t __sgxsan_strcat_s(char *dst, size_t dstSize, const char *src) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    size_t dst_len = strlen(dst);
    EnclaveStatus dst_read_status;
    uptr dst_read_first;
    RANGE_CHECK(dst, dst_len + 1, dst_read_status, dst_read_first, false);
    EnclaveStatus dst_write_status;
    uptr dst_write_first;
    RANGE_CHECK(dst, dstSize, dst_write_status, dst_write_first, true);
  }
  size_t src_len = strlen(src);
  if (LIKELY(asan_inited)) {
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, src_len + 1, src_status, src_first, false);
  }
  return strcat_s(dst, dstSize, src);
}

errno_t __sgxsan_strncat_s(char *dst, size_t dstSize, const char *src,
                           size_t count) {
  if (dstSize != 0 && LIKELY(asan_inited)) {
    size_t dst_len = strlen(dst);
    EnclaveStatus dst_read_status;
    uptr dst_read_first;
    RANGE_CHECK(dst, dst_len + 1, dst_read_status, dst_read_first, false);
    EnclaveStatus dst_write_status;
    uptr dst_write_first;
    RANGE_CHECK(dst, dstSize, dst_write_status, dst_write_first, true);
  }
  if (count != 0 && LIKELY(asan_inited)) {
    size_t src_len = strnlen(src, count);
    size_t src_read = src_len < count ? src_len + 1 : count;
    EnclaveStatus src_status;
    uptr src_first;
    RANGE_CHECK(src, src_read, src_status, src_first, false);
  }
  return strncat_s(dst, dstSize, src, count);
}

//==============================================================================
// 5. Formatting functions
//==============================================================================

int __sgxsan_snprintf(char *str, size_t n, const char *fmt, ...) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus str_status;
    uptr str_first;
    RANGE_CHECK(str, n, str_status, str_first, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(str, n, fmt, ap);
  va_end(ap);
  return ret;
}

int __sgxsan_vsnprintf(char *str, size_t n, const char *fmt, va_list ap) {
  if (n != 0 && LIKELY(asan_inited)) {
    EnclaveStatus str_status;
    uptr str_first;
    RANGE_CHECK(str, n, str_status, str_first, true);
  }
  return vsnprintf(str, n, fmt, ap);
}

int __sgxsan_sprintf_s(char *str, size_t sizeInBytes, const char *fmt, ...) {
  if (sizeInBytes != 0 && LIKELY(asan_inited)) {
    EnclaveStatus str_status;
    uptr str_first;
    RANGE_CHECK(str, sizeInBytes, str_status, str_first, true);
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
    EnclaveStatus str_status;
    uptr str_first;
    RANGE_CHECK(str, sizeInBytes, str_status, str_first, true);
  }
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(str, std::min(sizeInBytes, count + 1), fmt, ap);
  va_end(ap);
  return ret;
}

//==============================================================================
// 6. NUL-terminated string operations
//==============================================================================

size_t __sgxsan_strlen(const char *s) {
  size_t result = strlen(s);
  if (LIKELY(asan_inited)) {
    EnclaveStatus s_status;
    uptr s_first;
    RANGE_CHECK(s, result + 1, s_status, s_first, false);
  }
  return result;
}

int __sgxsan_strcmp(const char *s1, const char *s2) {
  int result = strcmp(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    EnclaveStatus s1_status, s2_status;
    uptr s1_first, s2_first;
    RANGE_CHECK(s1, len1 + 1, s1_status, s1_first, false);
    RANGE_CHECK(s2, len2 + 1, s2_status, s2_first, false);
  }
  return result;
}

char *__sgxsan_strchr(const char *s, int c) {
  char *result = (char *)strchr(s, c);
  if (LIKELY(asan_inited)) {
    size_t len = result ? (size_t)(result - s + 1) : strlen(s) + 1;
    EnclaveStatus s_status;
    uptr s_first;
    RANGE_CHECK(s, len, s_status, s_first, false);
  }
  return result;
}

char *__sgxsan_strrchr(const char *s, int c) {
  char *result = (char *)strrchr(s, c);
  if (LIKELY(asan_inited)) {
    size_t len = strlen(s) + 1;
    EnclaveStatus s_status;
    uptr s_first;
    RANGE_CHECK(s, len, s_status, s_first, false);
  }
  return result;
}

char *__sgxsan_strstr(const char *s, const char *find) {
  char *result = (char *)strstr(s, find);
  if (LIKELY(asan_inited)) {
    size_t slen = strlen(s) + 1;
    size_t flen = strlen(find) + 1;
    EnclaveStatus s_status, find_status;
    uptr s_first, find_first;
    RANGE_CHECK(s, slen, s_status, s_first, false);
    RANGE_CHECK(find, flen, find_status, find_first, false);
  }
  return result;
}

size_t __sgxsan_strspn(const char *s1, const char *s2) {
  size_t result = strspn(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    EnclaveStatus s1_status, s2_status;
    uptr s1_first, s2_first;
    RANGE_CHECK(s1, len1, s1_status, s1_first, false);
    RANGE_CHECK(s2, len2, s2_status, s2_first, false);
  }
  return result;
}

size_t __sgxsan_strcspn(const char *s1, const char *s2) {
  size_t result = strcspn(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    EnclaveStatus s1_status, s2_status;
    uptr s1_first, s2_first;
    RANGE_CHECK(s1, len1, s1_status, s1_first, false);
    RANGE_CHECK(s2, len2, s2_status, s2_first, false);
  }
  return result;
}

char *__sgxsan_strpbrk(const char *s1, const char *s2) {
  char *result = (char *)strpbrk(s1, s2);
  if (LIKELY(asan_inited)) {
    size_t len1 = strlen(s1) + 1;
    size_t len2 = strlen(s2) + 1;
    EnclaveStatus s1_status, s2_status;
    uptr s1_first, s2_first;
    RANGE_CHECK(s1, len1, s1_status, s1_first, false);
    RANGE_CHECK(s2, len2, s2_status, s2_first, false);
  }
  return result;
}

} // extern "C"
