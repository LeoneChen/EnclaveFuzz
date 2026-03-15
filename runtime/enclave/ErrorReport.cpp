#include "ErrorReport.hpp"
#include "Malloc.hpp"
#include "Quarantine.hpp"
#include "SGXSanRTTBridge.hpp"
#include <cstdlib>
#include <stdarg.h>
#include <stdio.h>

void PrintShadowMap(log_level ll, uptr addr) {
  uptr shadowAddr = MEM_TO_SHADOW(addr);
  uptr shadowAddrRow = RoundDownTo(shadowAddr, 0x10);
  int shadowAddrCol = (int)(shadowAddr - shadowAddrRow);
  sgxsan_log(ll, false, "Shadow bytes around the buggy address:\n");
  for (int i = 0; i <= 10; i++) {
    // line buffer: "=>0xADDRESS: [xx xx ... xx] \n" — 128 bytes is plenty
    char line[128];
    int pos = snprintf(line, sizeof(line), "%s%p:", i == 5 ? "=>" : "  ",
                       (void *)(shadowAddrRow - 0x50 + 0x10 * i));
    for (int j = 0; j < 16; j++) {
      const char *prefix = " ";
      const char *appendix = "";
      if (i == 5) {
        if (j == shadowAddrCol) {
          prefix = "[";
          if (shadowAddrCol == 15) {
            appendix = "]";
          }
        } else if (j == shadowAddrCol + 1)
          prefix = "]";
      }
      pos +=
          snprintf(line + pos, sizeof(line) - pos, "%s%02x%s", prefix,
                   *(uint8_t *)(shadowAddrRow - 0x50 + 0x10 * i + j), appendix);
    }
    sgxsan_log(ll, false, "%s \n", line);
  }
  sgxsan_log(
      ll, false,
      "Shadow byte legend (one shadow byte represents 8 application bytes):\n"
      "  Addressable:           00\n"
      "  Partially addressable: 01 02 03 04 05 06 07\n"
      "  SGX sensitive layout:  10\n"
      "  SGX sensitive data:    20\n"
      "  Heap left redzone:     fa\n"
      "  Heap righ redzone:     fb\n"
      "  Freed Heap region:     fd\n"
      "  Stack left redzone:    f1\n"
      "  Stack mid redzone:     f2\n"
      "  Stack right redzone:   f3\n"
      "  Stack partial redzone: f4\n"
      "  Stack after return:    f5\n"
      "  Stack use after scope: f8\n"
      "  Global redzone:        f9\n"
      "  Global init order:     f6\n"
      "  Poisoned by user:      f7\n"
      "  ASan internal:         fe\n");
}

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal, const char *msg, ...) {
  log_level ll;
  if (fatal) {
    ll = LOG_LEVEL_ERROR;
    log_error_np("\n================ Error Report ================\n"
                 "[!] SGXSan ERROR: ");
  } else {
    ll = LOG_LEVEL_WARNING;
    log_warning_np("\n================ Warning Report ================\n"
                   "[!] SGXSan WARNING: ");
  }

  char buf[BUFSIZ];
  va_list ap;
  va_start(ap, msg);
  vsnprintf(buf, BUFSIZ, msg, ap);
  va_end(ap);
  sgxsan_log(ll, false, "%s", buf);

  sgxsan_log(ll, false,
             " at pc 0x%lx %s 0x%lx with 0x%lx bytes (bp = 0x%lx sp = "
             "0x%lx)\n\n",
             pc, (is_write ? "write" : "read"), addr, access_size, bp, sp);
  sgxsan_backtrace(ll);

  if (AddrIsInMem(addr)) {
    uint8_t shadow = *(uint8_t *)MEM_TO_SHADOW(addr);
    if (shadow == (uint8_t)kAsanHeapFreeMagic) {
      QuarantineElement qe = QuarantineCache::find(addr);
      if (qe.alloc_beg != (uptr)-1) {
        uint64_t *malloc_bt, *free_bt;
        size_t malloc_cnt, free_cnt;
        if (GetHeapChunkBT(qe.user_beg, &malloc_bt, &malloc_cnt, &free_bt,
                           &free_cnt)) {
          if (malloc_cnt > 0) {
            sgxsan_log(ll, false, "\nAllocation stack:\n");
            sgxsan_ocall_addr2line(malloc_bt, malloc_cnt, ll);
          }
          if (free_cnt > 0) {
            sgxsan_log(ll, false, "\nFree stack:\n");
            sgxsan_ocall_addr2line(free_bt, free_cnt, ll);
          }
        }
      }
    }
  }

  PrintShadowMap(ll, addr);
  sgxsan_log(ll, false, "================= Report End =================\n");
  if (fatal)
    sgxsan_abort();
  return;
}

void ReportDoubleFetch(uptr cur_fetch, size_t cur_size, uptr prev_fetch,
                       size_t prev_size, uptr *prev_bt, size_t prev_bt_cnt) {
  log_error_np("\n================ Error Report ================\n"
               "[!] SGXSan ERROR: Double fetch 0x%lx(0x%lx)\n\n",
               cur_fetch, cur_size);
  sgxsan_backtrace();
  log_error_np("\nPreviously fetch 0x%lx(0x%lx)\n\n", prev_fetch, prev_size);
  sgxsan_ocall_addr2line(prev_bt, prev_bt_cnt, LOG_LEVEL_ERROR);
  PrintShadowMap(LOG_LEVEL_ERROR, prev_fetch);
  log_error_np("================= Report End =================\n");
  sgxsan_abort();
  return;
}
