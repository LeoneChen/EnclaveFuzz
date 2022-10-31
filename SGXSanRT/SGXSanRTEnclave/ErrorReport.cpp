#include "ErrorReport.hpp"
#include "PoisonCheck.hpp"
#include "StackTrace.hpp"
#include <cstdlib>
#include <stdarg.h>
#include <stdio.h>
#include <string>

// -------------------------- Run-time entry ------------------- {{{1
// exported functions
#define ASAN_REPORT_ERROR(type, is_write, size)                                \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_report_##type##size(     \
      uptr addr) {                                                             \
    GET_CALLER_PC_BP_SP;                                                       \
    ReportGenericError(pc, bp, sp, addr, is_write, size, true);                \
  }

ASAN_REPORT_ERROR(load, false, 1)
ASAN_REPORT_ERROR(load, false, 2)
ASAN_REPORT_ERROR(load, false, 4)
ASAN_REPORT_ERROR(load, false, 8)
ASAN_REPORT_ERROR(load, false, 16)
ASAN_REPORT_ERROR(store, true, 1)
ASAN_REPORT_ERROR(store, true, 2)
ASAN_REPORT_ERROR(store, true, 4)
ASAN_REPORT_ERROR(store, true, 8)
ASAN_REPORT_ERROR(store, true, 16)

#define ASAN_REPORT_ERROR_N(type, is_write)                                    \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE void __asan_report_##type##_n(       \
      uptr addr, uptr size) {                                                  \
    GET_CALLER_PC_BP_SP;                                                       \
    ReportGenericError(pc, bp, sp, addr, is_write, size, true);                \
  }

ASAN_REPORT_ERROR_N(load, false)
ASAN_REPORT_ERROR_N(store, true)

void PrintShadowMap(log_level ll, uptr addr) {
  uptr shadowAddr = MEM_TO_SHADOW(addr);
  uptr shadowAddrRow = RoundDownTo(shadowAddr, 0x10);
  int shadowAddrCol = (int)(shadowAddr - shadowAddrRow);
  char buf[BUFSIZ];
  snprintf(buf, BUFSIZ, "Shadow bytes around the buggy address:\n");
  std::string str = buf;
  for (int i = 0; i <= 10; i++) {
    snprintf(buf, BUFSIZ, "%s%p:", i == 5 ? "=>" : "  ",
             (void *)(shadowAddrRow - 0x50 + 0x10 * i));
    str += buf;
    for (int j = 0; j < 16; j++) {
      std::string prefix = " ", appendix = "";
      if (i == 5) {
        if (j == shadowAddrCol) {
          prefix = "[";
          if (shadowAddrCol == 15) {
            appendix = "]";
          }
        } else if (j == shadowAddrCol + 1)
          prefix = "]";
      }
      snprintf(buf, BUFSIZ, "%s%02x%s", prefix.c_str(),
               *(uint8_t *)(shadowAddrRow - 0x50 + 0x10 * i + j),
               appendix.c_str());
      str += buf;
    }
    str += " \n";
  }
  str +=
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
      "  ASan internal:         fe\n";
  sgxsan_log(ll, false, str.c_str());
}

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal, const char *msg) {
  log_level ll = fatal ? LOG_LEVEL_ERROR : LOG_LEVEL_WARNING;
  sgxsan_log(ll, false,
             "================ Error Report ================\n"
             "[ERROR MESSAGE] %s\n"
             "\tpc = 0x%lx\tbp   = 0x%lx\n"
             "\tsp = 0x%lx\taddr = 0x%lx\n"
             "\tshadow = 0x%lx\toffset = 0x%lx\n"
             "\tis_write = %d\t\taccess_size = 0x%lx\n",
             msg, pc, bp, sp, addr, MEM_TO_SHADOW(addr),
             addr & (SHADOW_GRANULARITY - 1), is_write, access_size);
  sgxsan_print_stack_trace(ll);
  PrintShadowMap(ll, addr);
  sgxsan_log(ll, false, "================= Report End =================\n");
  if (fatal)
    abort();
  return;
}
