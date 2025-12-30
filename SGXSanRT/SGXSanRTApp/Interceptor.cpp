#include "MemAccessMgr.h"
#include "PoisonCheck.h"
#include "SGXSanRTApp.h"
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

extern "C" {
int sgxsan_vsnprintf(char *str, size_t size, const char *format, va_list ap) {
  InOutEnclaveStatus RegionInOutEnclaveStatus;
  uptr RegionPoisonedAddr;
  RANGE_CHECK(str, size, RegionInOutEnclaveStatus, RegionPoisonedAddr, true);
  int res = vsnprintf(str, size, format, ap);
  va_end(ap);
  return res;
}
}
