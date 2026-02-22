#include "MemAccessMgr.hpp"
#include "SGXSanRTConfig.h"

__thread int64_t TLS_init_count;

extern "C" {
void _hook_tbridge_head(void) {
  if (TLS_init_count == 0) {
    // root ecall
    MemAccessMgrInit();
  }
  TLS_init_count++;
  sgxsan_assert(TLS_init_count < 1024);
}

void _hook_tbridge_tail(void) {
  if (TLS_init_count == 1) {
    // root ecall
    MemAccessMgrDestroy();
  }
  TLS_init_count--;
  sgxsan_assert(TLS_init_count >= 0);
}
}