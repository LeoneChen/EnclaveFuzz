#include "EncalveTLSLifetime.hpp"
#include "Quarantine.hpp"
#include "SGXInternal.hpp"
#include "SGXSanLog.hpp"
#include "ThreadFuncArgShadowStack.hpp"
#include "WhitelistCheck.hpp"

__thread int64_t TLS_init_count;

void EnclaveTLSConstructorAtTBridgeBegin() {
  if (TLS_init_count == 0) {
    // root ecall
    WhitelistOfAddrOutEnclave_init();
    init_thread_func_arg_shadow_stack();
  }
  TLS_init_count++;
  sgxsan_assert(TLS_init_count < 1024);
}

void EnclaveTLSDestructorAtTBridgeEnd() {
  if (TLS_init_count == 1) {
    // root ecall
    WhitelistOfAddrOutEnclave_destroy();
    destroy_thread_func_arg_shadow_stack();
  }
  TLS_init_count--;
  sgxsan_assert(TLS_init_count >= 0);
}