#include "SGXSanRTConfig.h"
#include "SGXSanRTTBridge.hpp"
#include "trts_util.h"
#define UNW_LOCAL_ONLY
#include "libunwind_i.h"
#include <cstdlib>
#include <sgx_trts.h>
#include <stdint.h>

static constexpr size_t kMaxStackFrames = 128;

// https://eli.thegreenplace.net/2015/programmatic-access-to-the-call-stack-in-c/
size_t libunwind_backtrace(uint64_t *ret_addrs, size_t max_count) {
  size_t count = 0;

  unw_context_t context;
  if (unw_getcontext(&context) != 0)
    return 0;

  // Initialize cursor to current frame for local unwinding.
  unw_cursor_t cursor;
  if (unw_init_local(&cursor, &context) != 0)
    return 0;

  // check before unw_step to avoid sgxsdk's abort
  // (sdk/cpprt/linux/libunwind/src/x86_64/Ginit.c:139)
  sgxsan_error(not sgx_is_within_enclave(
                   (const void *)((struct cursor *)&cursor)->dwarf.ip, 4096),
               "Fail to get first stack frame\n");

  // Unwind frames one by one, going up the frame stack.
  unw_word_t pc;
  while (unw_step(&cursor) > 0) {
    unw_get_reg(&cursor, UNW_REG_IP, &pc);
    if (pc == 0 or not sgx_is_within_enclave((const void *)pc, 1))
      break;
    ret_addrs[count++] = pc;
    if (count >= max_count)
      break;
    // check before unw_step to avoid sgxsdk's abort
    if (not sgx_is_within_enclave(
            (const void *)((struct cursor *)&cursor)->dwarf.ip, 4096))
      break;
  }
  return count;
}

void sgxsan_backtrace(log_level ll) {
  dump_sancov();
  uint64_t ret_addrs[kMaxStackFrames];
  size_t count = libunwind_backtrace(ret_addrs, kMaxStackFrames);
  if (count > 0) {
    sgxsan_ocall_addr2line(ret_addrs, count, ll);
  }
}
