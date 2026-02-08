#include "SGXSanRTConfig.h"
#include "SGXSanRTTBridge.hpp"
#include "trts_util.h"
#define UNW_LOCAL_ONLY
#include "libunwind_i.h"
#include <cstdlib>
#include <sgx_trts.h>
#include <stdint.h>
#include <vector>

// https://eli.thegreenplace.net/2015/programmatic-access-to-the-call-stack-in-c/
void libunwind_backtrace(std::vector<uint64_t> &ret_addrs,
                         size_t max_collect_count = 0) {
  unw_context_t context;
  if (unw_getcontext(&context) != 0)
    return;

  // Initialize cursor to current frame for local unwinding.
  unw_cursor_t cursor;
  if (unw_init_local(&cursor, &context) != 0)
    return;

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
    ret_addrs.push_back(pc);
    if (max_collect_count && ret_addrs.size() >= max_collect_count)
      break;
    // check before unw_step to avoid sgxsdk's abort
    if (not sgx_is_within_enclave(
            (const void *)((struct cursor *)&cursor)->dwarf.ip, 4096))
      break;
  }
}

void sgxsan_backtrace(log_level ll) {
  std::vector<uint64_t> ret_addrs, offset_ret_addrs;
  libunwind_backtrace(ret_addrs);
  for (auto ret_addr : ret_addrs) {
    offset_ret_addrs.push_back(ret_addr - g_enclave_base);
  }
  size_t ret_addr_arr_size = ret_addrs.size();
  if (ret_addr_arr_size > 0) {
    sgxsan_log(ll, false, "============= Stack Trace Begin ==============\n");
    sgxsan_ocall_addr2line(offset_ret_addrs.data(), ret_addr_arr_size, ll);
  }
}
