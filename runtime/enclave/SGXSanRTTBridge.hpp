#pragma once

#include "SGXSanRTEnclave.hpp"
#include <sgx_defs.h>
#include <sgx_error.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif
sgx_status_t SGX_CDECL sgxsan_ocall_init_shadow_memory(
    uptr enclave_base, uptr enclave_size, uptr *cntrs_copy_start,
    uptr *cntrs_copy_end, uptr *pcs_copy_start, uptr *pcs_copy_end);
sgx_status_t SGX_CDECL sgxsan_ocall_print_string(const char *str);
sgx_status_t SGX_CDECL sgxsan_ocall_addr2line(uint64_t *addr_arr,
                                              size_t arr_cnt, int level = 0);
#if defined(__cplusplus)
}
#endif