#pragma once

#include "SGXSanInt.h"
#include <sgx_defs.h>
#include <sgx_error.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif
void sgxsan_ecall_notify_update_mmap_infos(void);
sgx_status_t SGX_CDECL sgxsan_ocall_init_shadow_memory(
    uptr enclave_base, uptr enclave_size, uptr *shadow_beg_ptr,
    uptr *shadow_end_ptr, uint8_t **cov_map_beg_ptr);
sgx_status_t SGX_CDECL sgxsan_ocall_print_string(const char *str);
sgx_status_t SGX_CDECL sgxsan_ocall_addr2line(uint64_t *addr_arr,
                                              size_t arr_cnt, int level = 0);
sgx_status_t SGX_CDECL sgxsan_ocall_addr2func_name(uint64_t addr,
                                                   char *func_name,
                                                   size_t buf_size);
sgx_status_t SGX_CDECL sgxsan_ocall_depcit_distribute(uint64_t addr,
                                                      unsigned char *byte_arr,
                                                      size_t byte_arr_size,
                                                      int bucket_num,
                                                      bool is_cipher);
sgx_status_t SGX_CDECL sgxsan_ocall_get_mmap_infos(void **mmap_infos,
                                                   size_t *real_cnt);
#if defined(__cplusplus)
}
#endif