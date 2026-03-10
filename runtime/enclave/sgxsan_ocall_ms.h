#ifndef _SGXSAN_OCALL_MS_H_
#define _SGXSAN_OCALL_MS_H_

#include <stddef.h>
#include <stdint.h>

typedef struct ms_sgxsan_ocall_init_shadow_memory_t {
  uint64_t ms_enclave_base;
  uint64_t ms_enclave_size;
  uint64_t *ms_cntrs_copy_start;
  uint64_t *ms_cntrs_copy_end;
  uint64_t *ms_pcs_copy_start;
  uint64_t *ms_pcs_copy_end;
} ms_sgxsan_ocall_init_shadow_memory_t;

typedef struct ms_sgxsan_ocall_print_string_t {
  const char *ms_str;
} ms_sgxsan_ocall_print_string_t;

typedef struct ms_sgxsan_ocall_addr2line_t {
  uint64_t *ms_addr_arr;
  size_t ms_arr_cnt;
  int ms_level;
} ms_sgxsan_ocall_addr2line_t;

#endif /* _SGXSAN_OCALL_MS_H_ */
