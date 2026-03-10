// tRTS proxy implementations for SGXSan built-in ocalls.
// These replace the edger8r-generated proxies in *_t.c and call sgx_ocall
// with hardcoded negative indices so the ocall table is not needed.

#include "SGXSanRTTBridge.hpp"
#include "MemAccessMgr.hpp"  // For _hook_tproxy_head, _hook_tproxy_tail, etc.
#include "UntrustSPAdjust.h" // For _set_usp and _get_usp
#include "rts.h"             // SGXSAN_OCALL_* constants
#include "sgx_edger8r.h"     // for sgx_ocall etc.
#include "sgxsan_ocall_ms.h" // ms_sgxsan_ocall_*_t structs
#include <mbusafecrt.h>
#include <sgx_trts.h> // sgx_ocalloc, sgx_ocfree
#include <string.h>   // strlen

#define ADD_ASSIGN_OVERFLOW(a, b) (((a) += (b)) < (b))

#define CHECK_ENCLAVE_POINTER(ptr, siz)                                        \
  do {                                                                         \
    if ((ptr) && !sgx_is_within_enclave((ptr), (siz))) {                       \
      _hook_tproxy_tail();                                                     \
      return SGX_ERROR_INVALID_PARAMETER;                                      \
    }                                                                          \
  } while (0)

// ── sgxsan_ocall_init_shadow_memory ──────────────────────────────────────────
sgx_status_t SGX_CDECL sgxsan_ocall_init_shadow_memory(
    uptr enclave_base, uptr enclave_size, uptr *cntrs_copy_start,
    uptr *cntrs_copy_end, uptr *pcs_copy_start, uptr *pcs_copy_end) {
  _hook_tproxy_head();
  size_t _usp = 0;
  sgx_status_t status = SGX_SUCCESS;

  const size_t _len_out = sizeof(uint64_t);

  ms_sgxsan_ocall_init_shadow_memory_t *ms = NULL;
  size_t ocalloc_size = sizeof(ms_sgxsan_ocall_init_shadow_memory_t);
  void *__tmp = NULL;

  void *__tmp_cntrs_copy_start = NULL;
  void *__tmp_cntrs_copy_end = NULL;
  void *__tmp_pcs_copy_start = NULL;
  void *__tmp_pcs_copy_end = NULL;

  CHECK_ENCLAVE_POINTER(cntrs_copy_start, _len_out);
  CHECK_ENCLAVE_POINTER(cntrs_copy_end, _len_out);
  CHECK_ENCLAVE_POINTER(pcs_copy_start, _len_out);
  CHECK_ENCLAVE_POINTER(pcs_copy_end, _len_out);

  if (ADD_ASSIGN_OVERFLOW(ocalloc_size, cntrs_copy_start ? _len_out : 0) ||
      ADD_ASSIGN_OVERFLOW(ocalloc_size, cntrs_copy_end ? _len_out : 0) ||
      ADD_ASSIGN_OVERFLOW(ocalloc_size, pcs_copy_start ? _len_out : 0) ||
      ADD_ASSIGN_OVERFLOW(ocalloc_size, pcs_copy_end ? _len_out : 0)) {
    _hook_tproxy_tail();
    return SGX_ERROR_INVALID_PARAMETER;
  }

  _usp = _get_usp();
  __tmp = sgx_ocalloc(ocalloc_size);
  if (!__tmp) {
    sgx_ocfree();
    _set_usp(_usp);
    _hook_tproxy_tail();
    return SGX_ERROR_UNEXPECTED;
  }
  ms = (ms_sgxsan_ocall_init_shadow_memory_t *)__tmp;
  __tmp = (void *)((size_t)__tmp + sizeof(*ms));

  ms->ms_enclave_base = (uint64_t)enclave_base;
  ms->ms_enclave_size = (uint64_t)enclave_size;

  if (cntrs_copy_start) {
    ms->ms_cntrs_copy_start = (uint64_t *)__tmp;
    __tmp_cntrs_copy_start = __tmp;
    memset(__tmp, 0, _len_out);
    __tmp = (void *)((size_t)__tmp + _len_out);
  } else {
    ms->ms_cntrs_copy_start = NULL;
  }
  if (cntrs_copy_end) {
    ms->ms_cntrs_copy_end = (uint64_t *)__tmp;
    __tmp_cntrs_copy_end = __tmp;
    memset(__tmp, 0, _len_out);
    __tmp = (void *)((size_t)__tmp + _len_out);
  } else {
    ms->ms_cntrs_copy_end = NULL;
  }
  if (pcs_copy_start) {
    ms->ms_pcs_copy_start = (uint64_t *)__tmp;
    __tmp_pcs_copy_start = __tmp;
    memset(__tmp, 0, _len_out);
    __tmp = (void *)((size_t)__tmp + _len_out);
  } else {
    ms->ms_pcs_copy_start = NULL;
  }
  if (pcs_copy_end) {
    ms->ms_pcs_copy_end = (uint64_t *)__tmp;
    __tmp_pcs_copy_end = __tmp;
    memset(__tmp, 0, _len_out);
  } else {
    ms->ms_pcs_copy_end = NULL;
  }

  status = sgx_ocall((unsigned int)SGXSAN_OCALL_INIT_SHADOW, ms);

  if (status == SGX_SUCCESS) {
    if ((cntrs_copy_start && memcpy_s(cntrs_copy_start, _len_out,
                                      __tmp_cntrs_copy_start, _len_out)) ||
        (cntrs_copy_end &&
         memcpy_s(cntrs_copy_end, _len_out, __tmp_cntrs_copy_end, _len_out)) ||
        (pcs_copy_start &&
         memcpy_s(pcs_copy_start, _len_out, __tmp_pcs_copy_start, _len_out)) ||
        (pcs_copy_end &&
         memcpy_s(pcs_copy_end, _len_out, __tmp_pcs_copy_end, _len_out))) {
      sgx_ocfree();
      _set_usp(_usp);
      _hook_tproxy_tail();
      return SGX_ERROR_UNEXPECTED;
    }
  }

  sgx_ocfree();
  _set_usp(_usp);
  _hook_tproxy_tail();
  return status;
}

// ── sgxsan_ocall_print_string ────────────────────────────────────────────────
sgx_status_t SGX_CDECL sgxsan_ocall_print_string(const char *str) {
  _hook_tproxy_head();
  size_t _usp = 0;
  sgx_status_t status = SGX_SUCCESS;
  size_t _len_str = str ? strlen(str) + 1 : 0;

  ms_sgxsan_ocall_print_string_t *ms = NULL;
  size_t ocalloc_size = sizeof(ms_sgxsan_ocall_print_string_t);
  void *__tmp = NULL;

  CHECK_ENCLAVE_POINTER(str, _len_str);

  if (ADD_ASSIGN_OVERFLOW(ocalloc_size, str ? _len_str : 0)) {
    _hook_tproxy_tail();
    return SGX_ERROR_INVALID_PARAMETER;
  }

  _usp = _get_usp();
  __tmp = sgx_ocalloc(ocalloc_size);
  if (!__tmp) {
    sgx_ocfree();
    _set_usp(_usp);
    _hook_tproxy_tail();
    return SGX_ERROR_UNEXPECTED;
  }
  ms = (ms_sgxsan_ocall_print_string_t *)__tmp;
  __tmp = (void *)((size_t)__tmp + sizeof(*ms));

  if (str) {
    ms->ms_str = (const char *)__tmp;
    if (memcpy_s(__tmp, _len_str, str, _len_str)) {
      sgx_ocfree();
      _set_usp(_usp);
      _hook_tproxy_tail();
      return SGX_ERROR_UNEXPECTED;
    }
  } else {
    ms->ms_str = NULL;
  }

  status = sgx_ocall((unsigned int)SGXSAN_OCALL_PRINT_STRING, ms);

  sgx_ocfree();
  _set_usp(_usp);
  _hook_tproxy_tail();
  return status;
}

// ── sgxsan_ocall_addr2line ───────────────────────────────────────────────────
sgx_status_t SGX_CDECL sgxsan_ocall_addr2line(uint64_t *addr_arr,
                                              size_t arr_cnt, int level) {
  _hook_tproxy_head();
  size_t _usp = 0;
  sgx_status_t status = SGX_SUCCESS;
  size_t _len_addr_arr = arr_cnt * sizeof(uint64_t);

  ms_sgxsan_ocall_addr2line_t *ms = NULL;
  size_t ocalloc_size = sizeof(ms_sgxsan_ocall_addr2line_t);
  void *__tmp = NULL;

  CHECK_ENCLAVE_POINTER(addr_arr, _len_addr_arr);

  if (ADD_ASSIGN_OVERFLOW(ocalloc_size, addr_arr ? _len_addr_arr : 0)) {
    _hook_tproxy_tail();
    return SGX_ERROR_INVALID_PARAMETER;
  }

  _usp = _get_usp();
  __tmp = sgx_ocalloc(ocalloc_size);
  if (!__tmp) {
    sgx_ocfree();
    _set_usp(_usp);
    _hook_tproxy_tail();
    return SGX_ERROR_UNEXPECTED;
  }
  ms = (ms_sgxsan_ocall_addr2line_t *)__tmp;
  __tmp = (void *)((size_t)__tmp + sizeof(*ms));

  if (addr_arr) {
    ms->ms_addr_arr = (uint64_t *)__tmp;
    if (memcpy_s(__tmp, _len_addr_arr, addr_arr, _len_addr_arr)) {
      sgx_ocfree();
      _set_usp(_usp);
      _hook_tproxy_tail();
      return SGX_ERROR_UNEXPECTED;
    }
  } else {
    ms->ms_addr_arr = NULL;
  }
  ms->ms_arr_cnt = arr_cnt;
  ms->ms_level = level;

  status = sgx_ocall((unsigned int)SGXSAN_OCALL_ADDR2LINE, ms);

  sgx_ocfree();
  _set_usp(_usp);
  _hook_tproxy_tail();
  return status;
}
