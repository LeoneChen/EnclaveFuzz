#include "FuzzedDataProvider.h"
#include "sgx_error.h"
#include "sgx_urts.h"
#include <assert.h>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

sgx_enclave_id_t __g_harness_eid = 0;
FuzzedDataProvider *g_fdp = nullptr;
std::vector<uint8_t *> g_alloc_mgr;

uint8_t *g_sancov_cntrs_copy_start = nullptr,
        *g_sancov_cntrs_copy_end = nullptr;
uintptr_t *g_sancov_pcs_copy_start = nullptr, *g_sancov_pcs_copy_end = nullptr;

std::string exec_shell(const char *cmd) {
  std::array<char, 128> buffer;
  std::string result;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

extern "C" {

sgx_status_t sgxsan_ecall_dump_sancov(sgx_enclave_id_t eid,
                                      uint64_t cntrs_start, uint64_t cntrs_end,
                                      uint64_t pcs_start, uint64_t pcs_end);
void sgxsan_backtrace(int ll);
void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop);
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end);
void customized_init();
void customized_harness();
__attribute__((weak)) int SGXFuzzerEnvClearBeforeTest();
void __sanitizer_print_stack_trace() { sgxsan_backtrace(2); }

// libFuzzer Callbacks
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  auto result =
      exec_shell("size -A TestEnclave|grep __sancov_cntrs|awk '{print $2}'");
  auto cntrs_size = std::stoull(result);
  result = exec_shell("size -A TestEnclave|grep __sancov_pcs|awk '{print $2}'");
  auto pcs_size = std::stoull(result);
  if (!cntrs_size || !pcs_size || cntrs_size != (pcs_size / 16)) {
    fprintf(stderr, "cntrs/pcs size invalid\n");
    abort();
  }
  g_sancov_cntrs_copy_start = (uint8_t *)calloc(1, cntrs_size);
  g_sancov_pcs_copy_start = (uintptr_t *)calloc(16, cntrs_size);
  if (!g_sancov_cntrs_copy_start || !g_sancov_pcs_copy_start) {
    fprintf(stderr,
            "g_sancov_cntrs_copy_start/g_sancov_pcs_copy_start calloc fail\n");
    abort();
  }
  g_sancov_cntrs_copy_end = g_sancov_cntrs_copy_start + cntrs_size;
  __sanitizer_cov_8bit_counters_init(g_sancov_cntrs_copy_start,
                                     g_sancov_cntrs_copy_end);
  g_sancov_pcs_copy_end = g_sancov_pcs_copy_start + cntrs_size * 2;
  __sanitizer_cov_pcs_init(g_sancov_pcs_copy_start, g_sancov_pcs_copy_end);

  customized_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (SGXFuzzerEnvClearBeforeTest && SGXFuzzerEnvClearBeforeTest() != 0) {
    fprintf(stderr, "[!] SGXFuzzerEnvClearBeforeTest fail");
    abort();
  }

  delete g_fdp;
  g_fdp = new FuzzedDataProvider(Data, Size);

  if (sgx_create_enclave("TestEnclave",
                         SGX_DEBUG_FLAG /* Debug Support: set to 1 */, NULL,
                         NULL, &__g_harness_eid, NULL) != SGX_SUCCESS) {
    fprintf(stderr, "[!] sgx_create_enclave fail");
    abort();
  }

  customized_harness();

  sgxsan_ecall_dump_sancov(__g_harness_eid, (uint64_t)g_sancov_cntrs_copy_start,
                           (uint64_t)g_sancov_cntrs_copy_end,
                           (uint64_t)g_sancov_pcs_copy_start,
                           (uint64_t)g_sancov_pcs_copy_end);
  if (sgx_destroy_enclave(__g_harness_eid) != SGX_SUCCESS) {
    fprintf(stderr, "[!] sgx_destroy_enclave fail");
    abort();
  }

  for (auto memArea : g_alloc_mgr) {
    free(memArea);
  }
  g_alloc_mgr.clear();

  return 0;
}
}
