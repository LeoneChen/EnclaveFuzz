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

extern "C" {
sgx_status_t sgxsan_ecall_dump_sancov(sgx_enclave_id_t eid);

void customized_init();
void customized_harness();
void sancov_copy_init();
__attribute__((weak)) int SGXFuzzerEnvClearBeforeTest();

// libFuzzer Callbacks
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  sancov_copy_init();
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

  sgxsan_ecall_dump_sancov(__g_harness_eid);
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
