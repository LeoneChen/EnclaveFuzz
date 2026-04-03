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
#include <sys/mman.h>
#include <sys/time.h>

sgx_enclave_id_t __g_harness_eid = 0;
FuzzedDataProvider *g_fdp = nullptr;

// Bump-pointer arena for enclave-facing host buffers.
// Enclave ASAN does not check host memory OOB; an OOB write from the enclave
// can corrupt glibc malloc chunk metadata, causing free() to abort() while
// holding the arena mutex.  LibFuzzer's crash handler (PrintCoverage etc.)
// then calls malloc, deadlocking on the same mutex.
// Fix: keep all enclave ECall parameter buffers off the glibc heap entirely.
static uint8_t *g_arena = nullptr;
static size_t g_arena_used = 0;
static const size_t G_ARENA_CAP = 8 * 1024 * 1024; // 8 MB

uint8_t *g_arena_alloc(size_t size) {
  size = (size + 7u) & ~7u;
  if (g_arena_used + size > G_ARENA_CAP) {
    fprintf(stderr, "[!] g_arena overflow: need %zu, used %zu / %zu\n", size,
            g_arena_used, G_ARENA_CAP);
    abort();
  }
  uint8_t *p = g_arena + g_arena_used;
  g_arena_used += size;
  return p;
}

extern "C" {

void customized_init();
void customized_harness();
void sancov_copy_init();
__attribute__((weak)) int SGXFuzzerEnvClearBeforeTest();

// libFuzzer Callbacks
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  sancov_copy_init();
  g_arena = (uint8_t *)mmap(nullptr, G_ARENA_CAP + 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (g_arena == MAP_FAILED) {
    perror("[!] arena mmap");
    abort();
  }
  mprotect(g_arena + G_ARENA_CAP, 4096,
           PROT_NONE); // guard page: catch OOB past arena end
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

  sgx_status_t create_ret = sgx_create_enclave(
      "TestEnclave", SGX_DEBUG_FLAG /* Debug Support: set to 1 */, NULL, NULL,
      &__g_harness_eid, NULL);
  if (create_ret != SGX_SUCCESS) {
    fprintf(stderr, "[!] sgx_create_enclave fail: 0x%x\n", create_ret);
    return 0;  // EPC exhaustion or transient SGX error, skip this input
  }

  customized_harness();

  sgx_status_t destroy_ret = sgx_destroy_enclave(__g_harness_eid);
  if (destroy_ret != SGX_SUCCESS) {
    fprintf(stderr, "[!] sgx_destroy_enclave fail: 0x%x\n", destroy_ret);
    abort();
  }

  madvise(g_arena, G_ARENA_CAP, MADV_DONTNEED);
  g_arena_used = 0;

  return 0;
}
}
