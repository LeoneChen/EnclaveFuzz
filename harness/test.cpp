// Framework code uses the real glibc allocator; suppress the arena redirection
// that harness_framework.h would otherwise apply for app-side harness code.
// (harness_framework.h transitively pulls in FuzzedDataProvider.h and sgx_urts.h.)
#define HARNESS_FRAMEWORK_NO_ARENA_REDIRECT
#include "harness_framework.h"

#include "sgx_error.h"
#include <assert.h>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <cstdarg>
#include <ctime>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
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

// Harness registry storage (declared in harness_framework.h).
// BSS zero-initialization happens at program load, before any
// HARNESS_REGISTER static initializer runs, so this is safe regardless
// of cross-translation-unit init order.
struct TestHarnessEntry test_harness_registry[10240];
unsigned int test_harness_count = 0;
int total_weight = 0;

extern "C" {

void sancov_copy_init();
__attribute__((weak)) int SGXFuzzerEnvClearBeforeTest();

// Framework-owned: weighted random selection of a registered harness.
// Apps register via HARNESS_REGISTER macro; do not redefine this function.
void customized_harness(void) {
  if (test_harness_count == 0) {
    fprintf(stderr, "[!] No harnesses registered\n");
    abort();
  }
  if (total_weight == 0) {
    fprintf(stderr, "[!] All harness weights are 0\n");
    abort();
  }
  if (g_fdp->remaining_bytes() < 1) return;
  int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight - 1);
  int cumulative = 0;
  for (unsigned int i = 0; i < test_harness_count; i++) {
    cumulative += test_harness_registry[i].weight;
    if (rand_val < cumulative) {
      test_harness_registry[i].function();
      break;
    }
  }
}

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
