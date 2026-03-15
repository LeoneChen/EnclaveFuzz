#include "SGXSanRTApp.h"
#include "Malloc.h"
#include "MemAccessMgr.h"
#include "Sticker.h"
#include <atomic>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/stacktrace.hpp>
#include <dlfcn.h>
#include <execinfo.h>
#include <iostream>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *log_level_to_prefix[] = {
    "[!] SGXSan ALWAYS: ", "[!] SGXSan ERROR: ", "[!] SGXSan WARNING: ",
    "[!] SGXSan DEBUG: ",  "[!] SGXSan TRACE: ",
};

bool asan_inited = false;

static struct sigaction g_old_sigact[_NSIG];

// Cache for symbolization results
struct SymbolInfo {
  std::string func;
  std::string file;
  std::string line;
  std::string module_path;
  uptr module_base;
  bool has_module_info;
  int is_pie_result;
};

static thread_local std::unordered_map<uptr, SymbolInfo> symbolize_cache;

/// Sancov proxy scheme
/// libfuzzer registers proxy buffers once; enclave counters are copied into
/// them before each dlclose so libfuzzer always reads stable addresses.
#define ENCLAVE_FAKE_BASE 0x400000000UL
#define ENCLAVE_FAKE_SIZE (256UL * 1024 * 1024)

static uint8_t *g_sancov_proxy_cntrs_start = nullptr;
static uint8_t *g_sancov_proxy_cntrs_end = nullptr;
static uintptr_t *g_sancov_proxy_pcs_start = nullptr;
static uintptr_t *g_sancov_proxy_pcs_end = nullptr;

// Set by sancov hook when enclave DSO registers its counters/PCs
static uint8_t *g_sancov_enclave_cntrs_start = nullptr;
static uint8_t *g_sancov_enclave_cntrs_end = nullptr;
static const uintptr_t *g_sancov_enclave_pcs_start = nullptr;
static const uintptr_t *g_sancov_enclave_pcs_end = nullptr;

static std::string sgxsan_exec(const char *cmd) {
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

static void PrintAddressSpaceLayout(log_level ll = LOG_LEVEL_DEBUG) {
  sgxsan_log(ll, true, "|| `[%16p, %16p]` || LowMem          ||\n",
             (void *)kLowMemBeg, (void *)kLowMemEnd);
  sgxsan_log(ll, true, "|| `[%16p, %16p]` || LowShadowGuard  ||\n",
             (void *)kLowShadowGuardBeg, (void *)(kLowShadowBeg - 1));
  sgxsan_log(ll, true, "|| `[%16p, %16p]` || LowShadow       ||\n",
             (void *)kLowShadowBeg, (void *)kLowShadowEnd);
  sgxsan_log(ll, true, "|| `[%16p, %16p]` || ShadowGap       ||\n",
             (void *)kShadowGapBeg, (void *)kShadowGapEnd);
  sgxsan_log(ll, true, "|| `[%16p, %16p]` || HighShadow      ||\n",
             (void *)kHighShadowBeg, (void *)kHighShadowEnd);
  sgxsan_log(ll, true, "|| `[%16p, %16p]` || HighShadowGuard ||\n",
             (void *)(kHighShadowEnd + 1), (void *)kHighShadowGuardEnd);
  sgxsan_log(ll, true, "|| `[%16p, %16p]` || HighMem         ||\n",
             (void *)kHighMemBeg, (void *)kHighMemEnd);
}

typedef void (*DieCallbackType)(void);
static DieCallbackType UserDieCallback;
void SetUserDieCallback(DieCallbackType callback) {
  UserDieCallback = callback;
}

void NORETURN Die() {
  DumpSancov(); // 确保 proxy buffer 最新，再让 libfuzzer 读
  if (UserDieCallback)
    UserDieCallback();
  _Exit(77);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_print_stack_trace() {
  sgxsan_backtrace();
}

// https://github.com/google/sanitizers/issues/788
// __sanitizer_acquire_crash_state is important
extern "C" SANITIZER_INTERFACE_ATTRIBUTE int __sanitizer_acquire_crash_state() {
  static volatile int in_crash_state = 0;
  return !__atomic_exchange_n(&in_crash_state, 1, __ATOMIC_RELAXED);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__sanitizer_set_death_callback(void (*callback)(void)) {
  SetUserDieCallback(callback);
}

static void sgxsan_timeout_sigaction(int signum, siginfo_t *siginfo,
                                     void *priv) {
  _Exit(70);
}

/// \brief Signal handler to report illegal memory access
static void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv) {
  if (!__sanitizer_acquire_crash_state()) {
    return;
  }
  ucontext_t *ucontext = (ucontext_t *)priv;
  if (signum == SIGSEGV) {
    sgxsan_assert(siginfo->si_signo == SIGSEGV);
    const greg_t rip = ucontext->uc_mcontext.gregs[REG_RIP];
    if (siginfo->si_code == SI_KERNEL) {
      // If si_code is SI_KERNEL, #PF address is not true
      log_error("#PF Addr Unknown at pc %p\n", (void *)rip);
    } else {
      size_t page_size = getpagesize();
      // process siginfo
      void *_page_fault_addr = siginfo->si_addr;
      log_error("#PF Addr %p at pc %p => ", _page_fault_addr, (void *)rip);

      uint64_t page_fault_addr = (uint64_t)_page_fault_addr;
      if (0 <= page_fault_addr and page_fault_addr < page_size) {
        log_error_np("Null-Pointer Dereference\n");
      } else if ((kLowShadowGuardBeg <= page_fault_addr &&
                  page_fault_addr < kLowShadowBeg) ||
                 (kHighShadowEnd < page_fault_addr &&
                  page_fault_addr <= kHighShadowGuardEnd)) {
        log_error_np("ShadowMap's Guard Dereference\n");
      } else if ((kHighShadowEnd + 1 - page_size) <= page_fault_addr &&
                 page_fault_addr <= kHighShadowEnd) {
        log_error_np("Cross ShadowMap's Guard Dereference\n");
      } else if (kShadowGapBeg <= page_fault_addr &&
                 page_fault_addr < kShadowGapEnd) {
        log_error_np("ShadowMap's GAP Dereference\n");
      } else {
        log_error_np("Unknown page fault\n");
      }
    }

    sgxsan_backtrace();
    Die();
  }
  _Exit(-1);
}

void register_sgxsan_sigaction() {
  static bool AlreadyRegisterSignalHandler = false;
  if (AlreadyRegisterSignalHandler)
    return;
  struct sigaction sig_act;
  memset(&sig_act, 0, sizeof(sig_act));
  sig_act.sa_sigaction = sgxsan_sigaction;
  sig_act.sa_flags = SA_SIGINFO;
  sigemptyset(&sig_act.sa_mask);
  sgxsan_assert(0 == sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]));

  // Override libFuzzer's SIGALRM Handler
  struct sigaction sig_timeoue_act;
  memset(&sig_timeoue_act, 0, sizeof(sig_timeoue_act));
  sig_timeoue_act.sa_sigaction = sgxsan_timeout_sigaction;
  sig_timeoue_act.sa_flags = SA_SIGINFO;
  sigemptyset(&sig_timeoue_act.sa_mask);
  // sgxsan_assert(0 ==
  //               sigaction(SIGALRM, &sig_timeoue_act,
  //               &g_old_sigact[SIGALRM]));

  AlreadyRegisterSignalHandler = true;
}

/// \brief Initialize shadow memory
static void sgxsan_init_shadow_memory() {
  size_t page_size = getpagesize();
  sgxsan_assert(page_size == PAGE_SIZE);

  // mmap the shadow plus it's guard pages
  sgxsan_error(mmap((void *)kLowShadowGuardBeg,
                    kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                    0) == MAP_FAILED,
               "Shadow Memory is not available\n");
  madvise((void *)kLowShadowGuardBeg,
          kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
          MADV_NOHUGEPAGE); // Return -1 if CONFIG_TRANSPARENT_HUGEPAGE was not
                            // configured in kernel
  sgxsan_error(mprotect((void *)kLowShadowGuardBeg, page_size, PROT_NONE) ||
                   mprotect((void *)(kHighShadowEnd + 1), page_size, PROT_NONE),
               "Failed to make guard page for shadow map\n");
  sgxsan_error(mprotect((void *)kShadowGapBeg,
                        kShadowGapEnd - kShadowGapBeg + 1, PROT_NONE),
               "Failed to make gap in shadow not accessible\n");

  // make sure 0 address is not accessible
  auto mmap_min_addr = std::stoull(
      sgxsan_exec("sysctl vm.mmap_min_addr| tr -s ' '|cut -d \" \" -f3"),
      nullptr, 0);
  if (mmap_min_addr == 0) {
    sgxsan_error(mmap((void *)0, page_size, PROT_NONE,
                      MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1,
                      0) == MAP_FAILED,
                 "mmap zero address failed");
    sgxsan_error(mprotect((void *)0, page_size, PROT_NONE),
                 "Failed to make 0 address not accessible\n");
  }
}

__attribute__((constructor)) void SGXSanInit() {
  if (asan_inited) {
    return;
  }
  updateBackEndHeapAllocator();
  // make sure c++ stream is initialized
  std::ios_base::Init _init;
  sgxsan_init_shadow_memory();
  PrintAddressSpaceLayout();
  asan_inited = true;
}

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...) {
  if (ll > USED_LOG_LEVEL)
    return;

  if (with_prefix) {
#if (SHOW_TID)
    fprintf(stderr, "[TID=0x%x] ", gettid());
#endif
    fprintf(stderr, "%s", log_level_to_prefix[ll]);
  }

  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

void SGXSanLogEnter(const char *str) { log_always("Enter %s\n", str); }

static void PrintShadowMap(log_level ll, uptr addr) {
  uptr addr_mask = (~(((uptr)1 << ADDR_SPACE_BITS) - 1));
  sgxsan_assert((addr & addr_mask) == 0);
  uptr shadowAddr = MEM_TO_SHADOW(addr);
  uptr shadowAddrRow = RoundDownTo(shadowAddr, 0x10);
  int shadowAddrCol = (int)(shadowAddr - shadowAddrRow);

  sgxsan_assert(shadowAddrRow >= kLowShadowBeg &&
                shadowAddrRow <= (kHighShadowEnd - 0xF));
  uptr startRow = (shadowAddrRow - kLowShadowBeg) > 0x50 ? shadowAddrRow - 0x50
                                                         : kLowShadowBeg;
  uptr endRow = (kHighShadowEnd + 1 - shadowAddrRow) > 0x50
                    ? shadowAddrRow + 0x50
                    : (kHighShadowEnd + 1);
  char buf[BUFSIZ];
  snprintf(buf, BUFSIZ, "Shadow bytes around the buggy address:\n");
  std::string str(buf);
  for (uptr i = startRow; i < endRow; i += 0x10) {
    snprintf(buf, BUFSIZ, "%s%p:", i == shadowAddrRow ? "=>" : "  ", (void *)i);
    str += buf;
    for (int j = 0; j < 16; j++) {
      std::string prefix = " ", appendix = "";
      if (i == shadowAddrRow) {
        if (j == shadowAddrCol) {
          prefix = "[";
          if (shadowAddrCol == 15) {
            appendix = "]";
          }
        } else if (j == shadowAddrCol + 1)
          prefix = "]";
      }
      snprintf(buf, BUFSIZ, "%s%02x%s", prefix.c_str(), *(uint8_t *)(i + j),
               appendix.c_str());
      str += buf;
    }
    str += " \n";
  }
  str +=
      "Shadow byte legend (one shadow byte represents 8 application bytes):\n"
      "  Addressable:           00\n"
      "  Partially addressable: 01 02 03 04 05 06 07\n"
      "  SGX sensitive layout:  1X\n"
      "  SGX sensitive data:    2X\n"
      "  Data in Enclave:       4X\n"
      "  Stack left redzone:    81\n"
      "  Stack mid redzone:     82\n"
      "  Stack right redzone:   83\n"
      "  Stack after return:    85\n"
      "  Left alloca redzone:   86\n"
      "  Right alloca redzone:  87\n"
      "  Stack use after scope: 88\n"
      "  Global redzone:        89\n"
      "  Heap left redzone:     8a\n"
      "  Heap righ redzone:     8b\n"
      "  Freed Heap region:     8d\n"
      "  ASan internal:         8e\n";
  sgxsan_log(ll, false, str.c_str());
}

void ReportError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                 uptr access_size, const char *msg, ...) {
  log_level ll = LOG_LEVEL_ERROR;
  log_error_np("\n================ Error Report ================\n"
               "[!] SGXSan ERROR: ");

  char buf[BUFSIZ];
  va_list ap;
  va_start(ap, msg);
  vsnprintf(buf, BUFSIZ, msg, ap);
  va_end(ap);
  sgxsan_log(ll, false, "%s", buf);

  sgxsan_log(ll, false,
             " at pc %p %s 0x%lx with 0x%lx bytes (bp = 0x%lx sp = "
             "0x%lx)\n\n",
             (void *)pc, (is_write ? "write" : "read"), addr, access_size, bp,
             sp);
  sgxsan_backtrace(ll);
  sgxsan_log(ll, false, "================= Report End =================\n");

  Die();
}

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal, const char *msg, ...) {
  if (AddrIsInMem(addr) and
      L1F(*(uint8_t *)MEM_TO_SHADOW(addr)) == kAsanHeapFreeMagic) {
    ReportUseAfterFree(pc, bp, sp, addr);
    return;
  }
  log_level ll;
  if (fatal) {
    ll = LOG_LEVEL_ERROR;
    log_error_np("\n================ Error Report ================\n"
                 "[!] SGXSan ERROR: ");
  } else {
    ll = LOG_LEVEL_WARNING;
    log_warning_np("\n================ Warning Report ================\n"
                   "[!] SGXSan WARNING: ");
  }

  char buf[BUFSIZ];
  va_list ap;
  va_start(ap, msg);
  vsnprintf(buf, BUFSIZ, msg, ap);
  va_end(ap);
  sgxsan_log(ll, false, "%s", buf);

  sgxsan_log(ll, false,
             " at pc %p %s 0x%lx with 0x%lx bytes (bp = 0x%lx sp = "
             "0x%lx)\n\n",
             (void *)pc, (is_write ? "write" : "read"), addr, access_size, bp,
             sp);
  sgxsan_backtrace(ll);
  if (AddrIsInMem(addr))
    PrintShadowMap(ll, addr);
  sgxsan_log(ll, false, "================= Report End =================\n");
  Die();
  return;
}

void ReportUseAfterFree(uptr pc, uptr bp, uptr sp, uptr addr) {
  auto qe = gQCache->find(addr);
  sgxsan_assert(qe.alloc_beg != -1);
  MallocFreeBTTy bt = gHeapBT->GetHeapBacktrace(qe.user_beg);
  log_level ll = LOG_LEVEL_ERROR;
  log_error_np(
      "\n================ Error Report ================\n"
      "[!] SGXSan ERROR: %s Use after free 0x%lx at pc %p bp 0x%lx "
      "sp 0x%lx\n\n",
      (sgx_is_within_enclave((const void *)addr, 1) ? "Enclave" : "Host"), addr,
      (void *)pc, bp, sp);
  sgxsan_backtrace(ll);
  log_error_np("\nPreviously malloc at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.malloc_bt /* int array -> pointer array */,
                     bt.malloc_bt_cnt);
  log_error_np("\nPreviously free at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.free_bt, bt.free_bt_cnt);
  PrintShadowMap(ll, addr);
  log_error_np("================= Report End =================\n");
  Die();
  return;
}

void ReportDoubleFree(uptr pc, uptr bp, uptr sp, uptr addr) {
  MallocFreeBTTy bt = gHeapBT->GetHeapBacktrace(addr);
  log_level ll = LOG_LEVEL_ERROR;
  log_error_np(
      "\n================ Error Report ================\n"
      "[!] SGXSan ERROR: %s Double Free 0x%lx at pc %p bp 0x%lx "
      "sp 0x%lx\n\n",
      (sgx_is_within_enclave((const void *)addr, 1) ? "Enclave" : "Host"), addr,
      (void *)pc, bp, sp);
  sgxsan_backtrace(ll);
  log_error_np("\nPreviously malloc at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.malloc_bt /* int array -> pointer array */,
                     bt.malloc_bt_cnt);
  log_error_np("\nPreviously free at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.free_bt, bt.free_bt_cnt);
  PrintShadowMap(ll, addr);
  log_error_np("================= Report End =================\n");
  Die();
  return;
}

void ReportDoubleFetch(uptr cur_fetch, size_t cur_size, uptr prev_fetch,
                       size_t prev_size, uptr *prev_bt, size_t prev_bt_cnt) {
  log_error_np("\n================ Error Report ================\n"
               "[!] SGXSan ERROR: Double fetch 0x%lx(0x%lx)\n\n",
               cur_fetch, cur_size);
  sgxsan_backtrace();
  log_error_np("\nPreviously fetch 0x%lx(0x%lx)\n\n", prev_fetch, prev_size);
  sgxsan_dump_bt_buf((void **)prev_bt, prev_bt_cnt);
  PrintShadowMap(LOG_LEVEL_ERROR, prev_fetch);
  log_error_np("================= Report End =================\n");
  Die();
  return;
}

int is_pie(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return -1;
  }

  Elf64_Ehdr ehdr;
  if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
    fclose(f);
    return -1;
  }

  fclose(f);
  return ehdr.e_type == ET_DYN;
}

static bool resolve_module_info(uptr pc, SymbolInfo &sym_info) {
  if (g_sancov_proxy_pcs_start && ENCLAVE_FAKE_BASE <= pc &&
      pc < ENCLAVE_FAKE_BASE + ENCLAVE_FAKE_SIZE) {
    sym_info.has_module_info = true;
    sym_info.module_path = "TestEnclave";
    sym_info.module_base = ENCLAVE_FAKE_BASE;
    sym_info.is_pie_result = 1;
  } else {
    Dl_info info;
    sym_info.has_module_info = (dladdr((void *)pc, &info) != 0);
    if (sym_info.has_module_info) {
      sym_info.module_path = info.dli_fname;
      sym_info.module_base = (uptr)info.dli_fbase;
      sym_info.is_pie_result = is_pie(info.dli_fname);
    }
  }
  return sym_info.has_module_info;
}

static std::string run_addr2line(const char *module_path, uptr addr,
                                 int pie_status, uptr base_addr,
                                 const char *extra_flags = "") {
  std::stringstream cmd;
  cmd << "llvm-addr2line-13 -afC";
  if (extra_flags && extra_flags[0])
    cmd << " " << extra_flags;
  if (pie_status > 0)
    cmd << " --adjust-vma=0x" << std::hex << base_addr;
  cmd << " -e " << module_path << " " << std::hex << addr;
  return sgxsan_exec(cmd.str().c_str());
}

void sgxsan_dump_bt_buf(void **array, size_t size) {
  log_always_np("[*] SGXSan Backtrace:\n");
  for (size_t i = 0; i < size; i++) {
    uptr pc = (uptr)array[i] - 4;
    SymbolInfo sym_info;
    if (resolve_module_info(pc, sym_info)) {
      auto result =
          run_addr2line(sym_info.module_path.c_str(), pc,
                        sym_info.is_pie_result, sym_info.module_base, "-pi");
      log_always_np("%s", result.c_str());
    } else {
      log_always_np("%p\n", array[i]);
    }
  }
}

void sgxsan_backtrace(log_level ll) {
  if (ll > USED_LOG_LEVEL)
    return;

  size_t max_bt_count = 100;
  uint64_t bt_buf[max_bt_count];
  size_t bt_cnt =
      boost::stacktrace::safe_dump_to(bt_buf, sizeof(decltype(bt_buf)));
  sgxsan_dump_bt_buf((void **)bt_buf, bt_cnt);
}

static __thread int TD_init_count = 0;

extern "C" void _hook_tbridge_head() {
  if (TD_init_count == 0) {
    // root ecall
    MemAccessMgr::init();
  }
  TD_init_count++;
  sgxsan_assert(TD_init_count < 1024);
}

extern "C" void _hook_tbridge_tail() {
  if (TD_init_count == 1) {
    // root ecall
    MemAccessMgr::destroy();
  }
  TD_init_count--;
  sgxsan_assert(TD_init_count >= 0);
}

void ClearSGXSanRT() { sgxsan_assert(TD_init_count == 0); }

// Called from TSticker's protected-visibility sancov interceptors
extern "C" void SGXSanSaveEnclaveCntrsRange(uint8_t *Start, uint8_t *Stop) {
  g_sancov_enclave_cntrs_start = Start;
  g_sancov_enclave_cntrs_end = Stop;
}

extern "C" void SGXSanSaveEnclavePCsRange(const uintptr_t *Start,
                                          const uintptr_t *Stop) {
  g_sancov_enclave_pcs_start = Start;
  g_sancov_enclave_pcs_end = Stop;
}

extern "C" {
extern void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop);
extern void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                     const uintptr_t *pcs_end);
}

void SancovInit() {
  // Read section sizes from ELF without loading the DSO
  std::string result = sgxsan_exec(
      "size -A TestEnclave | grep __sancov_cntrs | awk '{print $2}'");
  size_t cntrs_size = std::stoull(result);

  result =
      sgxsan_exec("size -A TestEnclave | grep __sancov_pcs | awk '{print $2}'");
  size_t pcs_size = std::stoull(result);
  sgxsan_error(!cntrs_size || !pcs_size || cntrs_size != (pcs_size / 16),
               "cntrs/pcs size invalid\n");

  // Verify enclave fits within fake address range
  result = sgxsan_exec("size TestEnclave | awk 'NR==2{print $4}'");
  size_t enclave_vsize = std::stoull(result);
  sgxsan_error(enclave_vsize >= ENCLAVE_FAKE_SIZE,
               "Enclave virtual size %zu >= ENCLAVE_FAKE_SIZE %zu, "
               "increase ENCLAVE_FAKE_SIZE\n",
               enclave_vsize, (size_t)ENCLAVE_FAKE_SIZE);

  // Allocate proxy buffers (registered with libfuzzer once, never freed)
  g_sancov_proxy_cntrs_start = (uint8_t *)calloc(1, cntrs_size);
  g_sancov_proxy_pcs_start = (uintptr_t *)calloc(1, pcs_size);
  sgxsan_error(!g_sancov_proxy_cntrs_start || !g_sancov_proxy_pcs_start,
               "SancovInit: proxy buffer allocation failed\n");
  g_sancov_proxy_cntrs_end = g_sancov_proxy_cntrs_start + cntrs_size;
  g_sancov_proxy_pcs_end =
      (uintptr_t *)((uint8_t *)g_sancov_proxy_pcs_start + pcs_size);

  // Reserve fake address range to avoid collisions with real mappings
  void *ret = mmap((void *)ENCLAVE_FAKE_BASE, ENCLAVE_FAKE_SIZE, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  sgxsan_error(ret == MAP_FAILED,
               "SancovInit fatal: failed to reserve fake enclave base 0x%lx, "
               "symbolization may be inaccurate\n",
               ENCLAVE_FAKE_BASE);

  // Register proxy with libfuzzer (RunInEnclave=false, hooks forward to real)
  __sanitizer_cov_8bit_counters_init(g_sancov_proxy_cntrs_start,
                                     g_sancov_proxy_cntrs_end);
  __sanitizer_cov_pcs_init(g_sancov_proxy_pcs_start, g_sancov_proxy_pcs_end);
}

void DumpSancov() {
  if (!g_sancov_proxy_cntrs_start || !g_sancov_enclave_cntrs_start)
    return;

  // Copy counters
  size_t cntrs_size = g_sancov_proxy_cntrs_end - g_sancov_proxy_cntrs_start;
  memcpy(g_sancov_proxy_cntrs_start, g_sancov_enclave_cntrs_start, cntrs_size);

  // Copy PC table with normalization: absolute_pc -> (pc - base + FAKE_BASE)
  uptr enclave_start = 0, enclave_end = 0;
  gEnclaveInfo.GetEnclaveDSORange(&enclave_start, &enclave_end);

  size_t n = g_sancov_proxy_pcs_end - g_sancov_proxy_pcs_start;
  for (size_t i = 0; i + 1 < n; i += 2) {
    uptr pc = g_sancov_enclave_pcs_start[i];
    g_sancov_proxy_pcs_start[i] = (pc - enclave_start) + ENCLAVE_FAKE_BASE;
    g_sancov_proxy_pcs_start[i + 1] = g_sancov_enclave_pcs_start[i + 1];
  }
}

extern "C" {
void __sanitizer_symbolize_pc(uptr pc, const char *fmt, char *out_buf,
                              uptr out_buf_size) {
  if (out_buf == nullptr || out_buf_size == 0)
    return;

  // Check cache first
  auto it = symbolize_cache.find(pc);
  SymbolInfo sym_info;

  if (it != symbolize_cache.end()) {
    // Cache hit
    sym_info = it->second;
  } else {
    // Cache miss - perform symbolization
    sym_info.func = "??";
    sym_info.file = "??";
    sym_info.line = "0";

    if (resolve_module_info(pc, sym_info)) {
      std::string output =
          run_addr2line(sym_info.module_path.c_str(), pc,
                        sym_info.is_pie_result, sym_info.module_base);
      // Parse output
      std::stringstream ss(output);
      std::string line_addr, line_func, line_file_loc;

      std::getline(ss, line_addr); // Consume address line
      if (std::getline(ss, line_func))
        sym_info.func = line_func;
      if (std::getline(ss, line_file_loc)) {
        size_t last_colon = line_file_loc.find_last_of(':');
        if (last_colon != std::string::npos) {
          sym_info.file = line_file_loc.substr(0, last_colon);
          sym_info.line = line_file_loc.substr(last_colon + 1);
        } else {
          sym_info.file = line_file_loc;
        }
      }
    }

    // Add to cache
    symbolize_cache[pc] = sym_info;
  }

  // Format output according to fmt
  std::stringstream out;
  if (!fmt)
    fmt = "%p in %f %s:%l";

  for (const char *p = fmt; *p != '\0'; ++p) {
    if (*p != '%') {
      out << *p;
      continue;
    }
    p++;
    switch (*p) {
    case '%':
      out << "%";
      break;
    case 'n':
      out << "0"; // frame number (always 0 for single frame)
      break;
    case 'p':
      out << "0x" << std::hex << pc << std::dec;
      break;
    case 'm':
      out << (sym_info.has_module_info ? sym_info.module_path : "??");
      break;
    case 'o':
      if (sym_info.has_module_info && sym_info.is_pie_result > 0) {
        out << "0x" << std::hex << (pc - sym_info.module_base) << std::dec;
      } else {
        out << "0x" << std::hex << pc << std::dec;
      }
      break;
    case 'f':
      out << sym_info.func;
      break;
    case 'q':
      out << "0x0";
      break;
    case 's':
      out << sym_info.file;
      break;
    case 'l':
      out << sym_info.line;
      break;
    case 'c':
      out << "0";
      break;
    case 'F':
      out << "in " << sym_info.func;
      break;
    case 'S':
      out << sym_info.file << ":" << sym_info.line << ":0";
      break;
    case 'L':
      if (sym_info.file != "??") {
        out << sym_info.file << ":" << sym_info.line;
      } else if (sym_info.has_module_info) {
        out << "(" << sym_info.module_path << "+0x" << std::hex;
        if (sym_info.is_pie_result > 0) {
          out << (pc - sym_info.module_base);
        } else {
          out << pc;
        }
        out << std::dec << ")";
      } else {
        out << "(<unknown module>)";
      }
      break;
    case 'M':
      if (sym_info.has_module_info) {
        const char *basename = strrchr(sym_info.module_path.c_str(), '/');
        basename = basename ? basename + 1 : sym_info.module_path.c_str();
        out << "(" << basename << "+0x" << std::hex;
        if (sym_info.is_pie_result > 0) {
          out << (pc - sym_info.module_base);
        } else {
          out << pc;
        }
        out << std::dec << ")";
      } else {
        out << "(" << "0x" << std::hex << pc << std::dec << ")";
      }
      break;
    default:
      out << *p;
      break;
    }
  }

  snprintf(out_buf, out_buf_size, "%s", out.str().c_str());
}

int __sanitizer_get_module_and_offset_for_pc(uptr pc, char *module_name,
                                             uptr module_name_len,
                                             uptr *pc_offset) {
  SymbolInfo sym_info;
  if (!resolve_module_info(pc, sym_info)) {
    return false;
  }

  // Fill module name
  if (module_name && module_name_len) {
    strncpy(module_name, sym_info.module_path.c_str(), module_name_len - 1);
    module_name[module_name_len - 1] = '\0';
  }

  // Calculate offset
  if (pc_offset) {
    *pc_offset = sym_info.is_pie_result > 0 ? pc - sym_info.module_base : pc;
  }

  return true;
}

void __asan_version_mismatch_check_v8() {}
void __asan_handle_no_return() {
  if (!asan_inited)
    return;
  // Unpoison the current thread's stack before a noreturn call (e.g. exit,
  // longjmp, throw) to prevent false positives when the stack is reused.
  pthread_attr_t attr;
  void *stack_addr;
  size_t stack_size;
  if (pthread_getattr_np(pthread_self(), &attr) == 0) {
    if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) == 0) {
      uptr stack_top = (uptr)stack_addr + stack_size;
      int local_stack;
      const uptr page_size = (uptr)getpagesize();
      uptr current_bottom = ((uptr)&local_stack - page_size) & ~(page_size - 1);
      if (current_bottom < stack_top)
        PoisonShadow(current_bottom, stack_top - current_bottom, 0, true);
    }
    pthread_attr_destroy(&attr);
  }
}
}