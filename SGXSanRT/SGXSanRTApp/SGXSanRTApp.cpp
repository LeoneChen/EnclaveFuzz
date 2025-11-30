#include "SGXSanRTApp.h"
#include "ArgShadow.h"
#include "Interceptor.h"
#include "Malloc.h"
#include "MemAccessMgr.h"
#include "Sticker.h"
#include "plthook.h"
#include <atomic>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/stacktrace.hpp>
#include <dlfcn.h>
#include <execinfo.h>
#include <fstream>
#include <iostream>
#include <pthread.h>
#include <regex>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>

namespace po = boost::program_options;

static const char *log_level_to_prefix[] = {
    "[SGXSan] ALWAYS: ", "[SGXSan] ERROR: ", "[SGXSan] WARNING: ",
    "[SGXSan] DEBUG: ",  "[SGXSan] TRACE: ",
};

bool asan_inited = false;

std::unordered_map<void * /* callsite addr */,
                   std::vector<EncryptStatus> /* output type history */>
    output_history;
pthread_rwlock_t output_history_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct sigaction g_old_sigact[_NSIG];

extern "C" __attribute__((weak)) bool DFEnableSanCheckDie();

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
  if (UserDieCallback)
    UserDieCallback();
  _Exit(77);
}

// https://maskray.me/blog/2022-04-10-unwinding-through-signal-handler
extern "C" void sgxsan_signal_safe_dump_bt_buf(uint64_t *bt_buf,
                                               size_t bt_cnt) {
  log_always_np("== SGXSan Backtrace BEG ==\n");
  for (size_t i = 0; i < bt_cnt; i++) {
    uint64_t addr = bt_buf[i];
    Dl_info info;
    if (dladdr((void *)addr, &info) != 0) {
      if (info.dli_saddr) {
        log_always_np("0x%016lx: %s (offset 0x%lx) at %s\n",
                      addr - (uint64_t)info.dli_fbase,
                      info.dli_sname ? info.dli_sname : "?",
                      (uint64_t)info.dli_saddr - (uint64_t)info.dli_fbase,
                      info.dli_fname ? info.dli_fname : "?");
      } else {
        log_always_np("0x%016lx: %s at %s\n", addr - (uint64_t)info.dli_fbase,
                      info.dli_sname ? info.dli_sname : "?",
                      info.dli_fname ? info.dli_fname : "?");
      }
    }
  }
  log_always_np("== SGXSan Backtrace END ==\n");
}

extern "C" void sgxsan_signal_safe_dump_bt() {
  size_t max_bt_count = 100;
  uint64_t bt_buf[max_bt_count];
  size_t bt_cnt =
      boost::stacktrace::safe_dump_to(bt_buf, sizeof(decltype(bt_buf)));

  sgxsan_signal_safe_dump_bt_buf(bt_buf, bt_cnt);
}

extern "C" __attribute__((alias("sgxsan_signal_safe_dump_bt")))
SANITIZER_INTERFACE_ATTRIBUTE void
__sanitizer_print_stack_trace();

// https://github.com/google/sanitizers/issues/788
// __sanitizer_acquire_crash_state is important
extern "C" SANITIZER_INTERFACE_ATTRIBUTE int __sanitizer_acquire_crash_state() {
  static std::atomic<int> in_crash_state = 0;
  return !std::atomic_exchange_explicit(&in_crash_state, 1,
                                        std::memory_order_relaxed);
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
    auto PCOrEnclaveOffset = GetOffsetIfEnclave(rip);
    if (siginfo->si_code == SI_KERNEL) {
      // If si_code is SI_KERNEL, #PF address is not true
      log_error("#PF Addr Unknown at pc %p(%c)\n", (void *)PCOrEnclaveOffset,
                (PCOrEnclaveOffset == (uintptr_t)rip) ? 'A' : 'E');
    } else {
      size_t page_size = getpagesize();
      // process siginfo
      void *_page_fault_addr = siginfo->si_addr;
      log_error("#PF Addr %p at pc %p(%c) => ", _page_fault_addr,
                (void *)PCOrEnclaveOffset,
                (PCOrEnclaveOffset == (uintptr_t)rip) ? 'A' : 'E');

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

    sgxsan_signal_safe_dump_bt();
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
    mmap((void *)0, page_size, PROT_NONE,
         MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    sgxsan_error(mprotect((void *)0, page_size, PROT_NONE),
                 "Failed to make 0 address not accessible\n");
  }
}

int hook_enclave() {
  plthook_t *plthook;
  std::string fileName = gEnclaveInfo.GetEnclaveFileName();
  sgxsan_assert(fileName != "");
  if (plthook_open(&plthook, fileName.c_str()) != 0) {
    log_error("plthook_open error: %s\n", plthook_error());
    return -1;
  }

#define HOOK_SYM(res, plthookStuct, sym)                                       \
  res = plthook_replace(plthookStuct, #sym, (void *)SGXSAN(sym), NULL);        \
  if (res != 0 and res != PLTHOOK_FUNCTION_NOT_FOUND) {                        \
    log_error("plthook_replace error: %s\n", plthook_error());                 \
    plthook_close(plthookStuct);                                               \
    return -1;                                                                 \
  }
  int result;
  HOOK_SYM(result, plthook, __sanitizer_cov_8bit_counters_init)
  HOOK_SYM(result, plthook, __sanitizer_cov_pcs_init)
#undef HOOK_SYM
  plthook_close(plthook);
  return 0;
}

__attribute__((constructor)) void SGXSanInit() {
  if (asan_inited) {
    return;
  }
  updateBackEndHeapAllocator();
  InitInterceptor();
  // make sure c++ stream is initialized
  std::ios_base::Init _init;
  sgxsan_init_shadow_memory();
  PrintAddressSpaceLayout();
  asan_inited = true;
}

/// SLSan Callbacks to show dynamic value flow
extern "C" void PrintPtr(char *info, void *addr, size_t size) {
  sgxsan_assert(addr and size);
  log_trace("%s\n"
            "Address: 0x%p(0x%lx)\n"
            "Shadow: 0x%p(0x%lx)\n",
            info, addr, size, (void *)MEM_TO_SHADOW(addr),
            RoundUpDiv(size, SHADOW_GRANULARITY));
}

/// \param func_ptr address of function
/// \param pos -1 means it's return value of \p func_ptr
extern "C" void PrintArg(char *info, void *func_ptr, int pos) {
  log_trace("%s\n"
            "Function: 0x%p\n"
            "ArgIdx: %ld\n",
            info, func_ptr, pos);
}
extern "C" __attribute__((weak)) void
sgxfuzz_log(log_level ll, bool with_prefix, const char *fmt, ...);
void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...) {
  if (sgxfuzz_log) {
    if (with_prefix) {
#if (SHOW_TID)
      sgxfuzz_log(ll, false, "[TID=0x%x] ", gettid());
#endif
      sgxfuzz_log(ll, false, "%s", log_level_to_prefix[ll]);
    }

    char buf[BUFSIZ];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    sgxfuzz_log(ll, false, "%s", buf);
    return;
  }

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
  InitInterceptor();
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
  REAL(snprintf)(buf, BUFSIZ, "Shadow bytes around the buggy address:\n");
  std::string str(buf);
  for (uptr i = startRow; i < endRow; i += 0x10) {
    REAL(snprintf)
    (buf, BUFSIZ, "%s%p:", i == shadowAddrRow ? "=>" : "  ", (void *)i);
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
      REAL(snprintf)
      (buf, BUFSIZ, "%s%02x%s", prefix.c_str(), *(uint8_t *)(i + j),
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
               "[SGXSan] ERROR: ");

  char buf[BUFSIZ];
  va_list ap;
  va_start(ap, msg);
  vsnprintf(buf, BUFSIZ, msg, ap);
  va_end(ap);
  sgxsan_log(ll, false, "%s", buf);

  auto PCOrEnclaveOffset = GetOffsetIfEnclave(pc);
  sgxsan_log(ll, false,
             " at pc %p(%c) %s 0x%lx with 0x%lx bytes (bp = 0x%lx sp = "
             "0x%lx)\n\n",
             (void *)PCOrEnclaveOffset,
             (PCOrEnclaveOffset == (uintptr_t)pc) ? 'A' : 'E',
             (is_write ? "write" : "read"), addr, access_size, bp, sp);
  sgxsan_backtrace(ll);
  sgxsan_log(ll, false, "================= Report End =================\n");

  if (not DFEnableSanCheckDie or
      (DFEnableSanCheckDie and DFEnableSanCheckDie()))
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
                 "[SGXSan] ERROR: ");
  } else {
    ll = LOG_LEVEL_WARNING;
    log_warning_np("\n================ Warning Report ================\n"
                   "[SGXSan] WARNING: ");
  }

  char buf[BUFSIZ];
  va_list ap;
  va_start(ap, msg);
  vsnprintf(buf, BUFSIZ, msg, ap);
  va_end(ap);
  sgxsan_log(ll, false, "%s", buf);

  auto PCOrEnclaveOffset = GetOffsetIfEnclave(pc);
  sgxsan_log(ll, false,
             " at pc %p(%c) %s 0x%lx with 0x%lx bytes (bp = 0x%lx sp = "
             "0x%lx)\n\n",
             (void *)PCOrEnclaveOffset,
             (PCOrEnclaveOffset == (uintptr_t)pc) ? 'A' : 'E',
             (is_write ? "write" : "read"), addr, access_size, bp, sp);
  sgxsan_backtrace(ll);
  if (AddrIsInMem(addr))
    PrintShadowMap(ll, addr);
  sgxsan_log(ll, false, "================= Report End =================\n");
  if (fatal and (not DFEnableSanCheckDie or
                 (DFEnableSanCheckDie and DFEnableSanCheckDie())))
    Die();
  return;
}

void ReportUseAfterFree(uptr pc, uptr bp, uptr sp, uptr addr) {
  auto qe = gQCache->find(addr);
  sgxsan_assert(qe.alloc_beg != -1);
  MallocFreeBTTy bt = gHeapBT->GetHeapBacktrace(qe.user_beg);
  log_level ll = LOG_LEVEL_ERROR;
  auto PCOrEnclaveOffset = GetOffsetIfEnclave(pc);
  log_error_np(
      "\n================ Error Report ================\n"
      "[SGXSan] ERROR: %s Use after free 0x%lx at pc %p(%c) bp 0x%lx "
      "sp 0x%lx\n\n",
      (sgx_is_within_enclave((const void *)addr, 1) ? "Enclave" : "Host"), addr,
      (void *)PCOrEnclaveOffset,
      (PCOrEnclaveOffset == (uintptr_t)pc) ? 'A' : 'E', bp, sp);
  sgxsan_backtrace(ll);
  log_error_np("\nPreviously malloc at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.malloc_bt /* int array -> pointer array */,
                     bt.malloc_bt_cnt);
  log_error_np("\nPreviously free at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.free_bt, bt.free_bt_cnt);
  PrintShadowMap(ll, addr);
  log_error_np("================= Report End =================\n");
  if (not DFEnableSanCheckDie or
      (DFEnableSanCheckDie and DFEnableSanCheckDie()))
    Die();
  return;
}

void ReportDoubleFree(uptr pc, uptr bp, uptr sp, uptr addr) {
  MallocFreeBTTy bt = gHeapBT->GetHeapBacktrace(addr);
  log_level ll = LOG_LEVEL_ERROR;
  auto PCOrEnclaveOffset = GetOffsetIfEnclave(pc);
  log_error_np(
      "\n================ Error Report ================\n"
      "[SGXSan] ERROR: %s Double Free 0x%lx at pc %p(%c) bp 0x%lx "
      "sp 0x%lx\n\n",
      (sgx_is_within_enclave((const void *)addr, 1) ? "Enclave" : "Host"), addr,
      (void *)PCOrEnclaveOffset,
      (PCOrEnclaveOffset == (uintptr_t)pc) ? 'A' : 'E', bp, sp);
  sgxsan_backtrace(ll);
  log_error_np("\nPreviously malloc at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.malloc_bt /* int array -> pointer array */,
                     bt.malloc_bt_cnt);
  log_error_np("\nPreviously free at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.free_bt, bt.free_bt_cnt);
  PrintShadowMap(ll, addr);
  log_error_np("================= Report End =================\n");
  if (not DFEnableSanCheckDie or
      (DFEnableSanCheckDie and DFEnableSanCheckDie()))
    Die();
  return;
}

std::string addr2line(uptr addr, std::string fileName) {
  std::stringstream cmd;
  cmd << "addr2line -afCpe " << fileName.c_str() << " " << std::hex << addr;
  std::string cmd_str = cmd.str();
  return sgxsan_exec(cmd_str.c_str());
}

static std::string _addr2fname(uptr addr, std::string fileName) {
  std::stringstream cmd;
  cmd << "addr2line -fCe " << fileName.c_str() << " " << std::hex << addr
      << " | head -n 1";
  std::string cmd_str = cmd.str();
  return sgxsan_exec(cmd_str.c_str());
}

std::string addr2fname_try(void *addr) {
  std::string fname = "";
  Dl_info info;
  if (dladdr(addr, &info) != 0) {
    const char *_sname = info.dli_sname;
    fname = _sname ? std::string(_sname) : "";
  }
  return fname;
}

std::string addr2fname(void *addr) {
  std::string fname = "";
  Dl_info info;
  if (dladdr(addr, &info) != 0) {
    fname = _addr2fname(
        (uptr)addr -
            ((uptr)info.dli_fbase <= 0x400000 ? 0 : (uptr)info.dli_fbase) - 1,
        info.dli_fname);
    fname.erase(std::remove(fname.begin(), fname.end(), '\n'), fname.end());
  }
  return fname;
}

bool is_shared_object(const char *fileName) {
  std::stringstream cmd;
  cmd << "file $(realpath " << fileName << ")";
  std::string cmd_str = cmd.str();
  std::string ret = sgxsan_exec(cmd_str.c_str());
  return ret.find("shared object") == ret.npos ? false : true;
}

void sgxsan_dump_bt_buf(void **array, size_t size) {
  log_always_np("== SGXSan Backtrace BEG ==\n");
  Dl_info info;
  for (size_t i = 0; i < size; i++) {
    if (dladdr(array[i], &info) != 0) {
      std::string str = addr2line(
          (uptr)array[i] -
              (!is_shared_object(info.dli_fname) ? 0 : (uptr)info.dli_fbase) -
              1,
          info.dli_fname);
      log_always_np(str.c_str());
    }
  }
  log_always_np("== SGXSan Backtrace END ==\n");
}

extern "C" __attribute__((weak)) bool DFUseAddr2line();
void sgxsan_backtrace(log_level ll) {
#if (DUMP_STACK_TRACE)
  if (ll > USED_LOG_LEVEL)
    return;
  if (DFUseAddr2line and DFUseAddr2line()) {
    void *array[20];
    size_t size = backtrace(array, 20);
    sgxsan_dump_bt_buf(array, size);
  } else {
    sgxsan_signal_safe_dump_bt();
  }
#endif
}

void sgxsan_backtrace_boost(log_level ll) {
#if (DUMP_STACK_TRACE)
  if (ll > USED_LOG_LEVEL)
    return;
  log_always_np("== SGXSan Backtrace BEG ==\n");
  std::stringstream ss;
  ss << boost::stacktrace::stacktrace();
  log_always_np("%s", ss.str().c_str());
  log_always_np("== SGXSan Backtrace END ==\n");
#endif
}

/// Cipher detect

void ClearPlaintextOutputHistory() {
  pthread_rwlock_wrlock(&output_history_rwlock);
  output_history.clear();
  pthread_rwlock_unlock(&output_history_rwlock);
}

static __thread int TD_init_count = 0;

extern "C" void TDECallConstructor() {
  if (TD_init_count == 0) {
    // root ecall
    MemAccessMgr::init();
    ArgShadowStack::init();
  }
  TD_init_count++;
  sgxsan_assert(TD_init_count < 1024);
}

extern "C" void TDECallDestructor() {
  if (TD_init_count == 1) {
    // root ecall
    MemAccessMgr::destroy();
    ArgShadowStack::destroy();
  }
  TD_init_count--;
  sgxsan_assert(TD_init_count >= 0);
}

void TDECallClear() { TD_init_count = 0; }

void ClearSGXSanRT() {
  TDECallClear();
  ClearPlaintextOutputHistory();
}

enum SensitiveDataType { LoadedData = 0, ArgData, ReturnedData };
extern "C" void ReportSensitiveDataLeak(SensitiveDataType srcType,
                                        uptr srcInfo1, uptr srcInfo2,
                                        uptr dstAddr, uptr dstSize) {
  log_warning("Possible leak of sensitive data\n");
  if (srcType == LoadedData) {
    uptr srcAddr = srcInfo1;
    size_t srcSize = srcInfo2;
    GET_CALLER_PC_BP_SP;
    ReportGenericError(pc, bp, sp, srcAddr, false, srcSize, false,
                       "Leak of Sensitive Data");

  } else if (srcType == ArgData or srcType == ReturnedData) {
    sptr argPos = (sptr)srcInfo2;
    uptr funcAddr = srcInfo1;
    log_warning("Src info: Arg %ld of func at 0x%lx\n", argPos, funcAddr);
  } else {
    abort();
  }
  log_warning("Dst info: 0x%lx(0x%lx)\n", dstAddr, dstSize);
}

void ClearStackPoison() {
  std::fstream f("/proc/self/maps", std::ios::in);
  std::string line;
  while (std::getline(f, line)) {
    if (line.find("[stack]") != std::string::npos) {
      std::vector<std::string> vec1, vec2;
      boost::split(vec1, line, [](char c) { return c == ' '; });
      boost::trim(vec1[0]);
      boost::split(vec2, vec1[0], [](char c) { return c == '-'; });
      sgxsan_assert(vec2.size() == 2);
      uptr stackBase = std::stoull("0x" + vec2[0], 0, 16);
      uptr stackEnd = std::stoull("0x" + vec2[1], 0, 16);
      PoisonShadow(stackBase, stackEnd - stackBase, 0, true);
    }
  }
}
