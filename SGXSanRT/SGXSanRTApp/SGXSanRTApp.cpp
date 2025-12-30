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
#include <fstream>
#include <iostream>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *log_level_to_prefix[] = {
    "[SGXSan] ALWAYS: ", "[SGXSan] ERROR: ", "[SGXSan] WARNING: ",
    "[SGXSan] DEBUG: ",  "[SGXSan] TRACE: ",
};

bool asan_inited = false;

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

#ifndef KAFL_FUZZER
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
#endif

#ifdef KAFL_FUZZER

extern "C" int DFGetInt32();
extern "C" __attribute__((weak)) void
FuzzerSignalCB(int signum, siginfo_t *siginfo, void *priv);
extern "C" __attribute__((weak)) void FuzzerCrashCB();

void NORETURN Die() {
  if (FuzzerCrashCB)
    FuzzerCrashCB();
  _Exit(1);
}

/// \brief Signal handler to report illegal memory access
static void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv) {
  ucontext_t *uc = (ucontext_t *)priv;
  const greg_t rip = uc->uc_mcontext.gregs[REG_RIP];
  greg_t *const rip_p = &uc->uc_mcontext.gregs[REG_RIP];
  auto PCOrEnclaveOffset = GetOffsetIfEnclave(rip);
  if (siginfo->si_signo == SIGSEGV) {
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
  } else if (siginfo->si_signo == SIGILL) {
    if (*(uint32_t *)rip == 0x29ae0f48 /* XRSTOR64 RCX */) {
      *rip_p += 4;
      return;
    } else if ((*(uint32_t *)rip & 0xFFFFFF) == 0xf0c70f /* RDRAND EAX */) {
      uc->uc_mcontext.gregs[REG_RAX] = DFGetInt32();
      uc->uc_mcontext.gregs[REG_EFL] = 1; // CF->1 others->0
      *rip_p += 3;
      return;
    } else if ((*(uint32_t *)rip & 0xFFFFFF) == 0xf6c70f /* RDRAND ESI */) {
      uc->uc_mcontext.gregs[REG_RSI] = DFGetInt32();
      uc->uc_mcontext.gregs[REG_EFL] = 1; // CF->1 others->0
      *rip_p += 3;
      return;
    }
    log_error("SIGILL opcode is %lx\n", *(uint32_t *)rip);
  } else {
    log_error("Signal %d\n", siginfo->si_signo);
  }

  sgxsan_backtrace();
  if (FuzzerSignalCB)
    FuzzerSignalCB(signum, siginfo, priv);
  Die();
}
#else

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_print_stack_trace() {
  sgxsan_backtrace();
}

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

    sgxsan_backtrace();
    Die();
  }
  _Exit(-1);
}
#endif

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
#ifdef KAFL_FUZZER
  sgxsan_assert(0 == sigaction(SIGFPE, &sig_act, &g_old_sigact[SIGFPE]));
  sgxsan_assert(0 == sigaction(SIGBUS, &sig_act, &g_old_sigact[SIGBUS]));
  sgxsan_assert(0 == sigaction(SIGILL, &sig_act, &g_old_sigact[SIGILL]));
  sgxsan_assert(0 == sigaction(SIGABRT, &sig_act, &g_old_sigact[SIGABRT]));
  sgxsan_assert(0 == sigaction(SIGIOT, &sig_act, &g_old_sigact[SIGIOT]));
  sgxsan_assert(0 == sigaction(SIGTRAP, &sig_act, &g_old_sigact[SIGTRAP]));
  sgxsan_assert(0 == sigaction(SIGSYS, &sig_act, &g_old_sigact[SIGSYS]));
  sgxsan_assert(0 == sigaction(SIGUSR2, &sig_act, &g_old_sigact[SIGUSR2]));
#else
  // Override libFuzzer's SIGALRM Handler
  struct sigaction sig_timeoue_act;
  memset(&sig_timeoue_act, 0, sizeof(sig_timeoue_act));
  sig_timeoue_act.sa_sigaction = sgxsan_timeout_sigaction;
  sig_timeoue_act.sa_flags = SA_SIGINFO;
  sigemptyset(&sig_timeoue_act.sa_mask);
  // sgxsan_assert(0 ==
  //               sigaction(SIGALRM, &sig_timeoue_act,
  //               &g_old_sigact[SIGALRM]));
#endif
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

void sgxsan_dump_bt_buf(void **array, size_t size) {
  log_always_np("[*] SGXSan Backtrace:\n");
  Dl_info info;
  for (size_t i = 0; i < size; i++) {
    if (dladdr(array[i], &info) != 0) {
      std::string fname = info.dli_fname, app_name = "TestApp";
      uptr addr;
      if (fname.length() >= app_name.length() &&
          fname.rfind(app_name) == (fname.length() - app_name.length())) {
        addr = (uptr)array[i];
      } else {
        addr = (uptr)array[i] - (uptr)info.dli_fbase;
      }
      log_always_np(" \"%s\"+%p", info.dli_fname, (void *)addr);
    } else {
      log_always_np(" %p\n", array[i]);
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

extern "C" void TDECallConstructor() {
  if (TD_init_count == 0) {
    // root ecall
    MemAccessMgr::init();
  }
  TD_init_count++;
  sgxsan_assert(TD_init_count < 1024);
}

extern "C" void TDECallDestructor() {
  if (TD_init_count == 1) {
    // root ecall
    MemAccessMgr::destroy();
  }
  TD_init_count--;
  sgxsan_assert(TD_init_count >= 0);
}

void ClearSGXSanRT() { sgxsan_assert(TD_init_count == 0); }

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
