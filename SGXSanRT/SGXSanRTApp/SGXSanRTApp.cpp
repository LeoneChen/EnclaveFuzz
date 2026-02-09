#include "SGXSanRTConfig.h"
#include <array>
#include <assert.h>
#include <boost/stacktrace.hpp>
#include <dlfcn.h>
#include <elf.h>
#include <execinfo.h>
#include <iostream>
#include <memory>
#include <sgx_eid.h>
#include <sgx_error.h>
#include <signal.h>
#include <sstream>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

uptr g_enclave_base = 0, g_enclave_size = 0;
enum log_level g_log_level = LOG_LEVEL_WARNING;

std::string sgxsan_exec(const char *cmd) {
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

/* Log util */
static const char *log_level_to_prefix[] = {
    "",
    "[SGXSan error] ",
    "[SGXSan warning] ",
    "[SGXSan debug] ",
    "[SGXSan trace] ",
};

void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...) {
  if (ll > g_log_level)
    return;

  if (with_prefix) {
    fprintf(stderr, "%s", log_level_to_prefix[ll]);
  }

  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

void PrintAddressSpaceLayout() {
  log_debug("|| `[%16p, %16p]` || LowMem           ||\n", (void *)kLowMemBeg,
            (void *)kLowMemEnd);
  log_debug("|| `[%16p, %16p]` || LowShadowGuard   ||\n",
            (void *)kLowShadowGuardBeg, (void *)kLowShadowGuardEnd);
  log_debug("|| `[%16p, %16p]` || LowShadow        ||\n", (void *)kLowShadowBeg,
            (void *)kLowShadowEnd);
  log_debug("|| `[%16p, %16p]` || ShadowGap        ||\n", (void *)kShadowGapBeg,
            (void *)kShadowGapEnd);
  log_debug("|| `[%16p, %16p]` || HighShadow       ||\n",
            (void *)kHighShadowBeg, (void *)kHighShadowEnd);
  log_debug("|| `[%16p, %16p]` || HighShadowGuard  ||\n",
            (void *)kHighShadowGuardBeg, (void *)kHighShadowGuardEnd);
  log_debug("|| `[%16p, %16p]` || HighMem          ||\n", (void *)kHighMemBeg,
            (void *)kHighMemEnd);
  // consistent with modification in enclave_create_ex
  log_debug("|| `[%16p, %16p]` || LowElrangeGuard  ||\n",
            (void *)(g_enclave_base - PAGE_SIZE), (void *)(g_enclave_base - 1));
  log_debug("|| `[%16p, %16p]` || Elrange          ||\n",
            (void *)g_enclave_base,
            (void *)(g_enclave_base + g_enclave_size - 1));
  log_debug("|| `[%16p, %16p]` || HighElrangeGuard ||\n",
            (void *)(g_enclave_base + g_enclave_size),
            (void *)(g_enclave_base + g_enclave_size - 1 + PAGE_SIZE));
  log_debug("\n");
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

void sgxsan_dump_bt_buf(void **array, size_t size) {
  log_always_np("[*] SGXSan Backtrace:\n");
  Dl_info info;
  for (size_t i = 0; i < size; i++) {
    if (dladdr(array[i], &info) != 0) {
      std::stringstream cmd;
      if (is_pie(info.dli_fname) > 0) {
        cmd << "llvm-addr2line-13 -afCpi --adjust-vma=0x" << std::hex
            << (uptr)info.dli_fbase << " -e " << info.dli_fname << " "
            << ((uptr)array[i] - 4);
      } else {
        cmd << "llvm-addr2line-13 -afCpi -e " << info.dli_fname << " "
            << std::hex << ((uptr)array[i] - 4);
      }
      auto result = sgxsan_exec(cmd.str().c_str());
      log_always_np("%s", result.c_str());
    } else {
      log_always_np("%p\n", array[i]);
    }
  }
}

void sgxsan_backtrace(log_level ll) {
  if (ll > g_log_level)
    return;

  size_t max_bt_count = 100;
  uint64_t bt_buf[max_bt_count];
  size_t bt_cnt =
      boost::stacktrace::safe_dump_to(bt_buf, sizeof(decltype(bt_buf)));
  sgxsan_dump_bt_buf((void **)bt_buf, bt_cnt);
}

/* Signal */
static struct sigaction g_old_sigact[_NSIG];
void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv) {
  ucontext_t *ucontext = (ucontext_t *)priv;
  if (signum == SIGSEGV) {
    // process siginfo
    greg_t pc = ucontext->uc_mcontext.gregs[REG_RIP];
    if (siginfo->si_code == SI_KERNEL) {
      // If si_code is SI_KERNEL, #PF address is not true
      log_error("#PF Addr Unknown at pc %p\n", pc);
    } else {
      void *pf_addr_p = siginfo->si_addr;
      log_error("#PF Addr %p at pc %p => ", pf_addr_p, pc);
      uint64_t page_fault_addr = (uint64_t)pf_addr_p;
      if (pf_addr_p == nullptr) {
        log_error_np("Null-Pointer dereference\n");
      } else if (((g_enclave_base - PAGE_SIZE) <= page_fault_addr &&
                  page_fault_addr < g_enclave_base) ||
                 ((g_enclave_base + g_enclave_size) <= page_fault_addr &&
                  page_fault_addr <=
                      (g_enclave_base + g_enclave_size - 1 + PAGE_SIZE))) {
        log_error_np(
            "Pointer dereference overflows enclave boundray (Overlapping "
            "memory access)\n");
      } else if ((g_enclave_base + g_enclave_size - 0x1000) <=
                     page_fault_addr &&
                 page_fault_addr < (g_enclave_base + g_enclave_size)) {
        log_error_np(
            "Infer pointer dereference overflows enclave boundray, as "
            "mprotect's effort is page-granularity and si_addr only give "
            "page-granularity address\n");
      } else if ((kLowShadowGuardBeg <= page_fault_addr &&
                  page_fault_addr < kLowShadowBeg) ||
                 (kHighShadowEnd < page_fault_addr &&
                  page_fault_addr <= kHighShadowGuardEnd)) {
        log_error_np("Pointer dereference overflows shadow map boundray "
                     "(Overlapping memory access)\n");
      } else if ((kHighShadowEnd + 1 - 0x1000) <= page_fault_addr &&
                 page_fault_addr <= kHighShadowEnd) {
        log_error_np(
            "Infer pointer dereference overflows shadow map boundray, as "
            "mprotect's effort is page-granularity and si_addr only give "
            "page-granularity address\n");
      }
    }
  }

  // call previous signal handler
  if (SIG_DFL == g_old_sigact[signum].sa_handler) {
    signal(signum, SIG_DFL);
    raise(signum);
  }
  // if there is old signal handler, we need transfer the signal to the old
  // signal handler;
  else {
    // make sure signum to be masked if SA_NODEFER is not set
    if (!(g_old_sigact[signum].sa_flags & SA_NODEFER))
      sigaddset(&g_old_sigact[signum].sa_mask, signum);
    // use mask of old sigact
    sigset_t cur_set;
    pthread_sigmask(SIG_SETMASK, &g_old_sigact[signum].sa_mask, &cur_set);

    if (g_old_sigact[signum].sa_flags & SA_SIGINFO) {
      g_old_sigact[signum].sa_sigaction(signum, siginfo, priv);
    } else {
      g_old_sigact[signum].sa_handler(signum);
    }

    pthread_sigmask(SIG_SETMASK, &cur_set, NULL);

    // If the g_old_sigact set SA_RESETHAND, it will break the chain which means
    // g_old_sigact->next_old_sigact will not be called. Our signal handler does
    // not responsable for that. We just follow what os do on SA_RESETHAND.
    if (g_old_sigact[signum].sa_flags & SA_RESETHAND)
      g_old_sigact[signum].sa_handler = SIG_DFL;
  }
}

extern "C" void reg_sgxsan_sigaction() {
  // Register sgxsan_sigaction only once
  static bool HasRegisteredSigaction = false;
  if (HasRegisteredSigaction)
    return;
  HasRegisteredSigaction = true;
  struct sigaction sig_act;
  memset(&sig_act, 0, sizeof(sig_act));
  sig_act.sa_sigaction = sgxsan_sigaction;
  sig_act.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sig_act.sa_mask);
  sgxsan_assert(0 == sigprocmask(SIG_SETMASK, NULL, &sig_act.sa_mask));
  // make sure SIGSEGV is not blocked
  sigdelset(&sig_act.sa_mask, SIGSEGV);
  // take place before signal handler of sgx aex
  sgxsan_assert(0 == sigaction(SIGSEGV, &sig_act, &g_old_sigact[SIGSEGV]));
}

extern "C" {
// Memory layout
// ASAN's __asan_init -> __sanitizer_cov_8bit_counters_init ->
// setCovMapAddr -> sgx_create_enclave -> enclave_create_ex -> reg_sig_handler
// -> sgx_ecall -> SGXSan's __asan_init
void sgxsan_ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size) {
  // Init Enclave info outside Enclave
  g_enclave_base = enclave_base;
  g_enclave_size = enclave_size;

  sgxsan_assert(((g_enclave_base & 0xfff) == 0) &&
                (((g_enclave_base + g_enclave_size) & 0xfff) == 0));

  // mmap the shadow plus it's guard pages
  sgxsan_assert(mmap((void *)kLowShadowGuardBeg,
                     kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                     0) != MAP_FAILED);
  madvise((void *)kLowShadowGuardBeg,
          kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
          MADV_NOHUGEPAGE); // Return -1 if CONFIG_TRANSPARENT_HUGEPAGE was not
                            // configured in kernel
  sgxsan_assert(
      mprotect((void *)kLowShadowGuardBeg, PAGE_SIZE, PROT_NONE) == 0 &&
      mprotect((void *)kHighShadowGuardBeg, PAGE_SIZE, PROT_NONE) == 0);
  sgxsan_assert(mprotect((void *)kShadowGapBeg,
                         kShadowGapEnd - kShadowGapBeg + 1, PROT_NONE) == 0);

  PrintAddressSpaceLayout();

  reg_sgxsan_sigaction();
}

/* OCall functions */
void sgxsan_ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  log_always_np("%s", str);
}

/* addr2line */
void sgxsan_ocall_addr2line(uint64_t *addr_arr, size_t arr_cnt, int level) {
  for (size_t i = 0; i < arr_cnt; i++) {
    std::stringstream cmd;
    cmd << "llvm-addr2line-13 -afCpi --adjust-vma=0x" << std::hex
        << (uptr)g_enclave_base << " -e TestEnclave " << (addr_arr[i] - 4);
    auto ret = sgxsan_exec(cmd.str().c_str());
    sgxsan_log((log_level)level, false, ret.c_str());
  }
}
}