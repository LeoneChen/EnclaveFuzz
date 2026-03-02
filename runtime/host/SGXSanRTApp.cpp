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

extern "C" {
void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop);
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end);
int __sanitizer_acquire_crash_state();
}

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
uptr g_enclave_base = 0, g_enclave_size = 0;
enum log_level g_log_level = LOG_LEVEL_WARNING;
uint8_t *g_sancov_cntrs_copy_start = nullptr,
        *g_sancov_cntrs_copy_end = nullptr;
uintptr_t *g_sancov_pcs_copy_start = nullptr, *g_sancov_pcs_copy_end = nullptr;

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

  char buf[1024];
  int pos = 0;
  if (with_prefix) {
    pos = snprintf(buf, sizeof(buf), "%s", log_level_to_prefix[ll]);
  }

  va_list ap;
  va_start(ap, fmt);
  pos += vsnprintf(buf + pos, sizeof(buf) - pos, fmt, ap);
  va_end(ap);

  if (pos > (int)sizeof(buf))
    pos = sizeof(buf);
  write(STDERR_FILENO, buf, pos);
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

/// Resolve module info for a runtime PC.
/// Handles enclave, host PIE, and host non-PIE binaries.
bool resolve_module_info(uptr pc, SymbolInfo &sym_info) {
  if (g_enclave_base <= pc && pc < g_enclave_base + g_enclave_size) {
    sym_info.has_module_info = true;
    sym_info.module_path = "TestEnclave";
    sym_info.module_base = g_enclave_base;
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

/// Low-level addr2line: given explicit module info, run llvm-addr2line-13.
std::string run_addr2line(const char *module_path, uptr addr, int pie_status,
                          uptr base_addr, const char *extra_flags = "") {
  std::stringstream cmd;
  cmd << "llvm-addr2line-13 -afC";
  if (extra_flags && extra_flags[0])
    cmd << " " << extra_flags;
  if (pie_status > 0)
    cmd << " --adjust-vma=0x" << std::hex << base_addr;
  cmd << " -e " << module_path << " " << std::hex << addr;
  return sgxsan_exec(cmd.str().c_str());
}

/// High-level addr2line: auto-resolve module from a runtime PC.
std::string addr2line_for_pc(uptr pc, const char *extra_flags = "") {
  SymbolInfo sym_info;
  if (!resolve_module_info(pc, sym_info))
    return "";

  return run_addr2line(sym_info.module_path.c_str(), pc, sym_info.is_pie_result,
                       sym_info.module_base, extra_flags);
}

void sgxsan_backtrace(log_level ll) {
  if (ll > g_log_level)
    return;

  size_t max_bt_count = 100;
  uint64_t bt_buf[max_bt_count];
  size_t bt_cnt =
      boost::stacktrace::safe_dump_to(bt_buf, sizeof(decltype(bt_buf)));

  for (size_t i = 0; i < bt_cnt; i++) {
    auto result = addr2line_for_pc((uptr)bt_buf[i] - 4, "-pi");
    if (!result.empty()) {
      log_always_np("%s", result.c_str());
    } else {
      log_always_np("%p\n", bt_buf[i]);
    }
  }
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
      if (0 <= (uptr)pf_addr_p && (uptr)pf_addr_p < PAGE_SIZE) {
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

extern "C" {
void reg_sgxsan_sigaction() {
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

void sgxsan_abort() { abort(); }

// Memory layout
// ASAN's __asan_init -> __sanitizer_cov_8bit_counters_init ->
// setCovMapAddr -> sgx_create_enclave -> enclave_create_ex -> reg_sig_handler
// -> sgx_ecall -> SGXSan's __asan_init
void sgxsan_ocall_init_shadow_memory(uptr enclave_base, uptr enclave_size,
                                     uint64_t *cntrs_copy_start,
                                     uint64_t *cntrs_copy_end,
                                     uint64_t *pcs_copy_start,
                                     uint64_t *pcs_copy_end) {
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
  *cntrs_copy_start = (uint64_t)g_sancov_cntrs_copy_start;
  *cntrs_copy_end = (uint64_t)g_sancov_cntrs_copy_end;
  *pcs_copy_start = (uint64_t)g_sancov_pcs_copy_start;
  *pcs_copy_end = (uint64_t)g_sancov_pcs_copy_end;
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
  log_level ll = (log_level)level;

  // Capture host stack
  const size_t max_bt_count = 100;
  uint64_t bt_buf[max_bt_count];
  size_t bt_cnt =
      boost::stacktrace::safe_dump_to(bt_buf, sizeof(decltype(bt_buf)));

  // Print host ocall frames until we find sgx_urts_vdso_handler
  size_t i = 0;
  for (; i < bt_cnt; i++) {
    auto result = addr2line_for_pc((uptr)bt_buf[i] - 4, "-pi");
    if (!result.empty()) {
      // sgxsan_log(ll, false, "%s", result.c_str());
      if (result.find("sgx_urts_vdso_handler") != std::string::npos ||
          result.find("__morestack") != std::string::npos) {
        i++;
        break;
      }
    }
    // else {
    //   sgxsan_log(ll, false, "%p\n", (void *)bt_buf[i]);
    // }
  }
  // sgxsan_log(ll, false, "---- ocall to host ----\n");

  // Insert enclave frames
  for (size_t j = 0; j < arr_cnt; j++) {
    auto ret =
        run_addr2line("TestEnclave", addr_arr[j] - 4, 1, g_enclave_base, "-pi");
    sgxsan_log(ll, false, "%s", ret.c_str());
  }

  sgxsan_log(ll, false, "---- ecall to enclave ----\n");
  // Print remaining host caller frames
  for (; i < bt_cnt; i++) {
    auto result = addr2line_for_pc((uptr)bt_buf[i] - 4, "-pi");
    if (!result.empty())
      sgxsan_log(ll, false, "%s", result.c_str());
    else
      sgxsan_log(ll, false, "%p\n", (void *)bt_buf[i]);
  }
}

void sancov_copy_init() {
  auto result =
      sgxsan_exec("size -A TestEnclave|grep __sancov_cntrs|awk '{print $2}'");
  auto cntrs_size = std::stoull(result);
  result =
      sgxsan_exec("size -A TestEnclave|grep __sancov_pcs|awk '{print $2}'");
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
}

// void __sanitizer_print_stack_trace() { sgxsan_backtrace(LOG_LEVEL_ERROR); }

int __sanitizer_acquire_crash_state() {
  static volatile int in_crash_state = 0;
  return !__atomic_exchange_n(&in_crash_state, 1, __ATOMIC_RELAXED);
}

void ClearSymbolizeCache() { symbolize_cache.clear(); }
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
    resolve_module_info(pc, sym_info);

    sym_info.func = "??";
    sym_info.file = "??";
    sym_info.line = "0";
    if (sym_info.has_module_info) {
      // Get raw output
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
  if (g_enclave_base <= pc && pc < g_enclave_base + g_enclave_size) {
    // Fill module name
    if (module_name && module_name_len) {
      strncpy(module_name, "TestEnclave", module_name_len - 1);
      module_name[module_name_len - 1] = '\0';
    }

    // Calculate offset
    if (pc_offset) {
      *pc_offset = pc - g_enclave_base; // Relative offset for enclave
    }
  } else {
    Dl_info info;
    if (dladdr((void *)pc, &info) == 0) {
      return false;
    }

    // Fill module name
    if (module_name && module_name_len) {
      strncpy(module_name, info.dli_fname, module_name_len - 1);
      module_name[module_name_len - 1] = '\0';
    }

    // Calculate offset
    if (pc_offset) {
      if (is_pie(info.dli_fname) > 0) {
        *pc_offset = pc - (uptr)info.dli_fbase; // Relative offset for libraries
      } else {
        *pc_offset = pc; // Absolute address for main app
      }
    }
  }
  return true;
}
}