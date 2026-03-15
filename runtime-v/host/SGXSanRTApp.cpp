/// SGXSanRTApp.cpp — SGXSan runtime-v 宿主侧运行时核心实现
///
/// 负责：
///   - 运行时初始化（影子内存 mmap、构造函数）
///   - 信号处理（SIGSEGV 分类诊断）
///   - 日志输出
///   - ECall 嵌套深度计数（TD_init_count）
///   - libfuzzer / libasan 接口桩

#include "SGXSanRTApp.h"
#include "Malloc.h"
#include "MemAccessMgr.h"
#include <iostream>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

/// 各日志级别对应的输出前缀
static const char *log_level_to_prefix[] = {
    "[!] SGXSan ALWAYS: ", "[!] SGXSan ERROR: ", "[!] SGXSan WARNING: ",
    "[!] SGXSan DEBUG: ",  "[!] SGXSan TRACE: ",
};

/// 全局初始化标志（影子内存 mmap 完成后置 true）
bool asan_inited = false;

/// 保存被替换前的信号处理器（暂未使用，保留供将来链式调用）
static struct sigaction g_old_sigact[_NSIG];

// ── 崩溃回调 ─────────────────────────────────────────────────────────────

/// libfuzzer 注册的崩溃回调（通过 __sanitizer_set_death_callback 设置）
static void (*UserDieCallback)(void);

/// Die：不可恢复错误终止点
/// 在退出前先同步 sancov 代理缓冲区，确保 libfuzzer 能读到最新覆盖率
void NORETURN Die() {
  DumpSancov(); // 确保 proxy buffer 最新，再让 libfuzzer 读
  if (UserDieCallback)
    UserDieCallback();
  _Exit(77);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_print_stack_trace() {
  sgxsan_backtrace();
}

/// __sanitizer_acquire_crash_state：原子地获取"崩溃所有权"，
/// 防止多线程同时打印错误报告（参见 sanitizers issue #788）
extern "C" SANITIZER_INTERFACE_ATTRIBUTE int __sanitizer_acquire_crash_state() {
  static volatile int in_crash_state = 0;
  return !__atomic_exchange_n(&in_crash_state, 1, __ATOMIC_RELAXED);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__sanitizer_set_death_callback(void (*callback)(void)) {
  UserDieCallback = callback;
}

// ── 信号处理器 ────────────────────────────────────────────────────────────

/// SIGSEGV 处理器：对页错误地址进行分类诊断后调用 Die()
/// 分类：
///   - 空指针解引用（地址 < page_size）
///   - 影子内存 Guard Page 越界
///   - Shadow Gap 访问（影子内存中间禁用区）
///   - 其他未知页错误
static void sgxsan_sigaction(int signum, siginfo_t *siginfo, void *priv) {
  if (!__sanitizer_acquire_crash_state())
    return;
  (void)signum;
  ucontext_t *ucontext = (ucontext_t *)priv;
  const greg_t rip = ucontext->uc_mcontext.gregs[REG_RIP];
  if (siginfo->si_code == SI_KERNEL) {
    // SI_KERNEL 时 si_addr 不可信（如 vsyscall 触发）
    log_error("#PF Addr Unknown at pc %p\n", (void *)rip);
  } else {
    size_t page_size = getpagesize();
    log_error("#PF Addr %p at pc %p => ", siginfo->si_addr, (void *)rip);

    uint64_t page_fault_addr = (uint64_t)siginfo->si_addr;
    if (page_fault_addr < page_size) {
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

/// 注册 SGXSan 信号处理器（幂等，只注册一次）
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

  AlreadyRegisterSignalHandler = true;
}

// ── 影子内存初始化 ────────────────────────────────────────────────────────

/// 初始化影子内存映射：
///   1. mmap 整个 [kLowShadowGuardBeg, kHighShadowGuardEnd] 区间为读写
///   2. 设置两端 Guard Page 为 PROT_NONE（越界触发 SIGSEGV）
///   3. 设置 Shadow Gap 为 PROT_NONE
///   4. 若 vm.mmap_min_addr == 0，将零地址页设为不可访问
static void sgxsan_init_shadow_memory() {
  size_t page_size = getpagesize();
  sgxsan_assert(page_size == PAGE_SIZE);

  sgxsan_error(mmap((void *)kLowShadowGuardBeg,
                    kHighShadowGuardEnd - kLowShadowGuardBeg + 1,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                    0) == MAP_FAILED,
               "Shadow Memory is not available\n");
  madvise((void *)kLowShadowGuardBeg,
          kHighShadowGuardEnd - kLowShadowGuardBeg + 1, MADV_NOHUGEPAGE);
  sgxsan_error(mprotect((void *)kLowShadowGuardBeg, page_size, PROT_NONE) ||
                   mprotect((void *)(kHighShadowEnd + 1), page_size, PROT_NONE),
               "Failed to make guard page for shadow map\n");
  sgxsan_error(mprotect((void *)kShadowGapBeg,
                        kShadowGapEnd - kShadowGapBeg + 1, PROT_NONE),
               "Failed to make gap in shadow not accessible\n");
}

/// 以表格形式打印影子内存地址空间布局（调试用）
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

/// SGXSanInit：运行时构造函数，在 main 前自动执行
/// 顺序：初始化堆分配器 → 确保 C++ 流已初始化 → mmap 影子内存 → 打印布局
__attribute__((constructor)) void SGXSanInit() {
  if (asan_inited) {
    return;
  }
  InitHeapAllocator();
  // 确保 C++ iostream 在使用日志前已完成初始化
  std::ios_base::Init _init;
  sgxsan_init_shadow_memory();
  PrintAddressSpaceLayout();
  asan_inited = true;
}

// ── 日志实现 ──────────────────────────────────────────────────────────────

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

// ── ECall 桥接深度计数 ────────────────────────────────────────────────────

/// TD_init_count：当前线程的 ECall 嵌套深度计数（根 ECall = 1，嵌套递增）
static __thread int TD_init_count = 0;

/// _hook_tbridge_head：每次进入 ECall 时调用
/// 根 ECall（深度 0→1）时初始化 MemAccessMgr
extern "C" void _hook_tbridge_head() {
  if (TD_init_count == 0) {
    MemAccessMgr::init();
  }
  TD_init_count++;
  sgxsan_assert(TD_init_count < 1024); // 防止无限嵌套
}

/// _hook_tbridge_tail：每次 ECall 返回时调用
/// 根 ECall 返回（深度 1→0）时销毁 MemAccessMgr
extern "C" void _hook_tbridge_tail() {
  if (TD_init_count == 1) {
    MemAccessMgr::destroy();
  }
  TD_init_count--;
  sgxsan_assert(TD_init_count >= 0);
}

/// ClearSGXSanRT：断言当前无嵌套 ECall（Enclave 销毁时调用）
void ClearSGXSanRT() { sgxsan_assert(TD_init_count == 0); }

// ── libasan / libfuzzer 接口桩 ────────────────────────────────────────────
extern "C" {
/// __asan_version_mismatch_check_v8：避免 ASan 版本检查失败（空桩）
void __asan_version_mismatch_check_v8() {}

/// __asan_handle_no_return：noreturn 调用（exit/longjmp/throw）前
/// 将当前线程栈影子内存清零，防止栈复用时产生误报
void __asan_handle_no_return() {
  if (!asan_inited)
    return;
  pthread_attr_t attr;
  void *stack_addr;
  size_t stack_size;
  if (pthread_getattr_np(pthread_self(), &attr) == 0) {
    if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) == 0) {
      uptr stack_top = (uptr)stack_addr + stack_size;
      int local_stack;
      const uptr page_size = (uptr)getpagesize();
      // 从当前栈帧位置向下对齐一页作为清理起始点
      uptr current_bottom = ((uptr)&local_stack - page_size) & ~(page_size - 1);
      if (current_bottom < stack_top)
        PoisonShadow(current_bottom, stack_top - current_bottom,
                     kAsanNotPoisonedMagic, true);
    }
    pthread_attr_destroy(&attr);
  }
}
} // extern "C"
