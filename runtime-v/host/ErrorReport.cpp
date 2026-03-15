/// ErrorReport.cpp — SGXSan 错误上报实现
///
/// 每个 Report* 函数的输出格式：
///   ================================================================
///   [!] SGXSan ERROR/WARNING: [错误类型] at pc <PC> read/write <addr> with
///   <size> bytes <调用栈> <影子内存快照（若地址合法）>
///   ================================================================

#include "ErrorReport.h"
#include "Malloc.h"
#include "PoisonCheck.h"
#include "Quarantine.h"
#include <stdarg.h>

/// 统一报告分隔线（与 ASan 风格一致）
#define SGXSAN_SEP                                                             \
  "================================================================\n"

// ── 内部辅助函数 ──────────────────────────────────────────────────────────

/// 打印出错地址周围的影子内存内容（以 16 字节为一行，标记目标列）
/// 结果先拼成完整字符串再一次性输出，避免与并发线程的输出交错
static void PrintShadowMap(log_level level, uptr addr) {
  uptr addr_mask = (~(((uptr)1 << ADDR_SPACE_BITS) - 1));
  sgxsan_assert((addr & addr_mask) == 0);
  uptr shadowAddr = MEM_TO_SHADOW(addr);
  uptr shadowRow = RoundDownTo(shadowAddr, 0x10);
  int shadowCol = (int)(shadowAddr - shadowRow);

  sgxsan_assert(shadowRow >= kLowShadowBeg &&
                shadowRow <= (kHighShadowEnd - 0xF));
  // 打印目标行上下各 5 行（各 80 字节影子 = 640 字节应用内存）
  uptr startRow =
      (shadowRow - kLowShadowBeg) > 0x50 ? shadowRow - 0x50 : kLowShadowBeg;
  uptr endRow = (kHighShadowEnd + 1 - shadowRow) > 0x50 ? shadowRow + 0x50
                                                        : (kHighShadowEnd + 1);

  std::string output = "Shadow bytes around the buggy address:\n";
  char buf[BUFSIZ];
  for (uptr i = startRow; i < endRow; i += 0x10) {
    snprintf(buf, BUFSIZ, "%s%p:", i == shadowRow ? "=>" : "  ", (void *)i);
    output += buf;
    for (int j = 0; j < 16; j++) {
      uint8_t val = *(uint8_t *)(i + j);
      if (i == shadowRow && j == shadowCol)
        snprintf(buf, BUFSIZ, "[%02x]", val);
      else if (i == shadowRow && shadowCol < 15 && j == shadowCol + 1)
        snprintf(buf, BUFSIZ, "%02x", val); // ']' 已占用了前置空格
      else
        snprintf(buf, BUFSIZ, " %02x", val);
      output += buf;
    }
    output += " \n";
  }
  output +=
      "Shadow byte legend (one shadow byte represents 8 application bytes):\n"
      "  Addressable:           00\n"
      "  Partially addressable: 01 02 03 04 05 06 07\n"
      "  Data in Enclave:       4X\n"
      "  Stack left redzone:    81\n"
      "  Stack mid redzone:     82\n"
      "  Stack right redzone:   83\n"
      "  Left alloca redzone:   84\n"
      "  Stack after return:    85\n"
      "  Init order:            86\n"
      "  Right alloca redzone:  87\n"
      "  Stack use after scope: 88\n"
      "  Global redzone:        89\n"
      "  Heap left redzone:     8a\n"
      "  Heap right redzone:    8b\n"
      "  Freed Heap region:     8d\n"
      "  ASan internal:         8e\n";
  sgxsan_log(level, false, output.c_str());
}

// ── Report 函数实现 ───────────────────────────────────────────────────────

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, const char *msg, ...) {
  // 若影子内存显示该地址已被释放，转发给 ReportUseAfterFree
  if (AddrIsInMem(addr) and
      L1F(*(uint8_t *)MEM_TO_SHADOW(addr)) == kAsanHeapFreeMagic) {
    ReportUseAfterFree(pc, bp, sp, addr);
    return;
  }
  log_error_np("\n" SGXSAN_SEP "[!] SGXSan ERROR: ");

  char buf[BUFSIZ];
  va_list ap;
  va_start(ap, msg);
  vsnprintf(buf, BUFSIZ, msg, ap);
  va_end(ap);
  sgxsan_log(LOG_LEVEL_ERROR, false, "%s", buf);

  sgxsan_log(LOG_LEVEL_ERROR, false,
             " at pc %p: %s of size 0x%lx at %p (bp=%p sp=%p)\n\n", (void *)pc,
             is_write ? "write" : "read", access_size, (void *)addr, (void *)bp,
             (void *)sp);
  sgxsan_backtrace(LOG_LEVEL_ERROR);
  if (AddrIsInMem(addr))
    PrintShadowMap(LOG_LEVEL_ERROR, addr);
  log_error_np(SGXSAN_SEP);
  Die();
}

/// ReportHeapError：ReportUseAfterFree / ReportDoubleFree 的公共实现
static void ReportHeapError(const char *kind, uptr pc, uptr bp, uptr sp,
                            uptr addr, MallocFreeBT &bt) {
  log_error_np(
      "\n" SGXSAN_SEP "[!] SGXSan ERROR: %s %s %p at pc %p bp %p sp %p\n\n",
      sgx_is_within_enclave((const void *)addr, 1) ? "Enclave" : "Host", kind,
      (void *)addr, (void *)pc, (void *)bp, (void *)sp);
  sgxsan_backtrace(LOG_LEVEL_ERROR);
  log_error_np("\nPreviously malloc at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.malloc_bt, bt.malloc_bt_cnt);
  log_error_np("\nPreviously free at:\n\n");
  sgxsan_dump_bt_buf((void **)bt.free_bt, bt.free_bt_cnt);
  PrintShadowMap(LOG_LEVEL_ERROR, addr);
  log_error_np(SGXSAN_SEP);
  Die();
}

void ReportUseAfterFree(uptr pc, uptr bp, uptr sp, uptr addr) {
  // 从隔离缓存中找到对应的历史分配记录
  auto entry = gQCache->find(addr);
  sgxsan_assert(entry.alloc_beg != (uptr)-1);
  auto *m = (chunk *)(entry.user_beg - sizeof(chunk));
  sgxsan_assert(m->bt);
  ReportHeapError("Use after free", pc, bp, sp, addr, *m->bt);
}

void ReportDoubleFree(uptr pc, uptr bp, uptr sp, uptr addr) {
  auto *m = (chunk *)(addr - sizeof(chunk));
  sgxsan_assert(m->bt);
  ReportHeapError("Double Free", pc, bp, sp, addr, *m->bt);
}

void ReportDoubleFetch(uptr cur_fetch, size_t cur_size, uptr prev_fetch,
                       size_t prev_size, uptr *prev_bt, size_t prev_bt_cnt) {
  // cur_fetch：触发 double-fetch 的当前"使用读取"地址
  // prev_fetch：之前的"控制流读取"地址（两者地址范围重叠即判定为漏洞）
  log_error_np("\n" SGXSAN_SEP
               "[!] SGXSan ERROR: Double fetch 0x%lx(0x%lx)\n\n",
               cur_fetch, cur_size);
  sgxsan_backtrace();
  log_error_np("\nPreviously fetch 0x%lx(0x%lx)\n\n", prev_fetch, prev_size);
  sgxsan_dump_bt_buf((void **)prev_bt, prev_bt_cnt);
  PrintShadowMap(LOG_LEVEL_ERROR, prev_fetch);
  log_error_np(SGXSAN_SEP);
  Die();
}
