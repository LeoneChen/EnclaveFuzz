/// Symbolizer.cpp — sancov 代理方案、addr2line 符号化与调用栈打印
///
/// ── sancov 代理方案 ──────────────────────────────────────────────────────
/// libfuzzer 要求覆盖率缓冲区地址在整个进程生命周期内稳定，
/// 但 Enclave SO 每次 dlopen/dlclose 都会改变实际映射地址。
///
/// 解决方案：在首次加载 Enclave 前分配一组"代理缓冲区"注册给 libfuzzer，
/// 每次 dlclose 前将 Enclave 内的真实计数器/PC 表复制到代理缓冲区。
/// PC 值做归一化：absolute_pc → (pc - enclave_base + ENCLAVE_FAKE_BASE)，
/// 使 addr2line 可用固定假基址对 Enclave 二进制进行符号化。
///
/// ── 符号化 ───────────────────────────────────────────────────────────────
/// 使用 llvm-addr2line-13 对每个 PC 进行符号化，结果缓存在线程局部 map 中。
/// 同时实现 libfuzzer/libasan 要求的 __sanitizer_symbolize_pc 和
/// __sanitizer_get_module_and_offset_for_pc 接口。

#include "SGXSanRTApp.h"
#include "Sticker.h"
#include <array>
#include <boost/stacktrace.hpp>
#include <dlfcn.h>
#include <memory>
#include <sstream>
#include <stdint.h>
#include <string>
#include <sys/mman.h>
#include <unordered_map>

// ── sancov 代理缓冲区 ─────────────────────────────────────────────────────
/// 假基址：用于 PC 归一化，使 addr2line 可以用固定地址符号化 Enclave 二进制
#define ENCLAVE_FAKE_BASE 0x400000000UL
/// 假地址空间大小：须大于 Enclave 虚拟大小
#define ENCLAVE_FAKE_SIZE (256UL * 1024 * 1024)

/// 注册给 libfuzzer 的代理缓冲区（生命周期与进程相同，永不释放）
static uint8_t *g_sancov_proxy_cntrs_start = nullptr;
static uint8_t *g_sancov_proxy_cntrs_end = nullptr;
static uintptr_t *g_sancov_proxy_pcs_start = nullptr;
static uintptr_t *g_sancov_proxy_pcs_end = nullptr;

/// Enclave 侧真实 sancov 段地址（由 Enclave 的 sancov 钩子回调设置）
static uint8_t *g_sancov_enclave_cntrs_start = nullptr;
static uint8_t *g_sancov_enclave_cntrs_end = nullptr;
static const uintptr_t *g_sancov_enclave_pcs_start = nullptr;
static const uintptr_t *g_sancov_enclave_pcs_end = nullptr;

/// 由 Enclave sancov 钩子回调：保存 Enclave 计数器段地址
extern "C" void SGXSanSaveEnclaveCntrsRange(uint8_t *Start, uint8_t *Stop) {
  g_sancov_enclave_cntrs_start = Start;
  g_sancov_enclave_cntrs_end = Stop;
}

/// 由 Enclave sancov 钩子回调：保存 Enclave PC 表段地址
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

/// sgxsan_exec：执行 shell 命令并返回其 stdout 输出
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

/// sancov_copy_init：在 Enclave 加载后、fuzzer 启动前初始化 sancov 代理方案
/// 流程：
///   1. 用 `size` 命令读取 Enclave ELF 中 __sancov_cntrs / __sancov_pcs 段大小
///   2. 分配等大的代理缓冲区
///   3. mmap 假基址区间（防止真实映射占用该地址）
///   4. 将代理缓冲区注册给 libfuzzer
void sancov_copy_init() {
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
               "sancov_copy_init: proxy buffer allocation failed\n");
  g_sancov_proxy_cntrs_end = g_sancov_proxy_cntrs_start + cntrs_size;
  g_sancov_proxy_pcs_end =
      (uintptr_t *)((uint8_t *)g_sancov_proxy_pcs_start + pcs_size);

  // Reserve fake address range to avoid collisions with real mappings
  void *ret = mmap((void *)ENCLAVE_FAKE_BASE, ENCLAVE_FAKE_SIZE, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  sgxsan_error(ret == MAP_FAILED,
               "sancov_copy_init fatal: failed to reserve fake enclave base 0x%lx, "
               "symbolization may be inaccurate\n",
               ENCLAVE_FAKE_BASE);

  // Register proxy with libfuzzer (RunInEnclave=false, hooks forward to real)
  __sanitizer_cov_8bit_counters_init(g_sancov_proxy_cntrs_start,
                                     g_sancov_proxy_cntrs_end);
  __sanitizer_cov_pcs_init(g_sancov_proxy_pcs_start, g_sancov_proxy_pcs_end);
}

/// DumpSancov：在 dlclose 前将 Enclave 侧计数器/PC 表同步到代理缓冲区
/// PC 归一化：absolute_pc → (pc - enclave_base + ENCLAVE_FAKE_BASE)
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

// ── 符号化与调用栈打印 ────────────────────────────────────────────────────

/// 单个 PC 地址对应的符号信息（func/file/line + 模块路径与 PIE 状态）
struct SymbolInfo {
  std::string func;
  std::string file;
  std::string line;
  std::string module_path;
  uptr module_base;
  bool has_module_info;
  int is_pie_result;
};

/// 线程局部符号化缓存（避免对同一 PC 重复调用 addr2line）
static thread_local std::unordered_map<uptr, SymbolInfo> symbolize_cache;

/// 判断给定 ELF 文件是否为 PIE（ET_DYN）
/// 返回 1=PIE，0=非PIE，-1=无法读取
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

/// 解析 PC 对应的模块信息：
/// - 若 PC 在假基址范围内，认定为 Enclave 代码，模块为 "TestEnclave"
/// - 否则用 dladdr 查找所属共享库
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

/// 调用 llvm-addr2line-13 对给定模块内的地址进行符号化
/// PIE 模块使用 --adjust-vma 传入加载基址以正确计算偏移
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

/// 将 void* 地址数组逐帧符号化并输出（用于 malloc/free 调用栈打印）
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

/// 采集当前调用栈并符号化打印（ll 低于 USED_LOG_LEVEL 时跳过）
void sgxsan_backtrace(log_level ll) {
  if (ll > USED_LOG_LEVEL)
    return;

  constexpr size_t max_bt_count = 100;
  uint64_t bt_buf[max_bt_count];
  size_t bt_cnt =
      boost::stacktrace::safe_dump_to(bt_buf, sizeof(decltype(bt_buf)));
  sgxsan_dump_bt_buf((void **)bt_buf, bt_cnt);
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
    sym_info = it->second;
  } else {
    sym_info.func = "??";
    sym_info.file = "??";
    sym_info.line = "0";

    if (resolve_module_info(pc, sym_info)) {
      std::string output =
          run_addr2line(sym_info.module_path.c_str(), pc,
                        sym_info.is_pie_result, sym_info.module_base);
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
      out << "0";
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
        out << "(0x" << std::hex << pc << std::dec << ")";
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

  if (module_name && module_name_len) {
    strncpy(module_name, sym_info.module_path.c_str(), module_name_len - 1);
    module_name[module_name_len - 1] = '\0';
  }

  if (pc_offset) {
    *pc_offset = sym_info.is_pie_result > 0 ? pc - sym_info.module_base : pc;
  }

  return true;
}
} // extern "C"
