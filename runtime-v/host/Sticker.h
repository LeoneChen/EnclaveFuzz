#pragma once

/// Sticker.h — Enclave 模拟层（EnclaveInfo）接口
///
/// EnclaveInfo 维护当前加载的 Enclave 的元信息：
///   - 文件路径（绝对路径）
///   - dlopen 返回的 link_map handler
///   - 各 PT_LOAD 段的地址范围（用于判断代码指针是否来自 Enclave、sancov PC
///   归一化等）
///
/// RunInEnclave：线程局部标志，标记当前线程是否处于 Enclave 执行上下文
///   true  — 正在执行 ECall 主体（影子内存写入时叠加 InEnclave 标志）
///   false — 在 Host 侧或 OCall 期间

#include "Malloc.h"
#include "SGXSanRTApp.h"
#include <elf.h>
#include <link.h>
#include <map>

/// 地址范围映射类型：segment_start → segment_end
typedef std::map<uptr, uptr> AddrRangeMap;

/// ECall 权限检查类型
enum ECallCheck {
  CHECK_ECALL_PRIVATE, // 检查是否为私有 ECall（根调用不允许直接调用）
  CHECK_ECALL_ALLOWED, // 检查是否在当前 OCall 允许的 ECall 列表中
};

/// RunInEnclave：当前线程是否处于 Enclave 执行上下文
extern bool __thread RunInEnclave;

#if defined(__cplusplus)
extern "C" {
#endif
/// dl_iterate_phdr 回调：查找 Enclave DSO 并记录其 PT_LOAD 段范围
int dlItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size, void *data);
#if defined(__cplusplus)
}
#endif

class EnclaveInfo {
public:
  std::string GetEnclaveFileName() { return m_filename; }
  void SetEnclaveFileName(std::string fileName) { m_filename = fileName; }

  void SetHandler(struct link_map *handler) { m_handler = handler; }
  struct link_map *GetHandler() { return m_handler; }

  /// 判断地址 [addr, addr+len) 是否落在 Enclave DSO 的某个 PT_LOAD 段内
  bool isInEnclaveDSORange(uptr addr, size_t len) {
    for (auto pair : m_dso_ranges) {
      // 各段范围不重叠，只要有一个段包含该地址即返回 true
      if (pair.first <= addr and (addr + len) < pair.second) {
        return true;
      }
    }
    return false;
  }

  /// 清除所有 Enclave 元信息（Enclave 销毁时调用）
  void Clear() {
    m_filename = "";
    m_start_addr = 0;
    m_dso_ranges.clear();
    m_handler = nullptr;
  }

  /// 获取所有 PT_LOAD 段的合并地址范围（最小 start，最大 end）
  void GetEnclaveDSORange(uptr *start, uptr *end) {
    int count = 0;
    for (auto pair : m_dso_ranges) {
      if (count == 0) {
        *start = pair.first;
        *end = pair.second;
      } else {
        *start = std::min(*start, pair.first);
        *end = std::max(*end, pair.second);
      }
      count++;
    }
  }

  /// dl_iterate_phdr 回调实现：遍历目标 DSO 的所有 PT_LOAD 段并记录范围
  int DLItCBGetEnclaveDSO(struct dl_phdr_info *info, size_t size, void *data) {
    auto EnclaveDSOStart = *(uptr *)data;
    if (EnclaveDSOStart == info->dlpi_addr) {
      for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD) {
          uptr beg =
              RoundDownTo(EnclaveDSOStart + phdr->p_vaddr, phdr->p_align);
          uptr end =
              RoundUpTo(EnclaveDSOStart + phdr->p_vaddr + phdr->p_memsz - 1,
                        phdr->p_align);
          m_dso_ranges[beg] = end;
          log_debug("%s: [%p, %p]\n", info->dlpi_name, (void *)beg,
                    (void *)end);
        }
      }
      return 1; // 找到目标 DSO，停止迭代
    } else {
      return 0; // 继续迭代
    }
  }

  /// 将 Enclave 代码段在影子内存中标记为 NotPoisoned + InEnclave
  void PoisonEnclaveDSOCode();

private:
  std::string m_filename = "";
  uptr m_start_addr;
  /// PT_LOAD 段地址范围：segment_start → segment_end
  AddrRangeMap m_dso_ranges;
  struct link_map *m_handler;
};

/// 全局 Enclave 信息实例（单 Enclave 场景）
extern EnclaveInfo gEnclaveInfo;
