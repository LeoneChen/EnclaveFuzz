#pragma once

/// MemAccessMgr.h — ECall 内存访问管理器
///
/// 每次根 ECall 执行期间，MemAccessMgr 跟踪从 Enclave 内部发起的
/// Host 内存读取操作，用于检测 double-fetch 漏洞：
///   - "控制流读取"（toCmp=true）：用于条件判断/检查的外部内存读，
///     会被记录进 m_control_fetches 队列
///   - "使用读取"（toCmp=false）：实际使用数据的读，若与已记录的
///     控制流读取地址重叠，则上报 double-fetch 错误
///
/// 生命周期：
///   init()   在每次根 ECall 前调用
///   destroy() 在根 ECall 返回后调用
///   active/deactive 在 OCall 入口/出口调用，暂停/恢复监控

#include "ErrorReport.h"
#include "PoisonCheck.h"
#include "SGXSanRTApp.h"
#include <boost/stacktrace.hpp>
#include <cstddef>
#include <cstdint>
#include <deque>

/// 控制流读取队列最大容量（超出则淘汰最早的条目）
static constexpr size_t kControlFetchQueueMaxSize = 3;

/// 单次外部内存读取信息（用于 double-fetch 检测）
struct FetchInfo {
  const void *addr = nullptr;    // 读取的起始地址
  size_t size = 0;               // 读取字节数
  bool is_control_fetch = false; // 是否为控制流比较读取
  size_t bt_cnt;                 // 调用栈帧数
  uptr bt[30];                   // 调用栈帧地址
};

class MemAccessMgr {
public:
  /// 根 ECall 开始前初始化（断言队列为空、未激活）
  static void init() {
    sgxsan_assert(m_control_fetches.empty() and m_active == false and
                  m_inited == false);
    m_inited = true;
  }

  /// 根 ECall 返回后清理
  static void destroy() {
    sgxsan_assert(m_active == false);
    m_control_fetches.clear();
    m_inited = false;
  }

  /// 进入 ECall 主体时激活监控（由 _hook_before_ecall 调用）
  static void active() {
    if (m_inited) {
      m_active = true;
    }
  }

  /// 进入 OCall 时暂停监控（由 _hook_tproxy_head 调用）
  static void deactivate() {
    if (m_inited) {
      m_active = false;
    }
  }

  /// double-fetch 检测核心逻辑
  /// ptr 必须是外部（Host）内存的 Load 指令访问点
  static void double_fetch_detect(const void *ptr, size_t size,
                                  bool used_to_cmp) {
    sgxsan_assert(ptr && size && sgx_is_outside_enclave(ptr, size));
    // OCall 期间或 ECall 未初始化时不检测
    if (m_active) {
      if (used_to_cmp) {
        // 控制流读取：加入队列，超出上限时淘汰最旧条目
        while (m_control_fetches.size() >= kControlFetchQueueMaxSize) {
          m_control_fetches.pop_front();
        }

        FetchInfo info = {
            .addr = ptr, .size = size, .is_control_fetch = used_to_cmp};
        if (DFEnableCollectStack) {
          info.bt_cnt = boost::stacktrace::safe_dump_to(
              info.bt, sizeof(decltype(info.bt)));
        }
        m_control_fetches.push_back(info);
      } else {
        // 使用读取：检查是否与已记录的控制流读取地址重叠
        for (auto &cmp_fetch : m_control_fetches) {
          if (RangesOverlap((const char *)cmp_fetch.addr, cmp_fetch.size,
                            (const char *)ptr, size)) {
            ReportDoubleFetch((uptr)ptr, size, (uptr)cmp_fetch.addr,
                              cmp_fetch.size, cmp_fetch.bt, cmp_fetch.bt_cnt);
          }
        }
      }
    }
  }

  /// 强制清除所有状态（enclave 销毁时调用）
  static void clear() {
    m_control_fetches.clear();
    m_active = false;
    m_inited = false;
  }
  static bool inited() { return m_inited; }

private:
  /// 当前 ECall 中记录的控制流读取队列（线程本地）
  static thread_local std::deque<FetchInfo> m_control_fetches;
  /// 是否处于监控激活状态（ECall 主体执行期间为 true，OCall 期间为 false）
  static __thread bool m_active;
  /// 当前线程是否已为某次根 ECall 完成初始化
  static __thread bool m_inited;
};

// MemAccessMgr 的 C 语言接口（供 ASan 插桩回调使用）
#if defined(__cplusplus)
extern "C" {
#endif
void MemAccessMgrOutEnclaveAccess(const void *start, size_t size, bool is_write,
                                  bool used_to_cmp = false);
void MemAccessMgrInEnclaveAccess();
void MemAccessMgrClear();
bool MemAccessMgrInited();
#if defined(__cplusplus)
}
#endif
