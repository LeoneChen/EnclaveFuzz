/// MemAccessMgr.cpp — MemAccessMgr C 接口实现及 OCall 钩子

#include "MemAccessMgr.h"
#include <stack>

/// OCAllocStack：每层 OCall 在 Host 端通过 sgx_ocalloc 分配的内存列表
/// 每次 OCall 入栈一个新 vector，OCall 返回时统一释放
extern thread_local std::stack<std::vector<void *>> OCAllocStack;

// 线程局部静态成员定义
thread_local std::deque<FetchInfo> MemAccessMgr::m_control_fetches;
__thread bool MemAccessMgr::m_active;
__thread bool MemAccessMgr::m_inited;

// ── C 语言接口（供 PoisonCheck 中的插桩回调调用）────────────────────────
extern "C" {

/// Host 内存访问回调：忽略写操作，对读操作执行 double-fetch 检测
void MemAccessMgrOutEnclaveAccess(const void *ptr, size_t size, bool is_write,
                                  bool used_to_cmp) {
  if (ptr == nullptr)
    return; // 空指针由 guard page 处理，此处不介入
  if (not is_write) {
    MemAccessMgr::double_fetch_detect(ptr, size, used_to_cmp);
  }
}

/// Enclave 内存访问回调：当前无需额外操作（影子内存检查已在 PoisonCheck 完成）
void MemAccessMgrInEnclaveAccess() {}

/// 强制清除 MemAccessMgr 状态（enclave 销毁时调用）
void MemAccessMgrClear() { MemAccessMgr::clear(); }

/// 查询当前线程是否已初始化 MemAccessMgr
bool MemAccessMgrInited() { return MemAccessMgr::inited(); }

/// OCall 入口钩子：暂停 double-fetch 监控，并为本次 OCall 压入 ocalloc 栈帧
void _hook_tproxy_head(void) {
  MemAccessMgr::deactivate();
  OCAllocStack.emplace(std::vector<void *>{});
}

/// OCall 出口钩子：恢复 double-fetch 监控，弹出 ocalloc 栈帧
void _hook_tproxy_tail(void) {
  MemAccessMgr::active();
  OCAllocStack.pop();
}

/// ECall 主体开始前激活监控
void _hook_before_ecall() { MemAccessMgr::active(); };

/// ECall 主体结束后暂停监控
void _hook_after_ecall() { MemAccessMgr::deactivate(); };
}
