#include "MemAccessMgr.h"
#include <stack>

extern thread_local std::stack<std::vector<void *>> OCAllocStack;

thread_local std::deque<FetchInfo> MemAccessMgr::m_control_fetchs;
__thread bool MemAccessMgr::m_active;
__thread bool MemAccessMgr::m_inited;

// C Wrappers
extern "C" {
void MemAccessMgrOutEnclaveAccess(const void *ptr, size_t size, bool is_write,
                                  bool used_to_cmp) {
  if (ptr == nullptr)
    return; // leave it to guard page check
  if (not is_write) {
    MemAccessMgr::double_fetch_detect(ptr, size, used_to_cmp);
  }
}

void MemAccessMgrInEnclaveAccess() {}

void MemAccessMgrClear() { MemAccessMgr::clear(); }

bool MemAccessMgrInited() { return MemAccessMgr::inited(); }

void _hook_tproxy_head(void) {
  MemAccessMgr::deactive();
  OCAllocStack.emplace(std::vector<void *>{});
}
void _hook_tproxy_tail(void) {
  MemAccessMgr::active();
  OCAllocStack.pop();
}
void _hook_before_ecall() { MemAccessMgr::active(); };
void _hook_after_ecall() { MemAccessMgr::deactive(); };
}
