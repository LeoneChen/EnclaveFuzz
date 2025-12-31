#include "MemAccessMgr.h"

thread_local std::deque<FetchInfo> MemAccessMgr::m_control_fetchs;
__thread bool MemAccessMgr::m_active;
__thread bool MemAccessMgr::m_inited;

// C Wrappers
void MemAccessMgrOutEnclaveAccess(const void *ptr, size_t size, bool is_write,
                                  bool used_to_cmp, char *parent_func) {
  if (ptr == nullptr)
    return; // leave it to guard page check
  if (not is_write) {
    auto res =
        MemAccessMgr::double_fetch_detect(ptr, size, used_to_cmp, parent_func);
    sgxsan_error(res, "Detect Double-Fetch\n");
  }
}

void MemAccessMgrActive() { MemAccessMgr::active(); }

void MemAccessMgrDeactive() { MemAccessMgr::deactive(); }

void MemAccessMgrInEnclaveAccess() {}

void MemAccessMgrClear() { MemAccessMgr::clear(); }

bool MemAccessMgrInited() { return MemAccessMgr::inited(); }
