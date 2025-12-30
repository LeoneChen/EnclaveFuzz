#include "MemAccessMgr.h"

thread_local std::deque<FetchInfo> MemAccessMgr::m_control_fetchs;
__thread bool MemAccessMgr::m_active;
__thread bool MemAccessMgr::m_inited;

extern "C" __attribute__((weak)) bool DFEnableModifyDoubleFetchValue();
extern "C" __attribute__((weak)) uint8_t *DFGetBytesEx(uint8_t *ptr,
                                                       size_t byteArrLen,
                                                       char *cStrAsParamID,
                                                       int dataType);

// C Wrappers
void MemAccessMgrOutEnclaveAccess(const void *ptr, size_t size, bool is_write,
                                  bool used_to_cmp, char *parent_func) {
  if (ptr == nullptr)
    return; // leave it to guard page check
  if (not is_write) {
    auto res =
        MemAccessMgr::double_fetch_detect(ptr, size, used_to_cmp, parent_func);
    if (res) {
      if (DFEnableModifyDoubleFetchValue && DFGetBytesEx &&
          DFEnableModifyDoubleFetchValue()) {
        sgxsan_warning(
            true,
            "Detect Double-Fetch Situation, and modify it with fuzz data\n");
        if (size == sizeof(void *)) {
          // It may be a pointer
          DFGetBytesEx((uint8_t *)ptr, size, nullptr,
                       10 /* FUZZ_DATA_OR_PTR */);
        } else {
          DFGetBytesEx((uint8_t *)ptr, size, nullptr, 2 /* FUZZ_DATA */);
        }
      } else {
        sgxsan_warning(true,
                       "Detect Double-Fetch Situation, but don't modify it\n");
      }
    }
  }
}

void MemAccessMgrActive() { MemAccessMgr::active(); }

void MemAccessMgrDeactive() { MemAccessMgr::deactive(); }

void MemAccessMgrInEnclaveAccess() {}

void MemAccessMgrClear() { MemAccessMgr::clear(); }

bool MemAccessMgrInited() { return MemAccessMgr::inited(); }
