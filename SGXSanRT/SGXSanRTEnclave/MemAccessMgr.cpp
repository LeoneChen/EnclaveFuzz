#include "MemAccessMgr.hpp"
#include "PoisonCheck.hpp"
#include "SGXSanRTConfig.h"
#include <deque>
#include <sgx_trts.h>
#include <string.h>

#define FUNC_NAME_MAX_LEN 127
#define CONTROL_FETCH_QUEUE_MAX_SIZE 3
struct FetchInfo {
  const void *start_addr = nullptr;
  size_t size = 0;
  bool used_to_cmp = false;
};

class MemAccessMgr {
public:
  // add at TBridge
  static void init() {
    m_inited = true;
    m_active = false;
    m_control_fetchs = new std::deque<FetchInfo>();
  }

  static void destroy() {
    delete m_control_fetchs;
    m_control_fetchs = nullptr;
    m_active = false;
    m_inited = false;
  }

  static void active() { m_active = true; }

  static void deactive() { m_active = false; }

  static void add_out_of_enclave_access_cnt() {}

  static void add_in_enclave_access_cnt() {}

  static void double_fetch_detect(const void *ptr, size_t size,
                                  bool used_to_cmp) {
    sgxsan_assert(ptr && size > 0 && sgx_is_outside_enclave(ptr, size));
    // there may be ocall and ocall return before enter first ecall
    // When before ECall, OCall is called and return, m_active will set to true
    // but m_inited is still false
    if (!m_active or !m_inited)
      return;
    sgxsan_assert(m_control_fetchs);
    if (used_to_cmp) {
      // it's a fetch used to compare, maybe used to 'check'
      while (m_control_fetchs->size() >= CONTROL_FETCH_QUEUE_MAX_SIZE) {
        m_control_fetchs->pop_front();
      }
      FetchInfo info;
      info.start_addr = ptr;
      info.size = size;
      info.used_to_cmp = used_to_cmp;
      m_control_fetchs->push_back(info);
      return;
    } else {
      // it's a non-compared fetch, maybe used to 'use'
      for (auto &control_fetch : *m_control_fetchs) {
        bool is_overlap =
            RangesOverlap((const char *)control_fetch.start_addr,
                          control_fetch.size, (const char *)ptr, size);
        sgxsan_error(is_overlap, "Detect Double-Fetch Situation\n");
      }
      return;
    }
  }

private:
  static __thread bool m_inited;
  static __thread bool m_active;
  static __thread std::deque<FetchInfo> *m_control_fetchs;
};

__thread bool MemAccessMgr::m_inited;
__thread bool MemAccessMgr::m_active;
__thread std::deque<FetchInfo> *MemAccessMgr::m_control_fetchs;

// a list of c wrapper of MemAccessMgr that exported for use
void MemAccessMgrInit() { MemAccessMgr::init(); }

void MemAccessMgrDestroy() { MemAccessMgr::destroy(); }

void MemAccessMgrActive() { MemAccessMgr::active(); }

void MemAccessMgrDeactive() { MemAccessMgr::deactive(); }

void MemAccessMgrOutEnclaveAccess(const void *ptr, size_t size, bool is_write,
                                  bool used_to_cmp, char *parent_func) {
  if (ptr == nullptr)
    return;
  if (not is_write) {
    MemAccessMgr::double_fetch_detect(ptr, size, used_to_cmp);
  }
  MemAccessMgr::add_out_of_enclave_access_cnt();
}

void MemAccessMgrInEnclaveAccess() {
  MemAccessMgr::add_in_enclave_access_cnt();
}
