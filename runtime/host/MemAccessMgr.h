#pragma once

#include "PoisonCheck.h"
#include "SGXSanRTApp.h"
#include <boost/stacktrace.hpp>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FUNC_NAME_MAX_LEN 127
#define CONTROL_FETCH_QUEUE_MAX_SIZE 3

struct FetchInfo {
  const void *addr = nullptr;
  size_t size = 0;
  bool toCmp = false;
  size_t bt_cnt;
  uptr bt[30];
};

class MemAccessMgr {
public:
  /* Statistics each ECall */
  // Called before root ECall
  static void init() {
    sgxsan_assert(m_control_fetchs.empty() and m_active == false and
                  m_inited == false);
    m_inited = true;
  }

  // Called after root ECall return
  static void destroy() {
    sgxsan_assert(m_active == false);
    m_control_fetchs.clear();
    m_inited = false;
  }

  static void active() {
    if (m_inited) {
      m_active = true;
    }
  }

  static void deactive() {
    if (m_inited) {
      m_active = false;
    }
  }

  // fetch must be a LoadInst
  static void double_fetch_detect(const void *ptr, size_t size,
                                  bool used_to_cmp) {
    sgxsan_assert(ptr && size && sgx_is_outside_enclave(ptr, size));
    // there may be ocall and ocall return before enter first ecall, or in
    // hooked mem intrinsics
    if (m_active && m_inited) {
      if (used_to_cmp) {
        // it's a fetch used to compare, maybe used to 'check'
        while (m_control_fetchs.size() >= CONTROL_FETCH_QUEUE_MAX_SIZE) {
          m_control_fetchs.pop_front();
        }

        FetchInfo info = {.addr = ptr, .size = size, .toCmp = used_to_cmp};
        if (DFEnableCollectStack) {
          info.bt_cnt = boost::stacktrace::safe_dump_to(
              info.bt, sizeof(decltype(info.bt)));
        }
        m_control_fetchs.push_back(info);
      } else {
        // it's a non-compared fetch, maybe used to 'use'
        for (auto &cmp_fetch : m_control_fetchs) {
          // only check overlap
          if (RangesOverlap((const char *)cmp_fetch.addr, cmp_fetch.size,
                            (const char *)ptr, size)) {
            ReportDoubleFetch((uptr)ptr, size, (uptr)cmp_fetch.addr,
                              cmp_fetch.size, cmp_fetch.bt, cmp_fetch.bt_cnt);
          }
        }
      }
    }
  }

  static void clear() {
    m_control_fetchs.clear();
    m_active = false;
    m_inited = false;
  }
  static bool inited() { return m_inited; }

private:
  static thread_local std::deque<FetchInfo> m_control_fetchs;
  // used in nested ecall-ocall case
  static __thread bool m_active;
  static __thread bool m_inited;
};

// Callback of SGXSan
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
