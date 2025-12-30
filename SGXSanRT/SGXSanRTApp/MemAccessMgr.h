#pragma once

#include "PoisonCheck.h"
#include "SGXSanRTApp.h"
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
  char funcName[FUNC_NAME_MAX_LEN + 1] = {'\0'};
  bool toCmp = false;
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
  static bool double_fetch_detect(const void *ptr, size_t size,
                                  bool used_to_cmp, char *funcName) {
    sgxsan_assert(ptr && size && sgx_is_outside_enclave(ptr, size));
    // there may be ocall and ocall return before enter first ecall, or in
    // hooked mem intrinsics
    if (!m_active or !m_inited)
      return false;
    if (used_to_cmp) {
      // it's a fetch used to compare, maybe used to 'check'
      while (m_control_fetchs.size() >= CONTROL_FETCH_QUEUE_MAX_SIZE) {
        m_control_fetchs.pop_front();
      }
      FetchInfo info;
      info.addr = ptr;
      info.size = size;
      info.toCmp = used_to_cmp;
      strncpy(info.funcName, funcName,
              std::min((size_t)FUNC_NAME_MAX_LEN, strlen(funcName)));
      info.funcName[FUNC_NAME_MAX_LEN] = 0;
      m_control_fetchs.push_back(info);
      return false;
    } else {
      bool result = false;
      // it's a non-compared fetch, maybe used to 'use'
      for (auto &control_fetch : m_control_fetchs) {
        // if parent function name is not known, assume at same function and
        // only check overlap
        bool at_same_func = true;
        if (funcName)
          at_same_func = strncmp(control_fetch.funcName, funcName,
                                 std::min((size_t)FUNC_NAME_MAX_LEN,
                                          strlen(funcName))) == 0;
        bool is_overlap =
            RangesOverlap((const char *)control_fetch.addr, control_fetch.size,
                          (const char *)ptr, size);
        if (at_same_func and is_overlap) {
          result = true;
          break;
        }
      }
      return result;
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
                                  bool used_to_cmp = false,
                                  char *parent_func = nullptr);
void MemAccessMgrInEnclaveAccess();
void MemAccessMgrActive();
void MemAccessMgrDeactive();
void MemAccessMgrClear();
bool MemAccessMgrInited();
#if defined(__cplusplus)
}
#endif
