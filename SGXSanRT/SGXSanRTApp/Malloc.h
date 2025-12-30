#pragma once

#include "Poison.h"
#include "SGXSanRTApp.h"
#include <boost/stacktrace.hpp>
#include <deque>
#include <pthread.h>
#include <stddef.h>
#include <sys/resource.h>
#include <unordered_map>

#if defined(__cplusplus)
extern "C" {
#endif
void updateBackEndHeapAllocator();
void ClearHeapObject();
void *sgxsan_malloc(size_t size);
void sgxsan_free(void *ptr);
void *sgxsan_calloc(size_t n_elements, size_t elem_size);
void *sgxsan_realloc(void *oldmem, size_t bytes);
size_t sgxsan_malloc_usable_size(void *mem);
#if defined(__cplusplus)
}
#endif

// rz_log represent 2^(rz_log+4)
static inline uptr ComputeRZLog(uptr user_requested_size) {
  uint32_t rz_log = user_requested_size <= 64 - 16            ? 0
                    : user_requested_size <= 128 - 32         ? 1
                    : user_requested_size <= 512 - 64         ? 2
                    : user_requested_size <= 4096 - 128       ? 3
                    : user_requested_size <= (1 << 14) - 256  ? 4
                    : user_requested_size <= (1 << 15) - 512  ? 5
                    : user_requested_size <= (1 << 16) - 1024 ? 6
                                                              : 7;

  return rz_log;
}

static inline uint32_t RZLog2Size(uint32_t rz_log) {
  sgxsan_error(rz_log >= 8, "rz_log>= 8\n");
  return 16 << rz_log;
}

static inline uptr ComputeRZSize(uptr size) { return 16 << ComputeRZLog(size); }

void update_heap_usage(void *ptr, bool true_add_false_minus = true);

extern "C" __attribute__((weak)) bool DFEnableCollectStack();
class SGXSanHeapBacktrace {
public:
  SGXSanHeapBacktrace() { pthread_rwlock_init(&mRWLock, nullptr); }

  void StoreMallocBT(uptr user_beg) {
    if (not DFEnableCollectStack or DFEnableCollectStack()) {
      pthread_rwlock_wrlock(&mRWLock);
      auto &BT = mUserBeg2BT[user_beg];
      BT.malloc_bt_cnt = boost::stacktrace::safe_dump_to(
          BT.malloc_bt, sizeof(decltype(BT.malloc_bt)));
      BT.free_bt_cnt = 0;
      pthread_rwlock_unlock(&mRWLock);
    }
  }

  void StoreFreeBT(uptr user_beg) {
    if (not DFEnableCollectStack or DFEnableCollectStack()) {
      pthread_rwlock_wrlock(&mRWLock);
      auto &BT = mUserBeg2BT[user_beg];
      BT.free_bt_cnt = boost::stacktrace::safe_dump_to(
          BT.free_bt, sizeof(decltype(BT.free_bt)));
      pthread_rwlock_unlock(&mRWLock);
    }
  }

  void RemoveBT(uptr user_beg) {
    if (not DFEnableCollectStack or DFEnableCollectStack()) {
      pthread_rwlock_wrlock(&mRWLock);
      mUserBeg2BT.erase(user_beg);
      pthread_rwlock_unlock(&mRWLock);
    }
  }

  MallocFreeBTTy GetHeapBacktrace(uptr user_beg) {
    if (not DFEnableCollectStack or DFEnableCollectStack()) {
      pthread_rwlock_rdlock(&mRWLock);
      auto bt = mUserBeg2BT[user_beg];
      pthread_rwlock_unlock(&mRWLock);
      return bt;
    } else {
      return MallocFreeBTTy();
    }
  }

private:
  std::unordered_map<uptr, MallocFreeBTTy> mUserBeg2BT;
  pthread_rwlock_t mRWLock;
};

extern SGXSanHeapBacktrace *gHeapBT;

struct QuarantineElement {
  uptr alloc_beg;
  uptr alloc_size;
  uptr user_beg;
  uptr user_size;
};

typedef std::deque<QuarantineElement> QuarantineQueueTy;

#define SGXSAN_MAX_QUARANTINE_SIZE 0x10000000

class QuarantineCache {
public:
  QuarantineCache() {
    auto p = malloc(sizeof(QuarantineQueueTy));
    sgxsan_assert(p != nullptr);
    update_heap_usage(p);
    m_queue = new (p) QuarantineQueueTy();
    sgxsan_assert(m_queue != nullptr);
    m_mutex = PTHREAD_MUTEX_INITIALIZER;
    m_used_size = 0;
    // Calculate suitable quarantine size
    struct rlimit64 limit64;
    sgxsan_assert(getrlimit64(RLIMIT_DATA, &limit64) == 0);
    struct rlimit limit;
    sgxsan_assert(getrlimit(RLIMIT_DATA, &limit) == 0);
    m_max_size = std::min(std::min(limit64.rlim_cur, limit.rlim_cur) >> 4,
                          (size_t)SGXSAN_MAX_QUARANTINE_SIZE);
  }

  ~QuarantineCache() {
    sgxsan_assert(m_queue != nullptr);
    // free memory recorded in Quarantine, not only the struct that record
    // Quarantine
    while (not empty())
      freeOldestQuarantineElement();
    // free struct that record Quarantine
    m_queue->~deque();
    update_heap_usage(m_queue, false);
    free(m_queue);
    m_queue = nullptr;
    m_used_size = 0;
    m_max_size = 0;
  }

  QuarantineElement find(uptr addr) {
    pthread_mutex_lock(&m_mutex);
    auto it = std::find_if(
        m_queue->begin(), m_queue->end(), [addr](QuarantineElement qe) {
          return qe.user_beg <= addr and
                 addr < qe.user_beg + qe.user_size + (1 << SHADOW_SCALE);
        });
    QuarantineElement ret;
    ret.alloc_beg = -1;
    if (it != m_queue->end()) {
      ret = *it;
    }
    pthread_mutex_unlock(&m_mutex);
    return ret;
  }

  void show();

  void put(QuarantineElement qe) {
    pthread_mutex_lock(&m_mutex);
    if (m_queue == nullptr) {
      freeDirectly(qe);
      goto out;
    }

    if (m_queue->empty()) {
      sgxsan_assert(m_used_size == 0);
    }

    // if cache can not hold this element, directly free it
    if (qe.alloc_size > m_max_size) {
      freeDirectly(qe);
    } else {
      // pop queue util it can hold new element
      while (UNLIKELY((!m_queue->empty()) &&
                      (m_used_size + qe.alloc_size > m_max_size))) {
        freeOldestQuarantineElement();
        if (m_queue->empty()) {
          sgxsan_assert(m_used_size == 0);
        }
      }
      log_trace("[Put to Quaratine] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n",
                qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size,
                qe.alloc_beg + qe.alloc_size);
      gHeapBT->StoreFreeBT(qe.user_beg);
      m_queue->push_back(qe);
      m_used_size += qe.alloc_size;
    }
  out:
    pthread_mutex_unlock(&m_mutex);
  }

private:
  void freeQuarantineElement(QuarantineElement qe) {
    update_heap_usage((void *)qe.alloc_beg, false);
    gHeapBT->RemoveBT(qe.user_beg);
    free(reinterpret_cast<void *>(qe.alloc_beg));
    log_trace("[Free QuarantineElement] [0x%lx..0x%lx ~ 0x%lx..0x%lx) \n",
              qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size,
              qe.alloc_beg + qe.alloc_size);
    PoisonShadow(qe.alloc_beg, qe.alloc_size, kAsanHeapLeftRedzoneMagic, true);
    // update quarantine cache
    sgxsan_assert(m_used_size >= qe.alloc_size);
    m_used_size -= qe.alloc_size;
  }
  void freeDirectly(QuarantineElement qe) {
    update_heap_usage((void *)qe.alloc_beg, false);
    gHeapBT->RemoveBT(qe.user_beg);
    free((void *)qe.alloc_beg);
    log_trace("[Direct Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg,
              qe.user_beg, qe.user_beg + qe.user_size,
              qe.alloc_beg + qe.alloc_size);
    FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, SHADOW_GRANULARITY),
                     kAsanHeapLeftRedzoneMagic);
  }
  void freeOldestQuarantineElement() {
    QuarantineElement front_qe = m_queue->front();
    // free and poison
    freeQuarantineElement(front_qe);
    m_queue->pop_front();
  }
  bool empty() { return m_queue->empty(); }

  QuarantineQueueTy *m_queue;
  size_t m_used_size;
  size_t m_max_size;
  pthread_mutex_t m_mutex;
};

extern QuarantineCache *gQCache;
