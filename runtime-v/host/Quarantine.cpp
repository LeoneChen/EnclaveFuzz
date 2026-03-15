/// Quarantine.cpp — 堆释放隔离缓存实现

#include "Quarantine.h"
#include "Malloc.h"
#include <algorithm>
#include <boost/stacktrace.hpp>

QuarantineCache::QuarantineCache() {
  m_queue = new QuarantineQueue();
  update_heap_usage(m_queue);
  m_mutex = PTHREAD_MUTEX_INITIALIZER;
  m_used_size = 0;
  // 根据系统数据段资源限制动态确定隔离缓存上限
  // 取 RLIMIT_DATA (64-bit/32-bit) 的较小值的 1/16，再与硬编码上限取最小值
  struct rlimit64 limit64;
  sgxsan_assert(getrlimit64(RLIMIT_DATA, &limit64) == 0);
  struct rlimit limit;
  sgxsan_assert(getrlimit(RLIMIT_DATA, &limit) == 0);
  m_max_size = std::min(std::min(limit64.rlim_cur, limit.rlim_cur) >> 4,
                        (size_t)SGXSAN_MAX_QUARANTINE_SIZE);
}

QuarantineCache::~QuarantineCache() {
  sgxsan_assert(m_queue != nullptr);
  // 先逐一释放队列中所有隔离块的实际内存
  while (not empty())
    freeOldestQuarantineElement();
  update_heap_usage(m_queue, false);
  delete m_queue;
  m_queue = nullptr;
  m_used_size = 0;
  m_max_size = 0;
}

/// 在队列中查找包含 addr 的隔离条目
/// 匹配范围：[user_beg, user_beg + user_size + redzone_size)
/// 未找到时返回 alloc_beg == -1 的哨兵元素
QuarantineElement QuarantineCache::find(uptr addr) {
  pthread_mutex_lock(&m_mutex);
  auto it = std::find_if(
      m_queue->begin(), m_queue->end(), [addr](QuarantineElement qe) {
        return qe.user_beg <= addr and
               addr < qe.user_beg + qe.user_size + (1 << SHADOW_SCALE);
      });
  QuarantineElement ret;
  ret.alloc_beg = -1; // 哨兵：未找到
  if (it != m_queue->end()) {
    ret = *it;
  }
  pthread_mutex_unlock(&m_mutex);
  return ret;
}

/// 打印所有隔离条目（调试）
void QuarantineCache::show() {
  for (auto &qe : *m_queue) {
    log_always("[SHOW] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg,
               qe.user_beg, qe.user_beg + qe.user_size,
               qe.alloc_beg + qe.alloc_size);
  }
}

/// 将释放的堆块加入隔离队列
/// 若单块超出最大容量则直接释放；否则淘汰旧条目直至有足够空间
void QuarantineCache::put(QuarantineElement qe) {
  pthread_mutex_lock(&m_mutex);
  if (m_queue->empty()) {
    sgxsan_assert(m_used_size == 0);
  }

  if (qe.alloc_size > m_max_size) {
    // 单块超出最大容量，跳过隔离直接释放
    freeDirectly(qe);
  } else {
    // 淘汰队首旧条目，直至队列有足够空间容纳新条目
    while (UNLIKELY((!m_queue->empty()) &&
                    (m_used_size + qe.alloc_size > m_max_size))) {
      freeOldestQuarantineElement();
      if (m_queue->empty()) {
        sgxsan_assert(m_used_size == 0);
      }
    }
    log_trace("[Put to Quarantine] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n",
              qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size,
              qe.alloc_beg + qe.alloc_size);
    if (DFEnableCollectStack) {
      auto *m = (chunk *)(qe.user_beg - sizeof(chunk));
      if (m->bt)
        m->bt->free_bt_cnt = boost::stacktrace::safe_dump_to(
            m->bt->free_bt, sizeof(m->bt->free_bt));
    }
    m_queue->push_back(qe);
    m_used_size += qe.alloc_size;
  }
  pthread_mutex_unlock(&m_mutex);
}

/// 释放隔离条目：还原影子内存 → 删除调用栈记录 → 调用 free()
void QuarantineCache::freeQuarantineElement(QuarantineElement qe) {
  update_heap_usage((void *)qe.alloc_beg, false);
  auto *m_qe = (chunk *)(qe.user_beg - sizeof(chunk));
  delete m_qe->bt;
  m_qe->bt = nullptr;
  free(reinterpret_cast<void *>(qe.alloc_beg));
  log_trace("[Free QuarantineElement] [0x%lx..0x%lx ~ 0x%lx..0x%lx) \n",
            qe.alloc_beg, qe.user_beg, qe.user_beg + qe.user_size,
            qe.alloc_beg + qe.alloc_size);
  // skipInEnclaveTag=true：直接写 0，不带 InEnclave 位
  PoisonShadow(qe.alloc_beg, qe.alloc_size, kAsanNotPoisonedMagic, true);
  sgxsan_assert(m_used_size >= qe.alloc_size);
  m_used_size -= qe.alloc_size;
}

/// 直接释放（不经过隔离队列，用于超大块或队列不可用时）
void QuarantineCache::freeDirectly(QuarantineElement qe) {
  update_heap_usage((void *)qe.alloc_beg, false);
  auto *m_qe = (chunk *)(qe.user_beg - sizeof(chunk));
  delete m_qe->bt;
  m_qe->bt = nullptr;
  free((void *)qe.alloc_beg);
  log_trace("[Direct Free] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg,
            qe.user_beg, qe.user_beg + qe.user_size,
            qe.alloc_beg + qe.alloc_size);
  FastPoisonShadow(qe.user_beg, RoundUpTo(qe.user_size, SHADOW_GRANULARITY),
                   kAsanNotPoisonedMagic, true);
}

/// 淘汰并释放队首最旧的隔离条目
void QuarantineCache::freeOldestQuarantineElement() {
  QuarantineElement front_qe = m_queue->front();
  freeQuarantineElement(front_qe);
  m_queue->pop_front();
}
