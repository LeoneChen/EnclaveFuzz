#pragma once

#include "ContainerAllocator.hpp"
#include "Poison.hpp"
#include "SGXSanRTConfig.h"
#include <cstddef>
#include <queue>

struct QuarantineElement {
  uptr alloc_beg;
  uptr alloc_size;
  uptr user_beg;
  uptr user_size;
};

// Use SGXSan::ContainerAllocator(dlmalloc series as backend) avoid
// malloc-new-malloc's like infinitive loop
typedef std::deque<QuarantineElement,
                   SGXSan::ContainerAllocator<QuarantineElement>>
    QuarantineQueueTy;

class QuarantineCache {
public:
  static void init();
  static void destory();
  static void put(QuarantineElement qe);

private:
  static void freeQuarantineElement(QuarantineElement qe);
  static void freeDirectly(QuarantineElement qe);
  static void freeOldestQuarantineElement();
  static bool empty() { return m_queue->empty(); }
  static void show();

  static QuarantineQueueTy *m_queue;
  static size_t m_quarantine_cache_used_size;
  static size_t m_quarantine_cache_max_size;
};

// C Wrappers
#if defined(__cplusplus)
extern "C" {
#endif
// atomicity implemented by tRTS initializer about global constructor
void QuarantineCacheInit() __attribute__((constructor));
void QuarantineCacheDestroy() __attribute__((destructor));
#if defined(__cplusplus)
}
#endif
