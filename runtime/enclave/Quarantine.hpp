#pragma once

#include "InternalDlmalloc.hpp"
#include "Malloc.hpp"
#include "Poison.hpp"
#include "SGXSanRTConfig.h"
#include <cstddef>

struct QuarantineElement {
  uptr alloc_beg;
  uptr alloc_size;
  uptr user_beg;
  uptr user_size;
};

// Intrusive singly-linked list node for the quarantine queue.
struct QuarantineNode {
  QuarantineElement data;
  QuarantineNode *next;
};

// Simple FIFO queue backed entirely by dlmalloc.
// Avoids all STL containers so the sanitizer runtime never intercepts
// its own container memory accesses (no self-detection reentrancy).
struct QuarantineQueue {
  QuarantineNode *head; // dequeue (pop_front) from here
  QuarantineNode *tail; // enqueue (push_back) here

  QuarantineQueue() : head(nullptr), tail(nullptr) {}

  bool empty() const { return head == nullptr; }

  QuarantineElement &front() { return head->data; }

  void push_back(const QuarantineElement &qe) {
    QuarantineNode *node =
        static_cast<QuarantineNode *>(dlmalloc(sizeof(QuarantineNode)));
    update_heap_usage(node, dlmalloc_usable_size);
    node->data = qe;
    node->next = nullptr;
    if (tail)
      tail->next = node;
    else
      head = node;
    tail = node;
  }

  void pop_front() {
    QuarantineNode *old = head;
    head = head->next;
    if (!head)
      tail = nullptr;
    update_heap_usage(old, dlmalloc_usable_size, false);
    dlfree(old);
  }
};

class QuarantineCache {
public:
  static void init();
  static void destory();
  static void put(QuarantineElement qe);
  static QuarantineElement find(uptr addr);

private:
  static void freeQuarantineElement(QuarantineElement qe);
  static void freeDirectly(QuarantineElement qe);
  static void freeOldestQuarantineElement();
  static bool empty() { return m_queue->empty(); }
  static void show();

  static QuarantineQueue *m_queue;
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
