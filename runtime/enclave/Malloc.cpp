
#include "Malloc.hpp"
#include "ErrorReport.hpp"
#include "InternalDlmalloc.hpp"
#include "Poison.hpp"
#include "Quarantine.hpp"
#include "SGXSanRTEnclave.hpp"
#include <pthread.h>

extern size_t libunwind_backtrace(uint64_t *ret_addrs, size_t max_count);

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
size_t global_heap_usage = 0;

/* The maximum possible size_t value has all bits set */
#define MAX_SIZE_T (~(size_t)0)

static constexpr size_t kMaxBTFrames = 50;

struct HeapBT {
  uint64_t malloc_bt[kMaxBTFrames];
  size_t malloc_bt_cnt;
  uint64_t free_bt[kMaxBTFrames];
  size_t free_bt_cnt;
};

struct chunk {
  size_t magic; // ensure queried user_beg is correct
  uptr alloc_beg;
  uptr alloc_size;
  size_t user_size;
  HeapBT *bt; // separately allocated via dlmalloc; freed by FreeHeapChunkBT
};

void update_heap_usage(void *ptr, size_t (*malloc_usable_size_func)(void *),
                       bool true_add_false_minus) {
#if (g_log_level >= 3 /* LOG_LEVEL_DEBUG */)
  static uint64_t heapLogIndex = 0;
  if (ptr) {
    pthread_mutex_lock(&mutex);
    heapLogIndex++;
    size_t allocated_size = malloc_usable_size_func(ptr);
    if (true_add_false_minus) {
      log_trace("(%ld)[HEAP SIZE] 0x%lx=0x%lx+0x%lx\n", heapLogIndex,
                global_heap_usage + allocated_size, global_heap_usage,
                allocated_size);
      global_heap_usage += allocated_size;
    } else {
      log_trace("(%ld)[HEAP SIZE] 0x%lx=0x%lx-0x%lx\n", heapLogIndex,
                global_heap_usage - allocated_size, global_heap_usage,
                allocated_size);
      global_heap_usage -= allocated_size;
    }
    pthread_mutex_unlock(&mutex);
  }
#else
  (void)ptr;
  (void)malloc_usable_size_func;
  (void)true_add_false_minus;
  (void)mutex;
#endif
}

void *MALLOC(size_t size) {
  if (not asan_inited) {
    auto p = BACKEND_MALLOC(size);
    update_heap_usage(p, BACKEND_MALLOC_USABLE_SZIE);
    return p;
  }

  uptr alignment = SHADOW_GRANULARITY;

  uptr rz_size =
      std::max(ComputeRZSize(size), RoundUpTo(sizeof(chunk), alignment));
  uptr rounded_size = RoundUpTo(size, alignment);
  uptr needed_size = rounded_size + 2 * rz_size;

  void *allocated = BACKEND_MALLOC(needed_size);
  if (allocated == nullptr) {
    return nullptr;
  }
  update_heap_usage(allocated, BACKEND_MALLOC_USABLE_SZIE);

  size_t allocated_size = BACKEND_MALLOC_USABLE_SZIE(allocated);

  uptr alloc_beg = reinterpret_cast<uptr>(allocated);
  // If dlmalloc doesn't return an aligned memory, it's troublesome.
  // If it is so, we start to posion from RoundUpTo(allocated)
  sgxsan_assert(
      IsAligned(alloc_beg, alignment) &&
      "here I want to see whether dlmalloc return an unaligned memory");
  uptr alloc_end = alloc_beg + allocated_size;

  uptr user_beg = alloc_beg + rz_size;
  if (!IsAligned(user_beg, alignment))
    user_beg = RoundUpTo(user_beg, alignment);
  uptr user_end = user_beg + size;
  sgxsan_assert(user_end <= alloc_end);

  // place the chunk in left redzone
  uptr chunk_beg = user_beg - sizeof(chunk);
  chunk *m = reinterpret_cast<chunk *>(chunk_beg);

  // if alloc_beg is not aligned, we cannot automatically calculate it
  m->magic = 0xDEADBEEF;
  m->alloc_beg = alloc_beg;
  m->alloc_size = allocated_size;
  m->user_size = size;
  m->bt = static_cast<HeapBT *>(dlmalloc(sizeof(HeapBT)));
  if (m->bt) {
    m->bt->malloc_bt_cnt = libunwind_backtrace(m->bt->malloc_bt, kMaxBTFrames);
    m->bt->free_bt_cnt = 0;
  }
  log_trace("\n");
  log_trace("[Malloc] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", alloc_beg, user_beg,
            user_end, alloc_end);
  // start poisoning, if assume alloc_beg is 8-byte aligned, we can use
  // FastPoisonShadow()
  /* Fast */ PoisonShadow(alloc_beg, user_beg - alloc_beg,
                          kAsanHeapLeftRedzoneMagic);
  PoisonShadow(user_beg, size, 0x0); // user_beg is already aligned to alignment
  uptr right_redzone_beg = RoundUpTo(user_end, alignment);
  /* Fast */ PoisonShadow(right_redzone_beg, alloc_end - right_redzone_beg,
                          kAsanHeapLeftRedzoneMagic);

  return reinterpret_cast<void *>(user_beg);
}

void FREE(void *ptr) {
  uptr user_beg;
  chunk *m = nullptr;
  QuarantineElement qe;
  uptr alignment = SHADOW_GRANULARITY;
  if (not asan_inited) {
    goto fallback;
  }
  if (ptr == nullptr)
    return;

  user_beg = reinterpret_cast<uptr>(ptr);
  m = reinterpret_cast<chunk *>(user_beg - sizeof(chunk));
  if (m->magic != 0xDEADBEEF) {
    goto fallback;
  }

  if (*(uint8_t *)MEM_TO_SHADOW(user_beg) == kAsanHeapFreeMagic) {
    GET_CALLER_PC_BP_SP;
    ReportGenericError(pc, bp, sp, user_beg, 0, 1, true, "Double Free");
  }
  sgxsan_assert(IsAligned(user_beg, alignment));

  log_trace("\n");
  log_trace("[Recycle] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", m->alloc_beg, user_beg,
            user_beg + m->user_size,
            m->alloc_beg + ComputeRZSize(m->user_size) * 2 +
                RoundUpTo(m->user_size, alignment));
  FastPoisonShadow(user_beg, RoundUpTo(m->user_size, alignment),
                   kAsanHeapFreeMagic);

  qe = {.alloc_beg = m->alloc_beg,
        .alloc_size = m->alloc_size,
        .user_beg = user_beg,
        .user_size = m->user_size};
  if (m->bt)
    m->bt->free_bt_cnt = libunwind_backtrace(m->bt->free_bt, kMaxBTFrames);
  QuarantineCache::put(qe);
  return;

fallback:
  update_heap_usage(ptr, BACKEND_MALLOC_USABLE_SZIE, false);
  BACKEND_FREE(ptr);
}

void *CALLOC(size_t n_elements, size_t elem_size) {
  if (not asan_inited) {
    return BACKEND_CALLOC(n_elements, elem_size);
  }

  void *mem;
  size_t req = 0;
  if (n_elements != 0) {
    req = n_elements * elem_size;
    if (((n_elements | elem_size) & ~(size_t)0xffff) &&
        req / n_elements != elem_size) {
      req = MAX_SIZE_T; /* force downstream failure on overflow */
    }
  }
  mem = MALLOC(req);
  if (mem != nullptr) {
    memset(mem, 0, req);
  }
  return mem;
}

void *REALLOC(void *oldmem, size_t bytes) {
  if (not asan_inited) {
    return BACKEND_REALLOC(oldmem, bytes);
  }

  void *mem = 0;
  if (oldmem == nullptr) {
    return MALLOC(bytes);
  }
  if (bytes == 0) {
    FREE(oldmem);
    return nullptr;
  }

  mem = MALLOC(bytes);

  if (mem != 0) {
    uptr chunk_beg = reinterpret_cast<uptr>(oldmem) - sizeof(chunk);
    chunk *m = reinterpret_cast<chunk *>(chunk_beg);
    size_t old_size = m->user_size;

    memcpy(mem, oldmem, bytes > old_size ? old_size : bytes);
    FREE(oldmem);
  }

  return mem;
}

size_t MALLOC_USABLE_SZIE(void *mem) {
  uptr user_beg = reinterpret_cast<uptr>(mem);

  uptr chunk_beg = user_beg - sizeof(chunk);
  chunk *m = reinterpret_cast<chunk *>(chunk_beg);
  size_t user_size = m->user_size;

  return user_size;
}

size_t tc_malloc_size(void *ptr) __attribute__((weak));
size_t tc_malloc_size(void *ptr) {
  // dummy, should replaced by real tc_malloc_size when libsgx_tcmalloc.a is
  // loaded
  (void)ptr;
  sgxsan_error(true, "Unsupported tc_malloc_size\n");
  return 0;
}

bool GetHeapChunkBT(uptr user_beg, uint64_t **malloc_bt, size_t *malloc_cnt,
                    uint64_t **free_bt, size_t *free_cnt) {
  auto *m = reinterpret_cast<chunk *>(user_beg - sizeof(chunk));
  if (m->magic != 0xDEADBEEF || !m->bt)
    return false;
  *malloc_bt = m->bt->malloc_bt;
  *malloc_cnt = m->bt->malloc_bt_cnt;
  *free_bt = m->bt->free_bt;
  *free_cnt = m->bt->free_bt_cnt;
  return true;
}

void FreeHeapChunkBT(uptr user_beg) {
  auto *m = reinterpret_cast<chunk *>(user_beg - sizeof(chunk));
  if (m->magic != 0xDEADBEEF)
    return;
  dlfree(m->bt);
  m->bt = nullptr;
}
