/// Malloc.cpp — SGXSan 堆分配器实现
///
/// 每次分配布局（从低到高）：
///   [alloc_beg ... 左红区 ... chunk元数据 | user_beg ... 用户数据 ... user_end
///   ... 右红区 ... alloc_end]
///
/// chunk 元数据紧贴用户区左侧，存放 magic / alloc_beg / alloc_size /
/// user_size， 用于 free 时定位原始 malloc 指针和大小

#include "Malloc.h"
#include "ErrorReport.h"
#include "Poison.h"
#include "SGXSanRTApp.h"
#include <algorithm>
#include <boost/stacktrace.hpp>
#include <string.h>

/// 全局隔离缓存（Never free，退出时仍在使用）
QuarantineCache *gQCache = nullptr;

/// InitHeapAllocator：懒初始化 gQCache
/// 在 SGXSanInit 的构造函数中调用，但也可能在构造函数执行前被触发
/// （如全局对象的构造器先于 SGXSanInit），故加幂等保护
void InitHeapAllocator() {
  static bool initialized = false;
  // SGXSan 构造函数执行前只有主线程，无需考虑多线程
  if (initialized)
    return;
  gQCache = new QuarantineCache();
  initialized = true;
}

// ── 堆使用量统计（仅在 DEBUG 日志级别下启用）────────────────────────────

static pthread_mutex_t heap_usage_mutex = PTHREAD_MUTEX_INITIALIZER;
size_t global_heap_usage = 0;

/// chunk 魔数：用于校验 user_beg - sizeof(chunk) 处确实是 chunk 元数据，
/// 而非 SGXSanInit 前通过原始 malloc 分配的指针
const size_t kHeapObjectChunkMagic = 0xDEADBEEF;

/// chunk：嵌入左红区末尾的元数据，记录本次分配的原始信息
// （定义在 Malloc.h 以便 Quarantine.cpp / ErrorReport.cpp 直接访问 bt）

void update_heap_usage(void *ptr, bool is_alloc) {
#if (USED_LOG_LEVEL >= 3 /* LOG_LEVEL_DEBUG */)
  static uint64_t heapLogIndex = 0;
  if (ptr) {
    pthread_mutex_lock(&heap_usage_mutex);
    heapLogIndex++;
    size_t allocated_size = malloc_usable_size(ptr);
    if (is_alloc) {
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
    pthread_mutex_unlock(&heap_usage_mutex);
  }
#else
  (void)ptr;
  (void)is_alloc;
  (void)heap_usage_mutex;
#endif
}

// ── 分配实现 ──────────────────────────────────────────────────────────────

/// sgxsan_malloc_raw：带对齐要求的堆分配
/// 若未完成 SGXSan 初始化则降级为原始 malloc
void *sgxsan_malloc_raw(size_t size, uptr alignment) {
  if (not asan_inited) {
    auto p = malloc(size);
    update_heap_usage(p);
    return p;
  }

  // 红区大小取 ComputeRZSize 与 sizeof(chunk) 向上对齐的较大值
  uptr rz_size =
      std::max(ComputeRZSize(size), RoundUpTo(sizeof(chunk), alignment));
  uptr rounded_size = RoundUpTo(size, alignment);
  uptr needed_size = rounded_size + 2 * rz_size;

  void *allocated = malloc(needed_size);
  if (allocated == nullptr) {
    return nullptr;
  }
  update_heap_usage(allocated);

  size_t allocated_size = malloc_usable_size(allocated);

  uptr alloc_beg = (uptr)allocated;
  uptr alloc_end = alloc_beg + allocated_size;

  // 用户区起始地址向 alignment 对齐
  uptr user_beg = alloc_beg + rz_size;
  if (!IsAligned(user_beg, alignment))
    user_beg = RoundUpTo(user_beg, alignment);
  uptr user_end = user_beg + size;
  sgxsan_assert(user_end <= alloc_end);

  // chunk 元数据放在用户区左侧紧邻处
  uptr chunk_beg = user_beg - sizeof(chunk);
  chunk *m = (chunk *)chunk_beg;

  m->magic = kHeapObjectChunkMagic;
  m->alloc_beg = alloc_beg;
  m->alloc_size = allocated_size;
  m->user_size = size;
  if (DFEnableCollectStack) {
    m->bt = new MallocFreeBT();
    m->bt->malloc_bt_cnt = boost::stacktrace::safe_dump_to(
        m->bt->malloc_bt, sizeof(m->bt->malloc_bt));
    m->bt->free_bt_cnt = 0;
  } else {
    m->bt = nullptr;
  }
  log_trace("\n");
  log_trace("[Malloc] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", alloc_beg, user_beg,
            user_end, alloc_end);

  // 左红区、用户区、右红区分别写对应影子魔数
  PoisonShadow(alloc_beg, user_beg - alloc_beg, kAsanHeapLeftRedzoneMagic);
  sgxsan_assert(IsAligned(user_beg, alignment));
  PoisonShadow(user_beg, size, kAsanNotPoisonedMagic);
  uptr right_redzone_beg = RoundUpTo(user_end, alignment);
  PoisonShadow(right_redzone_beg, alloc_end - right_redzone_beg,
               kAsanHeapRightRedzoneMagic);

  return (void *)user_beg;
}

void *sgxsan_malloc(size_t size) {
  return sgxsan_malloc_raw(size, SHADOW_GRANULARITY);
}

// ── 释放实现 ──────────────────────────────────────────────────────────────

/// sgxsan_free_raw：释放时先检测 double-free，再将用户区影子标记为 HeapFree，
/// 最后放入隔离缓存（QuarantineCache）延迟实际 free，以便检测 use-after-free
void sgxsan_free_raw(void *ptr, uptr alignment, uptr expected_size) {
  if (ptr == nullptr)
    return;

  if (not asan_inited) {
    update_heap_usage(ptr, false);
    free(ptr);
    return;
  }

  uptr user_beg = (uptr)ptr;
  chunk *m = (chunk *)(user_beg - sizeof(chunk));
  if (m->magic != kHeapObjectChunkMagic) {
    // SGXSanInit 前分配的内存无 chunk 元数据，降级为原始 free
    update_heap_usage(ptr, false);
    free(ptr);
    return;
  }
  sgxsan_assert(expected_size == 0 || expected_size == m->user_size);

  // 检测 double-free：影子内存已标记为 HeapFree 则上报
  if (AddrIsInMem(user_beg) and
      L1F(*(uint8_t *)MEM_TO_SHADOW(user_beg)) == kAsanHeapFreeMagic) {
    GET_CALLER_PC_BP_SP;
    ReportDoubleFree(pc, bp, sp, user_beg);
  }
  sgxsan_assert(IsAligned(user_beg, alignment));

  log_trace("\n");
  log_trace("[Recycle] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", m->alloc_beg, user_beg,
            user_beg + m->user_size, m->alloc_beg + m->alloc_size);
  // 将用户区影子标记为已释放，后续访问触发 use-after-free 报告
  PoisonShadow(user_beg, RoundUpTo(m->user_size, alignment),
               kAsanHeapFreeMagic);

  QuarantineElement qe;
  qe.alloc_beg = m->alloc_beg;
  qe.alloc_size = m->alloc_size;
  qe.user_beg = user_beg;
  qe.user_size = m->user_size;

  gQCache->put(qe);
}

void sgxsan_free(void *ptr) { sgxsan_free_raw(ptr, SHADOW_GRANULARITY, 0); }

// ── calloc / realloc / malloc_usable_size ────────────────────────────────

void *sgxsan_calloc(size_t n_elements, size_t elem_size) {
  if (not asan_inited) {
    return calloc(n_elements, elem_size);
  }
  size_t total_size = n_elements * elem_size;
  if (total_size / n_elements != elem_size) {
    // 整数乘法溢出，直接返回 nullptr
    sgxsan_warning(true, "Multiple Overflow in calloc\n");
    return nullptr;
  }
  void *mem = sgxsan_malloc(total_size);
  if (mem != nullptr) {
    memset(mem, 0, total_size);
  }
  return mem;
}

void *sgxsan_realloc(void *oldmem, size_t bytes) {
  if (not asan_inited) {
    return realloc(oldmem, bytes);
  }
  if (oldmem == nullptr) {
    return sgxsan_malloc(bytes);
  }
  chunk *m = (chunk *)((uptr)oldmem - sizeof(chunk));
  sgxsan_assert(m->magic == kHeapObjectChunkMagic);
  if (bytes == 0) {
    sgxsan_free(oldmem);
    return nullptr;
  }
  void *mem = sgxsan_malloc(bytes);
  if (mem != nullptr) {
    memcpy(mem, oldmem, std::min(m->user_size, bytes));
    sgxsan_free(oldmem);
  }
  return mem;
}

size_t sgxsan_malloc_usable_size(void *mem) {
  if (not asan_inited) {
    return malloc_usable_size(mem);
  }
  chunk *m = (chunk *)((uptr)mem - sizeof(chunk));
  sgxsan_assert(m->magic == kHeapObjectChunkMagic);
  return m->user_size;
}
