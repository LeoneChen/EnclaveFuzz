#pragma once

/// Malloc.h — SGXSan 堆分配器接口与辅助工具
///
/// 提供：
///   - sgxsan_malloc/free/calloc/realloc：带影子内存红区的堆分配器
///   - 红区大小计算工具（ComputeRZSize 等）
///
/// 分配布局：
///   [左红区 | chunk 元数据 | 用户数据 | 右红区]
///   chunk 元数据紧贴用户数据左侧，包含原始分配地址、大小等信息

#include "Poison.h"
#include "Quarantine.h"
#include "SGXSanRTApp.h"
#include <pthread.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif
/// InitHeapAllocator：在 SGXSanInit 前懒初始化 gQCache
void InitHeapAllocator();
void *sgxsan_malloc(size_t size);
void *sgxsan_malloc_raw(size_t size, uptr alignment);
void sgxsan_free(void *ptr);
void sgxsan_free_raw(void *ptr, uptr alignment, uptr expected_size);
void *sgxsan_calloc(size_t n_elements, size_t elem_size);
void *sgxsan_realloc(void *oldmem, size_t bytes);
size_t sgxsan_malloc_usable_size(void *mem);
#if defined(__cplusplus)
}
#endif

// ── 红区大小计算 ──────────────────────────────────────────────────────────
/// 红区大小 = 2^(rz_log + 4)，按用户申请大小分档（越大的对象，红区越大）
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

/// update_heap_usage：在 DEBUG 日志级别下跟踪全局堆用量（统计用）
void update_heap_usage(void *ptr, bool is_alloc = true);

/// chunk：嵌入左红区末尾的元数据，记录本次分配的原始信息
struct chunk {
  size_t magic;      // 校验魔数，确保查询到的 user_beg 合法
  uptr alloc_beg;    // malloc 返回的原始地址
  size_t alloc_size; // malloc_usable_size 获取的实际分配大小
  size_t user_size;  // 用户请求的大小
  MallocFreeBT *bt;  // malloc/free 调用栈（DFEnableCollectStack 时分配）
};
