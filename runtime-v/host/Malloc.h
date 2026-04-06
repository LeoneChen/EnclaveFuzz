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
#include "SGXSanRTApp.h"
#include <pthread.h>
#include <stddef.h>

/// chunk 魔数：用于校验 user_beg - sizeof(chunk) 处确实是 chunk 元数据，
/// 而非 SGXSanInit 前通过原始 malloc 分配的指针
const size_t kHeapObjectChunkMagic = 0xDEADBEEF;

#if defined(__cplusplus)
extern "C" {
#endif
void *__libc_malloc(size_t size) noexcept;
void __libc_free(void *ptr) noexcept;
void *__libc_calloc(size_t nmemb, size_t size) noexcept;
void *__libc_realloc(void *ptr, size_t size) noexcept;

/// InitHeapAllocator：在 SGXSanInit 前懒初始化 gQCache
void InitHeapAllocator();

void *malloc(size_t size) noexcept;
void *sgxsan_malloc_raw(size_t size, uptr alignment);
void free(void *ptr) noexcept;
void sgxsan_free_raw(void *ptr, uptr alignment, uptr expected_size);
void *calloc(size_t n_elements, size_t elem_size) noexcept;
void *realloc(void *oldmem, size_t bytes) noexcept;
size_t malloc_usable_size(void *mem) noexcept;
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

/// chunk：嵌入左红区末尾的元数据，记录本次分配的原始信息
struct chunk {
  size_t magic;      // 校验魔数，确保查询到的 user_beg 合法
  uptr alloc_beg;    // malloc 返回的原始地址
  size_t alloc_size; // malloc_usable_size 获取的实际分配大小
  size_t user_size;  // 用户请求的大小
  MallocFreeBT *bt;  // malloc/free 调用栈（DFEnableCollectStack 时分配）
};

template <class T> class ContainerAllocator {
public:
  // type definitions
  typedef T value_type;
  typedef T *pointer;
  typedef const T *const_pointer;
  typedef T &reference;
  typedef const T &const_reference;
  typedef size_t size_type;
  typedef ptrdiff_t difference_type;

  // rebind allocator to type U
  template <class U> struct rebind {
    typedef ContainerAllocator<U> other;
  };

  // return address of values
  pointer address(reference value) const { return &value; }
  const_pointer address(const_reference value) const { return &value; }

  /* constructors and destructor
   * - nothing to do because the allocator has no state
   */
  ContainerAllocator() noexcept {}
  ContainerAllocator(const ContainerAllocator &) noexcept {}
  template <class U>
  ContainerAllocator(const ContainerAllocator<U> &) noexcept {}
  ~ContainerAllocator() noexcept {}

  // return maximum number of elements that can be allocated
  size_type max_size() const noexcept { return size_type(~0) / sizeof(T); }

  // allocate but don't initialize num elements of type T
  pointer allocate(size_type num, const void * = 0) {
    sgxsan_assert(num <= max_size());
    pointer ret = (pointer)(__libc_malloc(num * sizeof(T)));
    sgxsan_assert(ret != nullptr);
    return ret;
  }

  // initialize elements of allocated storage p with value value
  void construct(pointer p, const T &value) {
    // initialize memory with placement new
    new ((void *)p) T(value);
  }

  // destroy elements of initialized storage p
  void destroy(pointer p) {
    // destroy objects by calling their destructor
    p->~T();
  }

  // deallocate storage p of deleted elements
  void deallocate(pointer p, size_type num) {
    (void)num;
    if (p) {
      __libc_free((void *)p);
    }
  }
};

// return that all specializations of this allocator are interchangeable
template <class T1, class T2>
bool operator==(const ContainerAllocator<T1> &,
                const ContainerAllocator<T2> &) throw() {
  return true;
}
template <class T1, class T2>
bool operator!=(const ContainerAllocator<T1> &,
                const ContainerAllocator<T2> &) throw() {
  return false;
}
