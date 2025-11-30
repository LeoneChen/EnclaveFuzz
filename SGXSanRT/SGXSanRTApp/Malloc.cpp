
#include "Malloc.h"
#include "MemAccessMgr.h"
#include "Poison.h"
#include "Sticker.h"
#include <algorithm>
#include <set>
#include <string.h>
#include <tuple>

#define DEFINE_BACK_END(sym) decltype(sym) *BACK_END(sym)
DEFINE_BACK_END(malloc) = __libc_malloc;
DEFINE_BACK_END(free) = __libc_free;
DEFINE_BACK_END(calloc) = __libc_calloc;
DEFINE_BACK_END(realloc) = __libc_realloc;
DEFINE_BACK_END(malloc_usable_size) = nullptr;
#undef DEFINE_BACK_END

SGXSanHeapBacktrace *gHeapBT = nullptr;
QuarantineCache *gQCache = nullptr;
void updateBackEndHeapAllocator() {
  static bool alreadyUpdateBackEndHeapAllocator = false;
  // since we also update it in SGXSan ctor, so this statement only will be
  // triggered before SGXSan's ctor, and only one main thread exists, thus,
  // needn't consider multi-thread situation
  if (alreadyUpdateBackEndHeapAllocator)
    return;
#define GET_BACK_END(sym)                                                      \
  sgxsan_assert(BACK_END(sym) = (decltype(sym) *)dlsym(RTLD_NEXT, #sym))
  GET_BACK_END(malloc);
  GET_BACK_END(free);
  GET_BACK_END(calloc);
  GET_BACK_END(realloc);
  GET_BACK_END(malloc_usable_size);
#undef GET_BACK_END
  // Never free, since they are still used when exit()
  void *p = BACKEND_MALLOC(sizeof(SGXSanHeapBacktrace));
  gHeapBT = new (p) SGXSanHeapBacktrace();
  p = BACKEND_MALLOC(sizeof(QuarantineCache));
  gQCache = new (p) QuarantineCache();
  alreadyUpdateBackEndHeapAllocator = true;
}

static pthread_mutex_t heap_usage_mutex = PTHREAD_MUTEX_INITIALIZER;
size_t global_heap_usage = 0;
const size_t kHeapObjectChunkMagic = 0xDEADBEEF;

std::set<uptr, std::less<uptr>, ContainerAllocator<uptr>> gHeapObjs;
static pthread_mutex_t gHeapObjsUpdateMutex = PTHREAD_MUTEX_INITIALIZER;

struct chunk {
  size_t magic; // ensure queried user_beg is correct
  uptr alloc_beg;
  size_t alloc_size;
  size_t user_size;
};

void update_heap_usage(void *ptr, bool true_add_false_minus) {
#if (USED_LOG_LEVEL >= 3 /* LOG_LEVEL_DEBUG */)
  static uint64_t heapLogIndex = 0;
  if (ptr) {
    pthread_mutex_lock(&heap_usage_mutex);
    heapLogIndex++;
    size_t allocated_size = BACKEND_MALLOC_USABLE_SIZE(ptr);
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
    pthread_mutex_unlock(&heap_usage_mutex);
  }
#else
  (void)ptr;
  (void)true_add_false_minus;
  (void)heap_usage_mutex;
#endif
}

void *MALLOC(size_t size) {
  updateBackEndHeapAllocator();
  // if (size == 0) {
  //   sgxsan_warning(true, "Malloc 0 size\n");
  //   return nullptr;
  // }

  if (not asan_inited) {
    auto p = BACKEND_MALLOC(size);
    update_heap_usage(p);
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
  update_heap_usage(allocated);

  size_t allocated_size = BACKEND_MALLOC_USABLE_SIZE(allocated);

  uptr alloc_beg = (uptr)allocated;
  // If real malloc doesn't return an aligned memory, it's troublesome.
  sgxsan_assert(IsAligned(alloc_beg, alignment));
  uptr alloc_end = alloc_beg + allocated_size;

  uptr user_beg = alloc_beg + rz_size;
  if (!IsAligned(user_beg, alignment))
    user_beg = RoundUpTo(user_beg, alignment);
  uptr user_end = user_beg + size;
  sgxsan_assert(user_end <= alloc_end);

  // place the chunk in left redzone
  uptr chunk_beg = user_beg - sizeof(chunk);
  chunk *m = (chunk *)chunk_beg;

  m->magic = kHeapObjectChunkMagic;
  m->alloc_beg = alloc_beg;
  m->alloc_size = allocated_size;
  m->user_size = size;
  gHeapBT->StoreMallocBT(user_beg);
  log_trace("\n");
  log_trace("[Malloc] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", alloc_beg, user_beg,
            user_end, alloc_end);

  PoisonShadow(alloc_beg, user_beg - alloc_beg, kAsanHeapLeftRedzoneMagic);
  sgxsan_assert(IsAligned(user_beg, alignment));
  PoisonShadow(user_beg, size, kAsanNotPoisonedMagic);
  uptr right_redzone_beg = RoundUpTo(user_end, alignment);
  PoisonShadow(right_redzone_beg, alloc_end - right_redzone_beg,
               kAsanHeapLeftRedzoneMagic);

  if (RunInEnclave) {
    void *callPt = __builtin_return_address(0);
    if (gEnclaveInfo.isInEnclaveDSORange((uptr)callPt, 1) and
        MemAccessMgrInited()) {
      pthread_mutex_lock(&gHeapObjsUpdateMutex);
      bool successInsert;
      std::tie(std::ignore, successInsert) = gHeapObjs.emplace(user_beg);
      if (not successInsert) {
        abort();
      }
      pthread_mutex_unlock(&gHeapObjsUpdateMutex);
    }
  }

  return (void *)user_beg;
}

extern "C" bool AddrIsInHeapQuarantine(uptr addr) {
  return L1F(*(uint8_t *)MEM_TO_SHADOW(addr)) == kAsanHeapFreeMagic;
}

void FREE(void *ptr) {
  uptr user_beg, alignment;
  chunk *m;
  QuarantineElement qe;
  updateBackEndHeapAllocator();
  if (not asan_inited) {
    goto fallback;
  }
  if (ptr == nullptr)
    return;

  user_beg = (uptr)ptr;
  alignment = SHADOW_GRANULARITY;

  m = (chunk *)(user_beg - sizeof(chunk));
  if (m->magic != kHeapObjectChunkMagic) {
    // It may be malloced before SGXSan's init, directly free it, and leave
    // normal free to check pointer
    goto fallback;
  }

  if (AddrIsInMem(user_beg) and
      L1F(*(uint8_t *)MEM_TO_SHADOW(user_beg)) == kAsanHeapFreeMagic) {
    GET_CALLER_PC_BP_SP;
    ReportDoubleFree(pc, bp, sp, user_beg);
  }
  sgxsan_assert(IsAligned(user_beg, alignment));

  log_trace("\n");
  log_trace("[Recycle] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", m->alloc_beg, user_beg,
            user_beg + m->user_size, m->alloc_beg + m->alloc_size);
  PoisonShadow(user_beg, RoundUpTo(m->user_size, alignment),
               kAsanHeapFreeMagic);

  qe.alloc_beg = m->alloc_beg;
  qe.alloc_size = m->alloc_size;
  qe.user_beg = user_beg;
  qe.user_size = m->user_size;

  pthread_mutex_lock(&gHeapObjsUpdateMutex);
  if (gHeapObjs.count(user_beg)) {
    gHeapObjs.erase(user_beg);
  }
  pthread_mutex_unlock(&gHeapObjsUpdateMutex);

  gQCache->put(qe);
  goto exit;

fallback:
  update_heap_usage(ptr, false);
  BACKEND_FREE(ptr);
exit:
  return;
}

void *CALLOC(size_t n_elements, size_t elem_size) {
  // Since dlsym use calloc, so avoid call updateBackEndHeapAllocator and dlsym
  // in it, and we directly use __libc_calloc as backend calloc
  if (not asan_inited) {
    return BACKEND_CALLOC(n_elements, elem_size);
  }

  size_t req = n_elements * elem_size;
  // if (req == 0) {
  //   sgxsan_warning(true, "Calloc 0 size\n");
  //   return nullptr;
  // }
  if (req / n_elements != elem_size) {
    // mul overflow
    sgxsan_warning(true, "Multiple Overflow in calloc\n");
    return nullptr;
  }
  void *mem = MALLOC(req);
  if (mem != nullptr) {
    memset(mem, 0, req);
  }
  return mem;
}

void *REALLOC(void *oldmem, size_t bytes) {
  updateBackEndHeapAllocator();
  if (not asan_inited) {
    return BACKEND_REALLOC(oldmem, bytes);
  }

  if (oldmem == nullptr) {
    return MALLOC(bytes);
  }
  chunk *m = (chunk *)((uptr)oldmem - sizeof(chunk));
  sgxsan_assert(m->magic == kHeapObjectChunkMagic);
  if (bytes == 0) {
    FREE(oldmem);
    return nullptr;
  }

  void *mem = MALLOC(bytes);

  if (mem != nullptr) {
    memcpy(mem, oldmem, std::min(m->user_size, bytes));
    FREE(oldmem);
  }

  return mem;
}

size_t MALLOC_USABLE_SIZE(void *mem) throw() {
  updateBackEndHeapAllocator();
  chunk *m = (chunk *)((uptr)mem - sizeof(chunk));
  sgxsan_assert(m->magic == kHeapObjectChunkMagic);
  return m->user_size;
}

void ClearHeapObject() {
  pthread_mutex_lock(&gHeapObjsUpdateMutex);
  for (auto user_beg : gHeapObjs) {
    if ((void *)user_beg == nullptr)
      continue;

    uptr alignment = SHADOW_GRANULARITY;
    chunk *m = (chunk *)(user_beg - sizeof(chunk));
    if (m->magic != kHeapObjectChunkMagic) {
      abort();
    }

    if (AddrIsInMem(user_beg) and
        L1F(*(uint8_t *)MEM_TO_SHADOW(user_beg)) == kAsanHeapFreeMagic) {
      GET_CALLER_PC_BP_SP;
      ReportDoubleFree(pc, bp, sp, user_beg);
    }
    sgxsan_assert(IsAligned(user_beg, alignment));

    PoisonShadow(user_beg, RoundUpTo(m->user_size, alignment),
                 kAsanHeapLeftRedzoneMagic);
    BACKEND_FREE((void *)m->alloc_beg);
  }
  gHeapObjs.clear();
  pthread_mutex_unlock(&gHeapObjsUpdateMutex);
}

void QuarantineCache::show() {
  for (auto &qe : *m_queue) {
    log_always("[SHOW] [0x%lx..0x%lx ~ 0x%lx..0x%lx)\n", qe.alloc_beg,
               qe.user_beg, qe.user_beg + qe.user_size,
               qe.alloc_beg + qe.alloc_size);
  }
}
