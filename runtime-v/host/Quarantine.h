#pragma once

/// Quarantine.h — 堆释放隔离缓存（Quarantine Cache）
///
/// use-after-free 检测依赖于"释放后不立即归还给 OS/分配器"的策略：
/// 被 free 的堆块先放入隔离队列，影子内存保持 HeapFree 标记，
/// 直到队列空间满才真正调用 free()。
///
/// 这样，若代码在 free 后继续访问该内存，影子检查会命中 HeapFree 魔数
/// 并上报 use-after-free 错误。
///
/// 隔离队列容量由系统资源限制动态计算，最大不超过 SGXSAN_MAX_QUARANTINE_SIZE。

#include "Malloc.h"
#include "Poison.h"
#include "SGXSanRTApp.h"
#include <deque>
#include <pthread.h>
#include <stddef.h>
#include <sys/resource.h>

/// 隔离队列中单个元素，记录一次 free 的完整分配信息
struct QuarantineElement {
  uptr alloc_beg;  // malloc 返回的原始地址（用于最终 free）
  uptr alloc_size; // malloc_usable_size 获取的实际大小（用于空间计算）
  uptr user_beg;   // 用户区起始地址（用于查找和调用栈查询）
  uptr user_size;  // 用户请求的大小
};

typedef std::deque<QuarantineElement, ContainerAllocator<QuarantineElement>>
    QuarantineQueue;

/// 隔离缓存最大占用字节数（256 MB）
#define SGXSAN_MAX_QUARANTINE_SIZE 0x10000000

/// QuarantineCache：线程安全的 FIFO 隔离队列
/// - put()：将释放的堆块加入队列，若超出容量则淘汰最旧的条目
/// - find()：在队列中查找包含给定地址的条目（用于 UAF 报告定位）
/// - show()：打印当前队列内容（调试用）
class QuarantineCache {
public:
  QuarantineCache();
  ~QuarantineCache();

  /// 查找包含 addr 的隔离条目；未找到时返回 alloc_beg == -1 的元素
  QuarantineElement find(uptr addr);
  /// 打印所有隔离条目（调试用）
  void show();
  /// 将释放的堆块加入隔离队列
  void put(QuarantineElement qe);

private:
  /// 真正释放隔离条目：还原影子内存、删除调用栈记录、调用 free()
  void freeQuarantineElement(QuarantineElement qe);
  /// 直接释放（不经过隔离，用于超大块或队列不可用时）
  void freeDirectly(QuarantineElement qe);
  /// 淘汰队列头部最旧的隔离条目
  void freeOldestQuarantineElement();
  bool empty() { return m_queue->empty(); }

  QuarantineQueue
      *m_queue;       // 隔离队列（通过 placement new 在 malloc 内存上构造）
  size_t m_used_size; // 当前已占用的字节数
  size_t m_max_size;  // 由系统资源限制动态计算的最大容量
  pthread_mutex_t m_mutex;
};

extern QuarantineCache *gQCache;
