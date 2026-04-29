// EnclaveFuzz Framework — Per-app Harness Header
//
// 单一 include 即可拿到 harness 函数所需的全部接口：
//   - HARNESS_REGISTER 宏（注册 harness 函数）
//   - g_fdp（FuzzedDataProvider*，消费 fuzz 数据）
//   - __g_harness_eid（enclave id，传给 ECall）
//   - arena 分配器（calloc/malloc/free 自动重定向）
//
// Apps 不可重定义：HARNESS_REGISTER、registry 类型/全局、customized_harness
// （定义在 harness/test.cpp）。
//
// 包含此头会重定向 calloc/malloc/free 到 framework arena。framework 代码
// 自身定义 HARNESS_FRAMEWORK_NO_ARENA_REDIRECT 来避免重定向。

#pragma once

#include <sgx_urts.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include "FuzzedDataProvider.h"
#endif

// ============================================================================
// 1. Framework-provided globals
// ============================================================================
// 定义在 harness/test.cpp。Harness 函数可直接使用：
//   - g_fdp             消费 fuzz 数据（C++ 专用）
//   - __g_harness_eid   传给 ECall

#ifdef __cplusplus
extern "C" {
#endif

extern sgx_enclave_id_t __g_harness_eid;

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern FuzzedDataProvider *g_fdp;
#endif

// ============================================================================
// 2. Registry types & storage
// ============================================================================
// Storage 定义在 harness/test.cpp。Apps 不直接引用——HARNESS_REGISTER (§4)
// 展开时会引用。

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*TestHarness)(void);

struct TestHarnessEntry {
  TestHarness function;
  int weight; // Selection weight (default: 50)
};

extern struct TestHarnessEntry test_harness_registry[10240];
extern unsigned int test_harness_count;
extern int total_weight;

// ============================================================================
// 3. Arena allocator
// ============================================================================
// Bump-pointer arena 定义在 harness/test.cpp。把 ECall 参数缓冲区放在 arena
// 而非 glibc 堆上，避免 enclave OOB 时引发的 malloc-lock 死锁。

extern uint8_t *g_arena_alloc(size_t size);

#ifdef __cplusplus
}
#endif

static inline void *arena_calloc(size_t nmemb, size_t size) {
  return g_arena_alloc(nmemb * size);
}

#ifndef HARNESS_FRAMEWORK_NO_ARENA_REDIRECT
#define calloc(n, s) arena_calloc((n), (s))
#define malloc(s)    arena_calloc(1, (s))
#define free(p)      ((void)(p))
#endif

// ============================================================================
// 4. HARNESS_REGISTER macro
// ============================================================================
// 把 HARNESS_REGISTER(fn, weight) 放在每个 harness_fns/*.h 末尾。静态初始化
// 在 main() 之前运行，把条目追加进 registry。

#define HARNESS_REGISTER(fn, w)                                          \
  static bool _harness_reg_##fn =                                        \
      (test_harness_registry[test_harness_count++] =                     \
           (struct TestHarnessEntry){fn, w},                             \
       total_weight += w, true);
