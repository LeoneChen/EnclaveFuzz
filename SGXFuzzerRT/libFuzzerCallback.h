//
// #include "enclave_u.h"
//
#pragma once

#include "sgx_urts.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <string>
#include <sys/types.h>
#include <vector>

// log util
enum log_level {
  LOG_LEVEL_ALWAYS,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_WARNING,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_TRACE,
};

extern "C" void sgxfuzz_log(log_level ll, bool with_prefix, const char *fmt,
                            ...);

/// have prefix in output
#define log_always(...) sgxfuzz_log(LOG_LEVEL_ALWAYS, true, __VA_ARGS__)
#define log_error(...) sgxfuzz_log(LOG_LEVEL_ERROR, true, __VA_ARGS__)
#define log_warning(...) sgxfuzz_log(LOG_LEVEL_WARNING, true, __VA_ARGS__)
#define log_debug(...) sgxfuzz_log(LOG_LEVEL_DEBUG, true, __VA_ARGS__)
#define log_trace(...) sgxfuzz_log(LOG_LEVEL_TRACE, true, __VA_ARGS__)

/// no prefix in output
#define log_always_np(...) sgxfuzz_log(LOG_LEVEL_ALWAYS, false, __VA_ARGS__)
#define log_error_np(...) sgxfuzz_log(LOG_LEVEL_ERROR, false, __VA_ARGS__)
#define log_warning_np(...) sgxfuzz_log(LOG_LEVEL_WARNING, false, __VA_ARGS__)
#define log_debug_np(...) sgxfuzz_log(LOG_LEVEL_DEBUG, false, __VA_ARGS__)
#define log_trace_np(...) sgxfuzz_log(LOG_LEVEL_TRACE, false, __VA_ARGS__)

// Assert util
#define sgxfuzz_error(cond, ...)                                               \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_error(__VA_ARGS__);                                                  \
      abort();                                                                 \
    }                                                                          \
  } while (0);

#define sgxfuzz_assert(cond) sgxfuzz_error(!(cond), "Assert Fail: " #cond "\n");

#define sgxfuzz_warning(cond, ...)                                             \
  do {                                                                         \
    if (!!(cond)) {                                                            \
      log_warning(__VA_ARGS__);                                                \
    }                                                                          \
  } while (0);
