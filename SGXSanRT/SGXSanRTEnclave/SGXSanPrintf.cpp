#include "SGXSanRTConfig.h"
#include "SGXSanRTTBridge.hpp"
#include <mbusafecrt.h>
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <string>

static const char *log_level_to_prefix[] = {
    "",
    "[SGXSan error] ",
    "[SGXSan warning] ",
    "[SGXSan debug] ",
    "[SGXSan trace] ",
};

// can't call malloc, since malloc may call this function
void sgxsan_log(log_level ll, bool with_prefix, const char *fmt, ...) {
  if (ll > USED_LOG_LEVEL)
    return;

  char buf[BUFSIZ] = {'\0'};
  size_t offset = 0;
  if (with_prefix) {
    const char *prefix = log_level_to_prefix[ll];
    offset = strlen(buf);
    sgxsan_assert(strlen(prefix) < BUFSIZ - offset);
    strcat_s(buf + offset, BUFSIZ - offset, prefix);
  }

  va_list ap;
  va_start(ap, fmt);
  offset = strlen(buf);
  vsnprintf(buf + offset, BUFSIZ - offset, fmt, ap);
  va_end(ap);

  sgxsan_ocall_print_string(buf);
}
