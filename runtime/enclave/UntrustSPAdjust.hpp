#pragma once
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif
void set_untrust_sp(size_t addr);
size_t get_untrust_sp(void);
#if defined(__cplusplus)
}
#endif