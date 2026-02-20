#pragma once

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif
void *dlmalloc(size_t bytes);
void dlfree(void *mem);
void *dlcalloc(size_t n_elements, size_t elem_size);
void *dlrealloc(void *oldmem, size_t bytes);
size_t dlmalloc_usable_size(void *mem);
#if defined(__cplusplus)
}
#endif
