#pragma once

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

// A list of C wrapper of MemAccessMgr
void MemAccessMgrInit();
void MemAccessMgrDestroy();
void MemAccessMgrOutEnclaveAccess(const void *start, size_t size, bool is_write,
                                  bool used_to_cmp = false);
void MemAccessMgrInEnclaveAccess();

#if defined(__cplusplus)
}
#endif
