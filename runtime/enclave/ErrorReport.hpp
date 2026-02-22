#pragma once

#include "SGXSanRTEnclave.hpp"

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal = true,
                        const char *msg = "Out of Bound", ...);
void ReportDoubleFetch(uptr cur_fetch, size_t cur_size, uptr prev_fetch,
                       size_t prev_size, uptr *prev_bt, size_t prev_bt_cnt);
