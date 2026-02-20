#pragma once

#include "SGXSanRTEnclave.hpp"

void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, bool fatal = true,
                        const char *msg = "Out of Bound", ...);
