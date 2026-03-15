#pragma once

/// ErrorReport.h — SGXSan 错误上报接口
///
/// 所有检测到的内存安全错误最终通过这里的函数上报，
/// 打印错误类型、访问地址、调用栈、影子内存快照后调用 Die() 终止程序。

#include "SGXSanRTApp.h"

#if defined(__cplusplus)
extern "C" {
#endif
/// ReportGenericError：带影子内存快照的通用错误上报，上报后调用 Die()
/// 若影子内存显示该地址已被标记为 HeapFree，则转发至 ReportUseAfterFree
void ReportGenericError(uptr pc, uptr bp, uptr sp, uptr addr, bool is_write,
                        uptr access_size, const char *msg = "Out of bound",
                        ...);

/// ReportUseAfterFree：从隔离缓存中查找历史 malloc/free 调用栈并打印
void ReportUseAfterFree(uptr pc, uptr bp, uptr sp, uptr addr);

/// ReportDoubleFree：打印历史 malloc/free 调用栈后终止
void ReportDoubleFree(uptr pc, uptr bp, uptr sp, uptr addr);

/// ReportDoubleFetch：打印当前读取与之前控制流读取的地址及各自调用栈
void ReportDoubleFetch(uptr cur_fetch, size_t cur_size, uptr prev_fetch,
                       size_t prev_size, uptr *prev_bt, size_t prev_bt_cnt);
#if defined(__cplusplus)
}
#endif
