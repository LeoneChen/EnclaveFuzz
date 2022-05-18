#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include "SGXSanManifest.h"
#include "SGXSanDefs.h"
#include "SGXSanRTEnclave.hpp"
#include "SGXSanCommonShadowMap.hpp"
#include "SGXSanRTTBridge.hpp"
#include "SensitivePoisoner.hpp"
#include "Malloc.hpp"
#include "SGXSanPrintf.hpp"
#include "StackTrace.hpp"

struct SGXSanMMapInfo
{
    uint64_t start = 0;
    uint64_t end = 0;
    bool is_readable = false;
    bool is_writable = false;
    bool is_executable = false;
    bool is_shared = false;
    bool is_private = false;
    // char description[64] = {0};
};

const __thread size_t SGXSanMMapInfoMaxCount = 1024;
__thread size_t SGXSanMMapInfoRealCount = 0;
__thread SGXSanMMapInfo SGXSanMMapInfos[SGXSanMMapInfoMaxCount];

static pthread_mutex_t sgxsan_init_mutex = PTHREAD_MUTEX_INITIALIZER;

uint64_t kLowMemBeg = 0, kLowMemEnd = 0,
         kLowShadowBeg = 0, kLowShadowEnd = 0,
         kShadowGapBeg = 0, kShadowGapEnd = 0,
         kHighShadowBeg = 0, kHighShadowEnd = 0,
         kHighMemBeg = 0, kHighMemEnd = 0;

int asan_inited = 0;

static void init_shadow_memory_out_enclave()
{
    // only use LowMem and LowShadow
    if (SGX_SUCCESS != sgxsan_ocall_init_shadow_memory(g_enclave_base, g_enclave_size, &kLowShadowBeg, &kLowShadowEnd))
    {
        abort();
    }
    kLowMemBeg = g_enclave_base;
    kLowMemEnd = g_enclave_base + g_enclave_size - 1;
    assert(kLowShadowBeg == SGXSAN_SHADOW_MAP_BASE);
    SensitivePoisoner::collect_layout_infos();
    SensitivePoisoner::shallow_poison_senitive();
    init_real_malloc_usable_size();
}

static void AsanInitInternal()
{
    if (LIKELY(asan_inited))
        return;

    init_shadow_memory_out_enclave();

    asan_inited = 1;
}

void AsanInitFromRtl()
{
    pthread_mutex_lock(&sgxsan_init_mutex);
    AsanInitInternal();
    pthread_mutex_unlock(&sgxsan_init_mutex);
}

void __asan_init()
{
    // sgxsdk already ensure each ctor only run once
    AsanInitInternal();
}

extern "C" void get_mmap_infos()
{
    if (SGX_SUCCESS != sgxsan_ocall_get_mmap_infos(SGXSanMMapInfos, SGXSanMMapInfoMaxCount * sizeof(SGXSanMMapInfo), &SGXSanMMapInfoRealCount))
        abort();
    assert(SGXSanMMapInfoRealCount <= SGXSanMMapInfoMaxCount);
}

// assume SGXSanMMapInfos is sorted, and info range is [info.start, info.end]
bool _is_addr_readable(uint64_t addr, size_t length, size_t mmap_info_start_index)
{
    for (size_t i = mmap_info_start_index; i < SGXSanMMapInfoRealCount; i++)
    {
        auto &info = SGXSanMMapInfos[i];
        if (addr < info.start)
        {
            // Subsequent items will only be bigger, we can think it false early.
            return false;
        }
        else if (info.start <= addr && addr <= info.end && info.is_readable)
        {
            if (info.end < (addr + length - 1))
            {
                return _is_addr_readable(info.end + 1, addr + length - 1 - info.end, i + 1);
            }
            else
            {
                return true;
            }
        }
    }
    return false;
}

extern "C" bool is_pointer_readable(void *ptr, size_t element_size, int count)
{
    if (ptr == nullptr)
        return false;
    auto length = element_size * std::max(1, count);
    assert(length > 0);
    auto result = _is_addr_readable((uint64_t)ptr, length, 0);
    SGXSAN_WARNING(result == false, "Pass non-null unreadable pointer parameter");
    return result;
}
