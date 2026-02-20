set(RT_ENCLAVE_SOURCE
    asan_globals.cpp
    EncalveTLSLifetime.cpp
    ErrorReport.cpp
    InternalDlmalloc.cpp
    Malloc.cpp
    MemAccessMgr.cpp
    MemIntrinsics.cpp
    MemoryAccessCallback.cpp
    PoisonCheck.cpp
    Poison.cpp
    Quarantine.cpp
    SGXSanPrintf.cpp
    SGXSanRTEnclave.cpp
    StackTrace.cpp
    UntrustSPAdjust.cpp)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64 -Wall -Wextra -Wno-implicit-exception-spec-mismatch -nostdinc -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64 -Wall -Wextra -Wno-implicit-exception-spec-mismatch -nostdinc -nostdinc++ -fvisibility=hidden -std=c++11")

include_directories(
    ${SGXSDK_DIR}/common/inc
    ${SGXSDK_DIR}/common/inc/internal
    ${SGXSDK_DIR}/common/inc/tlibc
    ${SGXSDK_DIR}/common/inc/libcxx
    ${SGXSDK_DIR}/sdk/tlibcxx/include
    ${SGXSDK_DIR}/sdk/trts
    ../linux-sgx/sdk/cpprt/linux/libunwind/include
    ../linux-sgx/sdk/cpprt/linux/libunwind/include/tdep-x86_64
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)
add_library(SGXSanRTEnclave STATIC ${RT_ENCLAVE_SOURCE})
set_target_properties(SGXSanRTEnclave PROPERTIES POSITION_INDEPENDENT_CODE True)
