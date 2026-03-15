set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${SGXSDK_V_DIR}/common/inc
    ${SGXSDK_V_DIR}/common/inc/internal
    ${SGXSDK_V_DIR}/sdk/tlibthread
    ${SGXSDK_V_DIR}/sdk/trts
    ${SGXSDK_V_DIR}/psw/urts
    ${SGXSDK_V_DIR}/psw/urts/linux
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LLVM_INSTALL_PREFIX}/lib/clang/13.0.1/include/fuzzer
)

add_library(
    sgxsan_host_v STATIC
    Malloc.cpp
    Quarantine.cpp
    Poison.cpp
    PoisonCheck.cpp
    InstrumentedLibc.cpp
    ErrorReport.cpp
    Symbolizer.cpp
    SGXSanRTApp.cpp
    MemAccessMgr.cpp
    Sticker.cpp
    ${SGXSDK_V_DIR}/common/src/se_event.c
    ${SGXSDK_V_DIR}/psw/urts/enclave_mutex.cpp
    test.cpp
)

set_target_properties(sgxsan_host_v PROPERTIES POSITION_INDEPENDENT_CODE True)
