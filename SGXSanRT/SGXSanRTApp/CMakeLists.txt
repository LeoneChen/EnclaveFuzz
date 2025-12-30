set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${LINUX_SGX_SRC_DIR}/common/inc
    ${LINUX_SGX_MINI}/common/inc/internal
    ${LINUX_SGX_MINI}/common/inc/tlibc
    ${LINUX_SGX_MINI}/sdk/tlibthread
    ${LINUX_SGX_MINI}/sdk/simulation/tinst
    ${LINUX_SGX_MINI}/sdk/trts
    ${CMAKE_CURRENT_SOURCE_DIR})

add_library(
    SGXSanRTApp STATIC 
    Malloc.cpp
    Poison.cpp
    PoisonCheck.cpp
    SGXSanRTApp.cpp
    MemAccessMgr.cpp
    Sticker.cpp
    Interceptor.cpp
    ${LINUX_SGX_MINI}/sdk/tlibc/gen/spinlock.c 
    ${LINUX_SGX_MINI}/sdk/tlibc/string/consttime_memequal.c 
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_cond.cpp
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_mutex.cpp
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_rwlock.cpp
    ${LINUX_SGX_MINI}/sdk/tlibthread/sethread_utils.cpp
    ${LINUX_SGX_MINI}/psw/urts/enclave_mutex.cpp 
    ${LINUX_SGX_MINI}/common/src/se_event.c
)

set_target_properties(SGXSanRTApp PROPERTIES POSITION_INDEPENDENT_CODE True)
if(KAFL_FUZZER)
target_compile_definitions(SGXSanRTApp PUBLIC KAFL_FUZZER)
endif()