set(PLTHOOK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ThirdParty/plthook/")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${LINUX_SGX_SRC_DIR}/common/inc
    ${LINUX_SGX_SRC_DIR}/common/inc/internal
    ${LINUX_SGX_SRC_DIR}/sdk/tlibthread
    ${LINUX_SGX_SRC_DIR}/sdk/trts
    ${PLTHOOK_DIR}
    ../
    ${CMAKE_CURRENT_SOURCE_DIR})

add_library(
    SGXSanRTApp STATIC 
    Malloc.cpp
    Poison.cpp
    PoisonCheck.cpp
    SGXSanRTApp.cpp
    ArgShadow.cpp
    MemAccessMgr.cpp
    Sticker.cpp
    HostASanRT.cpp
    Interceptor.cpp
    ${PLTHOOK_DIR}/plthook_elf.c)

set_target_properties(SGXSanRTApp PROPERTIES POSITION_INDEPENDENT_CODE True)
if(KAFL_FUZZER)
target_compile_definitions(SGXSanRTApp PUBLIC KAFL_FUZZER)
endif()