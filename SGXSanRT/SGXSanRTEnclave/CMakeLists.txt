set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${LINUX_SGX_SRC_DIR}/common/inc
    ${LINUX_SGX_MINI}/common/inc/internal
    ${LINUX_SGX_MINI}/sdk/simulation/tinst
    ${LINUX_SGX_MINI}/sdk/trts
    ../SGXSanRTApp
    ../)

add_library(
    SGXSanRTEnclave STATIC 
    TSticker.cpp)

set_target_properties(SGXSanRTEnclave PROPERTIES POSITION_INDEPENDENT_CODE True)
if(KAFL_FUZZER)
target_compile_definitions(SGXSanRTEnclave PUBLIC KAFL_FUZZER)
endif()