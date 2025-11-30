set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${LINUX_SGX_SRC_DIR}/common/inc
    ${LINUX_SGX_SRC_DIR}/common/inc/internal
    ${LINUX_SGX_SRC_DIR}/sdk/simulation/tinst
    ${LINUX_SGX_SRC_DIR}/sdk/trts
    ../SGXSanRTApp
    ../)

add_library(
    SGXSanRTEnclave STATIC 
    TSticker.cpp)

set_target_properties(SGXSanRTEnclave PROPERTIES POSITION_INDEPENDENT_CODE True)
