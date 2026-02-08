include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../SGXSanRTEnclave
    ${SGXSDK_DIR}/common/inc
)
add_library(SGXSanRTApp SHARED SGXSanRTApp.cpp)
