include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../enclave
    ${SGXSDK_DIR}/common/inc
    ${LLVM_INSTALL_PREFIX}/lib/clang/13.0.1/include/fuzzer)

add_library(sgxsan_host STATIC SGXSanRTApp.cpp test.cpp)

set_target_properties(
    sgxsan_host PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall -Wno-unused-result -std=c++17")
