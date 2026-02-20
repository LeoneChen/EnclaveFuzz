set(LIBFUZZER_DIR ../../third_party/llvm-project/compiler-rt/lib/fuzzer/)
set(LIBFUZZER_SRC
    ${LIBFUZZER_DIR}/FuzzerCrossOver.cpp
    ${LIBFUZZER_DIR}/FuzzerDataFlowTrace.cpp
    ${LIBFUZZER_DIR}/FuzzerDriver.cpp
    ${LIBFUZZER_DIR}/FuzzerExtFunctionsDlsym.cpp
    ${LIBFUZZER_DIR}/FuzzerExtFunctionsWeak.cpp
    ${LIBFUZZER_DIR}/FuzzerExtFunctionsWindows.cpp
    ${LIBFUZZER_DIR}/FuzzerExtraCounters.cpp
    ${LIBFUZZER_DIR}/FuzzerFork.cpp
    ${LIBFUZZER_DIR}/FuzzerInterceptors.cpp
    ${LIBFUZZER_DIR}/FuzzerIO.cpp
    ${LIBFUZZER_DIR}/FuzzerIOPosix.cpp
    ${LIBFUZZER_DIR}/FuzzerIOWindows.cpp
    ${LIBFUZZER_DIR}/FuzzerLoop.cpp
    ${LIBFUZZER_DIR}/FuzzerMain.cpp
    ${LIBFUZZER_DIR}/FuzzerMerge.cpp
    ${LIBFUZZER_DIR}/FuzzerMutate.cpp
    ${LIBFUZZER_DIR}/FuzzerSHA1.cpp
    ${LIBFUZZER_DIR}/FuzzerTracePC.cpp
    ${LIBFUZZER_DIR}/FuzzerUtil.cpp
    ${LIBFUZZER_DIR}/FuzzerUtilDarwin.cpp
    ${LIBFUZZER_DIR}/FuzzerUtilFuchsia.cpp
    ${LIBFUZZER_DIR}/FuzzerUtilLinux.cpp
    ${LIBFUZZER_DIR}/FuzzerUtilPosix.cpp
    ${LIBFUZZER_DIR}/FuzzerUtilWindows.cpp)

include_directories(
    ${LIBFUZZER_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../enclave
    ${SGXSDK_DIR}/common/inc
    ${LLVM_INSTALL_PREFIX}/lib/clang/13.0.1/include/fuzzer)

add_library(SGXSanRTApp STATIC SGXSanRTApp.cpp test.cpp ${LIBFUZZER_SRC})

set_target_properties(
    SGXSanRTApp PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall -Wno-unused-result -std=c++17")
