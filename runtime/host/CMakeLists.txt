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

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${LINUX_SGX_SRC_DIR}/common/inc
    ${LINUX_SGX_SRC_DIR}/common/inc/internal
    ${LINUX_SGX_SRC_DIR}/sdk/tlibthread
    ${LINUX_SGX_SRC_DIR}/sdk/trts
    ${LINUX_SGX_SRC_DIR}/psw/urts
    ${LINUX_SGX_SRC_DIR}/psw/urts/linux
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LLVM_INSTALL_PREFIX}/lib/clang/13.0.1/include/fuzzer
    ${LIBFUZZER_DIR})

add_library(
    SGXSanRTApp STATIC 
    Malloc.cpp
    Poison.cpp
    PoisonCheck.cpp
    SGXSanRTApp.cpp
    MemAccessMgr.cpp
    Sticker.cpp
    Interceptor.cpp
    ${LINUX_SGX_SRC_DIR}/common/src/se_event.c
    ${LINUX_SGX_SRC_DIR}/psw/urts/enclave_mutex.cpp
    ${LIBFUZZER_SRC}
    test.cpp
)

set_target_properties(SGXSanRTApp PROPERTIES POSITION_INDEPENDENT_CODE True)
