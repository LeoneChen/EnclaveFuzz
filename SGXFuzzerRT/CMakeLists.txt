set(LIBFUZZER_SRC
    ../ThirdParty/libFuzzer/FuzzerCrossOver.cpp
    ../ThirdParty/libFuzzer/FuzzerDataFlowTrace.cpp
    ../ThirdParty/libFuzzer/FuzzerDriver.cpp
    ../ThirdParty/libFuzzer/FuzzerExtFunctionsDlsym.cpp
    ../ThirdParty/libFuzzer/FuzzerExtFunctionsWeak.cpp
    ../ThirdParty/libFuzzer/FuzzerExtFunctionsWindows.cpp
    ../ThirdParty/libFuzzer/FuzzerExtraCounters.cpp
    ../ThirdParty/libFuzzer/FuzzerFork.cpp
    ../ThirdParty/libFuzzer/FuzzerInterceptors.cpp
    ../ThirdParty/libFuzzer/FuzzerIO.cpp
    ../ThirdParty/libFuzzer/FuzzerIOPosix.cpp
    ../ThirdParty/libFuzzer/FuzzerIOWindows.cpp
    ../ThirdParty/libFuzzer/FuzzerLoop.cpp
    ../ThirdParty/libFuzzer/FuzzerMain.cpp
    ../ThirdParty/libFuzzer/FuzzerMerge.cpp
    ../ThirdParty/libFuzzer/FuzzerMutate.cpp
    ../ThirdParty/libFuzzer/FuzzerSHA1.cpp
    ../ThirdParty/libFuzzer/FuzzerTracePC.cpp
    ../ThirdParty/libFuzzer/FuzzerUtil.cpp
    ../ThirdParty/libFuzzer/FuzzerUtilDarwin.cpp
    ../ThirdParty/libFuzzer/FuzzerUtilFuchsia.cpp
    ../ThirdParty/libFuzzer/FuzzerUtilLinux.cpp
    ../ThirdParty/libFuzzer/FuzzerUtilPosix.cpp
    ../ThirdParty/libFuzzer/FuzzerUtilWindows.cpp)

set(FUZZER_RT_SRC
    libFuzzerCallback.cpp)


include_directories(
    ../ThirdParty/libFuzzer
    ../ThirdParty/json/single_include
    ../ThirdParty/magic_enum/include
    ${CMAKE_CURRENT_BINARY_DIR}/..
    ${LINUX_SGX_SRC_DIR}/common/inc
    ${LLVM_INSTALL_PREFIX}/lib/clang/13.0.1/include/fuzzer)

add_library(
    SGXFuzzerRT STATIC 
    ${LIBFUZZER_SRC}
    ${FUZZER_RT_SRC})

set_target_properties(
    SGXFuzzerRT PROPERTIES
    POSITION_INDEPENDENT_CODE True
    COMPILE_FLAGS "-Wall -Wno-unused-result -std=c++17")

# set_source_files_properties(${FUZZER_RT_SRC} PROPERTIES
#     COMPILE_FLAGS "-flegacy-pass-manager -Xclang -load -Xclang ${CMAKE_BINARY_DIR}/SGXSanPass/libSGXSanPass.so -mllvm -in-enclave=false")
