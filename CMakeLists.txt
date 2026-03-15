cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(SGXSDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/linux-sgx")
set(SGXSDK_V_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/linux-sgx-v")

set(LLVM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/install/llvm-project/")
message(STATUS "LLVM_DIR: ${LLVM_DIR}")
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM_DIR: ${LLVM_INSTALL_PREFIX}")

add_subdirectory(runtime)
add_subdirectory(runtime-v)

install(TARGETS
        sgxsan_host
        sgxsan_enclave
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64
        COMPONENT sgxsan)

# same one for sgxan and sgxsan_v, since they are compatible with each other
install(FILES ${SGXSDK_DIR}/sdk/edger8r/_build/default/linux/Edger8r.bc
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
    RENAME sgx_edger8r
    DESTINATION bin/x64)

install(DIRECTORY
    ${SGXSDK_DIR}/common/inc/
    DESTINATION include
    COMPONENT sgxsan
    PATTERN common/inc/internal EXCLUDE)

install(FILES
        ${SGXSDK_DIR}/external/sgx-emm/emm_src/include/sgx_mm.h
        ${SGXSDK_DIR}/external/sgx-emm/emm_src/include/sgx_mm_primitives.h
        ${SGXSDK_DIR}/external/sgx-emm/emm_src/include/sgx_mm_rt_abstraction.h
        DESTINATION include)

install(DIRECTORY ${SGXSDK_DIR}/sdk/tlibcxx/include/
        DESTINATION include/libcxx
        COMPONENT sgxsan)

install(DIRECTORY ${SGXSDK_DIR}/external/ippcp_internal/inc/
        DESTINATION include/ipp
        PATTERN "ippcp20u3.patch" EXCLUDE)

install(FILES ${SGXSDK_DIR}/common/buildenv.mk
        DESTINATION .)

install(DIRECTORY
    ${SGXSDK_V_DIR}/external/dcap_source/QuoteGeneration/pce_wrapper/inc/
    ${SGXSDK_V_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/inc/
    ${SGXSDK_V_DIR}/external/dcap_source/QuoteVerification/dcap_quoteverify/inc/
    DESTINATION include)

install(FILES
        ${SGXSDK_V_DIR}/external/dcap_source/QuoteGeneration/qpl/inc/sgx_default_quote_provider.h
        ${SGXSDK_V_DIR}/psw/enclave_common/sgx_enclave_common.h
        DESTINATION include)

# The following are for sgxsan_v, which is not compatible with sgxsan. We install them separately to avoid confusion.
install(TARGETS
        sgxsan_host_v
        sgxsan_enclave_v
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64
        COMPONENT sgxsan_v)

install(DIRECTORY
    ${SGXSDK_V_DIR}/common/inc/
    DESTINATION include
    COMPONENT sgxsan_v
    PATTERN common/inc/internal EXCLUDE
    PATTERN common/inc/stdc++ EXCLUDE
    PATTERN common/inc/tlibc EXCLUDE
    PATTERN common/inc/sgx_mm* EXCLUDE)

install(FILES
    ${SGXSDK_V_DIR}/common/inc/tlibc/mbusafecrt.h
    DESTINATION include/tlibc
    COMPONENT sgxsan_v)
