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

# Framework header used by per-app harness.cpp (HARNESS_REGISTER macro,
# registry type/extern declarations). Installed to both sgxsan and
# sgxsan_v include dirs so apps using either runtime can include it.
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/harness/harness_framework.h
        DESTINATION include
        COMPONENT sgxsan)

install(DIRECTORY
    ${SGXSDK_DIR}/common/inc/
    DESTINATION include
    COMPONENT sgxsan
    PATTERN common/inc/internal EXCLUDE
    PATTERN common/inc/sgx_mm* EXCLUDE)

install(DIRECTORY ${SGXSDK_DIR}/sdk/tlibcxx/include/
        DESTINATION include/libcxx
        COMPONENT sgxsan)

# Files installed into both prefix dirs, each using its own SDK
set(_comps  sgxsan       sgxsan_v)
set(_sdkdirs "${SGXSDK_DIR}" "${SGXSDK_V_DIR}")
foreach(i RANGE 1)
    list(GET _comps   ${i} _comp)
    list(GET _sdkdirs ${i} _sdk)

    install(FILES ${_sdk}/sdk/edger8r/_build/default/linux/Edger8r.bc
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
        RENAME sgx_edger8r
        DESTINATION bin/x64
        COMPONENT ${_comp})

    install(FILES
            ${_sdk}/external/sgx-emm/emm_src/include/sgx_mm.h
            ${_sdk}/external/sgx-emm/emm_src/include/sgx_mm_primitives.h
            ${_sdk}/external/sgx-emm/emm_src/include/sgx_mm_rt_abstraction.h
            DESTINATION include
            COMPONENT ${_comp})

    install(DIRECTORY ${_sdk}/external/ippcp_internal/inc/
            DESTINATION include/ipp
            COMPONENT ${_comp}
            PATTERN "ippcp20u3.patch" EXCLUDE)

    install(FILES ${_sdk}/common/buildenv.mk
            DESTINATION .
            COMPONENT ${_comp})

    install(DIRECTORY
        ${_sdk}/external/dcap_source/QuoteGeneration/pce_wrapper/inc/
        ${_sdk}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/inc/
        ${_sdk}/external/dcap_source/QuoteVerification/dcap_quoteverify/inc/
        DESTINATION include
        COMPONENT ${_comp})

    install(FILES
            ${_sdk}/external/dcap_source/QuoteGeneration/qpl/inc/sgx_default_quote_provider.h
            ${_sdk}/psw/enclave_common/sgx_enclave_common.h
            DESTINATION include
            COMPONENT ${_comp})
endforeach()

# The following are for sgxsan_v, which is not compatible with sgxsan. We install them separately to avoid confusion.
install(TARGETS
        sgxsan_host_v
        sgxsan_enclave_v
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64
        COMPONENT sgxsan_v)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/harness/harness_framework.h
        DESTINATION include
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
