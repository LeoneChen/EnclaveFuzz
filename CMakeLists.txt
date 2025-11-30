cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(LINUX_SGX_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/linux-sgx")
set(SGXSAN_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(KAFL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/kAFL)
configure_file(SGXSanConfig.h.in SGXSanConfig.h @ONLY)

# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    set(LLVM_DIR "/usr/lib/llvm-13")
endif()

list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM_DIR: ${LLVM_DIR} -> ${LLVM_INSTALL_PREFIX}")

add_subdirectory(SGXSanPass)
add_subdirectory(SGXSanRT)
add_subdirectory(SGXFuzzerPass)
add_subdirectory(SGXFuzzerRT)

install(TARGETS
        SGXSanPass
        SGXSanRTApp
        SGXSanRTEnclave
        SGXFuzzerPass
        SGXFuzzerRT
        FuncRenamePass
        GetOCallTable
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64)

install(DIRECTORY
    ${LINUX_SGX_SRC_DIR}/common/inc/
    ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteGeneration/pce_wrapper/inc/
    ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/inc/
    ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteVerification/dcap_quoteverify/inc/
    DESTINATION include
    PATTERN common/inc/internal EXCLUDE
    PATTERN common/inc/stdc++ EXCLUDE
    PATTERN common/inc/tlibc EXCLUDE
    PATTERN common/inc/sgx_mm* EXCLUDE
)

install(FILES
    ${LINUX_SGX_SRC_DIR}/external/sgx-emm/emm_src/include/sgx_mm.h
    ${LINUX_SGX_SRC_DIR}/external/sgx-emm/emm_src/include/sgx_mm_primitives.h
    ${LINUX_SGX_SRC_DIR}/external/sgx-emm/emm_src/include/sgx_mm_rt_abstraction.h
    ${LINUX_SGX_SRC_DIR}/external/dcap_source/QuoteGeneration/qpl/inc/sgx_default_quote_provider.h
    ${LINUX_SGX_SRC_DIR}/psw/enclave_common/sgx_enclave_common.h
    DESTINATION include)

install(FILES
    ${LINUX_SGX_SRC_DIR}/common/inc/tlibc/mbusafecrt.h
    DESTINATION include/tlibc)

install(FILES ThirdParty/edger8r/_build/default/linux/Edger8r.bc
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
    RENAME sgx_edger8r
    DESTINATION bin/x64)

install(FILES ${LINUX_SGX_SRC_DIR}/common/buildenv.mk
    DESTINATION .)
