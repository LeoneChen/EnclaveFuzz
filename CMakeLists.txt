cmake_minimum_required(VERSION 3.16)
project(SGXSan)

set(SGXSDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/linux-sgx")

# get LLVM_DIR
set(LLVM_DIR "$ENV{LLVM_DIR}")
if(NOT LLVM_DIR)
    set(LLVM_DIR "/usr/lib/llvm-13")
endif()

message(STATUS "LLVM_DIR: ${LLVM_DIR}")
list(APPEND CMAKE_PREFIX_PATH "${LLVM_DIR}/lib/cmake/llvm/")
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM_DIR: ${LLVM_INSTALL_PREFIX}")

add_subdirectory(pass)
add_subdirectory(runtime)

install(TARGETS
        SGXSanPass
        SGXSanRTApp
        SGXSanRTEnclave
        LIBRARY DESTINATION lib64
        ARCHIVE DESTINATION lib64)

install(FILES runtime/enclave/SGXSanRTEnclave.edl
        DESTINATION include)

install(FILES third_party/edger8r/_build/default/linux/Edger8r.bc
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
    RENAME sgx_edger8r
    DESTINATION bin/x64)

install(DIRECTORY
    ${SGXSDK_DIR}/common/inc/
    ${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/pce_wrapper/inc/
    DESTINATION include
    PATTERN common/inc/internal EXCLUDE)

install(DIRECTORY ${SGXSDK_DIR}/sdk/tlibcxx/include/
        DESTINATION include/libcxx)

install(DIRECTORY ${SGXSDK_DIR}/external/ippcp_internal/inc/
        DESTINATION include/ipp
        PATTERN "ippcp20u3.patch" EXCLUDE)

install(FILES ${SGXSDK_DIR}/common/buildenv.mk
        DESTINATION .)
