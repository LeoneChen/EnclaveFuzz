set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories(
    ${SGXSDK_V_DIR}/common/inc
    ${SGXSDK_V_DIR}/common/inc/internal
    ${SGXSDK_V_DIR}/sdk/simulation/tinst
    ${SGXSDK_V_DIR}/sdk/trts
    ../host)

add_library(
    sgxsan_enclave_v STATIC 
    TSticker.cpp)

set_target_properties(sgxsan_enclave_v PROPERTIES POSITION_INDEPENDENT_CODE True)
