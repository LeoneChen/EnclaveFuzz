# LLVM is normally built without RTTI. Be consistent with that.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti -std=c++17 -Wno-comment -Wno-unused-but-set-variable -Wno-unused-variable -Wno-return-type")

include_directories(${LLVM_INCLUDE_DIRS} ../ThirdParty/json/single_include ${CMAKE_CURRENT_BINARY_DIR})
add_library(SGXSanPass MODULE SGXSanPass.cpp AddressSanitizer.cpp PassUtil.cpp LLVMStructTypeSerialize.cpp)
