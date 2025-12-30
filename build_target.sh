#!/bin/bash
set -e

PROJ_DIR=$(realpath $(dirname $0))

BUILD_DIR=${PROJ_DIR}/build/
INSTALL_DIR=${PROJ_DIR}/install/

TARGET_NAME=llvm-project
TARGET_DIR=${PROJ_DIR}/ThirdParty/${TARGET_NAME}

JOBS=$(nproc)

pushd ${TARGET_DIR}
    cmake -B ${BUILD_DIR}/${TARGET_NAME} -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCOMPILER_RT_DEBUG=ON -DLLVM_TARGETS_TO_BUILD="X86" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;lld" -DLLVM_ABI_BREAKING_CHECKS=FORCE_OFF ${TARGET_DIR}/llvm/ -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}/${TARGET_NAME}
    cmake --build ${BUILD_DIR}/${TARGET_NAME} -j${JOBS}
    cmake --install ${BUILD_DIR}/${TARGET_NAME}
popd