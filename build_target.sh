#!/bin/bash
set -e

PROJ_DIR=$(realpath $(dirname $0))

TARGET_NAME=""
TARGET_DIR=""
BUILD_DIR=""
INSTALL_DIR=""

JOBS=$(nproc)
DEBUG=0
BUILD=0
AS_FUZZ=0

MY_CC=${PROJ_DIR}/install/llvm-project/bin/clang
MY_CXX=${PROJ_DIR}/install/llvm-project/bin/clang++

show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h|--help           Show this help message"
    echo "  -t|--target         Target to build"
    echo "  -b|--build          Build"
    echo "  -g|--debug          Debug mode"
    echo "  --fuzz              Build for fuzzing"
}

OPTS=$(getopt -o ht:gb -l help,target:,debug,build,fuzz -n 'parse-options' -- "$@")
eval set -- "$OPTS"
while true; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -t|--target)
            TARGET_NAME=$2
            shift 2
            ;;
        -g|--debug)
            DEBUG=1
            shift
            ;;
        -b|--build)
            BUILD=1
            shift
            ;;
        --fuzz)
            AS_FUZZ=1
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
done

###################################
# TARGET_DIR FOR DIFFERENT TARGETS
###################################
case "${TARGET_NAME}" in
    "llvm-project")
        TARGET_DIR=${PROJ_DIR}/third_party/${TARGET_NAME}
        BUILD_DIR=${PROJ_DIR}/build/${TARGET_NAME}
        INSTALL_DIR=${PROJ_DIR}/install/${TARGET_NAME}
        ;;
    "wasm-micro-runtime"|"sgxwallet"|"SGX_SQLite"|"ehsm"|"sgx-reencrypt"|"sgx-wallet"|"SGXCryptoFile"|"mbedtls-SGX"|"TaLoS"|"SampleSGXSan")
        TARGET_DIR=${PROJ_DIR}/sgx_apps/${TARGET_NAME}
        BUILD_DIR="InProject"
        INSTALL_DIR="InProject"
        ;;
    "intel-sgx-ssl")
        TARGET_DIR=${PROJ_DIR}/sgx_apps/${TARGET_NAME}
        BUILD_DIR="InProject"
        INSTALL_DIR=${PROJ_DIR}/install/enclave_fuzz/sgxssl
        ;;
    *)
        echo "[!] Error: Unsupported target: ${TARGET_NAME}"
        exit 1
        ;;
esac

echo "[+] Building target: ${TARGET_DIR}"
echo "[+] Build directory: ${BUILD_DIR}"
echo "[+] Install directory: ${INSTALL_DIR}"

###################################
# BUILD FOR DIFFERENT TARGETS
###################################
if [ ${BUILD} -eq 1 ]; then
    echo "[+] Building & installing..."
    case "${TARGET_NAME}" in
        "llvm-project")
            pushd ${TARGET_DIR}
                cmake -B ${BUILD_DIR} -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCOMPILER_RT_DEBUG=ON -DLLVM_TARGETS_TO_BUILD="X86" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;lld" -DLLVM_ABI_BREAKING_CHECKS=FORCE_OFF ./llvm/ -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
                cmake --build ${BUILD_DIR} -j${JOBS}
                cmake --install ${BUILD_DIR}
            popd
            ;;
        "wasm-micro-runtime")
            pushd ${TARGET_DIR}
                if [ ${DEBUG} -eq 1 ]; then
                    DEBUG_MAKE_FLAGS="SGX_DEBUG=1 SGX_PRERELEASE=0"
                    DEBUG_CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug"
                else
                    DEBUG_MAKE_FLAGS="SGX_DEBUG=0 SGX_PRERELEASE=1"
                    DEBUG_CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
                fi
                pushd product-mini/platforms/linux-sgx
                    rm -rf build
                    CC="${MY_CC}" CXX="${MY_CXX}" SGX_SDK="${PROJ_DIR}/install/enclave_fuzz_n" cmake -B build -DENCLAVE_FUZZ=1 ${DEBUG_CMAKE_FLAGS} -DWAMR_BUILD_SIMD=0
                    cmake --build build -j${JOBS}

                    pushd enclave-sample
                        make clean
                        make SGX_MODE=HW CC="${MY_CC}" CXX="${MY_CXX}" SGX_SDK="${PROJ_DIR}/install/enclave_fuzz_n" SGX_SSL="${PROJ_DIR}/install/enclave_fuzz/sgxssl" ENCLAVE_FUZZ=1 ${DEBUG_MAKE_FLAGS} -j${JOBS}
                    popd
                popd
            popd
            ;;
        "intel-sgx-ssl")
            pushd ${TARGET_DIR}
                # clean
                if [ -f openssl_source/openssl/Makefile ]
                then
                    make -C openssl_source/openssl distclean
                fi
                make -C Linux clean
                make -C Linux clean DEBUG=1
                rm -rf Linux/package/lib64/* Linux/package/include/crypto/
                # build
                if [ ${DEBUG} -eq 1 ]; then
                    DEBUG_MAKE_FLAGS="DEBUG=1"
                else
                    DEBUG_MAKE_FLAGS="DEBUG=0"
                fi
                make -C Linux sgxssl_no_mitigation SGX_MODE=SIM ENCLAVE_FUZZ=1 ${DEBUG_MAKE_FLAGS} CC="${MY_CC}" CXX="${MY_CXX}" SGX_SDK="${PROJ_DIR}/install/enclave_fuzz" SKIP_INTELCPU_CHECK=TRUE -j${JOBS}
                # install for other apps
                cp -rf ${TARGET_DIR}/Linux/package/* ${INSTALL_DIR}
                pushd ${INSTALL_DIR}/lib64
                    libs=(tsgxssl tsgxssl_crypto usgxssl tsgxssl_ssl)
                    for lib in "${libs[@]}"; do
                        if [[ ! -f libsgx_${lib}.a && -f libsgx_${lib}d.a ]]; then ln -sf libsgx_${lib}d.a libsgx_${lib}.a; fi
                    done
                popd
            popd
            ;;
        "sgxwallet")
            pushd ${TARGET_DIR}
                # pushd scripts
                #     ./build_deps.sh
                # popd
                if [ -f Makefile ]; then
                    make clean
                fi
                ./autoconf.bash
                if [ ${AS_FUZZ} -eq 1 ]; then
                    ./configure --with-sgxsdk=${PROJ_DIR}/install/enclave_fuzz_v CFLAGS=" -Og -g" CXXFLAGS=" -Og -g" CC="${MY_CC}" CXX="${MY_CXX}" --enable-enclave-fuzz --enable-sgx-simulation
                else
                    ./configure CFLAGS=" -Og -g" CXXFLAGS=" -Og -g" # --with-sgx-build=prerelease
                fi
                make -j${JOBS}
            popd
            ;;
        "SGX_SQLite"|"sgx-reencrypt"|"sgx-wallet"|"SGXCryptoFile"|"SampleSGXSan")
            pushd ${TARGET_DIR}
                make clean SGX_SDK="${PROJ_DIR}/install/enclave_fuzz"
                if [ ${DEBUG} -eq 1 ]; then
                    DEBUG_FLAG=" SGX_DEBUG=1 SGX_PRERELEASE=0"
                else
                    DEBUG_FLAG=" SGX_DEBUG=0 SGX_PRERELEASE=1"
                fi
                make SGX_MODE=HW CC=${MY_CC} CXX=${MY_CXX} SGX_SDK="${PROJ_DIR}/install/enclave_fuzz" ${DEBUG_FLAG} -j${JOBS} ENCLAVE_FUZZ=1
            popd
            ;;
        "ehsm")
            pushd ${TARGET_DIR}
                make clean SGX_SDK="${PROJ_DIR}/install/enclave_fuzz"
                if [ ${DEBUG} -eq 1 ]; then
                    DEBUG_FLAG=" SGX_DEBUG=1 SGX_PRERELEASE=0"
                else
                    DEBUG_FLAG=" SGX_DEBUG=0 SGX_PRERELEASE=1"
                fi
                make -C core SGX_MODE=SIM CC=${MY_CC} CXX=${MY_CXX} SGX_SDK="${PROJ_DIR}/install/enclave_fuzz" ${DEBUG_FLAG} -j${JOBS}
            popd
            ;;
        "mbedtls-SGX")
            pushd ${TARGET_DIR}
                rm -rf build
                if [ ${DEBUG} -eq 1 ]; then
                    DEBUG_FLAG=" -DCMAKE_BUILD_TYPE=Debug"
                else
                    DEBUG_FLAG=" -DCMAKE_BUILD_TYPE=Release"
                fi
                CC=${MY_CC} CXX=${MY_CXX} cmake -B build -DCOMPILE_EXAMPLES=1 -DSGX_SDK="${PROJ_DIR}/install/enclave_fuzz" ${DEBUG_FLAG}
                cmake --build build -j${JOBS}
            popd
            ;;
        "TaLoS")
            pushd ${TARGET_DIR}/crypto
                make -f Makefile.sgx clean
                if [ ${DEBUG} -eq 1 ]; then
                    DEBUG_FLAG=" SGX_DEBUG=1 SGX_PRERELEASE=0"
                else
                    DEBUG_FLAG=" SGX_DEBUG=0 SGX_PRERELEASE=1"
                fi
                make -f Makefile.sgx SGX_MODE=SIM CC=${MY_CC} CXX=${MY_CXX} SGX_SDK="${PROJ_DIR}/install/enclave_fuzz" ${DEBUG_FLAG} -j${JOBS}
            popd
            ;;
        *)
            echo "[!] Error: Unsupported target: ${TARGET_NAME}"
            exit 1
            ;;
    esac
fi

###################################
# SETUP WORKDIR FOR TARGETS
###################################
if [ ${AS_FUZZ} -eq 1 ]; then
    echo "[+] Setting up workdir..."
    case "${TARGET_NAME}" in
        "wasm-micro-runtime")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app product-mini/platforms/linux-sgx/enclave-sample/iwasm --enclave product-mini/platforms/linux-sgx/enclave-sample/enclave.signed.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "intel-sgx-ssl")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app Linux/sgx/test_app/TestApp --enclave Linux/sgx/test_app/TestEnclave.signed.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "sgxwallet")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app sgxwallet --enclave secure_enclave/secure_enclave.signed.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "SGX_SQLite")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app app --enclave enclave.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "ehsm")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app out/ehsm-core/ehsm_core_test --enclave out/ehsm-core/libenclave-ehsm-core.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "sgx-reencrypt")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app bin/test-app --enclave reencrypt.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "sgx-wallet")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app sgx-wallet --enclave enclave.signed.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "SGXCryptoFile")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app sgxCryptoFile --enclave CryptoEnclave.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "mbedtls-SGX")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app build/s_client --enclave build/enclave.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "TaLoS")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app crypto/link --enclave crypto/enclave.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        "SampleSGXSan")
            pushd ${TARGET_DIR}
                ${PROJ_DIR}/script/setup.sh --app app --enclave enclave.signed.so --workdir ${PROJ_DIR}/workdir/${TARGET_NAME}
            popd
            ;;
        *)
            echo "[!] Error: Unsupported target: ${TARGET_NAME}"
            exit 1
            ;;
    esac
fi