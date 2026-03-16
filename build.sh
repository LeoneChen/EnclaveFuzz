#!/bin/bash
set -e

PROJ_DIR=$(realpath $(dirname $0))

IS_DEBUG=0
PREPARE_SDK=0
BUILD_SDK=0

MY_CC=${PROJ_DIR}/install/llvm-project/bin/clang
MY_CXX=${PROJ_DIR}/install/llvm-project/bin/clang++

JOBS=$(nproc)

COMMON_COMPILE_FLAGS=""

show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h|--help           Show this help message"
    echo "  -g                  Build in debug mode"
    echo "  --prepare-sdk       Prepare SGX SDK (only once needed)"
    echo "  --build-sdk         Build SGX SDK"
    exit 0
}

OPTS=$(getopt -o hg -l help,prepare-sdk,build-sdk -n 'parse-options' -- "$@")
eval set -- "$OPTS"
while true; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -g)
            IS_DEBUG=1
            COMMON_COMPILE_FLAGS+=" -g -O0"
            export DEBUG=1
            shift
            ;;
        --prepare-sdk)
            PREPARE_SDK=1
            shift
            ;;
        --build-sdk)
            BUILD_SDK=1
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            show_help
            ;;
    esac
done

COMMON_COMPILE_FLAGS+=" -Wno-implicit-exception-spec-mismatch -Wno-unknown-warning-option -Wno-unknown-attributes"

echo "[+] CC: ${MY_CC}"
echo "[+] CXX: ${MY_CXX}"
echo "[+] COMMON_COMPILE_FLAGS: ${COMMON_COMPILE_FLAGS}"

########## Prepare SGX SDK ##########
if [ ${PREPARE_SDK} -eq 1 ]; then
    pushd ${PROJ_DIR}/third_party/linux-sgx
        make preparation
    popd
    pushd ${PROJ_DIR}/third_party/linux-sgx-v
        make preparation
    popd
fi

########## Build sgx_edger8r ##########
pushd ${PROJ_DIR}/third_party/linux-sgx/sdk/edger8r
    dune build
popd
pushd ${PROJ_DIR}/third_party/linux-sgx-v/sdk/edger8r
    dune build
popd

########## Build EnclaveFuzz and Sticker ##########
if [ ${IS_DEBUG} -eq 1 ]; then
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug"
else
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
fi
CC="${MY_CC}" CXX="${MY_CXX}" cmake -B ${PROJ_DIR}/build/enclave_fuzz ${CMAKE_FLAGS}
cmake --build ${PROJ_DIR}/build/enclave_fuzz -j$(nproc)
cmake --install ${PROJ_DIR}/build/enclave_fuzz --component sgxsan --prefix ${PROJ_DIR}/install/enclave_fuzz_n
cmake --install ${PROJ_DIR}/build/enclave_fuzz --component sgxsan_v --prefix ${PROJ_DIR}/install/enclave_fuzz_v

########## Build SGX SDK ##########
build_sdk() {
    local SGXSDK_DIR=$1
    local INSTALL_DIR=$2
    local OPT=$3
    local ENCLAVE_COMPILE_FLAGS=$4

    export SGX_SDK=${INSTALL_DIR}

    # remove old
    rm -rf ${INSTALL_DIR}/lib64/libsgx_* ${INSTALL_DIR}/bin/x64/sgx_sign ${INSTALL_DIR}/sgxssl
    # prepare directory
    mkdir -p ${INSTALL_DIR}/lib64 ${INSTALL_DIR}/bin/x64 ${INSTALL_DIR}/sgxssl

    get_host_lib() {
        echo "== Get $2 =="
        pushd "$1"
            make clean -s
            make -j${JOBS} -s COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
            cp $2 ${INSTALL_DIR}/lib64
        popd
    }

    get_enclave_lib() {
        echo "== Get $2 =="
        pushd "$1"
            make clean -s
            make -j${JOBS} -s CC="${MY_CC}" CXX="${MY_CXX}" COMMON_FLAGS="${ENCLAVE_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
            cp $2 ${INSTALL_DIR}/lib64
        popd
    }

    get_enclave_lib_orig() {
        echo "== Get $2 =="
        pushd "$1"
            make clean -s
            make -j${JOBS} -s COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
            cp $2 ${INSTALL_DIR}/lib64
        popd
    }

    ########## HOST ##########
    get_host_lib "${SGXSDK_DIR}/psw/urts/linux"                                     "libsgx_urts.so"
    ln -sf libsgx_urts.so ${INSTALL_DIR}/lib64/libsgx_urts.so.2
    get_host_lib "${SGXSDK_DIR}/psw/enclave_common"                                 "libsgx_enclave_common.so libsgx_enclave_common.a"
    ln -sf libsgx_enclave_common.so ${INSTALL_DIR}/lib64/libsgx_enclave_common.so.1
    get_host_lib "${SGXSDK_DIR}/psw/uae_service/linux"                              "libsgx_uae_service.so libsgx_epid.so libsgx_launch.so libsgx_quote_ex.so"
    get_host_lib "${SGXSDK_DIR}/sdk/ukey_exchange"                                  "libsgx_ukey_exchange.a"
    get_host_lib "${SGXSDK_DIR}/sdk/protected_fs/sgx_uprotected_fs"                 "libsgx_uprotected_fs.a"
    get_host_lib "${SGXSDK_DIR}/sdk/libcapable/linux"                               "libsgx_capable.a libsgx_capable.so"
    get_host_lib "${SGXSDK_DIR}/sdk/simulation/uae_service_sim/linux"               "libsgx_uae_service_sim.so libsgx_quote_ex_sim.so libsgx_epid_sim.so"
    local saved_jobs=${JOBS}
    JOBS=1
    get_host_lib "${SGXSDK_DIR}/sdk/simulation/urtssim/"                     "linux/libsgx_urts_sim.so"
    get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/linux"     "libsgx_dcap_ql.so"
    JOBS=${saved_jobs}
    ln -sf libsgx_dcap_ql.so ${INSTALL_DIR}/lib64/libsgx_dcap_ql.so.1
    get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/quote/linux"      "libsgx_qe3_logic.so"
    get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/pce_wrapper/linux"              "libsgx_pce_logic.so libsgx_pce_logic.a"
    ln -sf libsgx_pce_logic.so ${INSTALL_DIR}/lib64/libsgx_pce_logic.so.1
    get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteVerification/dcap_quoteverify/linux"          "libsgx_dcap_quoteverify.so libsgx_dcap_qvl_attestation.a libsgx_dcap_qvl_parser.a"
    ln -sf libsgx_dcap_quoteverify.so ${INSTALL_DIR}/lib64/libsgx_dcap_quoteverify.so.1

    ########## ENCLAVE ##########
    get_enclave_lib "${SGXSDK_DIR}/sdk/pthread"                                     "libsgx_pthread.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/tkey_exchange"                               "libsgx_tkey_exchange.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/tlibcrypto"                                  "libsgx_tcrypto.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/protected_fs/sgx_tprotected_fs"              "libsgx_tprotected_fs.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/tsafecrt"                                    "libsgx_tsafecrt.a"
    get_enclave_lib "${SGXSDK_DIR}/external/dcap_source/QuoteVerification/dcap_tvl" "libsgx_dcap_tvl.a"
    cp ${SGXSDK_DIR}/external/dcap_source/QuoteVerification/{dcap_tvl/sgx_dcap_tvl.edl,QvE/Include/sgx_qve_header.h} ${INSTALL_DIR}/include
    cp ${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/common/inc/{sgx_ql_lib_common,sgx_ql_quote,sgx_quote_3,sgx_quote_4}.h ${INSTALL_DIR}/include
    get_enclave_lib "${SGXSDK_DIR}/sdk/simulation/tservice_sim"                     "libsgx_tservice_sim.a"
    if [ ${OPT} -eq 0 ]; then
        # asan is not initialized before init_enclave in trts, enclave ctor is delayed until first ecall
        get_enclave_lib_orig "${SGXSDK_DIR}/sdk/simulation/trtssim"                          "linux/libsgx_trts_sim.a"
        get_enclave_lib_orig "${SGXSDK_DIR}/sdk/trts"                                   "linux/libsgx_trts.a"
    else
        get_enclave_lib "${SGXSDK_DIR}/sdk/simulation/trtssim"                          "linux/libsgx_trts_sim.a"
    fi

    echo "== Get libsgx_tcxx.a =="
    if [ ${OPT} -eq 0 ]; then
        rm -f ${SGXSDK_DIR}/build/linux/libsgx_tcxx.a
        make clean -s -C ${SGXSDK_DIR}/sdk/tlibcxx
        make clean -s -C ${SGXSDK_DIR}/sdk/cpprt
        make -C ${SGXSDK_DIR}/sdk tcxx -j${JOBS} COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
        cp ${SGXSDK_DIR}/build/linux/libsgx_tcxx.a ${INSTALL_DIR}/lib64/
        cp ${SGXSDK_DIR}/build/linux/libsgx_tcxx.a ${INSTALL_DIR}/lib64/libsgx_tstdcxx.a
    else
        pushd ${SGXSDK_DIR}/build/linux/
            rm -f libsgx_tcxx.a
            ar rcs libsgx_tcxx.a
            cp libsgx_tcxx.a ${INSTALL_DIR}/lib64/
            rm -f libsgx_tstdcxx.a
            ar rcs libsgx_tstdcxx.a
            cp libsgx_tstdcxx.a ${INSTALL_DIR}/lib64/libsgx_tstdcxx.a
        popd
    fi

    echo "== Get libsgx_tstdc.a =="
    if [ ${OPT} -eq 0 ]; then
        rm -f ${SGXSDK_DIR}/build/linux/libsgx_tstdc.a
        make clean -s -C ${SGXSDK_DIR}/sdk/tlibc
        make clean -s -C ${SGXSDK_DIR}/sdk/tlibthread
        make clean -s -C ${SGXSDK_DIR}/sdk/compiler-rt
        make clean -s -C ${SGXSDK_DIR}/sdk/tsafecrt
        make clean -s -C ${SGXSDK_DIR}/sdk/tsetjmp
        make clean -s -C ${SGXSDK_DIR}/sdk/tmm_rsrv
        make -C ${SGXSDK_DIR}/sdk tstdc -j${JOBS} COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
        cp ${SGXSDK_DIR}/build/linux/libsgx_tstdc.a ${INSTALL_DIR}/lib64/
    else
        pushd ${SGXSDK_DIR}/build/linux/
            rm -f libsgx_tstdc.a
            local INC_PATH="-I${SGXSDK_DIR}/common/inc/ -I${SGXSDK_DIR}/common/inc/internal -I${SGXSDK_DIR}/sdk/trts -I${SGXSDK_DIR}/psw/urts -I${SGXSDK_DIR}/psw/urts/linux"

            # Array of source files
            declare -a C_SOURCES=(
                "${SGXSDK_DIR}/sdk/tlibc/gen/spinlock.c"
                "${SGXSDK_DIR}/sdk/tlibc/gen/errno.c"
                "${SGXSDK_DIR}/sdk/tlibc/string/consttime_memequal.c"
            )
            # Array of source files
            declare -a CXX_SOURCES=(
                "${SGXSDK_DIR}/sdk/tlibthread/sethread_cond.cpp"
                "${SGXSDK_DIR}/sdk/tlibthread/sethread_mutex.cpp"
                "${SGXSDK_DIR}/sdk/tlibthread/sethread_rwlock.cpp"
                "${SGXSDK_DIR}/sdk/tlibthread/sethread_utils.cpp"
            )

            local OBJECTS=""
            for src in "${C_SOURCES[@]}"; do
                filename=$(basename "$src")
                out="${filename%.*}.o"
                if [ ${IS_DEBUG} -eq 1 ]; then
                    ${MY_CC} ${INC_PATH} -c "$src" -o "$out" -g -O0
                else
                    ${MY_CC} ${INC_PATH} -c "$src" -o "$out"
                fi
                OBJECTS+="$out "
            done
            for src in "${CXX_SOURCES[@]}"; do
                filename=$(basename "$src")
                out="${filename%.*}.o"
                if [ ${IS_DEBUG} -eq 1 ]; then
                    ${MY_CXX} ${INC_PATH} -c "$src" -o "$out" -g -O0
                else
                    ${MY_CXX} ${INC_PATH} -c "$src" -o "$out"
                fi
                OBJECTS+="$out "
            done

            ar rcs libsgx_tstdc.a $OBJECTS
            cp libsgx_tstdc.a ${INSTALL_DIR}/lib64/
        popd
    fi

    if [ ${OPT} -eq 0 ]; then
        echo "== Get libsgx_tservice.a =="
        rm -f ${SGXSDK_DIR}/build/linux/libsgx_tservice.a
        make clean -s -C ${SGXSDK_DIR}/sdk/selib/linux
        make clean -s -C ${SGXSDK_DIR}/sdk/tseal/linux
        make clean -s -C ${SGXSDK_DIR}/sdk/ec_dh_lib
        make -C ${SGXSDK_DIR}/sdk tservice -j${JOBS} COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
        cp ${SGXSDK_DIR}/build/linux/libsgx_tservice.a ${INSTALL_DIR}/lib64/
    fi

    ########## TOOL ##########
    echo "== Get sgx_sign =="
    pushd ${SGXSDK_DIR}/sdk/sign_tool/SignTool
        make clean -s
        make -j${JOBS}
        cp sgx_sign ${INSTALL_DIR}/bin/x64
    popd

    unset -f get_host_lib get_enclave_lib get_enclave_lib_orig
    echo "[*] Successfully get SGXSDK"
}

if [ ${BUILD_SDK} -eq 1 ]; then
    build_sdk "${PROJ_DIR}/third_party/linux-sgx" "${PROJ_DIR}/install/enclave_fuzz_n" 0 "-fsanitize=address -mllvm -asan-enclave -mllvm -asan-use-after-return=never -mllvm -asan-opt-globals=false -fsanitize-coverage=inline-8bit-counters,pc-table"
    build_sdk "${PROJ_DIR}/third_party/linux-sgx-v" "${PROJ_DIR}/install/enclave_fuzz_v" 1 "-fsanitize=address -mllvm -asan-enclave-v -mllvm -asan-use-after-return=never -mllvm -asan-opt-globals=false -fsanitize-coverage=inline-8bit-counters,pc-table"
fi

ln -sf enclave_fuzz_v ${PROJ_DIR}/install/enclave_fuzz
