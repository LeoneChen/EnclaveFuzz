#!/bin/bash
set -e

PROJ_DIR=$(realpath $(dirname $0))
INSTALL_DIR=""
SGXSDK_DIR=$(realpath ${PROJ_DIR}/third_party/linux-sgx)
SGXSDK_V_DIR=$(realpath ${PROJ_DIR}/third_party/linux-sgx-v)

IS_DEBUG=0
PREPARE_SDK=0
BUILD_SDK=0

MY_CC=${PROJ_DIR}/install/llvm-project/bin/clang
MY_CXX=${PROJ_DIR}/install/llvm-project/bin/clang++

JOBS=$(nproc)

COMMON_COMPILE_FLAGS=""
ENCLAVE_COMPILE_FLAGS=""

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

INSTALL_DIR=${PROJ_DIR}/install/enclave_fuzz
COMMON_COMPILE_FLAGS+=" -Wno-implicit-exception-spec-mismatch -Wno-unknown-warning-option -Wno-unknown-attributes"
ENCLAVE_COMPILE_FLAGS+=" -fsanitize=address -mllvm -asan-enclave -mllvm -asan-use-after-return=never -fsanitize-coverage=inline-8bit-counters,pc-table"


echo "[+] CC: ${MY_CC}"
echo "[+] CXX: ${MY_CXX}"
echo "[+] COMMON_COMPILE_FLAGS: ${COMMON_COMPILE_FLAGS}"
echo "[+] ENCLAVE_COMPILE_FLAGS: ${ENCLAVE_COMPILE_FLAGS}"

########## Prepare SGX SDK ##########
if [ ${PREPARE_SDK} -eq 1 ]; then
    pushd ${SGXSDK_DIR}
        make preparation
    popd
    pushd ${SGXSDK_V_DIR}
        make preparation
    popd
fi

########## Build sgx_edger8r ##########
pushd ${PROJ_DIR}/third_party/linux-sgx/sdk/edger8r
    dune build
popd

########## Build EnclaveFuzz and Sticker ##########
if [ ${IS_DEBUG} -eq 1 ]; then
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug"
else
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
fi
CC="${MY_CC}" CXX="${MY_CXX}" cmake -S . -B ${PROJ_DIR}/build/enclave_fuzz ${CMAKE_FLAGS}
cmake --build ${PROJ_DIR}/build/enclave_fuzz -j$(nproc)
cmake --install ${PROJ_DIR}/build/enclave_fuzz --component sgxsan --prefix ${INSTALL_DIR}
cmake --install ${PROJ_DIR}/build/enclave_fuzz --component sgxsan_v --prefix ${INSTALL_DIR}_v

########## Build SGX SDK ##########
build_sdk() {
    local SDK_DIR=$1
    local INST_DIR=$2
    local OPT=$3

    export SGX_SDK=${INST_DIR}

    # remove old
    rm -rf ${INST_DIR}/lib64/libsgx_* ${INST_DIR}/bin/x64/sgx_sign ${INST_DIR}/sgxssl
    # prepare directory
    mkdir -p ${INST_DIR}/lib64 ${INST_DIR}/bin/x64 ${INST_DIR}/sgxssl

    get_host_lib() {
        echo "== Get $2 =="
        pushd $1
            make clean -s
            make -j${JOBS} -s COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
            cp $2 ${INST_DIR}/lib64
        popd
    }

    get_enclave_lib() {
        echo "== Get $2 =="
        pushd $1
            make clean -s
            make -j${JOBS} -s CC="${MY_CC}" CXX="${MY_CXX}" COMMON_FLAGS="${ENCLAVE_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
            cp $2 ${INST_DIR}/lib64
        popd
    }

    get_enclave_lib_orig() {
        echo "== Get $2 =="
        pushd $1
            make clean -s
            make -j${JOBS} -s COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
            cp $2 ${INST_DIR}/lib64
        popd
    }

    ########## HOST ##########
    get_host_lib "${SDK_DIR}/psw/urts/linux"                                     "libsgx_urts.so"
    ln -sf libsgx_urts.so ${INST_DIR}/lib64/libsgx_urts.so.2
    get_host_lib "${SDK_DIR}/psw/enclave_common"                                 "libsgx_enclave_common.so libsgx_enclave_common.a"
    ln -sf libsgx_enclave_common.so ${INST_DIR}/lib64/libsgx_enclave_common.so.1
    get_host_lib "${SDK_DIR}/psw/uae_service/linux"                              "libsgx_uae_service.so libsgx_epid.so libsgx_launch.so libsgx_quote_ex.so"
    get_host_lib "${SDK_DIR}/sdk/ukey_exchange"                                  "libsgx_ukey_exchange.a"
    get_host_lib "${SDK_DIR}/sdk/protected_fs/sgx_uprotected_fs"                 "libsgx_uprotected_fs.a"
    get_host_lib "${SDK_DIR}/sdk/libcapable/linux"                               "libsgx_capable.a libsgx_capable.so"
    get_host_lib "${SDK_DIR}/sdk/simulation/uae_service_sim/linux"               "libsgx_uae_service_sim.so libsgx_quote_ex_sim.so libsgx_epid_sim.so"
    JOBS=1 get_host_lib "${SDK_DIR}/sdk/simulation/urtssim/"                     "linux/libsgx_urts_sim.so"
    JOBS=1 get_host_lib "${SDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/linux"     "libsgx_dcap_ql.so"
    ln -sf libsgx_dcap_ql.so ${INST_DIR}/lib64/libsgx_dcap_ql.so.1
    get_host_lib "${SDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/quote/linux"      "libsgx_qe3_logic.so"
    get_host_lib "${SDK_DIR}/external/dcap_source/QuoteGeneration/pce_wrapper/linux"              "libsgx_pce_logic.so libsgx_pce_logic.a"
    ln -sf libsgx_pce_logic.so ${INST_DIR}/lib64/libsgx_pce_logic.so.1
    get_host_lib "${SDK_DIR}/external/dcap_source/QuoteVerification/dcap_quoteverify/linux"          "libsgx_dcap_quoteverify.so libsgx_dcap_qvl_attestation.a libsgx_dcap_qvl_parser.a"
    ln -sf libsgx_dcap_quoteverify.so ${INST_DIR}/lib64/libsgx_dcap_quoteverify.so.1

    ########## ENCLAVE ##########
    get_enclave_lib "${SDK_DIR}/sdk/pthread"                                     "libsgx_pthread.a"
    get_enclave_lib "${SDK_DIR}/sdk/tkey_exchange"                               "libsgx_tkey_exchange.a"
    get_enclave_lib "${SDK_DIR}/sdk/tlibcrypto"                                  "libsgx_tcrypto.a"
    get_enclave_lib "${SDK_DIR}/sdk/protected_fs/sgx_tprotected_fs"              "libsgx_tprotected_fs.a"
    get_enclave_lib "${SDK_DIR}/sdk/tsafecrt"                                    "libsgx_tsafecrt.a"
    get_enclave_lib "${SDK_DIR}/external/dcap_source/QuoteVerification/dcap_tvl" "libsgx_dcap_tvl.a"
    cp ${SDK_DIR}/external/dcap_source/QuoteVerification/{dcap_tvl/sgx_dcap_tvl.edl,QvE/Include/sgx_qve_header.h} ${INST_DIR}/include
    cp ${SDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/common/inc/{sgx_ql_lib_common,sgx_ql_quote,sgx_quote_3,sgx_quote_4}.h ${INST_DIR}/include
    get_enclave_lib "${SDK_DIR}/sdk/simulation/tservice_sim"                     "libsgx_tservice_sim.a"
    if [ ${OPT} -eq 0 ]; then
        # asan is not initialized before init_enclave in trts, enclave ctor is delayed until first ecall
        get_enclave_lib_orig "${SDK_DIR}/sdk/simulation/trtssim"                          "linux/libsgx_trts_sim.a"
        get_enclave_lib_orig "${SDK_DIR}/sdk/trts"                                   "linux/libsgx_trts.a"
    else
        get_enclave_lib "${SDK_DIR}/sdk/simulation/trtssim"                          "linux/libsgx_trts_sim.a"
    fi

    echo "== Get libsgx_tcxx.a =="
    if [ ${OPT} -eq 0 ]; then
        rm -f ${SDK_DIR}/build/linux/libsgx_tcxx.a
        make clean -s -C ${SDK_DIR}/sdk/tlibcxx
        make clean -s -C ${SDK_DIR}/sdk/cpprt
        make -C ${SDK_DIR}/sdk tcxx -j${JOBS} COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
        cp ${SDK_DIR}/build/linux/libsgx_tcxx.a ${INST_DIR}/lib64/
        cp ${SDK_DIR}/build/linux/libsgx_tcxx.a ${INST_DIR}/lib64/libsgx_tstdcxx.a
    else
        pushd ${SDK_DIR}/build/linux/
            rm -f libsgx_tcxx.a
            ar rcs libsgx_tcxx.a
            cp libsgx_tcxx.a ${INST_DIR}/lib64/
            rm -f libsgx_tstdcxx.a
            ar rcs libsgx_tstdcxx.a
            cp libsgx_tstdcxx.a ${INST_DIR}/lib64/
            cp libsgx_tstdcxx.a ${INST_DIR}/lib64/libsgx_tstdcxx.a
        popd
    fi

    echo "== Get libsgx_tstdc.a =="
    if [ ${OPT} -eq 0 ]; then
        rm -f ${SDK_DIR}/build/linux/libsgx_tstdc.a
        make clean -s -C ${SDK_DIR}/sdk/tlibc
        make clean -s -C ${SDK_DIR}/sdk/tlibthread
        make clean -s -C ${SDK_DIR}/sdk/compiler-rt
        make clean -s -C ${SDK_DIR}/sdk/tsafecrt
        make clean -s -C ${SDK_DIR}/sdk/tsetjmp
        make clean -s -C ${SDK_DIR}/sdk/tmm_rsrv
        make -C ${SDK_DIR}/sdk tstdc -j${JOBS} COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
        cp ${SDK_DIR}/build/linux/libsgx_tstdc.a ${INST_DIR}/lib64/
    else
        pushd ${SDK_DIR}/build/linux/
            rm -f libsgx_tstdc.a
            INC_PATH="-I${SDK_DIR}/common/inc/ -I${SDK_DIR}/common/inc/internal -I${SDK_DIR}/sdk/trts -I${SDK_DIR}/psw/urts -I${SDK_DIR}/psw/urts/linux"

            # Array of source files
            declare -a C_SOURCES=(
                "${SDK_DIR}/sdk/tlibc/gen/spinlock.c"
                "${SDK_DIR}/sdk/tlibc/gen/errno.c"
                "${SDK_DIR}/sdk/tlibc/string/consttime_memequal.c"
            )
            # Array of source files
            declare -a CXX_SOURCES=(
                "${SDK_DIR}/sdk/tlibthread/sethread_cond.cpp"
                "${SDK_DIR}/sdk/tlibthread/sethread_mutex.cpp"
                "${SDK_DIR}/sdk/tlibthread/sethread_rwlock.cpp"
                "${SDK_DIR}/sdk/tlibthread/sethread_utils.cpp"
            )

            OBJECTS=""
            for src in "${C_SOURCES[@]}"; do
                filename=$(basename "$src")
                out="${filename%.*}.o"
                if [[ "${MODE}" = "DEBUG" ]]; then
                    ${MY_CC} ${INC_PATH} -c "$src" -o "$out" -g -O0
                else
                    ${MY_CC} ${INC_PATH} -c "$src" -o "$out"
                fi
                OBJECTS+="$out "
            done
            for src in "${CXX_SOURCES[@]}"; do
                filename=$(basename "$src")
                out="${filename%.*}.o"
                if [[ "${MODE}" = "DEBUG" ]]; then
                    ${MY_CXX} ${INC_PATH} -c "$src" -o "$out" -g -O0
                else
                    ${MY_CXX} ${INC_PATH} -c "$src" -o "$out"
                fi
                OBJECTS+="$out "
            done
            
            ar rcs libsgx_tstdc.a $OBJECTS
            cp libsgx_tstdc.a ${INST_DIR}/lib64/
        popd
    fi

    if [ ${OPT} -eq 0 ]; then
        echo "== Get libsgx_tservice.a =="
        rm -f ${SDK_DIR}/build/linux/libsgx_tservice.a
        make clean -s -C ${SDK_DIR}/sdk/selib/linux
        make clean -s -C ${SDK_DIR}/sdk/tseal/linux
        make clean -s -C ${SDK_DIR}/sdk/ec_dh_lib
        make -C ${SDK_DIR}/sdk tservice -j${JOBS} COMMON_FLAGS="${COMMON_COMPILE_FLAGS}"
        cp ${SDK_DIR}/build/linux/libsgx_tservice.a ${INST_DIR}/lib64/
    fi

    ########## TOOL ##########
    echo "== Get sgx_sign =="
    pushd ${SDK_DIR}/sdk/sign_tool/SignTool
        make clean -s
        make -j${JOBS}
        cp sgx_sign ${INST_DIR}/bin/x64
    popd

    echo "[*] Successfully get SGXSDK"
}

if [ ${BUILD_SDK} -eq 1 ]; then
    build_sdk "${SGXSDK_DIR}"   "${INSTALL_DIR}" 0
    build_sdk "${SGXSDK_V_DIR}" "${INSTALL_DIR}_v" 1
fi
