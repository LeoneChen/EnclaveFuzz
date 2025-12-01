#!/bin/bash
set -e

PROJ_DIR=$(realpath $(dirname $0))
BUILD_DIR="${PROJ_DIR}/build"
INSTALL_DIR="${PROJ_DIR}/install"
SGXSDK_DIR=$(realpath ${PROJ_DIR}/ThirdParty/linux-sgx)

INST_COV=0
PREPARE_SDK=0
BUILD_SDK=0
BUILD_SSL=0

CC=clang-13
CXX=clang++-13
# lld make src-cov work as expected
LD=lld
JOBS=$(nproc)

CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
COMMON_COMPILE_FLAGS=""
HOST_COMPILE_FLAGS=""
ENCLAVE_COMPILE_FLAGS=""

show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h|--help           Show this help message"
    echo "  -g                  Build in debug mode"
    echo "  --cov               Instrument coverage for SGXSDK"
    echo "  --prepare-sdk       Prepare SGX SDK (only once needed)"
    echo "  --build-sdk         Build SGX SDK"
    echo "  --build-ssl         Build SGX SSL"
}

OPTS=$(getopt -o hg -l help,cov,prepare-sdk,build-sdk,build-ssl -n 'parse-options' -- "$@")
eval set -- "$OPTS"
while true; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -g)
            COMMON_COMPILE_FLAGS+=" -g -O0"
            export DEBUG=1
            CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Debug"
            shift
            ;;
        --cov)
            INST_COV=1
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
        --build-ssl)
            BUILD_SSL=1
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

COMMON_COMPILE_FLAGS+=" -Wno-implicit-exception-spec-mismatch -Wno-unknown-warning-option -Wno-unknown-attributes -Wno-unused-command-line-argument"
ENCLAVE_COMPILE_FLAGS+=" -fno-discard-value-names -flegacy-pass-manager -Xclang -load -Xclang ${INSTALL_DIR}/lib64/libSGXSanPass.so"

if [ ${INST_COV} -eq 1 ]; then
    HOST_COMPILE_FLAGS+=" -fsanitize-coverage=inline-8bit-counters,bb,no-prune,pc-table,trace-cmp -fprofile-instr-generate -fcoverage-mapping -fuse-ld=${LD}"
    ENCLAVE_COMPILE_FLAGS+=" -fsanitize-coverage=inline-8bit-counters,bb,no-prune,pc-table,trace-cmp -fprofile-instr-generate -fcoverage-mapping -fuse-ld=${LD}"
fi

echo "[+] Instrument coverage: ${INST_COV}"
echo "[+] CMAKE_FLAGS: ${CMAKE_FLAGS}"
echo "[+] COMMON_COMPILE_FLAGS: ${COMMON_COMPILE_FLAGS}"
echo "[+] HOST_COMPILE_FLAGS: ${HOST_COMPILE_FLAGS}"
echo "[+] ENCLAVE_COMPILE_FLAGS: ${ENCLAVE_COMPILE_FLAGS}"

########## Prepare SGX SDK ##########
if [ ${PREPARE_SDK} -eq 1 ]; then
    pushd ${SGXSDK_DIR}
        make preparation
    popd
fi

########## Build sgx_edger8r ##########
pushd ThirdParty/edger8r
    eval $(opam env)
    dune build
popd

########## Build EnclaveFuzz and Sticker ##########
CC="${CC}" CXX="${CXX}" cmake -S . -B ${BUILD_DIR} -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} ${CMAKE_FLAGS}
cmake --build ${BUILD_DIR} -j${JOBS}
# pushd ${BUILD_DIR}
#     make VERBOSE=1
# popd
cmake --install ${BUILD_DIR}

########## Build SGX SDK ##########
if [ ${BUILD_SDK} -eq 1 ]; then
    export SGX_SDK=${INSTALL_DIR}

    rm -rf ${INSTALL_DIR}/lib64/libsgx_* ${INSTALL_DIR}/bin/x64/sgx_sign
    mkdir -p ${INSTALL_DIR}/lib64 ${INSTALL_DIR}/bin/x64

    get_host_lib() {
        echo "== Get $2 =="
        cd $1
        make clean -s
        make -j${JOBS} -s CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${HOST_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
        cp $2 ${INSTALL_DIR}/lib64
    }

    get_host_lib_orig() {
        echo "== Get $2 =="
        cd $1
        make clean -s
        make -j${JOBS} -s
        cp $2 ${INSTALL_DIR}/lib64
    }

    get_enclave_lib() {
        echo "== Get $2 =="
        cd $1
        make clean -s
        make -j${JOBS} -s CC="${CC}" CXX="${CXX}" COMMON_FLAGS="${ENCLAVE_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
        cp $2 ${INSTALL_DIR}/lib64
    }

    get_enclave_lib_orig() {
        echo "== Get $2 =="
        cd $1
        make clean -s
        make -j${JOBS} -s
        cp $2 ${INSTALL_DIR}/lib64
    }

    ########## HOST ##########
    get_host_lib_orig "${SGXSDK_DIR}/psw/urts/linux"                    "libsgx_urts.so"
    ln -sf libsgx_urts.so ${INSTALL_DIR}/lib64/libsgx_urts.so.2
    get_host_lib "${SGXSDK_DIR}/psw/enclave_common"                     "libsgx_enclave_common.so libsgx_enclave_common.a"
    ln -sf libsgx_enclave_common.so ${INSTALL_DIR}/lib64/libsgx_enclave_common.so.1
    get_host_lib "${SGXSDK_DIR}/psw/uae_service/linux"                  "libsgx_uae_service.so libsgx_epid.so libsgx_launch.so libsgx_quote_ex.so"
    get_host_lib "${SGXSDK_DIR}/sdk/ukey_exchange"                      "libsgx_ukey_exchange.a"
    get_host_lib "${SGXSDK_DIR}/sdk/protected_fs/sgx_uprotected_fs"     "libsgx_uprotected_fs.a"
    get_host_lib "${SGXSDK_DIR}/sdk/libcapable/linux"                   "libsgx_capable.a libsgx_capable.so"
    get_host_lib "${SGXSDK_DIR}/sdk/simulation/uae_service_sim/linux"   "libsgx_uae_service_sim.so libsgx_quote_ex_sim.so libsgx_epid_sim.so"
    JOBS=1 get_host_lib "${SGXSDK_DIR}/sdk/simulation/urtssim/"         "linux/libsgx_urts_sim.so"
    JOBS=1 get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/ql/linux"  "libsgx_dcap_ql.so"
    ln -sf libsgx_dcap_ql.so ${INSTALL_DIR}/lib64/libsgx_dcap_ql.so.1
    get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/quote/linux"      "libsgx_qe3_logic.so"
    get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/pce_wrapper/linux"              "libsgx_pce_logic.so libsgx_pce_logic.a"
    ln -sf libsgx_pce_logic.so ${INSTALL_DIR}/lib64/libsgx_pce_logic.so.1
    get_host_lib "${SGXSDK_DIR}/external/dcap_source/QuoteVerification/dcap_quoteverify/linux"       "libsgx_dcap_quoteverify.so libsgx_dcap_qvl_attestation.a libsgx_dcap_qvl_parser.a"
    ln -sf libsgx_dcap_quoteverify.so ${INSTALL_DIR}/lib64/libsgx_dcap_quoteverify.so.1

    ########## ENCLAVE ##########
    get_enclave_lib "${SGXSDK_DIR}/sdk/pthread"                         "libsgx_pthread.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/tkey_exchange"                   "libsgx_tkey_exchange.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/tlibcrypto"                      "libsgx_tcrypto.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/protected_fs/sgx_tprotected_fs"  "libsgx_tprotected_fs.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/tsafecrt"                        "libsgx_tsafecrt.a"
    get_enclave_lib "${SGXSDK_DIR}/external/dcap_source/QuoteVerification/dcap_tvl" "libsgx_dcap_tvl.a"
    cp ${SGXSDK_DIR}/external/dcap_source/QuoteVerification/{dcap_tvl/sgx_dcap_tvl.edl,QvE/Include/sgx_qve_header.h} ${INSTALL_DIR}/include
    cp ${SGXSDK_DIR}/external/dcap_source/QuoteGeneration/quote_wrapper/common/inc/{sgx_ql_lib_common,sgx_ql_quote,sgx_quote_3,sgx_quote_4}.h ${INSTALL_DIR}/include
    get_enclave_lib "${SGXSDK_DIR}/sdk/simulation/tservice_sim"         "libsgx_tservice_sim.a"
    get_enclave_lib "${SGXSDK_DIR}/sdk/simulation/trtssim"              "linux/libsgx_trts_sim.a"
    objcopy \
        --redefine-sym __tls_get_addr=_deleted__tls_get_addr \
        --redefine-sym atexit=_deleted_atexit \
        --redefine-sym __cxa_atexit=_deleted__cxa_atexit \
        --redefine-sym sgx_ocall=_deleted_sgx_ocall \
        --redefine-sym get_thread_data=_deleted_get_thread_data \
        --redefine-sym sgx_is_within_enclave=_deleted_sgx_is_within_enclave \
        --redefine-sym sgx_is_outside_enclave=_deleted_sgx_is_outside_enclave \
        --redefine-sym sgx_ocalloc=_deleted_sgx_ocalloc \
        --redefine-sym sgx_ocfree=_deleted_sgx_ocfree \
        ${INSTALL_DIR}/lib64/libsgx_trts_sim.a
    # get_enclave_lib_orig "${SGXSDK_DIR}/sdk/trts"                                  "linux/libsgx_trts.a"

    # echo "== Get libsgx_tcxx.a =="
    # rm -f ${SGXSDK_DIR}/build/linux/libsgx_tcxx.a
    # make clean -s -C ${SGXSDK_DIR}/sdk/tlibcxx
    # make clean -s -C ${SGXSDK_DIR}/sdk/cpprt
    # make -C ${SGXSDK_DIR}/sdk tcxx -j${JOBS}
    # cp ${SGXSDK_DIR}/build/linux/libsgx_tcxx.a ${INSTALL_DIR}/lib64/

    # echo "== Get libsgx_tstdc.a =="
    # rm -f ${SGXSDK_DIR}/build/linux/libsgx_tstdc.a
    # make clean -s -C ${SGXSDK_DIR}/sdk/tlibc
    # make clean -s -C ${SGXSDK_DIR}/sdk/tlibthread
    # make clean -s -C ${SGXSDK_DIR}/sdk/compiler-rt
    # make clean -s -C ${SGXSDK_DIR}/sdk/tsafecrt
    # make clean -s -C ${SGXSDK_DIR}/sdk/tsetjmp
    # make clean -s -C ${SGXSDK_DIR}/sdk/tmm_rsrv
    # make -C ${SGXSDK_DIR}/sdk tstdc -j${JOBS}
    # cp ${SGXSDK_DIR}/build/linux/libsgx_tstdc.a ${INSTALL_DIR}/lib64/

    # echo "== Get libsgx_tservice.a =="
    # rm -f ${SGXSDK_DIR}/build/linux/libsgx_tservice.a
    # make clean -s -C ${SGXSDK_DIR}/sdk/selib/linux
    # make clean -s -C ${SGXSDK_DIR}/sdk/tseal/linux
    # make clean -s -C ${SGXSDK_DIR}/sdk/ec_dh_lib
    # make -C ${SGXSDK_DIR}/sdk tservice -j${JOBS}
    # cp ${SGXSDK_DIR}/build/linux/libsgx_tservice.a ${INSTALL_DIR}/lib64/

    ########## TOOL ##########
    echo "== Get sgx_sign =="
    cd ${SGXSDK_DIR}/sdk/sign_tool/SignTool
    make clean -s
    make -j${JOBS}
    cp sgx_sign ${INSTALL_DIR}/bin/x64
fi

########## Build SGX SSL ##########
if [ ${BUILD_SSL} -eq 1 ]; then
    echo "== Get Intel SGXSSL =="
    rm -rf ${INSTALL_DIR}/sgxssl
    mkdir -p ${INSTALL_DIR}/sgxssl

    cd ${PROJ_DIR}/ThirdParty/intel-sgx-ssl
    ./clean.sh
    ./build.sh MODE=${MODE} INST_COV="TRUE"
    cp -rf ${PROJ_DIR}/ThirdParty/intel-sgx-ssl/Linux/package/* ${INSTALL_DIR}/sgxssl/
    cd ${INSTALL_DIR}/sgxssl/lib64
    if [[ ! -f libsgx_tsgxssl.a && -f libsgx_tsgxssld.a ]]; then ln -sf libsgx_tsgxssld.a libsgx_tsgxssl.a; fi
    if [[ ! -f libsgx_tsgxssl_crypto.a && -f libsgx_tsgxssl_cryptod.a ]]; then ln -sf libsgx_tsgxssl_cryptod.a libsgx_tsgxssl_crypto.a; fi
    if [[ ! -f libsgx_usgxssl.a && -f libsgx_usgxssld.a ]]; then ln -sf libsgx_usgxssld.a libsgx_usgxssl.a; fi
    if [[ ! -f libsgx_tsgxssl_ssl.a && -f libsgx_tsgxssl_ssld.a ]]; then ln -sf libsgx_tsgxssl_ssld.a libsgx_tsgxssl_ssl.a; fi
fi

echo "== Successfully =="
