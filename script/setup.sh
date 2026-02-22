#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
WORK_DIR=""
APP_PATH=""
ENCLAVE_PATH=""
TASKSET=""
JOBS=1
EXTRA_FUZZ_FLAGS=""

show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h|--help           Show this help message"
    echo "  --app               Path to the application"
    echo "  --enclave           Path to the enclave"
    echo "  --workdir           Path to the work directory"
    echo "  --taskset           Task set"
    echo "  -j|--jobs           Number of jobs to run in parallel"
    echo "  --extra-flags       Extra flags to pass to the fuzzing script"
    exit 0
}

OPTS=$(getopt -o hj: -l help,app:,enclave:,workdir:,taskset:,jobs:,extra-flags: -n 'parse-options' -- "$@")
eval set -- "$OPTS"
while true; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        --app)
            APP_PATH="$2"
            shift 2
            ;;
        --enclave)
            ENCLAVE_PATH="$2"
            shift 2
            ;;
        --workdir)
            WORKDIR="$2"
            shift 2
            ;;
        --taskset)
            TASKSET="taskset -c $2"
            shift 2
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        --extra-flags)
            EXTRA_FUZZ_FLAGS="$2"
            shift 2
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

echo "[+] APP_PATH: ${APP_PATH}"
echo "[+] ENCLAVE_PATH: ${ENCLAVE_PATH}"
echo "[+] WORKDIR: ${WORKDIR}"
echo "[+] TASKSET: ${TASKSET}"

mkdir -p ${WORKDIR}/result/{seeds,crashes,fixed}
cp ${APP_PATH} ${WORKDIR}/TestApp
cp ${ENCLAVE_PATH} ${WORKDIR}/TestEnclave
# cp ${SCRIPT_DIR}/stop.sh ${WORKDIR}
SGXSDK=$(realpath ${SCRIPT_DIR}/../install/enclave_fuzz) JOBS=${JOBS} TASKSET=${TASKSET} EXTRA_FUZZ_FLAGS=${EXTRA_FUZZ_FLAGS} envsubst '${SGXSDK} ${JOBS} ${TASKSET} ${EXTRA_FUZZ_FLAGS}' < ${SCRIPT_DIR}/fuzz.sh > ${WORKDIR}/fuzz.sh
chmod +x ${WORKDIR}/fuzz.sh
