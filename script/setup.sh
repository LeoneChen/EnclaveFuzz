#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
WORK_DIR=""
APP_PATH=""
ENCLAVE_PATH=""

show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h|--help           Show this help message"
    echo "  --app               Path to the application"
    echo "  --enclave           Path to the enclave"
    echo "  --workdir           Path to the work directory"
    exit 0
}

OPTS=$(getopt -o h -l help,app:,enclave:,workdir: -n 'parse-options' -- "$@")
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

mkdir -p ${WORKDIR}/result/{seeds,crashes,fixed}
cp ${APP_PATH} ${WORKDIR}/TestApp
cp ${ENCLAVE_PATH} ${WORKDIR}/TestEnclave
