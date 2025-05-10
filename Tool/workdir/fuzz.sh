#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))

echo "TMPDIR=${SCRIPT_DIR}"

LD_LIBRARY_PATH=${ENCLAVEFUZZ_DIR}/lib64 TMPDIR=${SCRIPT_DIR} LLVM_PROFILE_FILE="./result/profraw/%p" ${TASKSET} nohup ./TestApp --cb_enclave=TestEnclave ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 -timeout=60 -max_total_time=86400 -fork=${JOBS} $@ >> coverage_exp.log 2>&1 & 
echo $! >> fuzz.pid

nohup ./merge.sh &
echo $! >> merge.pid

echo $(date +%Y\_%m\_%d\_%H\_%M\_%S) >> StartTime.log
