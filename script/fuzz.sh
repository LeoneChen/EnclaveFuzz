#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))

echo $(date +%Y\_%m\_%d\_%H\_%M\_%S) > fuzz.log

echo "[*] See ${SCRIPT_DIR}/fuzz.log for details"
LD_LIBRARY_PATH=${SGXSDK}/lib64:${LD_LIBRARY_PATH} ${TASKSET} ./TestApp ./result/seeds -artifact_prefix=./result/crashes/ -use_value_profile=1 -max_total_time=86400 -ignore_crashes=0 -fork=${JOBS} &>> fuzz.log
