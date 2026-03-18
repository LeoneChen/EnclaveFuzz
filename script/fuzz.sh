#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))

echo $(date +%Y\_%m\_%d\_%H\_%M\_%S) > fuzz.log

echo "[*] See ${SCRIPT_DIR}/fuzz.log for details"
LD_LIBRARY_PATH=${SGXSDK}/lib64:${LD_LIBRARY_PATH} ${TASKSET} ./TestApp ./result/seeds -artifact_prefix=./result/crashes/ -max_total_time=3600 -print_coverage=0 -report_slow_units=60 ${EXTRA_FUZZ_FLAGS} > app.log 2> fuzz.log
