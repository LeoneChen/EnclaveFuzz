#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))

echo $(date +%Y\_%m\_%d\_%H\_%M\_%S) >> fuzz.log
${TASKSET} nohup ./TestApp --cb_enclave=TestEnclave ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=0 -max_len=10000000 -timeout=60 -max_total_time=86400 -fork=${JOBS} $@ >> fuzz.log 2>&1 & 
echo $! >> fuzz.pid
