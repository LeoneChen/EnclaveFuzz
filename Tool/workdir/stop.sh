#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))
for i in $(cat ${CUR_DIR}/fuzz.pid)
do
    echo "Kill ${i}"
    kill -9 ${i} || true
done
echo $(date +%Y\_%m\_%d\_%H\_%M\_%S) >> coverage_exp.log
