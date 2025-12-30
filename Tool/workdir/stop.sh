#!/bin/bash
set -e

CUR_DIR=$(realpath $(dirname $0))
for i in $(cat ${CUR_DIR}/fuzz.pid)
do
    echo "Kill ${i}"
    kill ${i} || true
done

rm -rf fuzz.pid

echo $(date +%Y\_%m\_%d\_%H\_%M\_%S) >> fuzz.log
