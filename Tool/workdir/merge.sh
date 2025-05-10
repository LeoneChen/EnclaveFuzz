#!/bin/bash
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
ALL_PROFDATA=${SCRIPT_DIR}/result/all.profdata

merge_cov() {
    # Reads the paths to prof data files from INPUT_FILENAME and then merges them into ALL_PROFDATA.
    PROFRAWS=($(find $(realpath ${SCRIPT_DIR}/result/profraw) -type f -printf "%T@ %p\n" | sort -n | cut -d ' ' -f 2 | head -n -${JOBS}))

    if [[ ${#PROFRAWS[@]} -ne 0 ]]; then
        echo "${#PROFRAWS[@]} new profraw"

        if [ ! -f "$ALL_PROFDATA" ]; then
            if llvm-profdata-13 merge -sparse -j=$(nproc) -o=${ALL_PROFDATA} ${PROFRAWS[0]}; then
                echo "Create ${ALL_PROFDATA}"
            else
                echo "Wrong profraw: ${PROFRAWS[0]}"
            fi
            rm ${PROFRAWS[0]}
            unset PROFRAWS[0]
        fi
        for raw in "${PROFRAWS[@]}"; do
            if llvm-profdata-13 merge -sparse -j=$(nproc) -o=${ALL_PROFDATA}.tmp ${raw} ${ALL_PROFDATA}; then
                mv ${ALL_PROFDATA}.tmp ${ALL_PROFDATA}
            else
                echo "Wrong profraw: ${raw}"
            fi
            rm ${raw}
        done
    else
        echo "No profraw file to merge"
    fi
}

log_cov() {
    AllBB=$1
    CovBB=$2
    DevAllBB=$3
    DevCovBB=$4
    mkdir -p ${SCRIPT_DIR}/coverage
    LOG_FILE="${SCRIPT_DIR}/coverage/cov_$(date +%Y\_%m\_%d\_%H\_%M\_%S)"

    echo -en "EnclaveCoverage:\t\t" > ${LOG_FILE}
    if [ ${AllBB} -gt 0 ]; then
        awk -v var1=$CovBB -v var2=$AllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${LOG_FILE}
    else
        awk -v var1=$CovBB -v var2=$AllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, 0 }' >> ${LOG_FILE}
    fi

    echo -en "InterestingCoverage:\t" >> ${LOG_FILE}
    if [ ${DevAllBB} -gt 0 ]; then
        awk -v var1=$DevCovBB -v var2=$DevAllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${LOG_FILE}
    else
        awk -v var1=$DevCovBB -v var2=$DevAllBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, 0 }' >> ${LOG_FILE}
    fi

    echo -en "Effectiveness:\t\t\t" >> ${LOG_FILE}
    if [ ${CovBB} -gt 0 ]; then
        awk -v var1=$DevCovBB -v var2=$CovBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, var1/var2*100 }' >> ${LOG_FILE}
    else
        awk -v var1=$DevCovBB -v var2=$CovBB 'BEGIN{ printf "%d/%d=%.2f%%\n", var1, var2, 0 }' >> ${LOG_FILE}
    fi
}

parse_cov() {
    COV_INFO=$(${SCRIPT_DIR}/show_cov.sh|grep -v Filename|grep -v TOTAL|grep -v "\-\-\-\-\-"|grep -v "Files which contain no functions"|grep -v "^$"|tr -s " ")
    read -r AllBB CovBB <<< $(echo "${COV_INFO}"|awk '{ col2_sum += $2; col3_sum += $3 } END { printf "%d %d", col2_sum, col2_sum-col3_sum }')
    read -r DevAllBB DevCovBB <<< $(echo "${COV_INFO}"|grep -v "_t[.]c"|grep -v "_t[.]h"|grep -Pv 'linux-sgx(?!/psw/ae)'|awk '{ col2_sum += $2; col3_sum += $3 } END { printf "%d %d", col2_sum, col2_sum-col3_sum }')
    log_cov ${AllBB} ${CovBB} ${DevAllBB} ${DevCovBB}
}

last_round=0
while true
do
    merge_cov
    if [ -f "$ALL_PROFDATA" ]; then
        parse_cov
    else
        log_cov 0 0 0 0
    fi
    if [[ "last_round" -eq "0" ]]; then
        if $(cat fuzz.pid|xargs kill -0); then
            sleep 5
        else
            echo "Fuzzer already stopped"
            last_round=1
        fi
    else
        exit
    fi
done
