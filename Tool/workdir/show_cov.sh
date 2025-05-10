#!/usr/bin/env bash
set -e

# llvm-profdata-13 merge --failure-mode=all -sparse -output=./result/all.profdata ./result/profraw/
llvm-cov-13 report TestEnclave -instr-profile=./result/all.profdata