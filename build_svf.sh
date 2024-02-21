#!/bin/bash
set -e

cd ThirdParty/SVF
patch -p1 < ../../patch/SVF.patch
./build.sh
git restore .