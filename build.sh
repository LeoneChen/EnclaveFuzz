#!/bin/bash
set -e

for ARG in "$@"
do
   KEY="$(echo $ARG | cut -f1 -d=)"
   VAL="$(echo $ARG | cut -f2 -d=)"
   export "$KEY"="$VAL"
done

CMAKE_FLAGS=
MODE=${MODE:="RELEASE"}
FUZZER=${FUZZER:="LIBFUZZER"}

echo "-- MODE: ${MODE}"
echo "-- FUZZER: ${FUZZER}"

if [[ "${MODE}" = "DEBUG" ]]
then
    BUILD_MOD=Debug
    CMAKE_FLAGS+=" -DCMAKE_BUILD_TYPE=Debug"
else
    BUILD_MOD=Release
    CMAKE_FLAGS+=" -DCMAKE_BUILD_TYPE=Release"
fi

if [[ "${FUZZER}" = "KAFL" ]]
then
    CMAKE_FLAGS+=" -DKAFL_FUZZER=1"
else
    CMAKE_FLAGS+=" -DKAFL_FUZZER=0"
fi

# build sgx_edger8r
if [ ! -f Tool/sgx_edger8r ]
then
    cd edger8r
    eval $(opam env)
    dune build
    cd ..
    cp edger8r/_build/default/linux/Edger8r.bc Tool/sgx_edger8r
fi
# build
CC="clang-13" CXX="clang++-13" cmake ${CMAKE_FLAGS} -B build_dir/${MODE}-${FUZZER}-build -DCMAKE_INSTALL_PREFIX=$(pwd)/install_dir/${MODE}-${FUZZER}-install
cmake --build build_dir/${MODE}-${FUZZER}-build -j$(nproc)
cmake --install build_dir/${MODE}-${FUZZER}-build
rm -f install
ln -sf install_dir/${MODE}-${FUZZER}-install install
