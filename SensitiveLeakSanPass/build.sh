cmake -DCMAKE_BUILD_TYPE=Debug -B build -S . && cd build && make -j$(nproc) -s && cd ..
cp build/libSensitiveLeakSanPass.so ../output/libSensitiveLeakSanPass.so