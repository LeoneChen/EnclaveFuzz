# 任务目标

分析目标程序报错原因，并根据错误根本原因给目标程序打补丁

# 第一步：分析报错原因

进入工作目录"/home/leone/EnclaveFuzz/workdir/WAMR/Fuzzer2"

## 分析程序

你可以通过命令"./TestApp ./result/crashes/crash-e1237ef374b3b0489a3716f522ee94b3a18f4a9c -max_len=1000000"得知细节。

你可以进一步利用mcp-gdb动态分析。

程序受到/home/leone/EnclaveFuzz/SGXSanRT提供的LLVM IR插桩，会有额外信息。由于大部分出错会触发这些report函数，在这里下断点进一步分析可以作为一种保底手段。

# 第二步：基于分析情况打补丁

请对/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime打补丁。

## SGX领域知识

SGX应用涉及可信域Enclave和不可信域Host的切换和交互，Enclave不信任Host。EDL文件描述了接口细节，Host可能提供恶意值，导致Enclave出问题。

## 修复目标

- 修复要求能编译成功：可以通过/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime/build.sh MODE=DEBUG确保编译成功。

- 重新运行"./TestApp ./result/crashes/crash-e1237ef374b3b0489a3716f522ee94b3a18f4a9c -max_len=1000000"确保执行不报错。

# 目录说明

工作目录位于"/home/leone/EnclaveFuzz/workdir/WAMR/Fuzzer2"

源代码目录位于"/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime"

SGX部分源代码在"/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime/product-mini/platforms/linux-sgx"
