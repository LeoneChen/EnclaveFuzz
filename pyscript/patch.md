# 工作目录

WAMR的源代码目录在/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime

WAMR的SGX相关代码部分在/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime/product-mini/platforms/linux-sgx

# 前置信息

之前分析了一项输入导致程序Crash的原因，见文件/home/leone/EnclaveFuzz/workdir/WAMR/Fuzzer2/analysis.log。

# 补丁任务

请对/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime打补丁。

# 细节

- SGX应用涉及可信域和不可信域的切换和交互，EDL文件描述了接口细节，SGX Enclave不信任Host的数据和行为，因此这里面非常容易出问题。具体来说，不可信的Host可能提供恶意的值，导致SGX Enclave出现问题。

- 修复要求能编译成功：可以通过/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime/build.sh MODE=DEBUG确保编译成功。

- 补丁分析和描述过程保存到/home/leone/EnclaveFuzz/workdir/WAMR/Fuzzer2/patch.log文件

- 我们用中文
