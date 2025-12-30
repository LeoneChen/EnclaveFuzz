# 工作目录

/home/leone/EnclaveFuzz/workdir/WAMR/Fuzzer2

# 源码目录

WAMR的源代码目录在/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime

WAMR的SGX相关代码部分在/home/leone/EnclaveFuzz/SGX_APP/wasm-micro-runtime/product-mini/platforms/linux-sgx

# 调试任务

使用mcp-gdb服务调试分析TestApp

# 调试参数

参数为"./result/crashes/crash-e1237ef374b3b0489a3716f522ee94b3a18f4a9c -max_len=1000000"

# 细节

- 我利用LLVM IR Pass插桩了程序，提供了额外的报错信息。

- 可以先运行一遍查看报错内容，帮助进一步调试分析。

- 可以用llvm-addr2line-13查看backtrace每一项对应的源文件及行号。

- /home/leone/EnclaveFuzz/SGXSanRT/SGXSanRT.cpp有一些report报错函数，由于大部分出错会触发这些report函数，在这里下断点进一步分析可以作为一种保底手段。

- 分析过程保存到/home/leone/EnclaveFuzz/workdir/WAMR/Fuzzer2/analysis.log文件

- 我们用中文吧
