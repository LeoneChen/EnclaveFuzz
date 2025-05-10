# EnclaveFuzz: Finding Vulnerabilities in SGX Applications

<a href="docs/EnclaveFuzz.pdf"><img align="right" width="170" height="220" src="docs/EnclaveFuzz.png">

This repo is the public code for paper [EnclaveFuzz](docs/EnclaveFuzz.pdf) ([Slide](docs/Slide.pdf), [Poster_CN](docs/Poster.pdf)) in [NDSS 2024](https://www.ndss-symposium.org/ndss2024/)

```
@inproceedings{chen2024enclavefuzz,
    title={EnclaveFuzz: Finding Vulnerabilities in SGX Applications},
    author={Chen, Liheng and Li, Zheming and Ma, Zheyu and Li, Yuan and Chen, Baojian and Zhang, Chao},
    booktitle={Proceedings of the 31st Annual Network and Distributed System Security Symposium (NDSS)},
    year={2024},
}
```

# Branch
master - Use fuzzing optimized SGX SDK for fuzz (Fuzzer2.0 is a deprecated branch)

Fuzzer1.0 - Use original SGX SDK for fuzz (support hardware mode and simulation mode)

# Platform
- Ubuntu 20.04
- LLVM 13

# How to use
See [Dockerfile](Dockerfile/EnclaveFuzz.Dockerfile) for detailed instructions

## Build EnclaveFuzz and get optimized SGX SDK
```bash
git submodule update --init --recursive
./build.sh -g --cov --prepare-sdk --build-sdk # here we debug build, with libfuzzer as fuzz engine, with SGXSDK instrumented
# ./clean.sh # clean EnclaveFuzz and optimized SGX SDK
```

## Prepare kAFL (Optional)
If you want to use kAFL as a fuzz engine, please prepare kAFL. Detailed installation guide please refer to [kAFL Doc](https://intellabs.github.io/kAFL/tutorials/installation.html)
```shell
cd kAFL
make deploy
cd ..
```

## Get prepared SGX applications
We have prepared all modified SGX applications which we can directly fuzz.
```shell
git clone git@github.com:LeoneChen/SGX_APP.git
```

### Branch of each SGX application
Fuzzer2.0 - Use fuzzing optimized SGX SDK for fuzz

Fuzzer1.0 - Use original SGX SDK for fuzz (support hardware mode and simulation mode)

sgxfuzz - Use SGXFuzz for fuzz

### How we modify them
[ehsm](https://github.com/LeoneChen/ehsm) as an example, we forked from the original repo, and add usually one commit (e.g. [commit for ehsm](https://github.com/LeoneChen/ehsm/commit/70948b65019b2b59fb23fe8af573dbfd54696c13)) above it.

All modifications made by us can be found in the commit.

### How to use them
[ehsm](https://github.com/LeoneChen/ehsm) as an example, use `build.sh [MODE=RELEASE|DEBUG] [FUZZER=LIBFUZZER|KAFL]` to build it, and use `clean.sh` to clean it, these scripts are added by us.

Some repos are built with Autotool, like [BiORAM-SGX](https://github.com/LeoneChen/BiORAM-SGX), you need to use `./bootstrap && build.sh [MODE=RELEASE|DEBUG] [FUZZER=LIBFUZZER|KAFL]` or something like that.

#### example
[sgx-wallet](https://github.com/LeoneChen/sgx-wallet) as an example

```shell
cd ~/EnclaveFuzz/SGX_APP/sgx-wallet # I put EnclaveFuzz repo at home path (~) , and put SGX_APP at EnclaveFuzz
git checkout Fuzzer2.0
./build.sh MODE=DEBUG
~/EnclaveFuzz/Tool/workdir/setup.sh --app sgx-wallet --enclave enclave.so --workdir ~/EnclaveFuzzData/SGX-WALLET/Fuzzer2 --taskset 127
cd ~/EnclaveFuzzData/SGX-WALLET/Fuzzer2-*
./fuzz.sh # default run 86400 second
# ./stop.sh # stop before fuzzing finish
# ./merge.sh # merge profraw from Source Based Coverage when fuzzing
# ./show_cov.sh # show result from Source Based Coverage
# coverage_exp.log # it is log from libfuzzer
```

# Contact to me
Any questions are welcome, you can ask them via issue or my email.

My Email: 791960492@qq.com
