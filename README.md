# EnclaveFuzz: Finding Vulnerabilities in SGX Applications

This repo is the public code for paper [EnclaveFuzz](docs/EnclaveFuzz.pdf) ([Slide](docs/EnclaveFuzzSlide.pdf)) in [NDSS 2024](https://www.ndss-symposium.org/ndss2024/)

```
@inproceedings{DBLP:conf/ndss/ChenLMLC024enclavefuzz,
  author       = {Liheng Chen and
                  Zheming Li and
                  Zheyu Ma and
                  Yuan Li and
                  Baojian Chen and
                  Chao Zhang},
  title        = {EnclaveFuzz: Finding Vulnerabilities in {SGX} Applications},
  booktitle    = {31st Annual Network and Distributed System Security Symposium, {NDSS}
                  2024, San Diego, California, USA, February 26 - March 1, 2024},
  publisher    = {The Internet Society},
  year         = {2024},
  url          = {https://www.ndss-symposium.org/ndss-paper/enclavefuzz-finding-vulnerabilities-in-sgx-applications/},
  timestamp    = {Sun, 24 Aug 2025 10:43:35 +0200},
  biburl       = {https://dblp.org/rec/conf/ndss/ChenLMLC024.bib},
  bibsource    = {dblp computer science bibliography, https://dblp.org}
}
```

# Branch

master/Fuzzer2.0 - Use fuzzing optimized SGX SDK for fuzz

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
~/EnclaveFuzz/Tool/workdir/setup.sh --app sgx-wallet --enclave enclave.so --workdir ~/EnclaveFuzzData/SGX-WALLET/Fuzzer2 --taskset 1
cd ~/EnclaveFuzzData/SGX-WALLET/Fuzzer2-*
./fuzz.sh # default run 86400 second
# ./stop.sh # stop before fuzzing finish
# ./merge.sh # merge profraw from Source Based Coverage when fuzzing
# ./show_cov.sh # show result from Source Based Coverage
# coverage_exp.log # it is log from libfuzzer
```

`coverage_exp.log` is like this
```shell
[2025-05-13 17:13:48.542] [Init] Num of ECall: 5
[2025-05-13 17:13:48.542] ECalls:
  0 - fuzz_ecall_add_item
  1 - fuzz_ecall_change_master_password
  2 - fuzz_ecall_create_wallet
  3 - fuzz_ecall_remove_item
  4 - fuzz_ecall_show_wallet

INFO: found LLVMFuzzerCustomMutator (0x3d0cc0). Disabling -len_control by default.
INFO: libFuzzer ignores flags that start with '--'
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3530517718
INFO: Loaded 3 modules   (6617 inline 8-bit counters): 407 [0x7a2856e3b6d0, 0x7a2856e3b867), 5873 [0x7a2856f29398, 0x7a2856f2aa89), 337 [0x3f90e8, 0x3f9239), 
INFO: Loaded 3 PC tables (6617 PCs): 407 [0x7a2856e3b868,0x7a2856e3d1d8), 5873 [0x7a2856f2aa90,0x7a2856f419a0), 337 [0x3f9240,0x3fa750), 
INFO: -fork=1: fuzzing in separate process(s)
INFO: -fork=1: 0 seed inputs, starting to fuzz in /home/admin/EnclaveFuzzData/SGX-WALLET/Fuzzer2-2025-05-13-16-46-36/libFuzzerTemp.FuzzWithFork46405.dir
#8: cov: 0 ft: 0 corp: 0 exec/s 0 oom/timeout/crash: 0/0/0 time: 0s job: 1 dft_time: 0
[SGXSan] ERROR: #PF Addr (nil) at pc 0x7871d6199915(A) => Null-Pointer Dereference
#82: cov: 731 ft: 2080 corp: 6 exec/s 74 oom/timeout/crash: 0/0/1 time: 1s job: 2 dft_time: 0
[SGXSan] ERROR: #PF Addr (nil) at pc 0x7507632ad915(A) => Null-Pointer Dereference
#209: cov: 745 ft: 3150 corp: 38 exec/s 127 oom/timeout/crash: 0/0/2 time: 3s job: 3 dft_time: 0
```

After fuzzing, we can filter crash inputs.

NOTICE: `extra-opt` should be same as flags in `~/EnclaveFuzzData/SGX-WALLET/Fuzzer2-*/fuzz.sh` to re-produce, e.g. flags in `fuzz.sh` is `--cb_enclave=TestEnclave -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -max_len=10000000 -timeout=60 -max_total_time=86400 -fork=1`. 
- `--cb_enclave=TestEnclave` is necessary to tell TestApp where TestEnclave is, but `cb_enclave` default value is TestEnclave, so here we can omit it.
- These flags is not necessary to reproduce: `-print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -timeout=60 -max_total_time=86400 -fork=1`.
- `-max_len=10000000` is necessary to reproduce, so we need add it in `extra-opt`.
- Other necessary flags can be found in [libFuzzerCallback.cpp](SGXFuzzerRT/libFuzzerCallback.cpp#L437)

```shell
cd ~/EnclaveFuzzData/SGX-WALLET/Fuzzer2-*
python ~/EnclaveFuzz/Tool/filter_crashes.py -b TestApp -c ./result/crashes --extra-opt="-max_len=10000000"
# it output simple-TestApp-xxx.result.json and TestApp-xxx.result.json
```

`simple-TestApp-xxx.result.json` is like this, `hash2bt` is helpful to get backtrace from hash-id:
```shell
{
    "0x7ffff7771915": {
        "02ab79a1b091e33f9ffe19bd5008c5efea273d7cda4349682c0375243829b44b": {
            "[SGXSan] ERROR: #PF Addr (nil) at pc 0x7ffff7771915(A) => Null-Pointer Dereference": {
                "inputs": [
                    "crash-40235d32d2ca2d1e21ccc691998188b2148e2cb6"
                ],
                "num_crashes": 5
            }
        },
        "fdcd72ba0d57315d74185f652382e64f9de700b08288956456f99236b9b87aa4": {
            "[SGXSan] ERROR: #PF Addr (nil) at pc 0x7ffff7771915(A) => Null-Pointer Dereference": {
                "inputs": [
                    "crash-20d888de888a5492af460970d3a7c994e22e474d"
                ],
                "num_crashes": 6
            }
        }
    },
    "hash2bt": {
        "02ab79a1b091e33f9ffe19bd5008c5efea273d7cda4349682c0375243829b44b": [
            "..."
        ],
        "fdcd72ba0d57315d74185f652382e64f9de700b08288956456f99236b9b87aa4": [
            "..."
        ]
    }
}
```


# Contact to me
Any questions are welcome, you can ask them via issue or my email.

My Email: 791960492@qq.com
