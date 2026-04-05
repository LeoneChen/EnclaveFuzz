# EnclaveFuzz: Finding Vulnerabilities in SGX Applications

This repo is the public code for paper [EnclaveFuzz](docs/EnclaveFuzz.pdf) ([Slide](docs/EnclaveFuzzSlide.pdf))


# Branch

- dev: Use our simulated and faster SGX SDK for fuzzing (under development, easier to use).

- Fuzzer2.0: Use our simulated and faster SGX SDK for fuzzing.

- Fuzzer1.0: Use Intel SGX SDK for fuzzing (support hardware/simulation mode).

# Platform

- Ubuntu 20.04

# Build

```bash
git submodule update --init --recursive # get submodule
./build.sh -g --prepare-sdk --build-sdk --build-ssl # build enclave_fuzz (-g for debug mode)
./build_target.sh -t wasm-micro-runtime -b -s -g # build wamr as example (-g for debug mode, -s for setting up fuzzing workdir)
```

**TODO:** We will provide better script for other SGX applications in the future. (Full and old support can be found in branch Fuzzer2.0/Fuzzer1.0)

## How we modify SGX Application?

[Commit](https://github.com/LeoneChen/wasm-micro-runtime/commit/762f84c4e24f2f247143b90ad4df7e06c39fb896) for wasm-micro-runtime can be an example.

# How to use?

```shell
cd workdir/WAMR/Fuzzer2
./fuzz.sh # output can be found in fuzz.log
```

## Found a crash?

Use `.vscode/launch.json` to debug it.

# Any problems?

Ask them via issue or my email (791960492@qq.com).

# Bibtex

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
