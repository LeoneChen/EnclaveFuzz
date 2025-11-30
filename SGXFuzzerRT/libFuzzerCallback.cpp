#include "libFuzzerCallback.h"
#include "FuzzDataType.h"
#include "FuzzedDataProvider.h"
#include "RandPool.h"
#include "magic_enum.hpp"
#include <array>
#include <assert.h>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ostream>
#include <random>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>


#define X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS 47
#define ADDR_SPACE_BITS X86_64_4LEVEL_PAGE_TABLE_ADDR_SPACE_BITS

using ordered_json = nlohmann::ordered_json;
namespace po = boost::program_options;
namespace fs = std::filesystem;

RandPool gRandPool;

sgx_enclave_id_t __hidden_sgxfuzzer_harness_global_eid = 0;
std::string ClEnclaveFileName;
size_t ClMaxStrlen, ClMaxCount, ClMaxSize, ClMaxCallSeqSize, ClMaxPayloadSize;
int ClUsedLogLevel = 2; /* may log before ClUsedLogLevel is initialized */
double ClProvideNullPointerProb, ClReturn0Prob, ClModifyOCallRetProb,
    ClModifyDoubleFetchValueProb, ClZoomRate;
bool ClEnableSanCheckDie, ClEnableNaiveHarness, ClEnableCollectStack,
    ClCmpFuncNameInTOCTOU, ClUseAddr2line;

// Fuzz sequence
enum FuzzMode { TEST_RANDOM, TEST_USER };
static std::vector<int> gFuzzerSeq;
static std::vector<int> gFilterOutIndices;
static FuzzMode gFuzzMode;

// Passed from DriverGen IR pass
extern sgx_status_t (*gFuzzECallArray[])();
extern int gFuzzECallNum;
extern char *gFuzzECallNameArray[];

// log util
static const char *log_level_to_prefix[] = {
    "",
    "[SGXFuzz error] ",
    "[SGXFuzz warning] ",
    "[SGXFuzz debug] ",
    "[SGXFuzz trace] ",
};

// https://stackoverflow.com/questions/24686846/get-current-time-in-milliseconds-or-hhmmssmmm-format
std::string time_in_HH_MM_SS_MMM() {
  using namespace std::chrono;

  // get current time
  auto now = system_clock::now();

  // get number of milliseconds for the current second
  // (remainder after division into seconds)
  auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

  // convert to std::time_t in order to convert to std::tm (broken time)
  auto timer = system_clock::to_time_t(now);

  // convert to broken time
  std::tm bt = *std::localtime(&timer);

  std::ostringstream oss;

  oss << std::put_time(&bt, "%F %T"); // HH:MM:SS
  oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

  return oss.str();
}

void sgxfuzz_log(log_level level, bool with_prefix, const char *format, ...) {
  if (level > ClUsedLogLevel)
    return;

  // get prefix
  if (with_prefix) {
    std::string prefix = std::string(log_level_to_prefix[level]) + "[" +
                         time_in_HH_MM_SS_MMM() + "] ";
    std::cerr << prefix;
  }

  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

// libFuzzer API
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
extern "C" __attribute__((weak)) bool AddrIsInHeapQuarantine(uint64_t addr);
// DataFactory Util
class FuzzDataFactory {
public:
  /// @brief fill random data in memory pointed by \p dst
  /// @param dst must be a valid memory area
  /// @param size memory area size
  void fillRand(uint8_t *dst, size_t size) {
    std::random_device rd;
    std::independent_bits_engine<std::mt19937, CHAR_BIT, unsigned short> ibe(
        rd());
    std::generate(dst, dst + size, std::ref(ibe));
  }

  void NeedMoreFuzzData(size_t size) { mExpectedFuzzDataSize += size; }

  size_t mutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    size_t NewSize = std::min(std::max(mExpectedFuzzDataSize, Size), MaxSize);
    sgxfuzz_assert(NewSize >= Size);
    if (NewSize > Size) {
      fillRand(Data + Size, NewSize - Size);
    }
    LLVMFuzzerMutate(Data, NewSize, MaxSize);
    return NewSize;
  }

  uint8_t *getBytes(uint8_t *dst, size_t bytesNum, FuzzDataTy dataTy) {
    if (bytesNum == 0 and dataTy != FUZZ_STRING and dataTy != FUZZ_WSTRING) {
      // Do nothing
      return dst;
    }

    switch (dataTy) {
    case FUZZ_P_DOUBLE: {
      sgxfuzz_assert(sizeof(double) == bytesNum);
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      *((double *)dst) = getFloatingPointInRange<double>(
          0.0, std::numeric_limits<double>::max());
      break;
    }
    case FUZZ_ARRAY:
    case FUZZ_DATA: {
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      FillByteArray(dst, bytesNum);
      break;
    }
    case FUZZ_DATA_OR_PTR: {
      sgxfuzz_assert(bytesNum == sizeof(void *));
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      FillByteArray(dst, bytesNum);
      *(uint64_t *)dst %= ((uint64_t)1 << ADDR_SPACE_BITS);
      break;
    }
    case FUZZ_RET: {
      double prob = getProbability<double>();
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      if (prob < ClReturn0Prob) {
        memset(dst, 0, bytesNum);
      } else {
        FillByteArray(dst, bytesNum);
      }
      break;
    }
    case FUZZ_WSTRING: {
      size_t givedStrlen = 1;
      if (not ClEnableNaiveHarness) {
        givedStrlen = getIntergerInRange<size_t>(0, ClMaxStrlen);
      }
      if (bytesNum != 0)
        givedStrlen %= (bytesNum + 1);
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc((givedStrlen + 1) * sizeof(wchar_t));
      FillByteArray(dst, givedStrlen * sizeof(wchar_t));
      ((wchar_t *)dst)[givedStrlen] = 0;
      break;
    }
    case FUZZ_STRING: {
      size_t givedStrlen = 1;
      if (not ClEnableNaiveHarness) {
        givedStrlen = getIntergerInRange<size_t>(0, ClMaxStrlen);
      }
      if (bytesNum != 0)
        givedStrlen %= (bytesNum + 1);
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc((givedStrlen + 1) * sizeof(char));
      FillByteArray(dst, givedStrlen * sizeof(char));
      ((char *)dst)[givedStrlen] = 0;
      break;
    }
    case FUZZ_SIZE:
    case FUZZ_COUNT: {
      sgxfuzz_assert((bytesNum <= sizeof(size_t)));
      size_t MaxVal = dataTy == FUZZ_SIZE ? ClMaxSize : ClMaxCount;
      size_t data = getIntergerInRange<size_t>(1, MaxVal);
      data = std::round(zoom(data, MaxVal, ClZoomRate, 1.0));
      if (dst == nullptr)
        dst = (uint8_t *)managedMalloc(bytesNum);
      memcpy(dst, &data, bytesNum);
      break;
    }
    default:
      sgxfuzz_error(true, "Unsupported FUZZ_XXX type\n");
    }
    return dst;
  }

  // (c,c) -> (a,a)
  double zoom(double x, double a, double b, double c = 0) {
    return a - std::pow(std::pow(a - c, b) - std::pow(x - c, b), 1.0 / b);
  }

  size_t getUserCheckCount(size_t eleSize) {
    sgxfuzz_assert(eleSize);
    size_t res = getIntergerInRange<size_t>(1, ClMaxCount);
    res = zoom(res, ClMaxCount, ClZoomRate, 1.0);
    return res;
  }

  bool EnableSetNull() {
    double prob = getProbability<double>();
    return prob < ClProvideNullPointerProb;
  }

  void init(const uint8_t *Data, size_t Size) {
    if (provider) {
      // Remove old
      delete provider;
    }
    provider = new FuzzedDataProvider(Data, Size);
    mExpectedFuzzDataSize = Size;
    mRandPoolBytesOffset = 0;
  }

  template <class T> T getProbability() {
    if (provider and provider->remaining_bytes() > 0) {
      return 1.0 - provider->ConsumeProbability<T>();
    } else {
      NeedMoreFuzzData((sizeof(T) <= sizeof(uint32_t)) ? sizeof(uint32_t)
                                                       : sizeof(uint64_t));
      return gRandPool.getProbability<T>(mRandPoolBytesOffset++);
    }
  }

  template <class T> T getInterger() {
    if (provider and provider->remaining_bytes() > 0) {
      return provider->ConsumeIntegral<T>();
    } else {
      NeedMoreFuzzData(sizeof(T));
      return gRandPool.getInterger<T>(mRandPoolBytesOffset++);
    }
  }

  template <class T> T getIntergerInRange(T min, T max) {
    if (provider and provider->remaining_bytes() > 0) {
      return provider->ConsumeIntegralInRange<T>(min, max);
    } else {
      NeedMoreFuzzData(sizeof(T));
      return gRandPool.getIntergerInRange<T>(min, max, mRandPoolBytesOffset++);
    }
  }

  template <typename T> T getFloatingPointInRange(T min, T max) {
    if (provider and provider->remaining_bytes() > 0) {
      return provider->ConsumeFloatingPointInRange<T>(min, max);
    } else {
      NeedMoreFuzzData(sizeof(T));
      return gRandPool.getFloatingPointInRange<T>(min, max,
                                                  mRandPoolBytesOffset++);
    }
  }
  bool FillByteArray(uint8_t *bytes, size_t size) {
    size_t wrCnt = 0;
    if (provider and provider->remaining_bytes() > 0) {
      wrCnt = provider->ConsumeData(bytes, size);
    }
    if (wrCnt < size) {
      gRandPool.getBytes(bytes + wrCnt, size - wrCnt, mRandPoolBytesOffset++);
      NeedMoreFuzzData(size - wrCnt);
    }
    return true;
  }

  void clear() {
    // Don't delete provider here, since later sgx_destroy_enclave may use it
    for (auto memArea : allocatedMemAreas) {
      // log_debug("free %p\n", memArea);
      if (AddrIsInHeapQuarantine && AddrIsInHeapQuarantine((uint64_t)memArea)) {
        // It may be freed by ECall
        continue;
      }
      free(memArea);
    }
    allocatedMemAreas.clear();
  }

  void *managedMalloc(size_t size) {
    if (size == 0)
      return nullptr;
    void *ptr = malloc(size);
    sgxfuzz_assert(ptr != nullptr);
    // log_debug("malloc %p(%d)\n", ptr, size);
    allocatedMemAreas.push_back((uint8_t *)ptr);
    return ptr;
  }

  void *managedCalloc(size_t count, size_t size) {
    if (count * size == 0)
      return nullptr;
    void *ptr = calloc(count, size);
    sgxfuzz_assert(ptr != nullptr);
    // log_debug("calloc %p(%d * %d)\n", ptr, count, size);
    allocatedMemAreas.push_back((uint8_t *)ptr);
    return ptr;
  }

  char *managedStr2CStr(std::string str) {
    char *cStr = (char *)managedMalloc(str.length() + 1);
    memcpy(cStr, str.c_str(), str.length());
    cStr[str.length()] = '\0';
    return cStr;
  }

  void getCallSequence(std::vector<int> &intCallSeq, size_t funcNum) {
    // Get CallSeqSize
    size_t CallSeqSize = getIntergerInRange<size_t>(1, ClMaxCallSeqSize);
    // Get CallSeq
    for (size_t i = 0; i < CallSeqSize; i++) {
      int idx = getIntergerInRange<int>(0, funcNum - 1);
      intCallSeq.push_back(idx);
    }
  }

  void AddNotModifyOCallRetSpecs(std::string ID) {
    mNotModifyOCallRetSpecs.emplace(ID);
  }

  bool EnableModifyOCallRet(char *cParamID) {
    std::string ParamID(cParamID);
    if (mNotModifyOCallRetSpecs.count(ParamID)) {
      return false;
    }
    double prob = getProbability<double>();
    return prob < ClModifyOCallRetProb;
  }

  bool EnableModifyDoubleFetchValue() {
    double prob = getProbability<double>();
    return prob < ClModifyDoubleFetchValueProb;
  }
  size_t GetExpectedFuzzDataSize() { return mExpectedFuzzDataSize; }

  bool EnableSanCheckDie() { return ClEnableSanCheckDie; }

private:
  FuzzedDataProvider *provider = nullptr;
  std::vector<uint8_t *> allocatedMemAreas;
  size_t mExpectedFuzzDataSize, mRandPoolBytesOffset = 0;
  std::unordered_set<std::string> mNotModifyOCallRetSpecs;
};
FuzzDataFactory data_factory;

void ShowAllECalls() {
  log_always("[Init] Num of ECall: %d\n", gFuzzECallNum);
  std::string ecalls;
  for (int i = 0; i < gFuzzECallNum; i++) {
    ecalls +=
        std::string("  " + std::to_string(i) + " - " + gFuzzECallNameArray[i]) +
        "\n";
  }
  log_always("ECalls:\n%s\n", ecalls.c_str());
}

// libFuzzer Callbacks
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  ShowAllECalls();

  // default mode is random
  gFuzzMode = TEST_RANDOM;

  // Declare the supported options.
  po::options_description desc("LibFuzzerCallback's inner options");
  auto add_opt = desc.add_options();
  add_opt("cb_help", "Produce help message");
  add_opt(
      "cb_enclave",
      po::value<std::string>(&ClEnclaveFileName)->default_value("TestEnclave"),
      "Name of target Enclave file");
  add_opt("cb_max_count", po::value<size_t>(&ClMaxCount)->default_value(32),
          "Max count of elements for pointer");
  add_opt("cb_max_size", po::value<size_t>(&ClMaxSize)->default_value(512),
          "Max size of pointer element");
  add_opt("cb_max_strlen", po::value<size_t>(&ClMaxStrlen)->default_value(128),
          "Max length of string (no tail 0)");
  add_opt("cb_filter_out", po::value<std::string>(), "Don't test these ECalls");
  add_opt("sgxfuzz_test_user", po::value<std::string>(), "Test these ECalls");
  add_opt("cb_log_level", po::value<int>(&ClUsedLogLevel)->default_value(2),
          "0-Always, 1-Error, 2-Warning(Default), 3-Debug, 4-Trace");
  add_opt("cb_nullptr_prob",
          po::value<double>(&ClProvideNullPointerProb)->default_value(0.01),
          "Probability to provide null as fuzz data to pointer");
  add_opt("cb_return0_prob",
          po::value<double>(&ClReturn0Prob)->default_value(0.01),
          "Probability to return all 0 in OCall return");
  add_opt("cb_ocall_ret_through", po::value<std::string>(),
          "Not modify OCall return value specified by ID, ID[,...] , e.g. "
          "/untrusted/ocall_current_time/parameter/0[,...]");
  add_opt("cb_ecall_queue_size",
          po::value<size_t>(&ClMaxCallSeqSize)->default_value(20),
          "Max ECall queue size");
  add_opt("cb_modify_ocall_ret_prob",
          po::value<double>(&ClModifyOCallRetProb)->default_value(0.5),
          "Probability to modify OCall return");
  add_opt("cb_modify_double_fetch_value_prob",
          po::value<double>(&ClModifyDoubleFetchValueProb)->default_value(0.5),
          "Probability to modify value when detect double fetch");
  add_opt("cb_zoom_rate", po::value<double>(&ClZoomRate)->default_value(1),
          "Give more or less probability to small count than big count, "
          "rate > 1 => zoom out, 0 < rate < 1 => zoom in");
  add_opt("cb_max_payload_size",
          po::value<size_t>(&ClMaxPayloadSize)->default_value(10000000),
          "Allocate buffer with cb_max_payload_size, to prepare fuzz data");
  add_opt("cb_enable_san_check_die",
          po::value<bool>(&ClEnableSanCheckDie)->default_value(true),
          "Enable Die when sanitizer check");
  add_opt("cb_naive_harness",
          po::value<bool>(&ClEnableNaiveHarness)->default_value(false),
          "Enable naive harness");
  add_opt("cb_enable_collect_stack",
          po::value<bool>(&ClEnableCollectStack)->default_value(false),
          "Enable collect stack");
  add_opt("cb_cmp_func_name_in_toctou",
          po::value<bool>(&ClCmpFuncNameInTOCTOU)->default_value(false),
          "Compare function name when checking TOCTOU");
  add_opt("cb_use_addr2line",
          po::value<bool>(&ClUseAddr2line)->default_value(false),
          "Use addr2line to get stack frame info");

  po::variables_map vm;
  po::parsed_options parsed = po::command_line_parser(*argc, *argv)
                                  .options(desc)
                                  .allow_unregistered()
                                  .run();
  std::vector<std::string> to_pass_further =
      collect_unrecognized(parsed.options, po::include_positional);
  po::store(parsed, vm);
  po::notify(vm);

  // process options
  if (vm.count("cb_help")) {
    std::stringstream ss;
    ss << desc << "\n";
    log_always("%s", ss.str().c_str());
    exit(0);
  }

  if (vm.count("sgxfuzz_test_user")) {
    gFuzzMode = TEST_USER;
    std::string indexList = vm["sgxfuzz_test_user"].as<std::string>();
    std::vector<std::string> indexVec;
    boost::split(indexVec, indexList, [](char c) { return c == ','; });
    for (auto index : indexVec) {
      boost::trim(index);
      if (index != "") {
        gFuzzerSeq.push_back(std::stoi(index, 0, 0));
      }
    }

    log_always("Test user specified:");
    for (auto id : gFuzzerSeq) {
      log_always_np(" %d", id);
    }
    log_always_np("\n");
  }

  if (vm.count("cb_filter_out")) {
    std::string fiterOutECalls = vm["cb_filter_out"].as<std::string>();
    std::vector<std::string> fiterOutECallVec;
    boost::split(fiterOutECallVec, fiterOutECalls,
                 [](char c) { return c == ','; });

    std::map<std::string, int> wrapperName2Idx;
    for (int i = 0; i < gFuzzECallNum; i++) {
      wrapperName2Idx[gFuzzECallNameArray[i]] = i;
    }

    for (auto fiterOutECall : fiterOutECallVec) {
      boost::trim(fiterOutECall);
      if (fiterOutECall != "") {
        std::string fuzzWrapperPrefix = "fuzz_";
        if (wrapperName2Idx.count(fuzzWrapperPrefix + fiterOutECall)) {
          size_t fiterOutECallIdx =
              wrapperName2Idx[fuzzWrapperPrefix + fiterOutECall];
          gFilterOutIndices.push_back(fiterOutECallIdx);
        }
      }
    }
    log_always("Filter out:");
    for (auto filterOutIdx : gFilterOutIndices) {
      log_always_np(" %d", filterOutIdx);
    }
    log_always_np("\n");
  }

  if (vm.count("cb_ocall_ret_through")) {
    std::string NotModifyOCallRetSpecList =
        vm["cb_ocall_ret_through"].as<std::string>();
    std::vector<std::string> NotModifyOCallRetSpecVec;
    boost::split(NotModifyOCallRetSpecVec, NotModifyOCallRetSpecList,
                 [](char c) { return c == ','; });

    for (auto NotModifyOCallRetSpec : NotModifyOCallRetSpecVec) {
      boost::trim(NotModifyOCallRetSpec);
      if (NotModifyOCallRetSpec != "") {
        data_factory.AddNotModifyOCallRetSpecs(NotModifyOCallRetSpec);
      }
    }
  }

  sgxfuzz_assert(ClUsedLogLevel <= 4);
  sgxfuzz_assert(ClMaxCallSeqSize >= 1);
  sgxfuzz_assert(ClZoomRate > 0 and ClZoomRate < 50);
  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  return data_factory.mutate(Data, Size, MaxSize);
}

extern "C" void LLVMFuzzerEarlyAfterRunOne() {
  // Destroy Enclave
  sgxfuzz_error(sgx_destroy_enclave(__hidden_sgxfuzzer_harness_global_eid) !=
                    SGX_SUCCESS,
                "[FAIL] Enclave destroy");
}

extern "C" __attribute__((weak)) int SGXFuzzerEnvClearBeforeTest();
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  log_always("Start LLVMFuzzerTestOneInput\n");
  // Remove last round environment remain
  if (SGXFuzzerEnvClearBeforeTest) {
    sgxfuzz_assert(SGXFuzzerEnvClearBeforeTest() == 0);
  }
  data_factory.init(Data, Size);

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  // Initialize Enclave
  ret = sgx_create_enclave(ClEnclaveFileName.c_str(),
                           SGX_DEBUG_FLAG /* Debug Support: set to 1 */, NULL,
                           NULL, &__hidden_sgxfuzzer_harness_global_eid, NULL);
  sgxfuzz_error(ret != SGX_SUCCESS, "[FAIL] Enclave initilize");
  // Reinit after create
  data_factory.init(Data, Size);

  // Test body
  std::vector<int> callSeq;
  if (gFuzzMode == TEST_USER) {
    callSeq = gFuzzerSeq;
  } else {
    data_factory.getCallSequence(callSeq, gFuzzECallNum);
  }
  for (int i : callSeq) {
    sgxfuzz_assert(i < gFuzzECallNum);
    if (std::find(gFilterOutIndices.begin(), gFilterOutIndices.end(), i) !=
        gFilterOutIndices.end()) {
      // Filter it out
      continue;
    }

    log_always("Try %s\n", gFuzzECallNameArray[i]);
    ret = gFuzzECallArray[i]();
    sgxfuzz_error(ret != SGX_SUCCESS and ret != SGX_ERROR_INVALID_PARAMETER and
                      ret != SGX_ERROR_ECALL_NOT_ALLOWED,
                  "[FAIL] ECall: %s", gFuzzECallNameArray[i]);
  }

  data_factory.clear();

  return 0;
}

// DriverGen Callbacks
extern "C" size_t DFGetUserCheckCount(size_t eleSize, char *cStrAsParamID) {
  return data_factory.getUserCheckCount(eleSize);
}

extern "C" uint8_t *DFGetBytesEx(uint8_t *ptr, size_t byteArrLen,
                                 char *cStrAsParamID, FuzzDataTy dataType) {
  return data_factory.getBytes(ptr, byteArrLen, dataType);
}

extern "C" uint8_t *DFGetBytes(uint8_t *ptr, size_t byteArrLen,
                               char *cStrAsParamID, FuzzDataTy dataType) {
  return data_factory.getBytes(ptr, byteArrLen, dataType);
}

extern "C" bool DFEnableSetNull(char *cStrAsParamID) {
  return data_factory.EnableSetNull();
}

extern "C" void *DFManagedMalloc(size_t size) {
  return data_factory.managedMalloc(size);
}
extern "C" void *DFManagedCalloc(size_t count, size_t size) {
  return data_factory.managedCalloc(count, size);
}

extern "C" uint64_t DFGetPtToCntECall(uint64_t size, uint64_t count,
                                      uint64_t eleSize) {
  sgxfuzz_assert(size and count and eleSize);
  // Maybe size * count != n * eleSize, due to problem of Enclave developer
  uint64_t ptCnt = (size * count + eleSize - 1) / eleSize;
  return ptCnt;
}

extern "C" uint64_t DFGetPtToCntOCall(uint64_t size, uint64_t count,
                                      uint64_t eleSize) {
  sgxfuzz_assert(size and count and eleSize);
  // Maybe size * count != n * eleSize, due to problem of Enclave developer
  uint64_t ptCnt = (size * count) / eleSize;
  return ptCnt;
}

extern "C" bool DFEnableModifyOCallRet(char *cParamID) {
  return data_factory.EnableModifyOCallRet(cParamID);
}

extern "C" bool DFEnableModifyDoubleFetchValue() {
  return data_factory.EnableModifyDoubleFetchValue();
}

extern "C" int DFGetInt32() { return data_factory.getInterger<int>(); }

extern "C" bool DFEnableSanCheckDie() {
  return data_factory.EnableSanCheckDie();
}

extern "C" bool DFEnableCollectStack() { return ClEnableCollectStack; }
extern "C" bool DFCmpFuncNameInTOCTOU() { return ClCmpFuncNameInTOCTOU; }
extern "C" bool DFUseAddr2line() { return ClUseAddr2line; }
