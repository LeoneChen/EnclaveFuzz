#include "AddressSanitizer.h"
#include "FuncRenamePass.h"
#include "PassUtil.h"
#include "nlohmann/json.hpp"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CFLSteensAliasAnalysis.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sys/time.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using ordered_json = nlohmann::ordered_json;
using namespace llvm;

static cl::opt<bool> ClDumpStructType("dump-struct", cl::desc("Dump Struct"),
                                      cl::Hidden, cl::init(false));

namespace {
struct SGXSanLegacyPass : public ModulePass {
  static char ID;
  SGXSanLegacyPass() : ModulePass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<TargetLibraryInfoWrapperPass>();
  }

  void DumpModuleStructs(Module &M) {
    if (ClDumpStructType) {
      ordered_json json;
      for (auto structTy : M.getIdentifiedStructTypes()) {
        TypeSerialize::Serializer serializer;
        serializer.SerializeStructType(structTy, json);
      }
      std::ofstream ofs(M.getName().str() + ".sgxsan.typeinfo.json");
      ofs << json.dump(4);
    }
  }

  bool DefaultRenameFunc(Module &M) {
    bool changed = false;
    std::string RenamePrefix = "__hidden_in_enclave_";
    std::vector<std::string> FuncRenameList{"access",
                                            "close",
                                            "dlclose",
                                            "dlerror",
                                            "dlopen",
                                            "dlsym",
                                            "dl_iterate_phdr",
                                            "fchmod",
                                            "fchown",
                                            "fclose",
                                            "fcntl",
                                            "fcntl64",
                                            "fdopen",
                                            "fflush",
                                            "fileno",
                                            "fopen",
                                            "fseek",
                                            "fsync",
                                            "ftell",
                                            "ftruncate",
                                            "fwrite",
                                            "getcwd",
                                            "getenv",
                                            "geteuid",
                                            "getpid",
                                            "gettimeofday",
                                            "localtime",
                                            "lseek64",
                                            "mkdir",
                                            "mmap",
                                            "mmap64",
                                            "mremap",
                                            "munmap",
                                            "open",
                                            "open64",
                                            "readlink"
                                            "rmdir",
                                            "setenv",
                                            "sleep",
                                            "time",
                                            "unlink",
                                            "utimes",
                                            "write"};
    for (auto origName : FuncRenameList) {
      auto F = M.getFunction(origName);
      if (F) {
        std::string newName = RenamePrefix + origName;
        dbgs() << "== FuncRename: " << M.getName() << ": " << origName << " => "
               << newName << " ==\n";
        F->setName(newName);
        changed = true;
      }
    }
    return changed;
  }

  bool runOnModule(Module &M) override {
    bool Changed = false;

    DumpModuleStructs(M);
    Changed |= RenameFuncSym(M);
    Changed |= DefaultRenameFunc(M);

    // run SGXSan Pass
    dbgs() << "== SGXSan Pass: " << M.getName().str() << " ==\n";
    GlobalsMetadata GlobalsMD = GlobalsMetadata(M);
    AddressSanitizer ASan(M, &GlobalsMD, false, false, true,
                          AsanDetectStackUseAfterReturnMode::Never);
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      const TargetLibraryInfo *TLI =
          &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
      Changed |= ASan.instrumentFunction(F, TLI);
    }
    ModuleAddressSanitizer MASan(M, &GlobalsMD);
    Changed |= MASan.instrumentModule(M);
    return Changed;
  }
}; // end of struct SGXSanLegacyPass
} // end of anonymous namespace

char SGXSanLegacyPass::ID = 0;

static RegisterStandardPasses register_lto_pass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });

static RegisterStandardPasses l0_register_std_pass(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });

static RegisterStandardPasses moe_register_std_pass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
      PM.add(new SGXSanLegacyPass());
    });
