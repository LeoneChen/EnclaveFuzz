#include "AddressSanitizer.h"
#include "AdjustUSP.hpp"
#include "llvm/Analysis/CFLSteensAliasAnalysis.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizer.h"

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

  bool runOnModule(Module &M) override {
    bool Changed = false;

    // run SGXSan Pass
    // dbgs() << "== SGXSan Pass: " << M.getName().str() << " ==\n";
    GlobalsMetadata GlobalsMD = GlobalsMetadata(M);
    AddressSanitizer ASan(M, &GlobalsMD, false, false, true,
                          AsanDetectStackUseAfterReturnMode::Never);
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      if (F.getName().startswith("sgxsan_ocall_") ||
          F.getName().startswith("sgx_sgxsan_ecall_") ||
          F.getName().startswith("fuzzer_ocall_") ||
          F.getName().startswith("sgx_fuzzer_ecall_")) {
        Changed |= adjustUntrustedSPRegisterAtOcallAllocAndFree(F);
        // Since we have monitored malloc-serial function, (linkonce_odr type
        // function) in library which will check shadowbyte whether instrumented
        // or not is not necessary. don't call instrumentFunction()
      } else {
        const TargetLibraryInfo *TLI =
            &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
        // hook sgx-specifical callee, normal asan, elrange check, Out-Addr
        // Whitelist check, GlobalPropageteWhitelist Sensitive area check,
        // Whitelist fill, Whitelist (De)Active, poison etc.
        Changed |= ASan.instrumentFunction(F, TLI);
      }
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
