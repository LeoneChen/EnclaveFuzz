#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "AddressSanitizer.hpp"
#include "ModuleAddressSanitizer.hpp"
#include "SGXSanManifest.h"
#include "AdjustUSP.hpp"

using namespace llvm;

namespace
{
    struct SGXSanPass : public ModulePass
    {
        static char ID;
        SGXSanPass() : ModulePass(ID) {}

        bool runOnModule(Module &M) override
        {
            errs() << "[SGXSanPass] " << M.getName().str() << "\n";
            // std::error_code EC;
            // raw_fd_stream f(M.getName().str() + ".dump", EC);
            // M.print(f, nullptr);
            bool Changed = false;
            ModuleAddressSanitizer MASan(M);
            MASan.instrumentModule(M);

            AddressSanitizer ASan(M);
            for (Function &F : M)
            {
                // errs() << "[SGXSanPass] [Function] " << F.getName().str() << "\n";
                if (F.isDeclaration())
                    continue;

                std::set<std::string> OCallsOnlyAdjustUSP{"sgxsan_ocall_print_string", "sgxsan_ocall_addr2line", "sgxsan_ocall_addr2line_ex", "sgxsan_ocall_addr2func_name", "sgxsan_ocall_depcit_distribute", "sgxsan_ocall_get_mmap_infos"};
                StringRef func_name = F.getName();
                if (std::find(OCallsOnlyAdjustUSP.begin(), OCallsOnlyAdjustUSP.end(), func_name.str()) != OCallsOnlyAdjustUSP.end())
                {
                    adjustUntrustedSPRegisterAtOcallAllocAndFree(F);
                }
                // When USE_SGXSAN_MALLOC==0: since we have monitored malloc-serial function, (linkonce_odr type function) in library which will check shadowbyte whether instrumented or not is not necessary.
                else if (func_name != "sgxsan_ocall_init_shadow_memory")
                {
                    // hook sgx-specifical callee, normal asan, elrange check, Out-Addr Whitelist check, GlobalPropageteWhitelist
                    // Sensitive area check, Whitelist fill, Whitelist (De)Active, poison etc.
                    Changed |= ASan.instrumentFunction(F);
                }
            }
            return Changed;
        }
    }; // end of struct SGXSanPass
} // end of anonymous namespace

char SGXSanPass::ID = 0;
static RegisterPass<SGXSanPass> register_sgxsan_pass("SGXSanPass", "SGXSanPass",
                                                     false /* Only looks at CFG */,
                                                     false /* Analysis Pass */);

static RegisterStandardPasses lto_register_std_pass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM)
    { PM.add(new SGXSanPass()); });

static RegisterStandardPasses l0_register_std_pass(
    /* EP_EarlyAsPossible can only be used in FunctionPass(https://lists.llvm.org/pipermail/llvm-dev/2018-June/123987.html) */
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SGXSanPass()); });

static RegisterStandardPasses moe_register_std_pass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM)
    { PM.add(new SGXSanPass()); });