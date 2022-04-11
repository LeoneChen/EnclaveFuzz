#ifndef ADDRESS_SANITIZER_HPP
#define ADDRESS_SANITIZER_HPP

#include "llvm/IR/Function.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/ADT/Statistic.h"
#include <assert.h>
#include "SGXSanManifest.h"
#include "PassCommon.hpp"
#include <unordered_set>

#ifndef DEBUG_TYPE
#define DEBUG_TYPE "sgxsan"
#endif

// Accesses sizes are powers of two: 1, 2, 4, 8, 16.
static const size_t kNumberOfAccessSizes = 5;

class AddressSanitizer
{
public:
    AddressSanitizer(llvm::Module &M, bool UseAfterScope = false);
    bool instrumentFunction(llvm::Function &F);
    void initializeCallbacks(llvm::Module &M);
    void getInterestingMemoryOperands(llvm::Instruction *I, llvm::SmallVectorImpl<llvm::InterestingMemoryOperand> &Interesting, llvm::SmallVector<llvm::StoreInst *, 16> &GlobalVariableStoreInsts);
    void instrumentMop(llvm::InterestingMemoryOperand &O, bool UseCalls);
    void instrumentGlobalPropageteWhitelist(llvm::StoreInst *SI);
    bool instrumentRealEcall(llvm::CallInst *CI, llvm::SmallVector<llvm::Instruction *, 8> &ReturnInstVec);
    bool instrumentOcallWrapper(llvm::Function &OcallWrapper, llvm::SmallVector<llvm::Instruction *, 8> &ReturnInstVec);
    bool instrumentParameterCheck(llvm::Value *operand, llvm::IRBuilder<> &IRB, const llvm::DataLayout &DL,
                                  int depth, llvm::Value *eleCnt = nullptr, llvm::Value *operandAddr = nullptr,
                                  bool checkCurrentLevelPtr = true);
    void replaceSGXSanIntrinName(llvm::Function &F);
    void instrumentAddress(llvm::Instruction *OrigIns, llvm::Instruction *InsertBefore, llvm::Value *Addr,
                           uint32_t TypeSize, bool IsWrite, llvm::Value *SizeArgument, bool UseCalls);
    void instrumentUnusualSizeOrAlignment(
        llvm::Instruction *I, llvm::Instruction *InsertBefore, llvm::Value *Addr, uint32_t TypeSize,
        bool IsWrite, llvm::Value *SizeArgument, bool UseCalls);
    void declareExternElrangeSymbol(llvm::Module &M);
    llvm::Value *memToShadow(llvm::Value *Shadow, llvm::IRBuilder<> &IRB);
    llvm::Value *createSlowPathCmp(llvm::IRBuilder<> &IRB, llvm::Value *AddrLong,
                                   llvm::Value *ShadowValue,
                                   uint32_t TypeSize);
    llvm::Instruction *generateCrashCode(llvm::Instruction *InsertBefore,
                                         llvm::Value *Addr, bool IsWrite,
                                         size_t AccessSizeIndex,
                                         llvm::Value *SizeArgument);
    void instrumentMemIntrinsic(llvm::MemIntrinsic *MI);
    void instrumentSecMemIntrinsic(llvm::CallInst *CI);
#if (USE_SGXSAN_MALLOC)
    void instrumentHeapCall(llvm::CallInst *CI);
#endif
    bool isInterestingAlloca(const llvm::AllocaInst &AI);
    uint64_t getAllocaSizeInBytes(const llvm::AllocaInst &AI) const;
    bool ignoreAccess(llvm::Value *Ptr);
    static llvm::Type *unpackArrayType(llvm::Type *type);

private:
    friend class FunctionStackPoisoner;
    llvm::LLVMContext *C;
    int LongSize;
    bool UseAfterScope;
    llvm::Type *IntptrTy;
    ShadowMapping Mapping;
    llvm::FunctionCallee AsanHandleNoReturnFunc;

    // These arrays is indexed by AccessIsWrite, Experiment and log2(AccessSize).
    llvm::FunctionCallee AsanErrorCallback[2][kNumberOfAccessSizes];
    llvm::FunctionCallee AsanMemoryAccessCallback[2][kNumberOfAccessSizes];

    // These arrays is indexed by AccessIsWrite and Experiment.
    llvm::FunctionCallee AsanErrorCallbackSized[2];
    llvm::FunctionCallee AsanMemoryAccessCallbackSized[2];

    llvm::FunctionCallee AsanMemmove, AsanMemcpy, AsanMemset;
    llvm::Value *LocalDynamicShadow = nullptr;

    llvm::DenseMap<const llvm::AllocaInst *, bool> ProcessedAllocas;

    llvm::GlobalVariable *ExternSGXSanEnclaveBaseAddr, *ExternSGXSanEnclaveSizeAddr;

    llvm::FunctionCallee WhitelistOfAddrOutEnclave_active, WhitelistOfAddrOutEnclave_deactive,
        WhitelistOfAddrOutEnclave_query, WhitelistOfAddrOutEnclave_global_propagate,
        sgxsan_edge_check, SGXSanMemcpyS, SGXSanMemsetS, SGXSanMemmoveS,
        EnclaveTLSConstructorAtTBridgeBegin, EnclaveTLSDestructorAtTBridgeEnd;
#if (USE_SGXSAN_MALLOC)
    llvm::FunctionCallee SGXSanMalloc, SGXSanFree, SGXSanCalloc, SGXSanRealloc;
#endif
    std::unordered_set<llvm::Function *> TLSMgrInstrumentedEcall;
};

#endif // ADDRESS_SANITIZER_HPP