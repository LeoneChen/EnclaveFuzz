#pragma once

#include "PassUtil.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizer.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include <unordered_set>

/// This struct defines the shadow mapping using the rule:
///   shadow = (mem >> Scale) ADD-or-OR Offset.
/// If InGlobal is true, then
///   extern char __asan_shadow[];
///   shadow = (mem >> Scale) + &__asan_shadow
struct ShadowMapping {
  int Scale;
  uint64_t Offset;
  bool OrShadowOffset;
  bool InGlobal;
};

ShadowMapping ASanGetShadowMapping(llvm::Triple &TargetTriple, int LongSize,
                                   bool IsKasan);

// Accesses sizes are powers of two: 1, 2, 4, 8, 16.
static const size_t kNumberOfAccessSizes = 5;

namespace llvm {
/// AddressSanitizer: instrument the code in module to find memory bugs.
struct AddressSanitizer {
  AddressSanitizer(Module &M, const GlobalsMetadata *GlobalsMD,
                   bool CompileKernel = false, bool Recover = false,
                   bool UseAfterScope = false,
                   AsanDetectStackUseAfterReturnMode UseAfterReturn =
                       AsanDetectStackUseAfterReturnMode::Runtime);

  uint64_t getAllocaSizeInBytes(const AllocaInst &AI) const;

  /// Check if we want (and can) handle this alloca.
  bool isInterestingAlloca(const AllocaInst &AI);

  bool ignoreAccess(Value *Ptr);
  void getInterestingMemoryOperands(
      Instruction *I, SmallVectorImpl<InterestingMemoryOperand> &Interesting);

  void instrumentMop(ObjectSizeOffsetVisitor &ObjSizeVis,
                     InterestingMemoryOperand &O, bool UseCalls,
                     const DataLayout &DL);
  void instrumentPointerComparisonOrSubtraction(Instruction *I);
  void instrumentAddress(Instruction *OrigIns, Instruction *InsertBefore,
                         Value *Addr, uint32_t TypeSize, bool IsWrite,
                         Value *SizeArgument, bool UseCalls, uint32_t Exp);
  Instruction *instrumentAMDGPUAddress(Instruction *OrigIns,
                                       Instruction *InsertBefore, Value *Addr,
                                       uint32_t TypeSize, bool IsWrite,
                                       Value *SizeArgument);
  void instrumentUnusualSizeOrAlignment(Instruction *I,
                                        Instruction *InsertBefore, Value *Addr,
                                        uint32_t TypeSize, bool IsWrite,
                                        Value *SizeArgument, bool UseCalls,
                                        uint32_t Exp);
  Value *createSlowPathCmp(IRBuilder<> &IRB, Value *AddrLong,
                           Value *ShadowValue, uint32_t TypeSize);
  Instruction *generateCrashCode(Instruction *InsertBefore, Value *Addr,
                                 bool IsWrite, size_t AccessSizeIndex,
                                 Value *SizeArgument, uint32_t Exp);
  void instrumentMemIntrinsic(MemIntrinsic *MI);
  Value *memToShadow(Value *Shadow, IRBuilder<> &IRB);
  bool suppressInstrumentationSiteForDebug(int &Instrumented);
  bool instrumentFunction(Function &F, const TargetLibraryInfo *TLI);
  bool maybeInsertAsanInitAtFunctionEntry(Function &F);
  bool maybeInsertDynamicShadowAtFunctionEntry(Function &F);
  void markEscapedLocalAllocas(Function &F);
  void declareAdditionalSymbol(Module &M);
  /// \brief Instrument \c memset_s/memmove_s/memcpy_s
  void instrumentSecMemIntrinsic(CallInst *CI);
  /// \brief Instrument \c TDECallConstructor and \c TDECallDestructor at begin
  /// and end of ecall wrapper respectively
  void instrumentTDECallMgr(Function *ecallWrapper);
  bool instrumentRealECall(CallInst *CI);
  bool instrumentOcallWrapper(Function &OcallWrapper);

private:
  friend struct FunctionStackPoisoner;

  void initializeCallbacks(Module &M);

  bool LooksLikeCodeInBug11395(Instruction *I);
  bool GlobalIsLinkerInitialized(GlobalVariable *G);
  bool isSafeAccess(ObjectSizeOffsetVisitor &ObjSizeVis, Value *Addr,
                    uint64_t TypeSize) const;

  /// Helper to cleanup per-function state.
  struct FunctionStateRAII {
    AddressSanitizer *Pass;

    FunctionStateRAII(AddressSanitizer *Pass) : Pass(Pass) {
      assert(Pass->ProcessedAllocas.empty() &&
             "last pass forgot to clear cache");
      assert(!Pass->LocalDynamicShadow);
    }

    ~FunctionStateRAII() {
      Pass->LocalDynamicShadow = nullptr;
      Pass->ProcessedAllocas.clear();
    }
  };

  LLVMContext *C;
  Triple TargetTriple;
  int LongSize;
  bool CompileKernel;
  bool Recover;
  bool UseAfterScope;
  AsanDetectStackUseAfterReturnMode UseAfterReturn;
  Type *IntptrTy;
  ShadowMapping Mapping;
  FunctionCallee AsanHandleNoReturnFunc;
  FunctionCallee AsanPtrCmpFunction, AsanPtrSubFunction;
  Constant *AsanShadowGlobal;

  // These arrays is indexed by AccessIsWrite, Experiment and log2(AccessSize).
  FunctionCallee AsanErrorCallback[2][2][kNumberOfAccessSizes];
  FunctionCallee AsanMemoryAccessCallback[2][2][kNumberOfAccessSizes];

  // These arrays is indexed by AccessIsWrite and Experiment.
  FunctionCallee AsanErrorCallbackSized[2][2];
  FunctionCallee AsanMemoryAccessCallbackSized[2][2];

  FunctionCallee AsanMemmove, AsanMemcpy, AsanMemset;
  Value *LocalDynamicShadow = nullptr;
  const GlobalsMetadata &GlobalsMD;
  DenseMap<const AllocaInst *, bool> ProcessedAllocas;

  FunctionCallee AMDGPUAddressShared;
  FunctionCallee AMDGPUAddressPrivate;

  FunctionCallee MemAccessMgrActive, MemAccessMgrDeactive,
      MemAccessMgrOutEnclaveAccess, MemAccessMgrInEnclaveAccess, SGXSanMemcpyS,
      SGXSanMemsetS, SGXSanMemmoveS, TDECallConstructor, TDECallDestructor,
      PushOCAllocStack, PopOCAllocStack;
  std::unordered_set<Function *> TDMgrInstrumentedEcall;
  Constant *globalFuncName = nullptr;
  std::map<Type *, bool> typeHasPointerMap;
  SGXSanInstVisitor mInstVisitor;
};

class ModuleAddressSanitizer {
public:
  ModuleAddressSanitizer(Module &M, const GlobalsMetadata *GlobalsMD,
                         bool CompileKernel = false, bool Recover = false,
                         bool UseGlobalsGC = true, bool UseOdrIndicator = false,
                         AsanDtorKind DestructorKind = AsanDtorKind::Global);

  bool instrumentModule(Module &);

private:
  void initializeCallbacks(Module &M);

  bool InstrumentGlobals(IRBuilder<> &IRB, Module &M, bool *CtorComdat);
  void InstrumentGlobalsCOFF(IRBuilder<> &IRB, Module &M,
                             ArrayRef<GlobalVariable *> ExtendedGlobals,
                             ArrayRef<Constant *> MetadataInitializers);
  void InstrumentGlobalsELF(IRBuilder<> &IRB, Module &M,
                            ArrayRef<GlobalVariable *> ExtendedGlobals,
                            ArrayRef<Constant *> MetadataInitializers,
                            const std::string &UniqueModuleId);
  void InstrumentGlobalsMachO(IRBuilder<> &IRB, Module &M,
                              ArrayRef<GlobalVariable *> ExtendedGlobals,
                              ArrayRef<Constant *> MetadataInitializers);
  void
  InstrumentGlobalsWithMetadataArray(IRBuilder<> &IRB, Module &M,
                                     ArrayRef<GlobalVariable *> ExtendedGlobals,
                                     ArrayRef<Constant *> MetadataInitializers);

  GlobalVariable *CreateMetadataGlobal(Module &M, Constant *Initializer,
                                       StringRef OriginalName);
  void SetComdatForGlobalMetadata(GlobalVariable *G, GlobalVariable *Metadata,
                                  StringRef InternalSuffix);
  Instruction *CreateAsanModuleDtor(Module &M);

  const GlobalVariable *getExcludedAliasedGlobal(const GlobalAlias &GA) const;
  bool shouldInstrumentGlobal(GlobalVariable *G) const;
  bool ShouldUseMachOGlobalsSection() const;
  StringRef getGlobalMetadataSection() const;
  void poisonOneInitializer(Function &GlobalInit, GlobalValue *ModuleName);
  void createInitializerPoisonCalls(Module &M, GlobalValue *ModuleName);
  uint64_t getMinRedzoneSizeForGlobal() const;
  uint64_t getRedzoneSizeForGlobal(uint64_t SizeInBytes) const;
  int GetAsanVersion(const Module &M) const;

  const GlobalsMetadata &GlobalsMD;
  bool CompileKernel;
  bool Recover;
  bool UseGlobalsGC;
  bool UsePrivateAlias;
  bool UseOdrIndicator;
  bool UseCtorComdat;
  AsanDtorKind DestructorKind;
  Type *IntptrTy;
  LLVMContext *C;
  Triple TargetTriple;
  ShadowMapping Mapping;
  FunctionCallee AsanPoisonGlobals;
  FunctionCallee AsanUnpoisonGlobals;
  FunctionCallee AsanRegisterGlobals;
  FunctionCallee AsanUnregisterGlobals;
  FunctionCallee AsanRegisterImageGlobals;
  FunctionCallee AsanUnregisterImageGlobals;
  FunctionCallee AsanRegisterElfGlobals;
  FunctionCallee AsanUnregisterElfGlobals;

  Function *AsanCtorFunction = nullptr;
  Function *AsanDtorFunction = nullptr;
};
} // namespace llvm