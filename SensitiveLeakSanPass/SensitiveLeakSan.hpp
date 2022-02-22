#pragma once

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizerCommon.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/CommandLine.h"

#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "SABER/LeakChecker.h"
#include "SVF-FE/PAGBuilder.h"

#include "SGXSanInstVisitor.hpp"

#include <unordered_set>
#include <unordered_map>

class SensitiveLeakSan
{

public:
    SensitiveLeakSan(llvm::Module &M);
    void includeThreadFuncArgShadow();
    void includeElrange();
    void includeSGXSanCheck();
    void initSVF();
    bool runOnModule();
    void collectAndPoisonSensitiveObj(llvm::Module &M);
    void doVFA(llvm::Value *work);
    void pushSensitiveObj(llvm::Value *annotatedVar);
    void instrumentSensitivePoison(llvm::Instruction *objI);
    llvm::Value *memToShadow(llvm::Value *Shadow, llvm::IRBuilder<> &IRB);
    llvm::Value *memToShadowPtr(llvm::Value *memPtr, llvm::IRBuilder<> &IRB);

    int getCallInstOperandPosition(llvm::CallInst *CI, llvm::Value *oprend, bool rawOperand = false);
    int getFuncArgPosition(llvm::Argument *arg);
    void getDirectAndIndirectCalledFunction(llvm::CallInst *CI, llvm::SmallVector<llvm::Function *> &calleeVec);
    llvm::Instruction *findInstByName(llvm::Function *F, std::string InstName);
    void getPtrValPNs(SVF::ObjPN *obj, std::unordered_set<SVF::ValPN *> &oneLevelPtrs);
    void add2SensitiveObjAndPoison(SVF::ObjPN *obj);
    static llvm::Value *RoundUpUDiv(llvm::IRBuilder<> &IRB, llvm::Value *size, uint64_t dividend);
    uint64_t RoundUpUDiv(uint64_t dividend, uint64_t divisor);
    void pushPtObj2WorkList(llvm::Value *ptr);
    static llvm::StringRef getBelongedFunctionName(SVF::PAGNode *node);
    static llvm::StringRef getBelongedFunctionName(llvm::Value *val);
    void setNoSanitizeMetadata(llvm::Instruction *I);
    void propagateShadowInMemTransfer(llvm::CallInst *CI, llvm::Instruction *insertPoint, llvm::Value *destPtr,
                                      llvm::Value *srcPtr, llvm::Value *size);
    uint64_t getPointerElementSize(llvm::Value *ptr);
    llvm::Value *getSensitiveObjSize(llvm::Value *obj, llvm::IRBuilder<> &IRB);
    void getNonPointerObjPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ObjPN *> &objs);
    llvm::Value *instrumentPoisonCheck(llvm::Value *src);
    llvm::Value *isLIPoisoned(llvm::LoadInst *src);
    llvm::Value *isArgPoisoned(llvm::Argument *src);
    llvm::Value *isCIRetPoisoned(llvm::CallInst *src);
    llvm::Value *isPtrPoisoned(llvm::Instruction *insertPoint, llvm::Value *ptr);
    static int getPointerLevel(llvm::Value *ptr);
    void PoisonCIOperand(llvm::Value *isPoisoned, llvm::CallInst *CI, int operandPosition);
    void PoisonSI(llvm::Value *isPoisoned, llvm::StoreInst *SI);
    void PoisonRetShadow(llvm::Value *isPoisoned, llvm::ReturnInst *calleeRI);
    static llvm::Value *stripCast(llvm::Value *v);
    void propagateShadow(llvm::Value *src);
    uint64_t getTypeAllocaSize(llvm::Type *type);
    static bool isAnnotationIntrinsic(llvm::CallInst *CI);
    static std::string extractAnnotation(llvm::Value *annotationStrVal);
    static bool isSecureVersionMemTransferCI(llvm::CallInst *CI);
    static bool StringRefContainWord(llvm::StringRef str, std::string word);
    static bool isEncryptionFunction(llvm::Function *F);
    void cleanStackObjectSensitiveShadow(llvm::Value *stackObject);
    void PoisonObject(llvm::Value *objPtr, llvm::Value *objSize, llvm::IRBuilder<> &IRB, uint8_t poisonValue);
    static void getNonCastUsers(llvm::Value *value, std::vector<llvm::User *> &users);
    void poisonSensitiveGlobalVariableAtRuntime();
    void initializeCallbacks();

private:
    std::unordered_set<SVF::ObjPN *> SensitiveObjs, WorkList, ProcessedList;
    std::unordered_set<llvm::Value *> poisonedInst;
    std::unordered_set<llvm::CallInst *> processedMemTransferInst;
    std::unordered_map<llvm::CallInst *, std::unordered_set<int>> poisonedCI;
    std::unordered_map<llvm::Value *, llvm::Value *> poisonCheckedValues;
    llvm::GlobalVariable *SGXSanEnclaveBaseAddr, *SGXSanEnclaveSizeAddr, *ThreadFuncArgShadow;
    llvm::FunctionCallee poison_thread_func_arg_shadow_stack,
        unpoison_thread_func_arg_shadow_stack, onetime_query_thread_func_arg_shadow_stack,
        query_thread_func_arg_shadow_stack, clear_thread_func_arg_shadow_stack,
        push_thread_func_arg_shadow_stack, pop_thread_func_arg_shadow_stack,
        sgxsan_region_is_poisoned, is_addr_in_elrange, is_addr_in_elrange_ex,
        sgxsan_region_is_in_elrange_and_poisoned, PoisonSensitiveGlobal;

    llvm::Module *M;
    llvm::LLVMContext *C;
    llvm::Type *IntptrTy;

    SVF::SVFModule *svfModule;
    SVF::PAG *pag;
    SVF::Andersen *ander;
    SVF::PTACallGraph *callgraph;

    SGXSanInstVisitor *instVisitor;
    llvm::SmallVector<llvm::Constant *> globalsToBePolluted;
    llvm::Function *PoisonSensitiveGlobalModuleCtor;
};
