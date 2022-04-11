#include "SensitiveLeakSan.hpp"
#include "SGXSanManifest.h"
#include "llvm/Demangle/Demangle.h"
using namespace llvm;

#define SGXSAN_SENSITIVE_OBJ_FLAG 0x20

ShadowMapping Mapping = {3, SGXSAN_SHADOW_MAP_BASE};

Value *SensitiveLeakSan::memToShadow(Value *Shadow, IRBuilder<> &IRB)
{
    // as shadow memory only map elrange, let Shadow - EnclaveBase
    // EnclaveBase have to be initialied before here
    // check instrumentation is before poison operation
    LoadInst *SGXSanEnclaveBase = IRB.CreateLoad(IRB.getInt64Ty(), SGXSanEnclaveBaseAddr);
    setNoSanitizeMetadata(SGXSanEnclaveBase);

    Shadow = IRB.CreateSub(Shadow, SGXSanEnclaveBase);

    // Shadow >> scale
    Shadow = IRB.CreateLShr(Shadow, Mapping.Scale);
    if (Mapping.Offset == 0)
        return Shadow;

    // (Shadow >> scale) + offset
    Value *ShadowBase = IRB.getInt64(Mapping.Offset);

    return IRB.CreateAdd(Shadow, ShadowBase);
}

Value *SensitiveLeakSan::memToShadowPtr(Value *memPtr, IRBuilder<> &IRB)
{
    Value *memPtrInt = IRB.CreatePtrToInt(memPtr, IRB.getInt64Ty());
    Value *shadowPtrInt = memToShadow(memPtrInt, IRB);
    Value *shadowPtr = IRB.CreateIntToPtr(shadowPtrInt, IRB.getInt8PtrTy());
    return shadowPtr;
}

Value *SensitiveLeakSan::RoundUpUDiv(IRBuilder<> &IRB, Value *size, uint64_t dividend)
{
    return IRB.CreateUDiv(IRB.CreateAdd(size, IRB.getInt64(dividend - 1)), IRB.getInt64(dividend));
}

void SensitiveLeakSan::instrumentSensitiveInstObjPoison(SVF::ObjPN *objPN)
{
    if (isFunctionObjPN(objPN))
        return;
    Instruction *objI = cast<Instruction>(const_cast<Value *>(objPN->getValue()));
    SmallVector<Instruction *> objLivePoints;
    if (AllocaInst *objAI = dyn_cast<AllocaInst>(objI))
    {
        SmallDenseMap<AllocaInst *, SmallVector<IntrinsicInst *>> AILifeTimeStart;
        instVisitor->getAILifeTimeStart(AILifeTimeStart);
        for (auto start : AILifeTimeStart[objAI])
        {
            objLivePoints.push_back(start->getNextNode());
        }
        if (objLivePoints.size() == 0)
        {
            objLivePoints.push_back(objAI->getNextNode());
        }
    }
    else if (CallInst *objCI = dyn_cast<CallInst>(objI))
    {
        objLivePoints.push_back(objCI->getNextNode());
    }
    else
    {
        abort();
    }
    assert(objLivePoints.size() >= 1);
    for (auto insertPt : objLivePoints)
    {
        IRBuilder<> IRB(insertPt);

        Value *obj = nullptr, *objSize = nullptr;
        if (SVF::GepObjPN *gepObjPN = SVF::SVFUtil::dyn_cast<SVF::GepObjPN>(objPN))
        {
            auto inStructOffset = gepObjPN->getLocationSet().getOffset();
            obj = IRB.CreateGEP(objI, {IRB.getInt32(0), IRB.getInt32(inStructOffset)});
            objSize = IRB.getInt64(getTypeAllocaSize(cast<PointerType>(obj->getType())->getElementType()));
        }
        else if (isa<SVF::FIObjPN>(objPN))
        {
            obj = objI;
            objSize = getStackOrHeapInstObjSize(objI, IRB);
            assert(objSize != nullptr);
        }
        else
            abort();
        Value *objAddrInt = IRB.CreatePtrToInt(obj, IRB.getInt64Ty());
        // IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr("\n-[Collect]->\n" + toString(objPN)),
        //                            objAddrInt,
        //                            objSize});
        // PoisonObject(obj, objSize, IRB, SGXSAN_SENSITIVE_OBJ_FLAG);
        IRB.CreateCall(__sgxsan_poison_valid_shadow, {objAddrInt, objSize, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG)});
    }
    // cleanStackObjectSensitiveShadow(objPN);
}

Value *SensitiveLeakSan::getStackOrHeapInstObjSize(Instruction *objI, IRBuilder<> &IRB)
{
    Value *objSize = nullptr;
    if (AllocaInst *AI = dyn_cast<AllocaInst>(objI))
    {
        objSize = IRB.getInt64(getTypeAllocaSize(AI->getAllocatedType()));
    }
    else if (CallInst *CI = dyn_cast<CallInst>(objI))
    {
        objSize = IRB.CreateIntCast(getHeapObjSize(CI, IRB), IRB.getInt64Ty(), false);
    }
    return objSize;
}

Value *SensitiveLeakSan::getHeapObjSize(CallInst *CI, IRBuilder<> &IRB)
{

    if (Function *callee = CI->getCalledFunction())
    {
        std::string calleeName = llvm::demangle(callee->getName().str());
        if (calleeName.find("new") != std::string::npos || calleeName == "malloc")
        {
            return CI->getArgOperand(0);
        }
        else if (calleeName == "realloc")
        {
            return CI->getArgOperand(1);
        }
        else if (calleeName == "calloc")
        {
            return IRB.CreateNUWMul(CI->getArgOperand(0), CI->getArgOperand(1));
        }
    }

    return nullptr;
}

std::string SensitiveLeakSan::extractAnnotation(Value *annotationStrVal)
{
    GlobalVariable *GV = nullptr;
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(annotationStrVal))
    {
        if (CE->getOpcode() == Instruction::GetElementPtr)
        {
            GV = dyn_cast<GlobalVariable>(CE->getOperand(0));
        }
    }
    else if (Instruction *I = dyn_cast<Instruction>(annotationStrVal))
    {
        if (I->getOpcode() == Instruction::GetElementPtr)
        {
            GV = dyn_cast<GlobalVariable>(I->getOperand(0));
        }
    }

    std::string annotation = "";
    if (GV)
    {
        Constant *initializer = GV->getInitializer();
        if (ConstantDataSequential *seq = dyn_cast<ConstantDataSequential>(initializer))
        {
            if (seq->isString())
            {
                annotation = seq->getAsString().str().c_str();
            }
        }
    }
    return annotation;
}

void SensitiveLeakSan::add2SensitiveObjAndPoison(SVF::ObjPN *objPN)
{
    assert(objPN->hasValue());
    Value *obj = const_cast<Value *>(objPN->getValue());
    assert(obj->getType()->isPointerTy());
    assert(getPointerLevel(obj) == 1);
    assert(not isa<Function>(obj));
    auto emplaceResult = SensitiveObjs.emplace(objPN);
    if (emplaceResult.second)
    {
        if (isa<Instruction>(obj))
        {
            instrumentSensitiveInstObjPoison(objPN);
        }
        // non-instruction obj like global variable need to be poisoned at runtime
        else if (GlobalVariable *objGV = dyn_cast<GlobalVariable>(obj))
        {
            uint64_t SizeInBytes = getTypeAllocaSize(objGV->getValueType());
            uint8_t poisonValue = SGXSAN_SENSITIVE_OBJ_FLAG;
            StructType *globalToBePollutedTy = StructType::get(IntptrTy, IntptrTy, Type::getInt8Ty(*C));
            Constant *globalToBePolluted = ConstantStruct::get(
                globalToBePollutedTy,
                ConstantExpr::getPointerCast(objGV, IntptrTy),
                ConstantInt::get(IntptrTy, SizeInBytes),
                ConstantInt::get(Type::getInt8Ty(*C), poisonValue));
            globalsToBePolluted.push_back(globalToBePolluted);
            // globalToBePolluted->dump();
        }
    }
}

int SensitiveLeakSan::getPointerLevel(Value *ptr)
{
    assert(ptr);
    int level = 0;
    Type *type = ptr->getType();
    while (PointerType *ptrTy = dyn_cast<PointerType>(type))
    {
        level++;
        type = ptrTy->getElementType();
    }
    return level;
}

Value *SensitiveLeakSan::stripCast(Value *v)
{
    Value *value = v;
    while (CastInst *castI = dyn_cast<CastInst>(value))
    {
        value = castI->getOperand(0);
    }
    return value;
}

void SensitiveLeakSan::getNonPointerObjPNs(Value *value, std::unordered_set<SVF::ObjPN *> &objs)
{
    if (isa<Function>(value))
        return;
    assert(pag->hasValueNode(value));
    for (SVF::NodeID objPNID : ander->getPts(pag->getValueNode(value)))
    {
        if (SVF::ObjPN *objPN = SVF::SVFUtil::dyn_cast<SVF::ObjPN>(pag->getPAGNode(objPNID)))
            getNonPointerObjPNs(objPN, objs);
    }
}

void SensitiveLeakSan::getNonPointerObjPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ObjPN *> &objs)
{
    assert(objPN && objPN->isPointer());
    if (isa<SVF::DummyObjPN>(objPN))
        return;
    Value *obj = const_cast<Value *>(objPN->getValue());
    if (isa<Function>(obj))
        return;
    // SVF ObjPN is a mem object and even maybe a pointer object
    // e.g. '%p = alloca i8*'
    // however mem object is pointed by 1-level pointer
    // e.g. '%a = alloca i8'
    // where %a is 'i8*' type, and mem object is 'i8' type
    int pointerLevel = getPointerLevel(obj);
    assert(pointerLevel != 0);
    if (pointerLevel == 1)
    {
        if (CallInst *CI = dyn_cast<CallInst>(obj))
        {
            Function *callee = CI->getCalledFunction();
            assert(callee); // assument svf-recognized callee is not an indirect callee
            std::vector<std::string> allocs{"malloc", "calloc", "realloc"};
            std::string calleeName = llvm::demangle(callee->getName().str());
            if (not(calleeName.find("new") /* 'operator new[](...)' */ != std::string::npos ||
                    std::find(allocs.begin(), allocs.end(), calleeName) != allocs.end()))
            {
                // not interesting CI, get next objPN
                return;
            }
        }
        // non-CI or alloc-CI
        objs.emplace(objPN);
    }
    else /* > 1 */
    {
        // SVF models ConstantObj as special ObjPN#1, so there is no individual ObjPN for string constant etc. .
        for (SVF::NodeID deepObjNodeID : ander->getPts(objPN->getId()))
        {
            if (SVF::ObjPN *deepObjPN = SVF::SVFUtil::dyn_cast<SVF::ObjPN>(pag->getPAGNode(deepObjNodeID)))
            {
                if (isa<SVF::DummyObjPN>(deepObjPN))
                    continue;
                Value *deepObj = const_cast<Value *>(deepObjPN->getValue());
                if (isa<Function>(deepObj))
                    continue;
                assert(getPointerLevel(deepObj) < pointerLevel);
                getNonPointerObjPNs(deepObjPN, objs);
            }
        }
    }
}

void SensitiveLeakSan::pushSensitiveObj(Value *annotatedPtr)
{
    std::unordered_set<SVF::ObjPN *> objSet;
    getNonPointerObjPNs(annotatedPtr, objSet);
    assert(objSet.size() <= 1);
    for (auto obj : objSet)
    {
        add2SensitiveObjAndPoison(obj);
    }
}

bool SensitiveLeakSan::isAnnotationIntrinsic(CallInst *CI)
{
    assert(CI != nullptr);
    Function *callee = CI->getCalledFunction();
    if (callee)
    {
        StringRef funcName = callee->getName();
        if (funcName.contains("llvm") && funcName.contains("annotation"))
        {
            return true;
        }
    }
    return false;
}

bool SensitiveLeakSan::StringRefContainWord(StringRef str, std::string word)
{
    std::string lowercaseWord = word;
    std::for_each(lowercaseWord.begin(), lowercaseWord.end(), [](char &c)
                  { c = std::tolower(c); });
    std::string uppercaseWord = lowercaseWord;
    std::for_each(uppercaseWord.begin(), uppercaseWord.end(), [](char &c)
                  { c = std::toupper(c); });
    std::string capitalWord = lowercaseWord;
    capitalWord[0] = std::toupper(capitalWord[0]);
    return str.contains(lowercaseWord) || str.contains(uppercaseWord) || str.contains(capitalWord);
}

bool SensitiveLeakSan::isEncryptionFunction(Function *F)
{
    StringRef funcName = F->getName();
    return (StringRefContainWord(funcName, "encrypt") && !StringRefContainWord(funcName, "decrypt") && !StringRefContainWord(funcName, "encrypted") ||
            StringRefContainWord(funcName, "seal") && !StringRefContainWord(funcName, "unseal") && !StringRefContainWord(funcName, "sealed"))
               ? true
               : false;
}

void SensitiveLeakSan::poisonSensitiveGlobalVariableAtRuntime()
{
    size_t N = globalsToBePolluted.size();
    if (N > 0)
    {
        PoisonSensitiveGlobalModuleCtor = createSanitizerCtor(*M, "PoisonSensitiveGlobalModuleCtor");
        IRBuilder<> IRB(PoisonSensitiveGlobalModuleCtor->getEntryBlock().getTerminator());

        ArrayType *ArrayOfGlobalStructTy =
            ArrayType::get(globalsToBePolluted[0]->getType(), N);
        auto AllGlobals = new GlobalVariable(
            *M, ArrayOfGlobalStructTy, false, GlobalVariable::InternalLinkage,
            ConstantArray::get(ArrayOfGlobalStructTy, globalsToBePolluted), "");

        IRB.CreateCall(PoisonSensitiveGlobal,
                       {IRB.CreatePointerCast(AllGlobals, IntptrTy),
                        ConstantInt::get(IntptrTy, N)});
        appendToGlobalCtors(*M, PoisonSensitiveGlobalModuleCtor, 103);
    }
}

void SensitiveLeakSan::collectAndPoisonSensitiveObj(Module &M)
{
    SmallVector<llvm::CallInst *> CallInstVec;
    instVisitor->getCallInstVec(CallInstVec);
    for (auto CI : CallInstVec)
    {
        SmallVector<llvm::Function *> calleeVec;
        getDirectAndIndirectCalledFunction(CI, calleeVec);
        for (auto callee : calleeVec)
        {
            if (isEncryptionFunction(callee))
            {
                std::vector<std::string> plaintextParamKeywords = {"2encrypt", "unencrypt", "src", "source", "2seal", "unseal", "plain", "in", "key"};

                for (int i = 0; i < CI->getNumArgOperands(); i++)
                {
                    Value *argOp = CI->getArgOperand(i);
                    if (argOp->getType()->isPointerTy())
                    {

                        std::unordered_set<SVF::ObjPN *> objSet;
                        getNonPointerObjPNs(argOp, objSet);
                        for (auto objPN : objSet)
                        {
                            StringRef argName = SGXSanGetValueName(const_cast<Value *>(objPN->getValue()));
                            bool isInterestingParam = false;
                            for (auto plaintextParamKeyword : plaintextParamKeywords)
                            {
                                isInterestingParam = isInterestingParam || StringRefContainWord(argName, plaintextParamKeyword);
                            }
                            if (isInterestingParam)
                            {
                                add2SensitiveObjAndPoison(objPN);
                            }
                        }
                    }
                }
                if (not callee->isDeclaration())
                {
                    for (Argument &arg : callee->args())
                    {
                        if (arg.getType()->isPointerTy())
                        {
                            StringRef argName = SGXSanGetValueName(&arg);
                            bool isInterestingParam = false;
                            for (auto plaintextParamKeyword : plaintextParamKeywords)
                            {
                                isInterestingParam = isInterestingParam || StringRefContainWord(argName, plaintextParamKeyword);
                            }
                            if (isInterestingParam)
                            {
                                Value *obj = CI->getArgOperand(arg.getArgNo());
                                std::unordered_set<SVF::ObjPN *> objSet;
                                getNonPointerObjPNs(obj, objSet);
                                for (auto objPN : objSet)
                                {
                                    add2SensitiveObjAndPoison(objPN);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (GlobalVariable *globalAnnotation = M.getGlobalVariable("llvm.global.annotations"))
    {
        for (Value *GAOp : globalAnnotation->operands())
        {
            ConstantArray *CA = cast<ConstantArray>(GAOp);
            for (Value *CAOp : CA->operands())
            {
                ConstantStruct *CS = cast<ConstantStruct>(CAOp);
                std::string annotation = extractAnnotation(CS->getOperand(1));
                if (annotation == "SGXSAN_SENSITIVE")
                {
                    Value *annotatedVar = CS->getOperand(0);
                    ConstantExpr *CE = dyn_cast<ConstantExpr>(annotatedVar);
                    while (CE && CE->getOpcode() == Instruction::BitCast)
                    {
                        annotatedVar = CE->getOperand(0);
                        CE = dyn_cast<ConstantExpr>(annotatedVar);
                    }
                    pushSensitiveObj(annotatedVar);
                }
            }
        }
    }
    poisonSensitiveGlobalVariableAtRuntime();

    for (auto CI : CallInstVec)
    {
        if (isAnnotationIntrinsic(CI))
        {
            Value *annotatedPtr = CI->getOperand(0),
                  *annotateStr = CI->getArgOperand(1);
            assert(isa<PointerType>(annotatedPtr->getType()));
            std::string annotation = extractAnnotation(annotateStr);
            if (annotation == "SGXSAN_SENSITIVE")
            {
                pushSensitiveObj(annotatedPtr);
            }
        }
    }
}

void SensitiveLeakSan::includeElrange()
{
    IRBuilder<> IRB(*C);

    SGXSanEnclaveBaseAddr = cast<GlobalVariable>(M->getOrInsertGlobal("g_enclave_base", IRB.getInt64Ty()));
    SGXSanEnclaveBaseAddr->setLinkage(GlobalValue::ExternalLinkage);

    SGXSanEnclaveSizeAddr = cast<GlobalVariable>(M->getOrInsertGlobal("g_enclave_size", IRB.getInt64Ty()));
    SGXSanEnclaveSizeAddr->setLinkage(GlobalValue::ExternalLinkage);
}

void SensitiveLeakSan::initSVF()
{
    svfModule = SVF::LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(*M);
    SVF::PAGBuilder builder;

    pag = builder.build(svfModule);
    // SVF::DDAClient *client = new SVF::DDAClient(svfModule);
    // client->initialise(svfModule);
    // ander = new SVF::ContextDDA(pag, client);
    // ander->initialize();
    ander = SVF::AndersenWaveDiff::createAndersenWaveDiff(pag);
    callgraph = ander->getPTACallGraph();
}

void SensitiveLeakSan::includeThreadFuncArgShadow()
{
    IRBuilder<> IRB(*C);

    poison_thread_func_arg_shadow_stack = M->getOrInsertFunction("poison_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty(), IRB.getInt64Ty());
    unpoison_thread_func_arg_shadow_stack = M->getOrInsertFunction("unpoison_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty(), IRB.getInt64Ty());
    onetime_query_thread_func_arg_shadow_stack = M->getOrInsertFunction("onetime_query_thread_func_arg_shadow_stack", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty());
    query_thread_func_arg_shadow_stack = M->getOrInsertFunction("query_thread_func_arg_shadow_stack", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty());
    clear_thread_func_arg_shadow_stack = M->getOrInsertFunction("clear_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty());
    push_thread_func_arg_shadow_stack = M->getOrInsertFunction("push_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty());
    pop_thread_func_arg_shadow_stack = M->getOrInsertFunction("pop_thread_func_arg_shadow_stack", IRB.getVoidTy(), IRB.getInt64Ty());
}

void SensitiveLeakSan::includeSGXSanCheck()
{
    IRBuilder<> IRB(*C);
    sgxsan_region_is_poisoned = M->getOrInsertFunction("sgxsan_region_is_poisoned", IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt8Ty());
    is_addr_in_elrange = M->getOrInsertFunction("is_addr_in_elrange", IRB.getInt1Ty(), IRB.getInt64Ty());
    is_addr_in_elrange_ex = M->getOrInsertFunction("is_addr_in_elrange_ex", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty());
    sgxsan_region_is_in_elrange_and_poisoned = M->getOrInsertFunction("sgxsan_region_is_in_elrange_and_poisoned", IRB.getInt1Ty(), IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt8Ty());
}

void SensitiveLeakSan::initializeCallbacks()
{
    IRBuilder<> IRB(*C);

    PoisonSensitiveGlobal = M->getOrInsertFunction(
        "PoisonSensitiveGlobal", IRB.getVoidTy(), IntptrTy, IntptrTy);
    Abort = M->getOrInsertFunction("abort", IRB.getVoidTy());
    Printf = M->getOrInsertFunction("sgxsan_printf", Type::getInt32Ty(*C), Type::getInt8PtrTy(*C), Type::getInt8PtrTy(*C));
    StrSpeicifier = IRB.CreateGlobalStringPtr("%s", "", 0, M);
    print_ptr = M->getOrInsertFunction("print_ptr", Type::getVoidTy(*C), Type::getInt8PtrTy(*C), Type::getInt64Ty(*C), Type::getInt64Ty(*C));
    print_arg = M->getOrInsertFunction("print_arg", Type::getVoidTy(*C), Type::getInt8PtrTy(*C), Type::getInt64Ty(*C), Type::getInt64Ty(*C));
    __sgxsan_poison_valid_shadow = M->getOrInsertFunction("__sgxsan_poison_valid_shadow", IRB.getVoidTy(), IRB.getInt64Ty(), IRB.getInt64Ty(), IRB.getInt8Ty());
}

SensitiveLeakSan::SensitiveLeakSan(Module &ArgM)
{
    M = &ArgM;
    C = &(M->getContext());
    int LongSize = M->getDataLayout().getPointerSizeInBits();
    IntptrTy = Type::getIntNTy(*C, LongSize);
    includeThreadFuncArgShadow();
    includeElrange();
    includeSGXSanCheck();
    initSVF();
    initializeCallbacks();
    instVisitor = new SGXSanInstVisitor(*M);
}

StringRef SensitiveLeakSan::getBelongedFunctionName(SVF::PAGNode *node)
{
    if (node->hasValue())
    {
        Value *value = const_cast<Value *>(node->getValue());
        return getBelongedFunctionName(value);
    }
    else
        return "None";
}

StringRef SensitiveLeakSan::getBelongedFunctionName(Value *val)
{
    Function *func = nullptr;
    if (Instruction *I = dyn_cast<Instruction>(val))
        func = I->getFunction();
    else if (Argument *arg = dyn_cast<Argument>(val))
        func = arg->getParent();
    else
        return StringRef("None");
    return func->getName();
}

void SensitiveLeakSan::getPtrValPNs(SVF::ObjPN *objPN, std::unordered_set<SVF::ValPN *> &ptrValPNs)
{
    for (SVF::NodeID ptrValPNID : ander->getRevPts(objPN->getId()))
    {
        if (pag->hasGNode(ptrValPNID))
        {
            SVF::PAGNode *node = pag->getPAGNode(ptrValPNID);
            if (SVF::ValPN *ptrValPN = SVF::SVFUtil::dyn_cast<SVF::ValPN>(node))
            {
                if (isa<SVF::DummyValPN>(ptrValPN))
                    continue;
                Value *ptr = const_cast<Value *>(ptrValPN->getValue());
                Value *obj = const_cast<Value *>(objPN->getValue());
                if (getPointerLevel(ptr) == getPointerLevel(obj))
                {
                    ptrValPNs.emplace(ptrValPN);
                }
            }
        }
    }
}

int SensitiveLeakSan::getCallInstOperandPosition(CallInst *CI, Value *operand, bool rawOperand)
{
    for (unsigned int i = 0; i < CI->getNumOperands(); i++)
    {
        if (rawOperand ? (CI->getOperand(i) == operand) : (stripCast(CI->getOperand(i)) == operand))
        {
            return i;
        }
    }
    return -1;
}

void SensitiveLeakSan::getDirectAndIndirectCalledFunction(CallInst *CI, SmallVector<Function *> &calleeVec)
{
    Function *callee = CI->getCalledFunction();
    if (callee == nullptr)
    {
        // it's an indirect call
        for (auto indCall : callgraph->getIndCallMap())
        {
            if (indCall.first->getCallSite() == CI)
            {
                for (auto svfCallee : indCall.second)
                {
                    calleeVec.push_back(svfCallee->getLLVMFun());
                }
            }
        }
    }
    else
    {
        // it's a direct call
        calleeVec.push_back(callee);
    }
}

Instruction *SensitiveLeakSan::findInstByName(Function *F, std::string InstName)
{
    for (auto &BB : *F)
    {
        for (auto &I : BB)
        {
            if (SGXSanGetValueName(&I).str() == InstName)
            {
                return &I;
            }
        }
    }

    return nullptr;
}

void SensitiveLeakSan::setNoSanitizeMetadata(Instruction *I)
{
    unsigned int MDKindID = M->getMDKindID("nosanitize");
    MDNode *node = MDNode::get(*C, None);
    I->setMetadata(MDKindID, node);
}

// check directly with SGXSan shadow map
Value *SensitiveLeakSan::isLIPoisoned(LoadInst *LI)
{
    return isPtrPoisoned(LI, LI->getPointerOperand());
}

uint64_t SensitiveLeakSan::getTypeAllocaSize(Type *type)
{
    const DataLayout &DL = M->getDataLayout();
    TypeSize size = DL.getTypeAllocSize(type);
    return size.getFixedSize();
}

uint64_t SensitiveLeakSan::getPointerElementSize(Value *ptr)
{
    Type *type = ptr->getType();
    PointerType *ptrTy = cast<PointerType>(type);
    Type *elemTy = ptrTy->getElementType();
    return getTypeAllocaSize(elemTy);
}

Value *SensitiveLeakSan::isPtrPoisoned(Instruction *insertPoint, Value *ptr)
{
    assert(isa<PointerType>(ptr->getType()));
    IRBuilder<> IRB(insertPoint);
    return IRB.CreateCall(sgxsan_region_is_in_elrange_and_poisoned,
                          {IRB.CreatePtrToInt(ptr, IRB.getInt64Ty()),
                           IRB.getInt64(getPointerElementSize(ptr)),
                           IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG)});
}

Value *SensitiveLeakSan::isArgPoisoned(Argument *arg)
{
    Instruction &firstFuncInsertPt = *arg->getParent()->begin()->begin();
    assert(&firstFuncInsertPt != nullptr);
    IRBuilder<> IRB(&firstFuncInsertPt);
    return IRB.CreateCall(query_thread_func_arg_shadow_stack,
                          {IRB.CreatePtrToInt(arg->getParent(), IRB.getInt64Ty()),
                           IRB.getInt64(arg->getArgNo())});
}

void SensitiveLeakSan::pushAndPopArgShadowFrameAroundCallInst(CallInst *CI)
{
    // instrument push/pop_thread_func_arg_shadow_stack around CI
    if (poisonedCI.count(CI) == 0)
    {
        // instrument push_thread_func_arg_shadow_stack
        IRBuilder<> IRB(CI);
        Value *callee = CI->getCalledOperand();
        Value *calleeAddrInt = IRB.CreatePtrToInt(callee, IRB.getInt64Ty());
        IRB.CreateCall(push_thread_func_arg_shadow_stack, calleeAddrInt);

        // instrument pop_thread_func_arg_shadow_stack
        IRB.SetInsertPoint(CI->getNextNode());
        IRB.CreateCall(pop_thread_func_arg_shadow_stack, calleeAddrInt);

        // record this CI has been instrumented with push/pop_thread_func_arg_shadow_stack
        poisonedCI.emplace(CI, std::unordered_set<int>{});
    }
}

Value *SensitiveLeakSan::isCIRetPoisoned(CallInst *CI)
{
    pushAndPopArgShadowFrameAroundCallInst(CI);

    Value *callee = CI->getCalledOperand();
    IRBuilder<> IRB(CI->getNextNode());
    CallInst *queryCI = IRB.CreateCall(query_thread_func_arg_shadow_stack,
                                       {IRB.CreatePtrToInt(callee, IRB.getInt64Ty()),
                                        IRB.getInt64(-1)});
    return queryCI;
}

Value *SensitiveLeakSan::instrumentPoisonCheck(Value *val)
{
    Value *isPoisoned = nullptr;
    if (poisonCheckedValues.count(val) == 0)
    {
        // never instrumented to check whether value is poisoned
        if (LoadInst *LI = dyn_cast<LoadInst>(val))
        {
            isPoisoned = isLIPoisoned(LI);
        }
        else if (Argument *arg = dyn_cast<Argument>(val))
        {
            isPoisoned = isArgPoisoned(arg);
        }
        else if (CallInst *CI = dyn_cast<CallInst>(val))
        {
            isPoisoned = isCIRetPoisoned(CI);
        }
        else
        {
            abort();
        }
        // record this source value has been checked whether is poisoned
        poisonCheckedValues[val] = isPoisoned;
    }
    else
    {
        // return records
        isPoisoned = poisonCheckedValues[val];
    }
    return isPoisoned;
}

void SensitiveLeakSan::printSrcAtRT(IRBuilder<> &IRB, Value *src)
{
    if (LoadInst *LI = dyn_cast<LoadInst>(src))
    {
        IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr("\n" + toString(LI)),
                                   IRB.CreatePtrToInt(LI->getPointerOperand(), IRB.getInt64Ty()),
                                   IRB.getInt64(getTypeAllocaSize(LI->getType()))});
    }
    else if (Argument *arg = dyn_cast<Argument>(src))
    {
        Value *funcAddrInt = IRB.CreatePtrToInt(arg->getParent(), IRB.getInt64Ty());
        auto pos = arg->getArgNo();
        IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr("\n" + toString(arg)), funcAddrInt, IRB.getInt64(pos)});
    }
    else if (CallInst *CI = dyn_cast<CallInst>(src))
    {
        Value *funcAddrInt = IRB.CreatePtrToInt(CI->getCalledOperand(), IRB.getInt64Ty());
        auto pos = -1;
        IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr("\n" + toString(CI)), funcAddrInt, IRB.getInt64(pos)});
    }
    else
    {
        abort();
    }
}

void SensitiveLeakSan::PoisonCIOperand(Value *src, Value *isPoisoned, CallInst *CI, int operandPosition)
{
    pushAndPopArgShadowFrameAroundCallInst(CI);

    // instrument to poison argument shadow
    if (poisonedCI[CI].count(operandPosition) == 0)
    {
        IRBuilder<> IRB(CI);
        Value *callee = CI->getCalledOperand();
        Value *calleeAddrInt = IRB.CreatePtrToInt(callee, IRB.getInt64Ty());
        Instruction *poisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, CI, false);
        IRB.SetInsertPoint(poisonedTerm);
        // printSrcAtRT(IRB, src);
        // printStrAtRT(IRB, "-[" + std::to_string(operandPosition) + "th Arg]->\n");
        // IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr(toString(CI)), calleeAddrInt, IRB.getInt64(operandPosition)});
        IRB.CreateCall(poison_thread_func_arg_shadow_stack, {calleeAddrInt, IRB.getInt64(operandPosition)});
        // record this argument's shadow has been poisoned
        poisonedCI[CI].emplace(operandPosition);
    }
}

uint64_t SensitiveLeakSan::RoundUpUDiv(uint64_t dividend, uint64_t divisor)
{
    return (dividend + divisor - 1) / divisor;
}

void SensitiveLeakSan::printStrAtRT(IRBuilder<> &IRB, std::string str)
{
    IRB.CreateCall(Printf, {StrSpeicifier, IRB.CreateGlobalStringPtr(str)});
}

void SensitiveLeakSan::PoisonSI(Value *src, Value *isPoisoned, StoreInst *SI)
{
    if (poisonedInst.count(SI) == 0)
    {
        Instruction *srcIsPoisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, SI, false);

        IRBuilder<> IRB(srcIsPoisonedTerm);
        Value *dstPtr = SI->getPointerOperand();
        Value *dstPtrInt = IRB.CreatePtrToInt(dstPtr, IRB.getInt64Ty());
        assert(not isa<Function>(dstPtr));
        CallInst *isDestInElrange = IRB.CreateCall(is_addr_in_elrange_ex, {dstPtrInt, IRB.getInt64(getPointerElementSize(dstPtr))});

        Instruction *destIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, srcIsPoisonedTerm, false);

        IRB.SetInsertPoint(destIsInElrangeTerm);
        uint64_t dstMemSize = getTypeAllocaSize(SI->getValueOperand()->getType());
        Value *dstMemSizeVal = IRB.getInt64(dstMemSize);
        // printSrcAtRT(IRB, src);
        // printStrAtRT(IRB, "-[Store]->\n");
        // IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr(toString(SI)), dstPtrInt, dstMemSizeVal});
        IRB.CreateCall(__sgxsan_poison_valid_shadow, {dstPtrInt, dstMemSizeVal, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG)});
        // PoisonObject(dstPtr, dstMemSizeVal, IRB, SGXSAN_SENSITIVE_OBJ_FLAG);
        // cleanStackObjectSensitiveShadow(dstPtr);
        poisonedInst.emplace(SI);
    }
}

void SensitiveLeakSan::PoisonRetShadow(Value *src, Value *isPoisoned, ReturnInst *calleeRI)
{
    if (poisonedInst.count(calleeRI) == 0)
    {
        Instruction *isPoisonedTerm = SplitBlockAndInsertIfThen(isPoisoned, calleeRI, false);
        IRBuilder<> IRB(isPoisonedTerm);
        Value *calleeAddrInt = IRB.CreatePtrToInt(calleeRI->getFunction(), IRB.getInt64Ty());
        // printSrcAtRT(IRB, src);
        // printStrAtRT(IRB, "-[Return]->\n");
        // IRB.CreateCall(print_arg, {IRB.CreateGlobalStringPtr(toString(calleeRI)), calleeAddrInt, IRB.getInt64(-1)});
        IRB.CreateCall(poison_thread_func_arg_shadow_stack, {calleeAddrInt, IRB.getInt64(-1)});
        poisonedInst.emplace(calleeRI);
    }
}

void SensitiveLeakSan::addPtObj2WorkList(Value *ptr)
{
    assert(ptr->getType()->isPointerTy());
    assert(getPointerLevel(ptr) == 1);
    assert(not isa<Function>(ptr));
    std::unordered_set<SVF::ObjPN *> objPNs;
    getNonPointerObjPNs(ptr, objPNs);
    for (auto objPN : objPNs)
    {
        if (ProcessedList.count(objPN) == 0)
            WorkList.emplace(objPN);
    }
}

void SensitiveLeakSan::PoisonObject(Value *objPtr, Value *objSize, IRBuilder<> &IRB, uint8_t poisonValue)
{
    assert(objPtr->getType()->isPointerTy());
    Value *shadowAddr = memToShadowPtr(objPtr, IRB);
    objSize = IRB.CreateIntCast(objSize, IRB.getInt64Ty(), false);
    Value *shadowSpan = RoundUpUDiv(IRB, objSize, SHADOW_GRANULARITY);
    Value *shadowSpanMinusOne = IRB.CreateSub(shadowSpan, IRB.getInt64(1));
    CallInst *memsetCI = IRB.CreateMemSet(shadowAddr, IRB.getInt8(poisonValue), shadowSpanMinusOne, MaybeAlign());
    setNoSanitizeMetadata(memsetCI);

    Value *lastShadowBytePtr = IRB.CreateIntToPtr(IRB.CreateAdd(IRB.CreatePtrToInt(shadowAddr, IRB.getInt64Ty()), shadowSpanMinusOne), IRB.getInt8PtrTy());
    LoadInst *lastShadowByte = IRB.CreateLoad(lastShadowBytePtr);
    setNoSanitizeMetadata(lastShadowByte);
    Value *validShadow = IRB.CreateICmpULT(lastShadowByte, IRB.getInt8(0x8));
    StoreInst *lastShadowByteSI = IRB.CreateStore(IRB.CreateSelect(validShadow,
                                                                   IRB.CreateAdd(lastShadowByte, IRB.getInt8(poisonValue)),
                                                                   IRB.getInt8(poisonValue)),
                                                  lastShadowBytePtr);
    setNoSanitizeMetadata(lastShadowByteSI);
}

/* void SensitiveLeakSan::cleanStackObjectSensitiveShadow(SVF::ObjPN *objPN)
{
    if (isa<SVF::DummyObjPN>(objPN) || isFunctionObjPN(objPN))
        return;
    Value *obj = const_cast<Value *>(objPN->getValue());
    if (cleanedStackObjs.count(obj) == 0)
    {
        if (AllocaInst *AI = dyn_cast<AllocaInst>(obj))
        {
            SGXSanInstVisitor visitor(*AI->getFunction());
            SmallVector<llvm::ReturnInst *> ReturnInstVec;
            visitor.getRetInstVec(ReturnInstVec);
            for (ReturnInst *RI : ReturnInstVec)
            {
                IRBuilder<> IRB(RI);
                Value *objSize = IRB.getInt64(getTypeAllocaSize(AI->getAllocatedType()));
                IRB.CreateCall(__sgxsan_poison_valid_shadow, {IRB.CreatePtrToInt(AI, IRB.getInt64Ty()),
                                                              objSize, IRB.getInt8(0x0)});
                // PoisonObject(AI, objSize, IRB, 0x0);
                cleanedStackObjs.emplace(obj);
            }
        }
    }
}

void SensitiveLeakSan::cleanStackObjectSensitiveShadow(Value *obj)
{
    auto pts = ander->getPts(pag->getValueNode(obj));
    // for (auto objPNID : pts)
    // {
    //     SVF::ObjPN *objPN = cast<SVF::ObjPN>(pag->getPAGNode(objPNID));
    //     errs() << getBelongedFunctionName(objPN) << " "
    //            << (objPN->hasValue()
    //                    ? SGXSanGetValueName(const_cast<Value *>(objPN->getValue()))
    //                    : "")
    //            << " ";
    //     objPN->dump();
    // }
    // inter-procedure situation may have multi point-tos
    for (auto objPNID : pts)
    {
        SVF::ObjPN *objPN = cast<SVF::ObjPN>(pag->getPAGNode(objPNID));
        cleanStackObjectSensitiveShadow(objPN);
    }
} */

void SensitiveLeakSan::propagateShadowInMemTransfer(CallInst *CI, Instruction *insertPoint, Value *destPtr, Value *srcPtr, Value *size)
{
    assert(not isa<Function>(destPtr));
    assert(CI != nullptr);
    if (processedMemTransferInst.count(CI) == 0)
    {
        // current memory transfer instruction has never been instrumented

        // we have to avoid 0-size in mem transfer call
        IRBuilder<> IRB(insertPoint);
        size = IRB.CreateIntCast(size, IRB.getInt64Ty(), false);
        Instruction *term = SplitBlockAndInsertIfThen(IRB.CreateICmpNE(size, IRB.getInt64(0)), insertPoint, false);
        IRB.SetInsertPoint(term);

        Value *isSrcPoisoned = isPtrPoisoned(term, srcPtr);

        Instruction *sourceIsPoisonedTerm = SplitBlockAndInsertIfThen(isSrcPoisoned, term, false);

        IRB.SetInsertPoint(sourceIsPoisonedTerm);
        Value *dstPtrInt = IRB.CreatePtrToInt(destPtr, IRB.getInt64Ty());
        CallInst *isDestInElrange = IRB.CreateCall(is_addr_in_elrange_ex, {dstPtrInt, IRB.getInt64(getPointerElementSize(destPtr))});

        Instruction *dstIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, sourceIsPoisonedTerm, false);

        IRB.SetInsertPoint(dstIsInElrangeTerm);
        // IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr("\n" + toString(srcPtr)),
        //                            IRB.CreatePtrToInt(srcPtr, IRB.getInt64Ty()),
        //                            IRB.CreateIntCast(size, IRB.getInt64Ty(), false)});
        // printStrAtRT(IRB, "-[Mem Transfer]->\n");
        // IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr(toString(destPtr)),
        //                            dstPtrInt,
        //                            IRB.CreateIntCast(size, IRB.getInt64Ty(), false)});

        // there is a situation that small-size src memory copied to large-size dst memory
        // so directly copy shadow of src to dst may cause problem
        // PoisonObject(destPtr, size, IRB, SGXSAN_SENSITIVE_OBJ_FLAG);
        IRB.CreateCall(__sgxsan_poison_valid_shadow, {dstPtrInt, size, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG)});
        // Instruction *memcpyCI = IRB.CreateMemCpy(memToShadowPtr(destPtr, IRB), MaybeAlign(),
        //                                          memToShadowPtr(srcPtr, IRB), MaybeAlign(),
        //                                          RoundUpUDiv(IRB, size, SHADOW_GRANULARITY));
        // setNoSanitizeMetadata(memcpyCI);
        addPtObj2WorkList(destPtr);
        // cleanStackObjectSensitiveShadow(destPtr);
        // record this memory transfer CI has been instrumented
        processedMemTransferInst.emplace(CI);
    }
}

bool SensitiveLeakSan::isMemsetS(CallInst *CI)
{
    Function *callee = CI->getCalledFunction();
    if (callee)
    {
        StringRef calleeName = callee->getName();
        if (calleeName.equals("memset_s"))
        {
            return true;
        }
    }
    return false;
}

bool SensitiveLeakSan::isSecureVersionMemTransferCI(CallInst *CI)
{
    Function *callee = CI->getCalledFunction();
    if (callee)
    {
        StringRef calleeName = callee->getName();
        if (calleeName.equals("memcpy_s") ||
            calleeName.equals("memmove_s"))
        {
            return true;
        }
    }
    return false;
}

void SensitiveLeakSan::doVFA(Value *work)
{
    for (User *user : work->users())
    {
        if (LoadInst *LI = dyn_cast<LoadInst>(user))
        {
            propagateShadow(LI);
        }
        else if (CallInst *CI = dyn_cast<CallInst>(user))
        {
            MemTransferInst *MTI = dyn_cast<MemTransferInst>(user);
            if (MTI && MTI->getRawSource() == work)
            {
                propagateShadowInMemTransfer(MTI, MTI->getNextNode(), MTI->getDest(),
                                             MTI->getSource(), MTI->getOperand(2));
            }
            else if (isSecureVersionMemTransferCI(CI) && CI->getOperand(2) == work)
            {
                propagateShadowInMemTransfer(CI, CI->getNextNode(),
                                             CI->getOperand(0), CI->getOperand(2),
                                             CI->getOperand(1));
            }
            else
            {
                Function *callee = CI->getCalledFunction();
                if (callee && callee->getName().contains("llvm.ptr.annotation"))
                {
                    doVFA(CI);
                }
            }
        }
    }
}

void SensitiveLeakSan::getNonCastUsers(Value *value, std::vector<User *> &users)
{
    for (User *user : value->users())
    {
        if (CastInst *CastI = dyn_cast<CastInst>(user))
        {
            getNonCastUsers(CastI, users);
        }
        else
        {
            users.push_back(user);
        }
    }
}

void SensitiveLeakSan::PoisonMemsetDst(Value *src, Value *isSrcPoisoned, CallInst *MSI, Value *dstPtr, Value *setSize)
{
    if (poisonedInst.count(MSI) == 0)
    {
        Instruction *srcIsPoisonedTerm = SplitBlockAndInsertIfThen(isSrcPoisoned, MSI, false);
        IRBuilder<> IRB(srcIsPoisonedTerm);
        Value *dstPtrInt = IRB.CreatePtrToInt(dstPtr, IRB.getInt64Ty());
        assert(not isa<Function>(dstPtr));
        CallInst *isDestInElrange = IRB.CreateCall(is_addr_in_elrange_ex, {dstPtrInt, setSize});

        Instruction *destIsInElrangeTerm = SplitBlockAndInsertIfThen(isDestInElrange, srcIsPoisonedTerm, false);

        IRB.SetInsertPoint(destIsInElrangeTerm);
        // printSrcAtRT(IRB, src);
        // printStrAtRT(IRB, "-[Memset]->\n");
        // IRB.CreateCall(print_ptr, {IRB.CreateGlobalStringPtr(toString(MSI)), dstPtrInt, setSize});
        IRB.CreateCall(__sgxsan_poison_valid_shadow, {dstPtrInt, setSize, IRB.getInt8(SGXSAN_SENSITIVE_OBJ_FLAG)});
        // PoisonObject(dstPtr, setSize, IRB, SGXSAN_SENSITIVE_OBJ_FLAG);
        // cleanStackObjectSensitiveShadow(dstPtr);
        poisonedInst.emplace(MSI);
    }
}

void SensitiveLeakSan::propagateShadow(Value *src)
{
    // src maybe 'Function Argument'/LoadInst/'Return Value of CallInst'
    std::vector<User *> srcUsers;
    getNonCastUsers(src, srcUsers);
    for (User *srcUser : srcUsers)
    {
        if (isa<StoreInst>(srcUser) || isa<CallInst>(srcUser) || isa<ReturnInst>(srcUser))
        {
            // there is a value flow, then check whether src is poisoned(at runtime)
            Value *isSrcPoisoned = instrumentPoisonCheck(src);
            if (StoreInst *SI = dyn_cast<StoreInst>(srcUser))
            {
                assert(stripCast(SI->getValueOperand()) == src);
                PoisonSI(src, isSrcPoisoned, SI);
                addPtObj2WorkList(SI->getPointerOperand());
            }
            else if (CallInst *CI = dyn_cast<CallInst>(srcUser))
            {
                if (MemSetInst *MSI = dyn_cast<MemSetInst>(CI))
                {
                    if (stripCast(MSI->getArgOperand(1)) == src)
                    {
                        PoisonMemsetDst(src, isSrcPoisoned, MSI, MSI->getArgOperand(0), MSI->getArgOperand(2));
                        addPtObj2WorkList(MSI->getArgOperand(0));
                    }
                }
                else if (isMemsetS(CI))
                {
                    if (stripCast(CI->getArgOperand(2)) == src)
                    {
                        IRBuilder<> IRB(CI);
                        Value *setSize = IRB.CreateSelect(IRB.CreateICmpSLT(CI->getArgOperand(1), CI->getArgOperand(3)), CI->getArgOperand(1), CI->getArgOperand(3));
                        PoisonMemsetDst(src, isSrcPoisoned, CI, CI->getArgOperand(0), setSize);
                        addPtObj2WorkList(CI->getArgOperand(0));
                    }
                }
                else
                {
                    llvm::SmallVector<Function *> calleeVec;
                    getDirectAndIndirectCalledFunction(CI, calleeVec);
                    for (Function *callee : calleeVec)
                    {
                        if (callee->isDeclaration() || isEncryptionFunction(callee))
                            continue;
                        int opPos = getCallInstOperandPosition(CI, src);
                        assert(opPos != -1);
                        PoisonCIOperand(src, isSrcPoisoned, CI, opPos);
                        if (!callee->isVarArg())
                        {
                            auto arg = callee->getArg(opPos);
                            if (getPointerLevel(arg) == getPointerLevel(src))
                            {
                                propagateShadow(arg);
                            }
                        }
                    }
                }
            }
            else if (ReturnInst *RI = dyn_cast<ReturnInst>(srcUser))
            {
                assert(stripCast(RI->getOperand(0)) == src);
                Function *callee = RI->getFunction();
                for (auto callInstToCallGraphEdges : callgraph->getCallInstToCallGraphEdgesMap())
                {
                    for (auto callGraphEdge : callInstToCallGraphEdges.second)
                    {
                        if (callGraphEdge->getDstNode()->getFunction()->getLLVMFun() == callee)
                        {
                            CallInst *callerCI = cast<CallInst>(const_cast<Instruction *>(callInstToCallGraphEdges.first->getCallSite()));
                            PoisonRetShadow(src, isSrcPoisoned, RI);
                            propagateShadow(callerCI);
                        }
                    }
                }
            }
        }
    }
}

bool SensitiveLeakSan::runOnModule()
{

    collectAndPoisonSensitiveObj(*M);

    for (auto objPN : SensitiveObjs)
    {
        dump(objPN);
    }

    WorkList = this->SensitiveObjs;
    while (!WorkList.empty())
    {
        // update work status
        SVF::ObjPN *workObjPN = *WorkList.begin();
        Value *work = const_cast<Value *>(workObjPN->getValue());
        WorkList.erase(WorkList.begin());
        ProcessedList.emplace(workObjPN);

        std::unordered_set<SVF::ValPN *> ptrValPNs;
        getPtrValPNs(workObjPN, ptrValPNs);

        // errs() << "============== Show point-to set ==============\n";
        // dump(workObjPN);
        // errs() << "-----------------------------------------------\n";

        for (auto ptrValPN : ptrValPNs)
        {
            // dump(ptrValPN);
            doVFA(const_cast<Value *>(ptrValPN->getValue()));
        }
        // errs() << "========= End of showing point-to set ==========\n";
    }
    return true;
}

void SensitiveLeakSan::dumpPts(SVF::PAGNode *PN)
{
    for (SVF::NodeID nodeID : ander->getPts(PN->getId()))
    {
        pag->getPAGNode(nodeID)->dump();
    }
}

void SensitiveLeakSan::dumpRevPts(SVF::PAGNode *PN)
{
    for (SVF::NodeID nodeID : ander->getRevPts(PN->getId()))
    {
        if (pag->hasGNode(nodeID))
        {
            pag->getPAGNode(nodeID)->dump();
        }
    }
}

StringRef SensitiveLeakSan::SGXSanGetPNName(SVF::PAGNode *PN)
{
    if (PN->hasValue())
    {
        return SGXSanGetValueName(const_cast<Value *>(PN->getValue()));
    }
    else
        return "None";
}

std::string SensitiveLeakSan::toString(SVF::PAGNode *PN)
{
    std::stringstream ss;
    ss << "Func: " << getBelongedFunctionName(PN).str() << "; Name: " << SGXSanGetPNName(PN).str() << "; " << PN->toString();
    return ss.str();
}

std::string SensitiveLeakSan::toString(Value *val)
{
    std::string str;
    raw_string_ostream str_ostream(str);
    val->print(str_ostream, true);
    std::stringstream ss;
    ss << "Func: " << getBelongedFunctionName(val).str() << "; Name: " << SGXSanGetValueName(val).str() << "\n"
       << str;
    return ss.str();
}

void SensitiveLeakSan::dump(SVF::PAGNode *PN)
{
    errs() << toString(PN) << "\n";
}

void SensitiveLeakSan::dump(Value *val)
{
    errs() << toString(val) << "\n";
}

bool SensitiveLeakSan::isFunctionObjPN(SVF::PAGNode *PN)
{
    if (PN->hasValue())
    {
        Value *obj = const_cast<Value *>(PN->getValue());
        return isa<Function>(obj);
    }
    else
        return false;
}