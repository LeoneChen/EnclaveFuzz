#include <fstream>
#include <string>
#include <tuple>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "DriverGen.h"

using namespace llvm;
using json = nlohmann::json;

static cl::opt<std::string>
    ClEdlJsonFile("edl-json",
                  cl::desc("Path of *.edl.json generated by EdlParser.py"),
                  cl::Hidden);

static cl::opt<bool>
    ClEnableFillAtOnce("enable-fill-at-once", cl::init(true),
                       cl::desc("Enable fill parameter data at once for pure "
                                "data that don't contain pointer in subfield"),
                       cl::Hidden);

enum GetByteType {
  FUZZ_STRING,
  FUZZ_WSTRING,
  FUZZ_DATA,
  FUZZ_ARRAY,
  FUZZ_SIZE,
  FUZZ_COUNT,
  FUZZ_RET,
  FUZZ_STRUCT
};

void DriverGenerator::initialize(Module &M) {
  this->M = &M;
  C = &M.getContext();
  IRBuilder<> IRB(*C);

  // add function declaration
  getFuzzDataPtr = M.getOrInsertFunction(
      "get_bytes", Type::getInt8PtrTy(*C), Type::getInt64Ty(*C),
      Type::getInt8PtrTy(*C), Type::getInt32Ty(*C));
  getUserCheckCount = M.getOrInsertFunction("get_count", Type::getInt64Ty(*C),
                                            Type::getInt64Ty(*C) /* ele size */,
                                            Type::getInt8PtrTy(*C));
  _strlen = M.getOrInsertFunction("strlen", Type::getInt64Ty(*C),
                                  Type::getInt8PtrTy(*C));
  _wcslen = M.getOrInsertFunction("wcslen", Type::getInt64Ty(*C),
                                  Type::getInt32PtrTy(*C));
  whetherSetNullPointer = M.getOrInsertFunction(
      "is_null_pointer", Type::getInt1Ty(*C), Type::getInt8PtrTy(*C));
  DFJoinID = M.getOrInsertFunction(
      "DFJoinID", Type::getInt8PtrTy(*C), Type::getInt8PtrTy(*C),
      Type::getInt8PtrTy(*C), Type::getInt8PtrTy(*C));
  DFGetInstanceID =
      M.getOrInsertFunction("DFGetInstanceID", Type::getInt8PtrTy(*C),
                            Type::getInt8PtrTy(*C), Type::getInt64Ty(*C));
  DFManagedMalloc = M.getOrInsertFunction(
      "DFManagedMalloc", Type::getInt8PtrTy(*C), Type::getInt64Ty(*C));

  GStr0 = IRB.CreateGlobalStringPtr("0", "GStr0", 0, this->M);
  GStrField = IRB.CreateGlobalStringPtr("field", "GStrField", 0, this->M);
  GNullInt8Ptr = Constant::getNullValue(Type::getInt8PtrTy(*C));

  // read *.edl.json file
  auto fileBuffer = MemoryBuffer::getFile(ClEdlJsonFile);
  if (auto EC = fileBuffer.getError()) {
    errs() << "Can't open " << ClEdlJsonFile << ": " << EC.message() << "\n";
    abort();
  }
  edlJson = json::parse(fileBuffer->get()->getBuffer());
}

// FOR_LOOP may change insert point of IRBuilder
#define FOR_LOOP_BEG(insert_point, count)                                      \
  Instruction *forBodyTerm = SplitBlockAndInsertIfThen(                        \
      IRB.CreateICmpSGT(count, IRB.getInt64(0), ""), insert_point, false);     \
  IRB.SetInsertPoint(forBodyTerm);                                             \
  PHINode *phi = IRB.CreatePHI(IRB.getInt64Ty(), 2, "");                       \
  phi->addIncoming(IRB.getInt64(0), forBodyTerm->getParent()->getPrevNode());  \
  BasicBlock *forBodyEntry = phi->getParent();

#define FOR_LOOP_END(count)                                                    \
  /*  instrumentParameterCheck may insert new bb, so forBodyTerm may not       \
   * belong to forBodyEntry BB */                                              \
  IRB.SetInsertPoint(forBodyTerm);                                             \
  Value *inc = IRB.CreateAdd(phi, IRB.getInt64(1), "", true, true);            \
  phi->addIncoming(inc, forBodyTerm->getParent());                             \
  ReplaceInstWithInst(                                                         \
      forBodyTerm, BranchInst::Create(forBodyEntry,                            \
                                      forBodyTerm->getParent()->getNextNode(), \
                                      IRB.CreateICmpSLT(inc, count)));

// propagate [in]/[out]/[user_check] to it's element
void DriverGenerator::inheritDirectionAttr(json::json_pointer jsonPtr,
                                           size_t field_index) {
  if (edlJson[jsonPtr / "field"].is_null()) {
    edlJson[jsonPtr / "field"] = json::object();
  }
  if (edlJson[jsonPtr / "field" / field_index].is_null()) {
    edlJson[jsonPtr / "field" / field_index] = json::object();
  }
  if (edlJson[jsonPtr / "user_check"] == true) {
    edlJson[jsonPtr / "field" / field_index / "user_check"] = true;
  }
  if (edlJson[jsonPtr / "in"] == true) {
    edlJson[jsonPtr / "field" / field_index / "in"] = true;
  }
  if (edlJson[jsonPtr / "out"] == true) {
    edlJson[jsonPtr / "field" / field_index / "out"] = true;
  }
  if (edlJson[jsonPtr / "isOCallRet"] == true) {
    edlJson[jsonPtr / "field" / field_index / "isOCallRet"] = true;
  }
}

json::json_pointer DriverGenerator::getRootPtr(json::json_pointer jsonPtr) {
  json::json_pointer parentPtr = jsonPtr.parent_pointer();
  while (not parentPtr.empty()) {
    jsonPtr = parentPtr;
    parentPtr = parentPtr.parent_pointer();
  }
  return jsonPtr;
}

bool DriverGenerator::isECallPtr(json::json_pointer jsonPtr) {
  auto rootPtr = getRootPtr(jsonPtr);
  if (rootPtr.to_string() == "/trusted")
    return true;
  else if (rootPtr.to_string() == "/untrusted")
    return false;
  else
    abort();
}

bool DriverGenerator::whetherFeedRandom(json::json_pointer jsonPtr) {
  bool isEcall = isECallPtr(jsonPtr);
  bool feedRandom = isEcall;
  if (edlJson[jsonPtr / "user_check"] == true)
    feedRandom = true;
  else if (isEcall) {
    if (edlJson[jsonPtr / "in"] == true)
      feedRandom = true;
    else if (edlJson[jsonPtr / "out"] == true)
      feedRandom = false;
  } else {
    if (edlJson[jsonPtr / "out"] == true)
      feedRandom = true;
    else if (edlJson[jsonPtr / "in"] == true)
      feedRandom = false;
  }
  return feedRandom;
}

void DriverGenerator::dump(json js, json::json_pointer jsonPtr) {
  dbgs() << jsonPtr.to_string() << "\n" << js[jsonPtr].dump(4) << "\n";
}

void DriverGenerator::dataCopy(Value *dstPtr, Value *srcPtr, Type *type,
                               Instruction *insertPt, Value *arrCnt) {
  assert(dstPtr && srcPtr && type && insertPt &&
         dstPtr->getType()->isPointerTy() && srcPtr->getType()->isPointerTy());
  IRBuilder<> IRB(insertPt);
  if (type->isAggregateType() or arrCnt) {
    Value *tySize = ConstantExpr::getSizeOf(type);
    if (arrCnt)
      tySize = IRB.CreateMul(tySize, arrCnt);
    IRB.CreateMemCpy(dstPtr, MaybeAlign(), srcPtr, MaybeAlign(), tySize);
  } else {
    srcPtr = IRB.CreatePointerCast(srcPtr, type->getPointerTo());
    dstPtr = IRB.CreatePointerCast(dstPtr, type->getPointerTo());
    IRB.CreateStore(IRB.CreateLoad(type, srcPtr), dstPtr);
  }
}

GlobalVariable *DriverGenerator::CreateZeroInitizerGlobal(StringRef Name,
                                                          Type *Ty) {
  auto GV = cast<GlobalVariable>(M->getOrInsertGlobal(Name, Ty));
  GV->setInitializer(ConstantAggregateZero::get(Ty));
  return GV;
}

Value *DriverGenerator::createParamContent(
    SmallVector<Type *> types, json::json_pointer jsonPtr, Value *parentID,
    Value *currentID, std::map<uint64_t, Value *> *paramPtrs,
    Instruction *insertPt, size_t recursion_depth) {
  recursion_depth++;
  // get index from json pointer
  size_t idx =
      jsonPtr.back() == "return" ? 0 : std::stoull(jsonPtr.back(), nullptr, 0);
  // we may have prepared this param in other rounds
  if (paramPtrs && paramPtrs->count(idx)) {
    return (*paramPtrs)[idx];
  }
  // show current edl info in json
  // dump(edlJson, jsonPtr);
  // get current type
  auto type = types[idx];
  // prepare a pointer to store content
  IRBuilder<> IRB(&insertPt->getFunction()->front().front());
  Value *typePtr = IRB.CreateAlloca(type);
  IRB.SetInsertPoint(insertPt);
  // use json pointer as node ID
  auto jsonPtrAsID =
      IRB.CreateCall(DFJoinID, {parentID, currentID, GNullInt8Ptr}, "id");
  // we have labelled all data belonged to [in]/[out]/[user_check] pointer with
  // same attribute label If it's not labelled, then set default true
  bool feedRandom = whetherFeedRandom(jsonPtr);
  // process type case by case, and store content to generated pointer
  if (auto pointerTy = dyn_cast<PointerType>(type)) {
    inheritDirectionAttr(jsonPtr, 0);
    // get element size and type
    auto eleTy = pointerTy->getElementType();
    StructType *eleSt = dyn_cast<StructType>(eleTy);
    if (eleSt and eleSt->isOpaque()) {
      // replace opaque struct type with uint8
      eleTy = Type::getInt8Ty(*C);
    }
    if (eleTy->isFunctionTy() or recursion_depth >= 10) {
      // feed callback with nullptr
      IRB.CreateStore(Constant::getNullValue(pointerTy), typePtr);
    } else {
      size_t _eleSize = M->getDataLayout().getTypeAllocSize(eleTy);
      assert(_eleSize > 0);
      auto eleSize = IRB.getInt64(_eleSize);
      Value *contentPtr = nullptr;
      // if it's a string, directly fill it
      if (edlJson[jsonPtr / "string"] == true or
          edlJson[jsonPtr / "wstring"] == true) {
        // [string/wstring] must exist with [in]
        assert(eleTy->isIntegerTy() and edlJson[jsonPtr / "in"] == true);
        contentPtr = IRB.CreatePointerCast(
            IRB.CreateCall(getFuzzDataPtr,
                           {IRB.getInt64(0), jsonPtrAsID,
                            IRB.getInt32(edlJson[jsonPtr / "string"] == true
                                             ? FUZZ_STRING
                                             : FUZZ_WSTRING)}),
            pointerTy);
      } else {
        // calculate count of elements the pointer point to
        Value *ptCnt = nullptr;
        // EDL: c array can't be decorated with [count]/[size], and must have
        // it's count
        if (edlJson[jsonPtr / "c_array_count"].is_number()) {
          size_t _c_array_count = edlJson[jsonPtr / "c_array_count"];
          if (_c_array_count <= 0) {
            errs() << "c_array_count must > 0\n";
            abort();
          }
          ptCnt = IRB.getInt64(_c_array_count);
        } else if (edlJson[jsonPtr / "user_check"] == true) {
          ptCnt = IRB.CreateCall(getUserCheckCount, {eleSize, jsonPtrAsID});
        } else {
          Value *count = nullptr, *size = nullptr;
          if (edlJson[jsonPtr / "count"].is_null()) {
            count = IRB.getInt64(1);
          } else if (edlJson[jsonPtr / "count"].is_number()) {
            count = IRB.getInt64(edlJson[jsonPtr / "count"]);
          } else {
            size_t co_param_pos = edlJson[jsonPtr / "count" / "co_param_pos"];
            edlJson[jsonPtr.parent_pointer() / co_param_pos /
                    "isEdlCountAttr"] = true;
            auto co_param_ptr = createParamContent(
                types, jsonPtr.parent_pointer() / co_param_pos, parentID,
                IRB.CreateGlobalStringPtr(std::to_string(co_param_pos)),
                paramPtrs, insertPt, recursion_depth - 1);
            IRB.SetInsertPoint(insertPt);
            count = IRB.CreateLoad(co_param_ptr->getType()
                                       ->getScalarType()
                                       ->getPointerElementType(),
                                   co_param_ptr);
          }
          if (edlJson[jsonPtr / "size"].is_null()) {
            size = eleSize;
          } else if (edlJson[jsonPtr / "size"].is_number()) {
            // means "size" bytes
            size_t _size = edlJson[jsonPtr / "size"];
            size = IRB.getInt64(_size);
            if (eleTy->isIntegerTy() && _size <= 8) {
              // we can regard it as (size*8)bits integer
              _eleSize = _size;
              eleTy = IRB.getIntNTy(_size * 8);
              eleSize = IRB.getInt64(_size);
            }
          } else {
            size_t co_param_pos = edlJson[jsonPtr / "size" / "co_param_pos"];
            edlJson[jsonPtr.parent_pointer() / co_param_pos / "isEdlSizeAttr"] =
                true;
            auto co_param_ptr = createParamContent(
                types, jsonPtr.parent_pointer() / co_param_pos, parentID,
                IRB.CreateGlobalStringPtr(std::to_string(co_param_pos)),
                paramPtrs, insertPt, recursion_depth - 1);
            IRB.SetInsertPoint(insertPt);
            size = IRB.CreateLoad(co_param_ptr->getType()
                                      ->getScalarType()
                                      ->getPointerElementType(),
                                  co_param_ptr);
          }
          ptCnt = IRB.CreateUDiv(IRB.CreateMul(size, count), eleSize);
          // Maybe size*count < eleSize, due to problem of Enclave developer
          ptCnt = IRB.CreateSelect(IRB.CreateICmpSGT(ptCnt, IRB.getInt64(1)),
                                   ptCnt, IRB.getInt64(1), "ptCnt");
        }

        if (ptCnt == IRB.getInt64(1)) {
          contentPtr = createParamContent(
              {eleTy}, jsonPtr / "field" / 0,
              IRB.CreateCall(DFJoinID, {parentID, currentID, GStrField}), GStr0,
              nullptr, insertPt, recursion_depth);
        } else {
          assert(M->getDataLayout().getTypeAllocSize(eleTy) == _eleSize);
          contentPtr = IRB.CreatePointerCast(
              IRB.CreateCall(
                  DFManagedMalloc,
                  {IRB.CreateMul(
                      IRB.getInt64(M->getDataLayout().getTypeAllocSize(eleTy)),
                      ptCnt)}),
              eleTy->getPointerTo());
          if (!ClEnableFillAtOnce or hasPointerElement(pointerTy)) {
            // fall back
            FOR_LOOP_BEG(insertPt, ptCnt)
            auto innerInsertPt = &*IRB.GetInsertPoint();
            auto elePtr = createParamContent(
                {eleTy}, jsonPtr / "field" / 0,
                IRB.CreateCall(DFJoinID, {parentID, currentID, GStrField}),
                IRB.CreateCall(DFGetInstanceID, {GStr0, phi}), nullptr,
                innerInsertPt, recursion_depth);
            IRB.SetInsertPoint(innerInsertPt);
            dataCopy(IRB.CreateGEP(eleTy, contentPtr, phi), elePtr, eleTy,
                     innerInsertPt);
            FOR_LOOP_END(ptCnt)
          } else if (feedRandom) {
            fillAtOnce(contentPtr, jsonPtr, jsonPtrAsID, insertPt, eleTy,
                       ptCnt);
          }
        }
      }
      IRB.SetInsertPoint(insertPt);
      IRB.CreateStore(IRB.CreatePointerCast(contentPtr, pointerTy), typePtr);
      if (feedRandom) {
        // we call function to query whether fill pointer with meaningful
        // address or not
        Instruction *term = SplitBlockAndInsertIfThen(
            IRB.CreateCall(whetherSetNullPointer, jsonPtrAsID), insertPt,
            false);
        IRB.SetInsertPoint(term);
        IRB.CreateStore(Constant::getNullValue(pointerTy), typePtr);
      }
    }
  } else if (auto structTy = dyn_cast<StructType>(type)) {
    if (!ClEnableFillAtOnce or hasPointerElement(structTy)) {
      // fall back
      // structure's member pointers may have size/count attributes(deep copy),
      // so we have to prepare a map to record everything
      std::map<uint64_t, Value *> preparedSubFieldParamPtrs;
      for (size_t index = 0; index < structTy->getNumElements(); index++) {
        inheritDirectionAttr(jsonPtr, index);
        auto elePtr = createParamContent(
            SmallVector<Type *>{structTy->elements().begin(),
                                structTy->elements().end()},
            jsonPtr / "field" / index,
            IRB.CreateCall(DFJoinID, {parentID, currentID, GStrField}),
            IRB.CreateGlobalStringPtr(std::to_string(index)),
            &preparedSubFieldParamPtrs, insertPt, recursion_depth);
        IRB.SetInsertPoint(insertPt);
        auto eleTy = elePtr->getType()->getPointerElementType();
        dataCopy(IRB.CreateGEP(type, typePtr,
                               {IRB.getInt32(0), IRB.getInt32(index)}),
                 elePtr, eleTy, insertPt);
      }
    } else if (feedRandom) {
      fillAtOnce(typePtr, jsonPtr, jsonPtrAsID, insertPt);
    }
  } else if (auto arrTy = dyn_cast<ArrayType>(type)) {
    inheritDirectionAttr(jsonPtr, 0);
    auto eleTy = arrTy->getElementType();
    auto eleCnt = IRB.getInt64(arrTy->getNumElements());
    if (!ClEnableFillAtOnce or hasPointerElement(arrTy)) {
      // fall back
      FOR_LOOP_BEG(insertPt, eleCnt)
      auto innerInsertPt = &*IRB.GetInsertPoint();
      auto elePtr = createParamContent(
          {eleTy}, jsonPtr / "field" / 0,
          IRB.CreateCall(DFJoinID, {parentID, currentID, GStrField}),
          IRB.CreateCall(DFGetInstanceID, {GStr0, phi}), nullptr, innerInsertPt,
          recursion_depth);
      IRB.SetInsertPoint(innerInsertPt);
      dataCopy(IRB.CreateGEP(type, typePtr, {IRB.getInt32(0), phi}), elePtr,
               eleTy, innerInsertPt);
      FOR_LOOP_END(eleCnt)
    } else if (feedRandom) {
      fillAtOnce(typePtr, jsonPtr, jsonPtrAsID, insertPt);
    }
  } else if (feedRandom) {
    assert(not isa<VectorType>(type) and not isa<FunctionType>(type));
    fillAtOnce(typePtr, jsonPtr, jsonPtrAsID, insertPt);
  }

  if (paramPtrs)
    (*paramPtrs)[idx] = typePtr;
  return typePtr;
}

void DriverGenerator::fillAtOnce(Value *dstPtr, json::json_pointer jsonPtr,
                                 Value *jsonPtrAsID, Instruction *insertPt,
                                 Type *type, Value *arrCnt, bool isOcall) {
  assert(dstPtr && insertPt && dstPtr->getType()->isPointerTy());
  if (type == nullptr)
    type = dstPtr->getType()->getPointerElementType();
  IRBuilder<> IRB(insertPt);
  size_t _tySize = M->getDataLayout().getTypeAllocSize(type);
  assert(_tySize > 0);
  Value *tySize = IRB.getInt64(_tySize);
  GetByteType byteType = edlJson[jsonPtr / "isEdlSizeAttr"] == true ? FUZZ_SIZE
                         : edlJson[jsonPtr / "isEdlCountAttr"] == true
                             ? FUZZ_COUNT
                         : edlJson[jsonPtr / "isOCallRet"] == true ? FUZZ_RET
                         : (isa<ArrayType>(type) or arrCnt)        ? FUZZ_ARRAY
                         : isa<StructType>(type)                   ? FUZZ_DATA
                                                                   : FUZZ_DATA;
  if (arrCnt) {
    tySize = IRB.CreateMul(tySize, arrCnt);
  }
  Value *fuzzDataPtr = IRB.CreateCall(
      getFuzzDataPtr, {tySize, jsonPtrAsID, IRB.getInt32(byteType)});
  dataCopy(dstPtr, fuzzDataPtr, type, insertPt, arrCnt);
}

bool DriverGenerator::hasPointerElement(Type *type) {
  if (typeHasPointerMap.count(type))
    return typeHasPointerMap[type];
  bool result = _hasPointerElement(type);
  typeHasPointerMap[type] = result;
  return result;
}

bool DriverGenerator::_hasPointerElement(Type *type, size_t level) {
  bool result = false;
  // start from 1
  level++;
  if (auto ptrTy = dyn_cast<PointerType>(type)) {
    result =
        level == 1 ? _hasPointerElement(ptrTy->getElementType(), level) : true;
  } else if (auto structTy = dyn_cast<StructType>(type)) {
    for (auto eleTy : structTy->elements()) {
      if (_hasPointerElement(eleTy, level)) {
        result = true;
        break;
      }
    }
  } else if (auto arrTy = dyn_cast<ArrayType>(type)) {
    result = _hasPointerElement(arrTy->getElementType(), level);
  }
  // don't prepare data for function type as well
  return result;
}

Function *DriverGenerator::createEcallFuzzWrapperFunc(std::string ecallName) {
  // create empty fuzz_ecall_xxx() function
  auto ecallToBeFuzzed = M->getFunction(ecallName);
  assert(ecallToBeFuzzed && M->getFunction("fuzz_" + ecallName) == nullptr);
  auto ecallFuzzWrapperFunc =
      M->getOrInsertFunction("fuzz_" + ecallName, Type::getInt32Ty(*C));
  auto EntryBB = BasicBlock::Create(
      *C, "", cast<Function>(ecallFuzzWrapperFunc.getCallee()));
  auto retVoidI = ReturnInst::Create(*C, EntryBB);

  // start to fill code
  std::map<uint64_t, Value *> preparedParamPtrs;
  // 1. get all parameter types and return paramter(ECall will use pointer of
  // return as second parameter, while the first parameter is Enclave ID), in
  // case of corelative parameter's preparation
  SmallVector<Type *> paramTypes;
  Argument *returnParamPtrArg = nullptr;
  for (auto &arg : ecallToBeFuzzed->args()) {
    if (arg.getArgNo() == 0)
      // it's eid parameter
      continue;
    else if (arg.getArgNo() == 1 &&
             (edlJson["trusted"][ecallName]["return"]["type"] != "void"))
      // it's pointer of return parameter
      returnParamPtrArg = &arg;
    else
      paramTypes.push_back(arg.getType());
  }
  // 2. prepare all parameters, and save their pointer
  size_t edlParamNo = 0;
  for (auto &arg : ecallToBeFuzzed->args()) {
    auto argNo = arg.getArgNo();
    if (argNo == 0 /* it's eid parameter */ or
        (argNo == 1 && (edlJson["trusted"][ecallName]["return"]["type"] !=
                        "void")) /* it's pointer of return parameter */)
      continue;
    else {
      // it's a parameter declareted at edl file
      json::json_pointer jsonPtr = json::json_pointer("/trusted") / ecallName /
                                   "parameter" / edlParamNo++;
      IRBuilder<> IRB(*C);
      Value *parentID = IRB.CreateGlobalStringPtr(
                jsonPtr.parent_pointer().to_string(), "", 0, M),
            *currentID = IRB.CreateGlobalStringPtr(jsonPtr.back(), "", 0, M);
      createParamContent(paramTypes, jsonPtr, parentID, currentID,
                         &preparedParamPtrs, retVoidI);
    }
  }
  // 3. prepare Enclave ID parameter
  auto eid = cast<GlobalVariable>(
      M->getOrInsertGlobal("global_eid", Type::getInt64Ty(*C)));
  eid->setLinkage(GlobalValue::ExternalLinkage);
  IRBuilder<> IRB(retVoidI);
  SmallVector<Value *> preparedParams = {
      IRB.CreateLoad(Type::getInt64Ty(*C), eid)};
  // 4. prepare return parameter
  if (returnParamPtrArg) {
    edlJson[json::json_pointer("/trusted") / ecallName / "return" / "out"] =
        true;
    json::json_pointer jsonPtr =
        json::json_pointer("/trusted") / ecallName / "return";
    IRBuilder<> IRB(*C);
    Value *parentID = IRB.CreateGlobalStringPtr(
              jsonPtr.parent_pointer().to_string(), "", 0, M),
          *currentID = IRB.CreateGlobalStringPtr(jsonPtr.back(), "", 0, M);
    auto returnParamPtr =
        createParamContent({returnParamPtrArg->getType()}, jsonPtr, parentID,
                           currentID, nullptr, retVoidI);
    IRB.SetInsertPoint(retVoidI);
    preparedParams.push_back(IRB.CreateLoad(
        returnParamPtr->getType()->getScalarType()->getPointerElementType(),
        returnParamPtr));
  }
  // 5. get prepared parameters from their pointers
  for (size_t argPos = 0; argPos < preparedParamPtrs.size(); argPos++) {
    preparedParams.push_back(IRB.CreateLoad(preparedParamPtrs[argPos]
                                                ->getType()
                                                ->getScalarType()
                                                ->getPointerElementType(),
                                            preparedParamPtrs[argPos]));
  }
  // 6. call ECall
  auto callEcall = IRB.CreateCall(ecallToBeFuzzed, preparedParams);
  IRB.CreateRet(callEcall);
  retVoidI->eraseFromParent();
  return cast<Function>(ecallFuzzWrapperFunc.getCallee());
}

// create content for ocall [out] pointer parameters
void DriverGenerator::saveCreatedInput2OCallPtrParam(Function *ocallFunc,
                                                     Instruction *insertPt) {
  auto ocallName = ocallFunc->getName().str();
  for (auto &arg : ocallFunc->args()) {
    auto idx = arg.getArgNo();
    if (auto pointerTy = dyn_cast<PointerType>(arg.getType())) {
      json::json_pointer jsonPtr("/untrusted/" + ocallName + "/parameter/" +
                                 std::to_string(idx));
      Value *parentID = nullptr, *currentID = nullptr;
      {
        IRBuilder<> IRB(*C);
        parentID = IRB.CreateGlobalStringPtr(
            jsonPtr.parent_pointer().to_string(), "", 0, M);
        currentID = IRB.CreateGlobalStringPtr(jsonPtr.back(), "", 0, M);
      }
      if (edlJson[jsonPtr / "out"] == true or
          edlJson[jsonPtr / "user_check"] == true) {
        // dump(edlJson, jsonPtr);
        inheritDirectionAttr(jsonPtr, 0);
        IRBuilder<> IRB(insertPt);
        auto jsonPtrAsID =
            IRB.CreateCall(DFJoinID, {parentID, currentID, GNullInt8Ptr});
        auto eleTy = pointerTy->getElementType();
        StructType *eleSt = dyn_cast<StructType>(eleTy);
        if (eleSt and eleSt->isOpaque()) {
          // replace opaque struct type with uint8
          eleTy = Type::getInt8Ty(*C);
        }
        assert(M->getDataLayout().getTypeAllocSize(eleTy) > 0);
        auto eleSize = IRB.getInt64(M->getDataLayout().getTypeAllocSize(eleTy));
        // if it's a string, directly fill it
        if (edlJson[jsonPtr / "string"] == true or
            edlJson[jsonPtr / "wstring"] == true) {
          // [string/wstring] must exist with [in]
          assert(eleTy->isIntegerTy() and edlJson[jsonPtr / "in"] == true);
          Value *fuzzDataPtr = IRB.CreatePointerCast(
              IRB.CreateCall(getFuzzDataPtr,
                             {IRB.getInt64(0), jsonPtrAsID,
                              IRB.getInt32(edlJson[jsonPtr / "string"] == true
                                               ? FUZZ_STRING
                                               : FUZZ_WSTRING)}),
              pointerTy);
          Value *charCnt = IRB.CreateCall(
              edlJson[jsonPtr / "string"] == true ? _strlen : _wcslen,
              fuzzDataPtr);
          IRB.CreateMemCpy(&arg, MaybeAlign(), fuzzDataPtr, MaybeAlign(),
                           IRB.CreateMul(eleSize, charCnt));
        } else {
          // calculate count of elements the pointer point to
          Value *ptCnt = nullptr;
          // EDL: c array can't be decorated with [count]/[size], and must have
          // it's count
          if (edlJson[jsonPtr / "c_array_count"].is_number()) {
            ptCnt = IRB.getInt64(edlJson[jsonPtr / "c_array_count"]);
          } else if (edlJson[jsonPtr / "user_check"] == true) {
            ptCnt = IRB.CreateCall(getUserCheckCount, {eleSize, jsonPtrAsID});
          } else {
            auto _count = edlJson[jsonPtr / "count"],
                 _size = edlJson[jsonPtr / "size"];
            Value *count = _count.is_null() ? IRB.getInt64(1)
                           : _count.is_number()
                               ? cast<Value>(IRB.getInt64(_count))
                               : IRB.CreateIntCast(
                                     ocallFunc->getArg(_count["co_param_pos"]),
                                     Type::getInt64Ty(*C), false);
            Value *size = nullptr;
            if (_size.is_null()) {
              size = eleSize;
            } else if (_size.is_number()) {
              // means "size" bytes
              size_t num_size = _size;
              size = IRB.getInt64(num_size);
              if (eleTy->isIntegerTy() && num_size <= 8) {
                // we can regard it as (size*8)bits integer
                eleTy = IRB.getIntNTy(num_size * 8);
                eleSize = IRB.getInt64(num_size);
              }
            } else {
              size = IRB.CreateIntCast(ocallFunc->getArg(_size["co_param_pos"]),
                                       Type::getInt64Ty(*C), false);
            }
            ptCnt = IRB.CreateUDiv(IRB.CreateMul(size, count), eleSize);
          }
          if (ptCnt == IRB.getInt64(1)) {
            Value *elePtr = createParamContent(
                {eleTy}, jsonPtr / "field" / 0,
                IRB.CreateCall(DFJoinID, {parentID, currentID, GStrField}),
                GStr0, nullptr, insertPt);
            IRB.SetInsertPoint(insertPt);
            elePtr = IRB.CreatePointerCast(elePtr, pointerTy);
            dataCopy(&arg, elePtr, eleTy, insertPt);
          } else {
            if (!ClEnableFillAtOnce or hasPointerElement(pointerTy)) {
              // fall back
              FOR_LOOP_BEG(insertPt, ptCnt)
              auto innerInsertPt = &*IRB.GetInsertPoint();
              auto elePtr = createParamContent(
                  {eleTy}, jsonPtr / "field" / 0,
                  IRB.CreateCall(DFJoinID, {parentID, currentID, GStrField}),
                  IRB.CreateCall(DFGetInstanceID, {GStr0, phi}), nullptr,
                  innerInsertPt);
              IRB.SetInsertPoint(innerInsertPt);
              dataCopy(
                  IRB.CreateGEP(
                      arg.getType()->getScalarType()->getPointerElementType(),
                      &arg, phi),
                  elePtr, eleTy, innerInsertPt);
              FOR_LOOP_END(ptCnt)
            } else {
              fillAtOnce(&arg, jsonPtr, jsonPtrAsID, insertPt, eleTy, ptCnt,
                         true);
            }
          }
        }
      }
    }
  }
}

void DriverGenerator::createOcallFunc(std::string ocallName) {
  // create empty ocall_xxx() function when it's only a declaration
  auto ocallFunc = M->getFunction(ocallName);
  if (not ocallFunc->isDeclaration())
    return;
  ocallFunc->setLinkage(GlobalValue::WeakAnyLinkage);
  auto EntryBB = BasicBlock::Create(*C, "", ocallFunc);
  // create return instruction
  IRBuilder<> IRB(EntryBB);
  auto retVoidI = IRB.CreateRetVoid();
  auto funcRetType = ocallFunc->getReturnType();
  ReturnInst *retI = nullptr;
  if (funcRetType->isVoidTy()) {
    retI = retVoidI;
  } else {
    auto jsonPtr = json::json_pointer("/untrusted") / ocallName / "return";
    Value *parentID = IRB.CreateGlobalStringPtr(
              jsonPtr.parent_pointer().to_string(), "", 0, M),
          *currentID = IRB.CreateGlobalStringPtr(jsonPtr.back(), "", 0, M);
    edlJson[jsonPtr / "out"] = true;
    edlJson[jsonPtr / "isOCallRet"] = true;
    auto retValuePtr = createParamContent({funcRetType}, jsonPtr, parentID,
                                          currentID, nullptr, retVoidI);
    IRB.SetInsertPoint(retVoidI);
    auto retVal = IRB.CreateLoad(
        retValuePtr->getType()->getScalarType()->getPointerElementType(),
        retValuePtr);
    retI = IRB.CreateRet(retVal);
    retVoidI->eraseFromParent();
  }
  retVoidI = nullptr;

  saveCreatedInput2OCallPtrParam(ocallFunc, retI);
}

void DriverGenerator::passStaticAnalysisResultToRuntime(
    SmallVector<Constant *> &ecallFuzzWrapperFuncs) {
  IRBuilder<> IRB(*C);

  // create a global int to store number of ecall
  auto _ecallNum = edlJson["trusted"].size();
  auto ecallNum = cast<GlobalVariable>(
      M->getOrInsertGlobal("sgx_fuzzer_ecall_num", Type::getInt32Ty(*C)));
  ecallNum->setInitializer(ConstantInt::get(IRB.getInt32Ty(), _ecallNum));

  // create a global array to store all ecall fuzz wrappers
  auto ecallFuzzWrapperFuncPtrArrayType = ArrayType::get(
      FunctionType::get(IRB.getInt32Ty(), false)->getPointerTo(), _ecallNum);
  auto globalEcallFuzzWrappers = cast<GlobalVariable>(M->getOrInsertGlobal(
      "sgx_fuzzer_ecall_array", ecallFuzzWrapperFuncPtrArrayType));
  globalEcallFuzzWrappers->setInitializer(ConstantArray::get(
      ecallFuzzWrapperFuncPtrArrayType, ecallFuzzWrapperFuncs));

  // create a global array of string to store names of all ecall fuzz wrappers
  auto ecallFuzzWrapperNameArrTy =
      ArrayType::get(IRB.getInt8PtrTy(), _ecallNum);
  auto globalEcallFuzzWrapperNameArr =
      cast<GlobalVariable>(M->getOrInsertGlobal(
          "sgx_fuzzer_ecall_wrapper_name_array", ecallFuzzWrapperNameArrTy));
  SmallVector<Constant *> wrapperNames;
  for (auto fuzzWrapper : ecallFuzzWrapperFuncs) {
    wrapperNames.push_back(IRB.CreateGlobalStringPtr(
        cast<Function>(fuzzWrapper)->getName(), "", 0, M));
  }
  globalEcallFuzzWrapperNameArr->setInitializer(
      ConstantArray::get(ecallFuzzWrapperNameArrTy, wrapperNames));
}

bool DriverGenerator::runOnModule(Module &M) {
  bool isAtUBridge = false;
  for (auto &GV : M.globals()) {
    if (GV.getName().contains("ocall_table_")) {
      isAtUBridge = true;
      break;
    }
  }
  if (not isAtUBridge) {
    // dbgs() << M.getName() << " isn't a UBridge\n";
    return false;
  }
  dbgs() << M.getName() << " is a UBridge, start generating...\n";
  initialize(M);

  // create wrapper functions used to fuzz ecall
  SmallVector<Constant *> ecallFuzzWrapperFuncs;
  for (auto &ecallInfo : edlJson["trusted"].items()) {
    ecallFuzzWrapperFuncs.push_back(
        createEcallFuzzWrapperFunc(ecallInfo.key()));
  }

  // create ocalls
  for (auto &ocallInfo : edlJson["untrusted"].items()) {
    createOcallFunc(ocallInfo.key());
  }
  // at the end
  passStaticAnalysisResultToRuntime(ecallFuzzWrapperFuncs);
  return true;
}
