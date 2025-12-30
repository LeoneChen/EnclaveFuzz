#include "LLVMStructTypeSerialize.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <string>
#include <unordered_map>

using ordered_json = nlohmann::ordered_json;
using namespace llvm;

std::string GetTypeName(const Type *ty) {
  std::string str;
  raw_string_ostream ss(str);
  ty->print(ss, false, true);
  return str;
}

namespace TypeSerialize {
void Serializer::RecGetTypeJson(ordered_json &json, const Type *ty) {
  json["Type"] = GetTypeName(ty);
  if (auto pointerTy = dyn_cast<PointerType>(ty)) {
    json["Kind"] = "Pointer";
    auto eleTy = pointerTy->getElementType();
    if (eleTy->isFunctionTy()) {
      json["IsFunctionPointer"] = true;
    } else if (pointerTy->isOpaque()) {
      abort();
      json["IsOpaque"] = true;
    }
    RecGetTypeJson(json["Element"]["0"], eleTy);
  } else if (auto structTy = dyn_cast<StructType>(ty)) {
    if (structTy->isOpaque()) {
      json["IsOpaque"] = true;
    }
    json["Kind"] = "Struct";
    // Not expend element of struct
  } else if (auto arrTy = dyn_cast<ArrayType>(ty)) {
    json["Kind"] = "Array";
    json["Count"] = arrTy->getNumElements();
    RecGetTypeJson(json["Element"]["0"], arrTy->getElementType());
  } else {
    if (ty->isFunctionTy()) {
      json["IsFunction"] = true;
    }
    json["Kind"] = "Primitive";
  }
}

void Serializer::SerializeStructType(StructType *structTy, ordered_json &json) {
  auto structName = GetTypeName(structTy);
  if (StringRef(structName).startswith("\%struct.anon") ||
      StringRef(structName).startswith("\%union.anon")) {
    return;
  }
  for (size_t idx = 0; idx < structTy->getNumElements(); idx++) {
    RecGetTypeJson(json[structName][std::to_string(idx)],
                   structTy->getElementType(idx));
  }
}

void DeSerializer::init(LLVMContext *C, const ordered_json &TypeJson) {
  this->C = C;
  mTypeJson = TypeJson;
  mStr2Type.clear();
  mStr2Type = std::unordered_map<std::string, Type *>{
      {"void", Type::getVoidTy(*C)},

      {"i1", Type::getInt1Ty(*C)},
      {"i8", Type::getInt8Ty(*C)},
      {"i16", Type::getInt16Ty(*C)},
      {"i32", Type::getInt32Ty(*C)},
      {"i64", Type::getInt64Ty(*C)},
      {"i128", Type::getInt128Ty(*C)},

      {"half", Type::getHalfTy(*C)},
      {"bfloat", Type::getBFloatTy(*C)},
      {"float", Type::getFloatTy(*C)},
      {"double", Type::getDoubleTy(*C)},
      {"fp128", Type::getFP128Ty(*C)},
      {"x86_fp80", Type::getX86_FP80Ty(*C)},
      {"ppc_fp128", Type::getPPC_FP128Ty(*C)},

      {"x86_amx", Type::getX86_AMXTy(*C)},

      {"x86_mmx", Type::getX86_MMXTy(*C)},

      {"label", Type::getLabelTy(*C)},

      {"token", Type::getTokenTy(*C)},

      {"metadata", Type::getMetadataTy(*C)},
  };
}

void DeSerializer::ResolveOpaqueStruct(StructType *OpaqueStructTy) {
  if (not OpaqueStructTy->isOpaque()) {
    return;
  }
  std::string OpaqueStructName = OpaqueStructTy->getName().str();
  ordered_json OpaqueStructTyJson = mTypeJson[OpaqueStructName];
  if (OpaqueStructTyJson.is_null() or OpaqueStructTyJson.size() == 0) {
    // There is no information, don't change
  } else {
    // dbgs() << OpaqueStructTyJson.dump(4) << "\n";
    SmallVector<Type *, 10> ElementTypes;
    for (size_t i = 0; i < OpaqueStructTyJson.size(); i++) {
      ElementTypes.push_back(GetType(OpaqueStructTyJson[std::to_string(i)]));
    }
    OpaqueStructTy->setBody(ElementTypes);
    // OpaqueStructTy->dump();
  }
}

Type *DeSerializer::GetType(ordered_json &json) {
  std::string typeKind = json["Kind"];
  if (typeKind == "Pointer") {
    return PointerType::get(GetType(json["Element"]["0"]), 0);
  } else if (typeKind == "Struct") {
    std::string StructTyName = json["Type"];
    auto structTy = StructType::getTypeByName(*C, StructTyName);
    if (structTy == nullptr) {
      structTy = StructType::create(*C, StructTyName);
      ResolveOpaqueStruct(structTy);
    }
    return structTy;
  } else if (typeKind == "Array") {
    size_t arrCnt = json["Count"];
    return ArrayType::get(GetType(json["Element"]["0"]), arrCnt);
  } else if (typeKind == "Primitive") {
    std::string primTyName = json["Type"];
    const std::regex iNPattern = std::regex("i([0-9]+)");
    std::smatch iNMatch;
    bool IsFunction = false;
    if (not json["IsFunction"].is_null() and json["IsFunction"] == true) {
      IsFunction = true;
    }
    if (mStr2Type.count(primTyName)) {
      return mStr2Type[primTyName];
    } else if (IsFunction) {
      return FunctionType::get(Type::getVoidTy(*C), false);
    } else if (std::regex_match(primTyName, iNMatch, iNPattern)) {
      std::string NStr = iNMatch[1];
      unsigned int N = std::stoul(NStr, 0, 0);
      return Type::getIntNTy(*C, N);
    } else {
      errs() << "TODO: Need to process " << primTyName << "\n";
      abort();
    }
  } else {
    abort();
  }
}
} // namespace TypeSerialize