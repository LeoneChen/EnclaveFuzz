#pragma once

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_map>

namespace llvm {

static inline Function *getCalledFunctionStripPointerCast(CallInst *CallI) {
  if (Function *callee = CallI->getCalledFunction()) {
    return callee;
  } else if (Value *calledOp = CallI->getCalledOperand()) {
    if (auto callee = dyn_cast<Function>(calledOp->stripPointerCasts())) {
      return callee;
    }
  }
  return nullptr;
}

static inline StringRef getDirectCalleeName(Value *value) {
  if (auto CI = dyn_cast<CallInst>(value)) {
    if (auto callee = getCalledFunctionStripPointerCast(CI)) {
      return callee->getName();
    }
  }
  return "";
}

static inline SmallVector<User *> getNonCastUsers(Value *value) {
  SmallVector<User *> users;
  for (User *user : value->users()) {
    if (CastInst *CastI = dyn_cast<CastInst>(user)) {
      users.append(getNonCastUsers(CastI));
    } else {
      users.push_back(user);
    }
  }
  return users;
}

static inline bool hasCmpUser(Value *val) {
  for (auto user : getNonCastUsers(val)) {
    auto I = dyn_cast<Instruction>(user);
    if (I && (I->getOpcode() == Instruction::ICmp ||
              I->getOpcode() == Instruction::FCmp)) {
      return true;
    }
  }
  return false;
}

struct VisitInfo {
  SmallVector<ReturnInst *> ReturnInstVec;
  SmallVector<Instruction *> BroadReturnInstVec;
  SmallVector<CallInst *> CallInstVec;
  std::unordered_map<AllocaInst *, SmallVector<IntrinsicInst *>>
      AILifeTimeStart, AILifeTimeEnd;
};

class SGXSanInstVisitor {
public:
  VisitInfo &visitBasicBlock(BasicBlock &BB) {
    if (BasicBlockVisitInfoMap.count(&BB) == 0) {
      VisitInfo &info = BasicBlockVisitInfoMap[&BB];
      for (auto &I : BB) {
        if (auto RetI = dyn_cast<ReturnInst>(&I)) {
          info.ReturnInstVec.push_back(RetI);
          info.BroadReturnInstVec.push_back(RetI);
        } else if (auto ResumeI = dyn_cast<ResumeInst>(&I)) {
          info.BroadReturnInstVec.push_back(ResumeI);
        } else if (auto CleanupReturnI = dyn_cast<CleanupReturnInst>(&I)) {
          info.BroadReturnInstVec.push_back(CleanupReturnI);
        } else if (auto CallI = dyn_cast<CallInst>(&I)) {
          info.CallInstVec.push_back(CallI);

          auto IntrinsicI = dyn_cast<IntrinsicInst>(CallI);
          if (IntrinsicI) {
            auto IntrinsicID = IntrinsicI->getIntrinsicID();
            if (IntrinsicID == Intrinsic::lifetime_start) {
              // it's a lifetime_start IntrinsicInst
              AllocaInst *AllocaI =
                  findAllocaForValue(IntrinsicI->getArgOperand(1), true);
              if (AllocaI)
                info.AILifeTimeStart[AllocaI].push_back(IntrinsicI);
            } else if (IntrinsicID == Intrinsic::lifetime_end) {
              // it's a lifetime_end IntrinsicInst
              AllocaInst *AllocaI =
                  findAllocaForValue(IntrinsicI->getArgOperand(1), true);
              if (AllocaI)
                info.AILifeTimeEnd[AllocaI].push_back(IntrinsicI);
            }
          }
        }
      }
    }
    return BasicBlockVisitInfoMap[&BB];
  }

  VisitInfo &visitFunction(Function &F) {
    if (FunctionVisitInfoMap.count(&F) == 0) {
      auto &FVisitInfo = FunctionVisitInfoMap[&F];
      for (auto &BB : F) {
        auto &BBVisitInfo = visitBasicBlock(BB);
        for (auto pair : BBVisitInfo.AILifeTimeStart) {
          FVisitInfo.AILifeTimeStart[pair.first].append(pair.second);
        }
        for (auto pair : BBVisitInfo.AILifeTimeEnd) {
          FVisitInfo.AILifeTimeEnd[pair.first].append(pair.second);
        }
        FVisitInfo.BroadReturnInstVec.append(BBVisitInfo.BroadReturnInstVec);
        FVisitInfo.ReturnInstVec.append(BBVisitInfo.ReturnInstVec);
        FVisitInfo.CallInstVec.append(BBVisitInfo.CallInstVec);
      }
    }
    return FunctionVisitInfoMap[&F];
  }

  VisitInfo &visitModule(Module &M) {
    if (ModuleVisitInfoMap.count(&M) == 0) {
      auto &MVisitInfo = ModuleVisitInfoMap[&M];
      for (auto &F : M) {
        auto &FVisitInfo = visitFunction(F);
        for (auto pair : FVisitInfo.AILifeTimeStart) {
          MVisitInfo.AILifeTimeStart[pair.first].append(pair.second);
        }
        for (auto pair : FVisitInfo.AILifeTimeEnd) {
          MVisitInfo.AILifeTimeEnd[pair.first].append(pair.second);
        }
        MVisitInfo.BroadReturnInstVec.append(FVisitInfo.BroadReturnInstVec);
        MVisitInfo.ReturnInstVec.append(FVisitInfo.ReturnInstVec);
        MVisitInfo.CallInstVec.append(FVisitInfo.CallInstVec);
      }
    }
    return ModuleVisitInfoMap[&M];
  }

private:
  std::map<BasicBlock *, VisitInfo> BasicBlockVisitInfoMap;
  std::map<Function *, VisitInfo> FunctionVisitInfoMap;
  std::map<Module *, VisitInfo> ModuleVisitInfoMap;
};

} // namespace llvm
