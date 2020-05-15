#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizer.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include<vector>


using namespace std;
using namespace llvm;



namespace {

  struct SkeletonPass : public FunctionPass {
    static char ID;
    SkeletonPass() : FunctionPass(ID) {}


    virtual bool runOnFunction(Function &F) {
     if(F.getName()=="add_cov"||F.getName()=="_xmalloc"||F.getName()=="xfree"||F.getName()=="mem_to_shadow"||F.getName()=="mem_to_mem_shadow"||F.getName()=="mem_to_hp_flag_shadow"||F.getName()=="report_action"||F.getName()=="report_xasan"||F.getName()=="willInject"||F.getName()=="mark_write_flag"||F.getName()=="mark_write_flag_r"||F.getName()=="mark_hp_flag"||F.getName()=="mark_hp_flag_r"||F.getName()=="mark_valid"||F.getName()=="mark_invalid"||F.getName()=="enter_func"||F.getName()=="leave_func"||F.getName()=="memcpy"||F.getName()=="printk"||F.getName()=="vprintk_common"||F.getName()=="_spin_lock_recursive"||F.getName()=="_spin_lock"||F.getName()=="_spin_lock_cb"||F.getName()=="vsnprintf"){
	  return false;
     }

     LLVMContext &context = F.getParent()->getContext();

     int LongSize = F.getParent()->getDataLayout().getPointerSizeInBits();
     Type* IntptrTy = Type::getIntNTy(context, LongSize);

     int flag=0;

      for (auto &BB : F) {
        for (auto &Inst : BB) {
	   if(LooksLikeCodeInBug11395(&Inst)){
		return false;
	   }
        }
      }
      for (auto &BB : F) {
        for (auto &Inst : BB) {
	    if(flag==0){
		    //insert enter func
		    flag=1;
		    IRBuilder<> builder(&BB);
		    FunctionType *type = FunctionType::get(Type::getVoidTy(context), {Type::getInt8PtrTy(context), Type::getInt8PtrTy(context)}, false);
		    auto callee = BB.getModule()->getOrInsertFunction("enter_func", type);

		    GlobalVariable* name= builder.CreateGlobalString(F.getName());
		    GlobalVariable* file= builder.CreateGlobalString(F.getParent()->getSourceFileName());

		    CallInst::Create(callee, {name,file}, "",&Inst);

		}

          bool IsWrite;
          uint64_t TypeSize;
          unsigned Alignment;
          if(isInterestingMemoryAccess(&Inst,&IsWrite,&TypeSize,&Alignment)){
            IRBuilder<> builder(&BB);

            FunctionType *type = FunctionType::get(Type::getVoidTy(context), {Type::getInt8PtrTy(context),Type::getInt64Ty(context),Type::getInt64Ty(context)}, false);
            auto callee = BB.getModule()->getOrInsertFunction("report_xasan", type);


            ConstantInt *size = builder.getInt64(TypeSize/8);
            ConstantInt *iswrite = builder.getInt64(1);
            ConstantInt *isread = builder.getInt64(0);

            Value* addr=IsWrite?Inst.getOperand(1):Inst.getOperand(0);

            if(IsWrite)
                CallInst::Create(callee, {addr,size,iswrite}, "",&Inst);
            else
                CallInst::Create(callee, {addr,size,isread}, "",&Inst);
              }

      if (ReturnInst *RI = dyn_cast<ReturnInst>(&Inst)) {

            // insert leave func
            FunctionType *type = FunctionType::get(Type::getVoidTy(context), {Type::getVoidTy(context)}, false);
            auto callee = BB.getModule()->getOrInsertFunction("leave_func", type);
            CallInst::Create(callee, {}, "",&Inst);
      }
	}

    }

 
      return false;

    }
	bool LooksLikeCodeInBug11395(Instruction *I) {
	  CallInst *CI = dyn_cast<CallInst>(I);
	  if (!CI || !CI->isInlineAsm()) return false;
	  // We have inline assembly with quite a few arguments.
	  return true;
	}

    Value * isInterestingMemoryAccess(Instruction *I,
                                                      bool *IsWrite,
                                                      uint64_t *TypeSize,
                                                      unsigned *Alignment
                                                      ) {
      Value *PtrOperand = nullptr;
      const DataLayout &DL = I->getModule()->getDataLayout();
      if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
        *IsWrite = false;
        *TypeSize = DL.getTypeStoreSizeInBits(LI->getType());
        *Alignment = LI->getAlignment();
        PtrOperand = LI->getPointerOperand();
      } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
        *IsWrite = true;
        *TypeSize = DL.getTypeStoreSizeInBits(SI->getValueOperand()->getType());
        *Alignment = SI->getAlignment();
        PtrOperand = SI->getPointerOperand();
      } else if (AtomicRMWInst *RMW = dyn_cast<AtomicRMWInst>(I)) {
        *IsWrite = true;
        *TypeSize = DL.getTypeStoreSizeInBits(RMW->getValOperand()->getType());
        *Alignment = 0;
        PtrOperand = RMW->getPointerOperand();
      } else if (AtomicCmpXchgInst *XCHG = dyn_cast<AtomicCmpXchgInst>(I)) {
        *IsWrite = true;
        *TypeSize = DL.getTypeStoreSizeInBits(XCHG->getCompareOperand()->getType());
        *Alignment = 0;
        PtrOperand = XCHG->getPointerOperand();
      } else if (auto CI = dyn_cast<CallInst>(I)) {
        auto *F = dyn_cast<Function>(CI->getCalledValue());
        if (F && (F->getName().startswith("llvm.masked.load.") ||
                  F->getName().startswith("llvm.masked.store."))) {
          unsigned OpOffset = 0;
          if (F->getName().startswith("llvm.masked.store.")) {
            // Masked store has an initial operand for the value.
            OpOffset = 1;
            *IsWrite = true;
          } else {
            *IsWrite = false;
          }

          auto BasePtr = CI->getOperand(0 + OpOffset);
          auto Ty = cast<PointerType>(BasePtr->getType())->getElementType();
          *TypeSize = DL.getTypeStoreSizeInBits(Ty);
          if (auto AlignmentConstant =
                  dyn_cast<ConstantInt>(CI->getOperand(1 + OpOffset)))
            *Alignment = (unsigned)AlignmentConstant->getZExtValue();
          else
            *Alignment = 1; // No alignment guarantees. We probably got Undef
          PtrOperand = BasePtr;
        }
      }

      if (PtrOperand) {
        // Do not instrument acesses from different address spaces; we cannot deal
        // with them.
        Type *PtrTy = cast<PointerType>(PtrOperand->getType()->getScalarType());
        if (PtrTy->getPointerAddressSpace() != 0)
          return nullptr;

        // Ignore swifterror addresses.
        // swifterror memory addresses are mem2reg promoted by instruction
        // selection. As such they cannot have regular uses like an instrumentation
        // function and it makes no sense to track them as memory.
        if (PtrOperand->isSwiftError())
          return nullptr;
      }
      if (auto AI = dyn_cast_or_null<AllocaInst>(PtrOperand))
	      return isInterestingAlloca(*AI) ? AI : nullptr;

      return PtrOperand;
    }
    bool isInterestingAlloca(const AllocaInst &AI) {
	  bool IsInteresting =
	      (AI.getAllocatedType()->isSized() &&
	       // alloca() may be called with 0 size, ignore it.
	       ((!AI.isStaticAlloca()) || getAllocaSizeInBytes(AI) > 0) &&
	       // We are only interested in allocas not promotable to registers.
	       // Promotable allocas are common under -O0.
	       (!isAllocaPromotable(&AI)) &&
	       // inalloca allocas are not treated as static, and we don't want
	       // dynamic alloca instrumentation for them as well.
	       !AI.isUsedWithInAlloca() &&
	       // swifterror allocas are register promoted by ISel
	       !AI.isSwiftError());
	  return IsInteresting;
    }

  uint64_t getAllocaSizeInBytes(const AllocaInst &AI) const {
    uint64_t ArraySize = 1;
    if (AI.isArrayAllocation()) {
      const ConstantInt *CI = dyn_cast<ConstantInt>(AI.getArraySize());
      assert(CI && "non-constant array size");
      ArraySize = CI->getZExtValue();
    }
    Type *Ty = AI.getAllocatedType();
    uint64_t SizeInBytes =
        AI.getModule()->getDataLayout().getTypeAllocSize(Ty);
    return SizeInBytes * ArraySize;
  }



  };
}

char SkeletonPass::ID = 0;

static void registerSkeletonPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new SkeletonPass());
}
static RegisterStandardPasses
  RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                 registerSkeletonPass);
