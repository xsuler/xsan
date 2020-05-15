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
#include <fstream>
using namespace llvm;
namespace {
  struct SkeletonPass : public FunctionPass {
    static char ID;
    SkeletonPass() : FunctionPass(ID) {}

    virtual bool runOnFunction(Function &F) {
        if (F.getName() == "func_df" ||F.getName() == "_xmalloc_c" ||F.getName() == "_xmalloc" ||F.getName() == "xfree" ||F.getName() == "do_unset_cov_array" ||F.getName() == "do_set_cov_array" ||F.getName() == "add_cov" || F.getName()=="mem_to_shadow"||F.getName()=="report_action"||F.getName()=="report_xasan"||F.getName()=="willInject"||F.getName()=="mark_write_flag"||F.getName()=="mark_write_flag_r"||F.getName()=="mark_hp_flag"||F.getName()=="mark_hp_flag_r"||F.getName()=="mark_valid"||F.getName()=="mark_invalid"||F.getName()=="enter_func"||F.getName()=="leave_func"||F.getName()=="memcpy"||F.getName()=="printk"||F.getName()=="vprintk_common"||F.getName()=="_spin_lock_recursive"||F.getName()=="_spin_lock"||F.getName()=="_spin_lock_cb"||F.getName()=="vsnprintf")
        {
            return false;
        }
        LLVMContext &context = F.getParent()->getContext();
        for (Function::iterator I = F.begin(), E=F.end(); I != E; ++I)
        {
            BasicBlock &BB = *I;
            if (Instruction *BI = BB.getTerminator()  ){  
              insertFunc(BB, BI, context);
              std::ofstream fileof;
              fileof.open("/root/coverfile",std::ios_base::app);
              fileof<<F.getParent()->getSourceFileName()<<"\n";
              fileof.close(); 
            } 
        }
        return false;
    }
 
    void insertFunc(BasicBlock &BB, Instruction *BI, LLVMContext &context){
      FunctionType *type = FunctionType::get(Type::getInt32Ty(context), {Type::getInt32PtrTy(context)}, false);
      auto callee = BB.getModule()->getOrInsertFunction("add_cov", type);
      Function *c=(Function*)callee.getCallee();    
      std::ifstream uidf;
      uidf.open("/root/cover_uid");
      int uid;
      uidf>>uid;
      uidf.close(); 
      std::ofstream uidof;
      uidof.open("/root/cover_uid");
      uidof<<uid+1;
      uidof.close(); 
      errs()<<"Rrooach:----------insrt_cover: "<<uid<< " ----------\n";
      IRBuilder<> builder(&BB);
      ConstantInt *cuid = builder.getInt32(uid); 
      CallInst *inst = CallInst::Create(callee, {cuid}, "",BI);  

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
