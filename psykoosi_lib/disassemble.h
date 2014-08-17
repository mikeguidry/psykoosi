#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H
#include <udis86.h>
#include <capstone/capstone.h>
#include <pe_lib/pe_bliss.h>

#include "virtualmemory.h"

namespace psykoosi {

  class Disasm {


    //typedef void * DisassembleHandle;
  public:
	  enum {
		  LIST_TYPE_NEXT=0,
		  LIST_TYPE_PREV=1,
		  LIST_TYPE_REBASED=2,
		  LIST_TYPE_INITIAL=3,
		  LIST_TYPE_INJECTED=4,
		  LIST_TYPE_JUMP=5,
		  LIST_TYPE_MAX=6,
		  JUMP_TABLE=7
	  };

	  typedef uint32_t CodeAddr;
	  typedef struct _instruction_information {
		  struct _instruction_information *Lists[LIST_TYPE_MAX];

		  unsigned char *RawData;
		  unsigned short Size;
		  int RawOffset;
		  CodeAddr Address;

		  // this is for when we rebuild later... so we can find instructions for things
		  CodeAddr Original_Address;
		  struct _instruction_information *OriginalInstructionInformation;

		  int AnalysisCount;
		  int Realigned;
		  int Analyzed;
		  int Removed;
		  int FromInjection;
		  int Priority;
		  int Requires_Realignment;


		  int CatchOriginalRelativeDestinations;
		  struct _instruction_information *InjectedInstructions;

		  // some quick ways to scan over these later.. push/call are important
		  int IsPush;
		  int IsCall;
		  int IsEntryPoint;
		  int IsImmediate;

		  // Operand destination information
		  struct _instruction_information *OpDstInstructionInformation;
		  CodeAddr OpDstAddress;
		  struct _instruction_information * OpDstAddress_realigned;

		  std::string *InstructionMnemonicString;

		  // now lets keep track of all references to us from other instructions (very good to double check this stuff)
		  struct _instruction_information *ReferencesBackwards;

		  cs_insn *DisFrameworkIns;
		  //cs_detail *InsDetail;
		  cs_detail *InsDetail;
		  cs_detail _InsDetail;
		  ud_t ud_obj;
		  int DstAddressOffset;

		  int Displacement_Type;
		  int Displacement_Offset;
		  long orig;
		  int IsPointer;

		  int InRelocationTable;
		  int RelocationType;
	  } InstructionInformation;
  
      class InstructionIterator {
      public:
          InstructionIterator(InstructionInformation* ptr = nullptr);
          InstructionIterator(const InstructionIterator&) = default;
          bool operator==(const InstructionIterator& other);
          bool operator!=(const InstructionIterator& other);
          InstructionInformation* operator->();
          void operator++();
          void operator--();
          void jump();
          InstructionInformation* get();
          // todo: over operations
      private:
          InstructionInformation *InstInfoPtr = nullptr;
      };
  
  public:
    Disasm(VirtualMemory *);
    ~Disasm();
    
    void Clear_Instructions();

    std::string disasm_str(CodeAddr Address, char *, int);
    // disassemble a single instruction.. returning InstructionInformation for it
    int DisassembleSingleInstruction(CodeAddr Address, InstructionInformation **, int priority);
    // task to disassemble a section or cluster.. puts in the classes array of Instructrions
    int RunDisasm(CodeAddr StartAddress, int priority, int MaxRawSize, int MaxInstructions);

    int DeleteAddressRange(CodeAddr Address, int Size, int priority);
    int DeleteInstruction(InstructionInformation *InsInfoPtr, CodeAddr Address, int strict, int priority);

    void SetPEHandle(pe_bliss::pe_base *);

    int InstructionsCount(int type);
    // mark the current instructions array as a specific type (initial, rebased, etc)
    int SetCurrentListAsListType(int type);

    int Cache_Load(const char *filename);
    int Cache_Save(const char *filename);

    void SetBinaryLoaderHA(CodeAddr Addr);
    int DeleteInstruction(InstructionInformation *InsInfoPtr, CodeAddr Address);
    // return a linked list of instructions of a particular type (to be used for allow other classes to access the data)
    InstructionInformation *GetInstructionsData(int type) {	return Instructions[type]; }
    InstructionInformation *GetInstructionInformationByAddress(CodeAddr Address, int type, int strict, InstructionInformation *InsInfo);
    Disasm::InstructionInformation *GetInstructionInformationByAddressOriginal(CodeAddr Address, int type, int strict, InstructionInformation *InsInfo);
    int DCount;
    InstructionInformation **Instructions;
    InstructionInformation **Instructions_Jump;
    int JUMP_SIZE;

  private:
    void *EngineHandle;
    VirtualMemory *vmem;
    CodeAddr HighestCode;
    pe_bliss::pe_base *PE_Handle;
    int Loaded_from_Cache;

  };
}








#endif
