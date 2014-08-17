#ifndef REBUILD_H_
#define REBUILD_H_
namespace psykoosi {

typedef struct _modified_addresses {
	struct _modified_addresses *next;
    Disasm::CodeAddr Original_Address;
    Disasm::CodeAddr New_Address;
} ModifiedAddresses;

  class Rebuilder {
  	  public:
      Rebuilder(Disasm *, InstructionAnalysis *, VirtualMemory *, pe_bliss::pe_base *, const char *);
	  ~Rebuilder();

	  int RebuildInstructionsSetsModifications();
	  int RealignInstructions();
	  int WriteBinaryPE();
	  int WriteBinaryPE2();
	  void SetBinaryLoader(BinaryLoader *BL);
	  int ModifyRelocations();
      int RebaseCodeSection();
      void Add_Modified_Address(Disasm::CodeAddr Original_Address, Disasm::CodeAddr New_Address);
      Disasm::CodeAddr CheckForModifiedAddress(Disasm::CodeAddr Lookup);
      Disasm::CodeAddr CodeStart;
      Disasm::CodeAddr CodeEnd;
      Disasm::CodeAddr CodeSize;

  	  private:


	  int warp;
	  int final_size;
	  int final_i;
	  unsigned char *final_chr;
	  std::string raw_final;
	  int Must_Rebase_Section;
	  int Must_Realign;
      Disasm::InstructionInformation *EntryPointInstruction;
	  char FileName_output[1024];
	  char FileName[1024];


	  pe_bliss::pe_base *_PE;
      Disasm *_DT;
	  InstructionAnalysis *_IA;
	  VirtualMemory *_VM;

	  // we want new Virtual memory when rebuilding
	  VirtualMemory *vmem;
	  // and a new PE
	  pe_bliss::pe_base *newpe;
	  pe_bliss::pe_base *new_image;

	  ModifiedAddresses *Modified_Addresses;
	  BinaryLoader *_BL;

  };

}


#endif /* REBUILD_H_ */
