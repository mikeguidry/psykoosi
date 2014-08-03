#ifndef ANALYSIS_H
#define ANALYSIS_H

namespace psykoosi {

  class InstructionAnalysis {
  	  public:
	  typedef uint32_t CodeAddr;
	  typedef struct _Analysis_Queue {
		  struct _Analysis_Queue *next;
		  CodeAddr Address;
		  int Already_Analyzed;
		  int Priority;
		  int Max_Instructions;
		  int Max_Bytes;
		  int Count;
	  } AnalysisQueue;

	  InstructionAnalysis(DisassembleTask *);
	  ~InstructionAnalysis();
	  long InstructionAddressDistance(DisassembleTask::CodeAddr first, int Size, DisassembleTask::InstructionInformation *second);
	  long AddressDistance(DisassembleTask::CodeAddr first, int Size, DisassembleTask::CodeAddr second, int type);

	  int QueueAddressForDisassembly(CodeAddr Address, int Priority, int Max_Instructions, int Max_Bytes, int Redo);

	  int Complete_Analysis_Queue(int redo);

	  int  QueueCache_Save(char *filename);
	  int  QueueCache_Load(char *filename);
	  int Queue_Clear();

	  void CleanInstructionAnalysis();
	  void SetPEHandle(pe_bliss::pe_base *);
	  int AnalyzeInstruction(DisassembleTask::InstructionInformation *InsInfo);

	  int CallCount;
	  int PushCount;
	  int RealignCount;
  	  private:
	  AnalysisQueue *Analysis_Queue_List;
	  AnalysisQueue *Analysis_Queue_Last;
	  DisassembleTask *Disassembler_Handle;
	  pe_bliss::pe_base *PE_Handle;
  };
}


#endif
