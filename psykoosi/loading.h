/*
 * loading.h
 *
 *  Created on: Jul 27, 2014
 *      Author: mike
 */

#ifndef LOADING_H_
#define LOADING_H_
namespace psykoosi {

  class BinaryLoader {
  	  public:
	  enum {
		  // architectures
		  INPUT_ARCH_X86,
		  INPUT_ARCH_X64,
		  INPUT_ARCH_MIPS,
		  INPUT_ARCH_ARM,

		  // file formats
		  INPUT_TYPE_PE,
		  INPUT_TYPE_ELF,
		  INPUT_TYPE_MACHO
	  };

	  BinaryLoader(DisassembleTask *, InstructionAnalysis *, VirtualMemory *);

	  char *GetInputRaw(int *Size);
	  pe_bliss::pe_base *LoadFile(int Arch, int FileFormat, char *FileName);
	  int WriteFile(int Arch, int FileFormat, char *FileName);

	  uint32_t HighestAddress(int raw);

	  int LoadImports(pe_bliss::pe_base *imp_image, VirtualMemory *VMem);
	  VirtualMemory::Memory_Section *LoadDLL(char *, pe_bliss::pe_base *imp_image, VirtualMemory *VMem, int analyze);


	  DisassembleTask *_DT;
	  InstructionAnalysis *_IA;
	  VirtualMemory *_VM;
	  pe_bliss::section *code_section;

	  uint32_t CheckImageBase(uint32_t Address);

  	  private:
	  std::string InputData;
	  int InputSize;
	  int InputFileType;
	  int InputArchitecture;
	  pe_bliss::pe_base *image;
  };

}


#endif /* LOADING_H_ */
