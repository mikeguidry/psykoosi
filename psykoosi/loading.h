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
	  typedef uint32_t CodeAddr;

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
    
 

	  typedef struct _loaded_images {
		  struct _loaded_images *next;

		  pe_bliss::pe_base *PEimage;

		  CodeAddr ImageBase;

		  char *filename;

		  VirtualMemory::Memory_Section *CodeSection;
		  // which image was the reason this was loaded..
		  char *LoadedBecause;

	  } LoadedImages;

	  // emulation queue for loading DLLs, etc and then we can run the PE's entry point...
	  typedef struct _emulation_queue {
		  struct _emulation_queue *next;
		  LoadedImages *Image;
		  CodeAddr Entry;
		  int IsDLL; // dll or main entry?
		  int completed;
	  } EmulationQueue;

	  typedef struct _loaded_symbols {
		  struct _loaded_symbols *next;
		  char *filename;
		  char *function_name;
		  CodeAddr FunctionPtr;
	  } Symbols;

    typedef struct _iat {
      struct _iat *next;
      
      char *module;
      char *function;
      
      CodeAddr Address;
      CodeAddr Redirect;
    } IAT;

  	  BinaryLoader(DisassembleTask *, InstructionAnalysis *, VirtualMemory *);

	  char *GetInputRaw(int *Size);
	  pe_bliss::pe_base *ProcessFile(pe_bliss::pe_base *, uint32_t ImageBase, int);
    pe_bliss::pe_base *OpenFile(int Arch, int FileFormat, char *FileName, uint32_t *ImageBase, uint32_t *ImageSize);
	  int WriteFile(int Arch, int FileFormat, char *FileName);

	  uint32_t HighestAddress(int raw);

	  int LoadImports(pe_bliss::pe_base *imp_image,  VirtualMemory *VMem, CodeAddr ImageBase, int);
    int ProcessRelocations(pe_bliss::pe_base *imp_image,  VirtualMemory *VMem, CodeAddr ImageBase);
	  VirtualMemory::Memory_Section *LoadDLL(char *, pe_bliss::pe_base *imp_image, VirtualMemory *VMem, int analyze, uint32_t, int);

    BinaryLoader::IAT *FindIAT(uint32_t Address);
	  BinaryLoader::LoadedImages *AddLoadedImage(char  *filename, pe_bliss::pe_base *PEimage, CodeAddr ImageBase, char *Reference);
	  BinaryLoader::LoadedImages *FindLoadedByName(char *filename);
	  BinaryLoader::CodeAddr GetProcAddress(char *filename, char *function_name);
#ifdef EMU_QUEUE
	  EmulationQueue *EmulationQueueAdd(LoadedImages *iptr, CodeAddr CodeEntry, int IsDLL);
	  EmulationQueue *EmulationRetrieve();
	  //EmulationQueue *
#endif

    //int BinaryLoader::LoadExecutionSnapshot(char *filename);

	  DisassembleTask *_DT;
	  InstructionAnalysis *_IA;
	  VirtualMemory *_VM;
	  pe_bliss::section *code_section;

	  uint32_t CheckImageBase(uint32_t Address);

	  void SetDLLDirectory(char *dir);

	  char system_dll_dir[1024];

    APIClient *Proxy;
	  LoadedImages *Images_List;
	  // this one needs last so its in order!
#ifdef EMU_QUEUE
	  EmulationQueue *Emulation_List, *Emulation_Last;
#endif

	  Symbols *Symbols_List;
    
    IAT *Imports;
    
    
    
    uint32_t EntryPoint;
	  int load_for_emulation;

    int iat_count;
    CodeAddr OriginalImageBase;
  	  private:
	  std::string InputData;
	  int InputSize;
	  int InputFileType;
	  int InputArchitecture;
	  pe_bliss::pe_base *image;
  };

}


#endif /* LOADING_H_ */
