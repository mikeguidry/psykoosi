#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <inttypes.h>
#include <fstream>
#include <sys/time.h>
#include <pe_lib/pe_bliss.h>
#include <pe_lib/pe_section.h>
extern "C" {
#include <capstone/capstone.h>
}
#include "virtualmemory.h"
#include "disassemble.h"
#include "analysis.h"
#include "loading.h"


using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;

BinaryLoader::BinaryLoader(DisassembleTask *DT, InstructionAnalysis *IA, VirtualMemory *VM) {
	image = NULL;

	_DT = DT;
	_IA = IA;
	_VM = VM;
	code_section = 0;
	iat_count = 0;
	Images_List = NULL;
	Symbols_List = NULL;
#ifdef EMU_QUEUE
	Emulation_List = Emulation_Last = NULL;
#endif

	load_for_emulation = 1;

	memset(system_dll_dir, 0, 1024);
}

char *BinaryLoader::GetInputRaw(int *Size) {

	return NULL;
}

// returns highest section address (so we can add new ones that wont affect others)
uint32_t BinaryLoader::HighestAddress(int raw) {
	 const section_list sections(image->get_image_sections());
	 uint32_t highestaddr = 0;

	 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
		 const section &s = *it;
		 uint32_t sectionhigh = 0;
		 sectionhigh = image->get_image_base_32() + s.get_virtual_address();
		 sectionhigh += raw ? s.get_size_of_raw_data() : s.get_virtual_size();
		 //(s.get_aligned_virtual_size(image->get_section_alignment()));
		 if (sectionhigh > highestaddr) highestaddr = sectionhigh;
	 }

	 return highestaddr;
}

pe_base *BinaryLoader::OpenFile(int Arch, int FileFormat, char *FileName, uint32_t *ImageBase,
uint32_t *ImageSize) {
	std::ifstream pe_file(FileName, std::ios::in | std::ios::binary);
	
	std::cout << "BinaryLoader::OpenFile: " << FileName << std::endl;
	
	if (!pe_file) {
		std::cout << "Cannot open " << FileName << std::endl;
		return 0;
	}
	
	try {
		 image = new pe_base(pe_factory::create_pe(pe_file));

		 // save our original base in case we need to realign, build reloc fixups, 
		 // or as a short fix just write our IAT into the original..
		 // to save some time *** FIX 
		OriginalImageBase = image->get_image_base_32();
		
		 // lets return image base to caller...
		 if (ImageBase != 0)
		 	*ImageBase = image->get_image_base_32();
		 if (ImageSize != NULL)
		 	*ImageSize = image->get_size_of_image(); 
			 
	} catch (const pe_exception& e) {
		std::cout << "Error: " << e.what() << std::endl;
		delete image;
		image = NULL;
		return 0;
	}
	return image;
}


pe_base *BinaryLoader::ProcessFile(pe_base *image, uint32_t ImageBase) {
	DisassembleTask::CodeAddr Last_Section_Addr = 0;
	LoadedImages *main_image = NULL;
	VirtualMemory::Memory_Section *mptr = NULL;

	std::cout << "BinaryLoader::ProcessFile: " <<  std::endl;
	
	if (!image) {
		std::cout << "No handle to image" << std::endl;
		return 0;
	}

	try {
		 //image = new pe_base(pe_factory::create_pe(pe_file));

		 if (ImageBase == 0)
		 	ImageBase = image->get_image_base_32();
		 else {
			 if (image->has_reloc()) {
				 ProcessRelocations(image, _VM, ImageBase);
			 }
			image->set_image_base(ImageBase);
		 }
			
		 //std::cout << "Reading PE sections..." << std::hex << std::showbase << std::endl << std::endl;
		 const section_list sections(image->get_image_sections());

		 // calculate entry points virtual address
		 EntryPoint = ImageBase + image->get_ep();
		 // calculate the highest address of that section
		 uint32_t HighestAddressInEntrySection = image->section_from_rva(image->get_ep()).get_size_of_raw_data() + image->section_from_rva(image->get_ep()).get_virtual_address();//.get_aligned_virtual_size(image->get_section_alignment());
		 //printf("\nhighest %p Entry %p\n", HighestAddressInEntrySection, EntryPoint);
		 _DT->SetBinaryLoaderHA(HighestAddressInEntrySection);
		 // queue to disassemble from the entry point to the end of the section.. with priority 100 (top)
		 // this means it should find all code coverage from entry and disassemble correctly.. linear pass later
		 _IA->QueueAddressForDisassembly(EntryPoint, 10, 0, (ImageBase + HighestAddressInEntrySection) - EntryPoint, 0);

		 //printf("section alignment: %d\n", image->get_section_alignment());
		 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			 const section &s = *it;

			 if (Last_Section_Addr == 0) {
				 Last_Section_Addr = s.get_pointer_to_raw_data() + s.get_virtual_address();
			 } else {
				 int space = (s.get_virtual_address()) - Last_Section_Addr;
				 //printf("Space in-between section: %d\n", space);
			 }

			 std::cout << "Section [" << s.get_name() << "]" << std::endl
					 << "RVA " << s.get_pointer_to_raw_data() << std::endl
					 << "Characteristics: " << s.get_characteristics() << std::endl
					 << "Size of raw data: " << s.get_size_of_raw_data() << std::endl
					 << "Virtual address: " << s.get_virtual_address() << std::endl
					 << "Virtual size: " << s.get_virtual_size() << std::endl
					 << "Raw Data Size: " << s.get_size_of_raw_data() << std::endl
					 << "addr: " << (ImageBase + s.get_virtual_address()) << std::endl
					 << std::endl;

			 mptr = _VM->Add_Section((VirtualMemory::CodeAddr)s.get_virtual_address(),s.get_size_of_raw_data(),s.get_virtual_size(),s.executable() ? VirtualMemory::SECTION_TYPE_CODE : VirtualMemory::SECTION_TYPE_NONE,s.get_characteristics(),s.get_pointer_to_raw_data(),(char *)s.get_name().c_str(),(unsigned char *) s.raw_data_.data());
			 mptr->ImageBase = ImageBase;
			 // insert into images loaded list... (used later for getprocaddress, etc maybe hooking of win32 api)


			 // rather than setting the filename.. we'll keep it NULL for easily enumerating the main file's sections
			 //_VM->Section_SetFilename(mptr, FileName);

			//mptr->Section_Type = s.executable() ? VirtualMemory::SECTION_TYPE_CODE : VirtualMemory::SECTION_TYPE_NONE;

			 // write section into virtual memory...
			 _VM->MemDataWrite((ImageBase + s.get_virtual_address()),
					 (unsigned char *) s.raw_data_.data(), s.get_size_of_raw_data());

			 // if this is an executable section..
			 if (s.executable()) {
				 // disassemble because this is the code section
				 uint32_t SectionAddress = ImageBase + s.get_virtual_address();
				 // queue for analysis after...
				 //int InstructionAnalysis::QueueAddressForDisassembly(CodeAddr Address, int Priority, int Max_Instructions, int Max_Bytes, int Redo) {

				 main_image = AddLoadedImage(NULL, image, (CodeAddr)mptr->ImageBase, NULL);
				 if (main_image) {
					 main_image->CodeSection = mptr;
				 }

				printf("Section addr %X\n", SectionAddress);
				 _IA->QueueAddressForDisassembly(SectionAddress, 1, 0, s.get_size_of_raw_data(), 0);
				 //_DT->RunDisassembleTask((image->get_image_base_32() + s.get_virtual_address()), 1,  s.get_virtual_size(), 0,0);
			 }

		}

		 if (load_for_emulation) {
			 if (image->has_imports())
				LoadImports(image, _VM, ImageBase);
				
			if (image->has_exports()) {
				// FIX *** for fuzzing we wanna cache the exports..
				// PE bliss = too slow to enumerate every GetProcAddress..
				// for API proxy its fine for now
			}

			if (main_image) {
#ifdef EMU_QUEUE
				EmulationQueue *qptr = EmulationQueueAdd(main_image, mptr->ImageBase + main_image->PEimage->get_ep(), 0);
#endif
			}
		}
	} catch(const pe_exception& e) {
		std::cout << "Error: " << e.what() << std::endl;
		delete image;
		image = NULL;
		return 0;
	}


	_IA->SetPEHandle(image);
	return image;
}


#ifdef EMU_QUEUE
// this function adds to a list of queued addresses for execution.. although they still have to be executed properly
// within the emulation system by CPU cycles
BinaryLoader::EmulationQueue *BinaryLoader::EmulationQueueAdd(LoadedImages *iptr, CodeAddr CodeEntry, int IsDLL) {
	EmulationQueue *qptr = new EmulationQueue;
	std::memset(qptr, 0, sizeof(EmulationQueue));
	
	qptr->Image = iptr;
	qptr->IsDLL = IsDLL;
	qptr->Entry = CodeEntry;

	if (Emulation_Last == NULL) {
		 Emulation_List = Emulation_Last = qptr;
	} else {
		 Emulation_Last->next = qptr;
		 Emulation_Last = qptr;
	}

	return qptr;
}

// this will pop a single queued address for execution... any following execution queues should be handled
// within the emulator (via CPU cycles, and branches). this is only to initialize DLLs, and then start
// the entry point of the application
BinaryLoader::EmulationQueue *BinaryLoader::EmulationRetrieve() {
	for (EmulationQueue *qptr = Emulation_List; qptr != NULL; qptr = qptr->next) {
		if (qptr->completed) continue;
		return qptr;
	}
	
	return NULL;
}
#endif


// find us a good image base for loading DLLs...
uint32_t BinaryLoader::CheckImageBase(uint32_t Address) {
	for (VirtualMemory::Memory_Section *sptr = _VM->Section_List; sptr != NULL; sptr = sptr->next) {
		if ((Address >= (sptr->ImageBase) && (Address < (sptr->ImageBase + sptr->VirtualSize+(1024*1024))))) {
			//if its within 64kb of this other section.. it has to be changed...
			return CheckImageBase(sptr->ImageBase + sptr->Address + sptr->VirtualSize + (1024*1024));
		}
	}
	return Address;
}

void BinaryLoader::SetDLLDirectory(char *dir) {
	strncpy(system_dll_dir, dir, 1024);
}

BinaryLoader::LoadedImages *BinaryLoader::AddLoadedImage(char *filename, pe_bliss::pe_base *PEimage, CodeAddr ImageBase, char *Reference) {
	LoadedImages *lptr = new LoadedImages;
	std::memset(lptr, 0, sizeof(LoadedImages));

	if (filename != NULL) {
		int flen = strlen(filename);
		lptr->filename = new char [flen+2];
		std::memcpy(lptr->filename, filename, flen);
		lptr->filename[flen] = 0;
	}
	lptr->PEimage = PEimage;
	lptr->ImageBase = ImageBase;
	if (Reference) {
		int rlen = strlen(Reference);
		lptr->LoadedBecause = new char[rlen+2];
		std::memcpy(lptr->LoadedBecause, filename, rlen);
		lptr->LoadedBecause[rlen] = 0;
	}

	lptr->next = Images_List;
	Images_List = lptr;

	return lptr;
}

VirtualMemory::Memory_Section *BinaryLoader::LoadDLL(char *filename, pe_bliss::pe_base *imp_image, VirtualMemory *VMem, int analyze) {
	VirtualMemory::Memory_Section *ret = NULL;
	BinaryLoader::LoadedImages *lptr = NULL;
	CodeAddr Entry=0, ImageBase = 0;
	char fname[1024];

	for (BinaryLoader::LoadedImages *lptr = Images_List; lptr != NULL; lptr = lptr->next) {
		if (lptr->filename != NULL && (strcasecmp(filename, lptr->filename)==0)) {
			return lptr->CodeSection;
		}
	}
	sprintf(fname, "%s/%s", system_dll_dir, filename);

	for (int i = 0; i < strlen(fname); i++) fname[i] = tolower(fname[i]);
	std::ifstream pe_file(fname, std::ios::in | std::ios::binary);
	if (!pe_file) {
		printf("LoadDLL(\"%s\"): couldn't open file\n", filename);
		return NULL;
	}

	 pe_base *dll_image = new pe_base(pe_factory::create_pe(pe_file));
	 if (!dll_image->get_ep()) {
		 printf("Issues loading PE file into memory[%s]\n", filename);
		 return NULL;
	 }


	 ImageBase = CheckImageBase(dll_image->get_image_base_32());
	 if (strstr(fname, "kernel32")) ImageBase = 0x7B810000;

	 dll_image->set_image_base(ImageBase);
	 Entry = ImageBase + dll_image->get_ep();
	 printf("Loading DLL %s @ PE ImageBase %p has exports %d %d - Analyze %d\n", filename, ImageBase, dll_image->has_exports(), dll_image->has_imports(), analyze);
	 const section_list sections(dll_image->get_image_sections());
	 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			 const section &s = *it;


			 VirtualMemory::Memory_Section *mptr = VMem->Add_Section((VirtualMemory::CodeAddr)s.get_virtual_address(),s.get_size_of_raw_data(),s.get_virtual_size(),s.executable() ? VirtualMemory::SECTION_TYPE_CODE : VirtualMemory::SECTION_TYPE_NONE,s.get_characteristics(),s.get_pointer_to_raw_data(),(char *)s.get_name().c_str(),(unsigned char *) s.raw_data_.data());
			 mptr->IsDLL = 1;
			 mptr->ImageBase = dll_image->get_image_base_32();
			 VMem->Section_SetFilename(mptr, 	filename);

			 // we return the writable section
			 if (s.executable()) ret = mptr;
			 //mptr->Section_Type = s.executable() ? VirtualMemory::SECTION_TYPE_CODE : VirtualMemory::SECTION_TYPE_NONE;

			 // write section into virtual memory...
			 VMem->MemDataWrite(ImageBase + s.get_virtual_address(),
					 (unsigned char *) s.raw_data_.data(), s.get_size_of_raw_data());

			 // if this is an executable section..
			 if (s.executable()) {
				 // disassemble because this is the code section
				 uint32_t SectionAddress = ImageBase + s.get_virtual_address();
				 // queue for analysis after...
				 //int InstructionAnalysis::QueueAddressForDisassembly(CodeAddr Address, int Priority, int Max_Instructions, int Max_Bytes, int Redo) {

				 lptr = AddLoadedImage(filename, dll_image, ImageBase, NULL);
				 lptr->CodeSection = mptr;
				 
				 if (analyze)
					 _IA->QueueAddressForDisassembly(SectionAddress, 1, 0, s.get_size_of_raw_data(), 0);
				 //_DT->RunDisassembleTask((image->get_image_base_32() + s.get_virtual_address()), 1,  s.get_virtual_size(), 0,0);
			 }
	 }

	 if (lptr != NULL) {
		 // *** FIX build symbol table for export so we increase the speed of GetProcAddress
		 
		 if (dll_image->has_imports()) {
			 //LoadImports(dll_image, VMem, ImageBase);
		 }

		 // put in queue for emulation since each DLL will have to be executed before we can run the
		 // PEs code itself since we are loading them..
#ifdef EMU_QUEUE
		 EmulationQueue *qptr = EmulationQueueAdd(lptr, Entry, 1);
#endif
	 }
	 return ret;
}

BinaryLoader::LoadedImages *BinaryLoader::FindLoadedByName(char *filename) {
	for (LoadedImages *lptr = Images_List; lptr != NULL; lptr = lptr->next) {
		if ((filename && lptr->filename && (strcasecmp(filename, lptr->filename)==0)) ||
				(!filename && !lptr->filename))
			return lptr;
	}

	return NULL;
}

BinaryLoader::CodeAddr BinaryLoader::GetProcAddress(char *filename, char *function_name) {
	CodeAddr FunctionAddr = NULL;
	LoadedImages *lptr = FindLoadedByName(filename);

	if (lptr == NULL) {
		return NULL;
	}

	for (Symbols *sptr = Symbols_List; sptr != NULL; sptr = sptr->next) {
		if ((strcasecmp(filename, sptr->filename)==0) && strcasecmp(function_name, sptr->function_name)==0) {
			return sptr->FunctionPtr;
		}
	}

	// make sure it has exports before we start enumerating..
	if (!lptr->PEimage->has_exports()) {
		return NULL;
	}


	export_info info;
	exported_functions_list exports = get_exported_functions(*lptr->PEimage, info);
	for(exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it) {
		const exported_function& func = *it;
		const std::string name = func.get_name();

		if (strcasecmp((char *)name.c_str(), function_name)==0) {
			FunctionAddr = lptr->ImageBase + func.get_rva();
			break;
		}

	}

	if (FunctionAddr != NULL) {
		Symbols *sptr = new Symbols;
		sptr->FunctionPtr = FunctionAddr;

		int len = strlen(filename);

		sptr->filename = new char [len+2];
		std::memcpy(sptr->filename, filename, len);
		sptr->filename[len] = 0;

		len = strlen(function_name);
		sptr->function_name = new char[len+2];
		std::memcpy(sptr->function_name, function_name, len);
		sptr->function_name[len] = 0;

		sptr->next = Symbols_List;
		Symbols_List = sptr;
	}

	return FunctionAddr;
}

// handle relocations in image after we load it..
int BinaryLoader::ProcessRelocations(pe_bliss::pe_base *imp_image, VirtualMemory *VMem, CodeAddr ImageBase) {
	if (imp_image == NULL || !imp_image->has_reloc()) {
		printf("cannot find relocations\n");
		return -1;
	}
	
	// enumerate the relocations fixing as needed
	const relocation_table_list tables(get_relocations(*imp_image));
	rebase_image(*imp_image, tables, ImageBase);
	/*
	for(relocation_table_list::const_iterator it = tables.begin(); it != tables.end(); ++it) {
		 relocation_table& table = (relocation_table &)*it;

		// iterate through each section looping for the section that this table belongs to
		section_list sections(*imp_image->get_image_sections());
		for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			const section &s = *it;

			if ((table.get_rva() >= s.get_virtual_address()) && (table.get_rva() < (s.get_virtual_address() + s.get_virtual_size()))) {
				// found section of this specific relocation table's RVA
				const relocation_table::relocation_list& relocs = table.get_relocations();
				DisassembleTask::InstructionInformation *InsInfo = 0;
				for(relocation_table::relocation_list::const_iterator reloc_it = relocs.begin(); reloc_it != relocs.end(); ++reloc_it) {
						relocation_entry &at = (relocation_entry &)(*reloc_it);
						uint32_t rva = at.get_rva(NewReloc);
						uint32_t type = (*reloc_it).get_type();
					
						InsInfo->InRelocationTable = 1;
						InsInfo->RelocationType = (*reloc_it).get_type();
						offset = CodeAddr - InsInfo->Original_Address;

						uint16_t NewReloc = (int16_t)(InsInfo->Address - _PE->get_image_base_32() - table.get_rva() + offset);
						// make sure we modify in place... not a new copy
					}
					//printf("RVA %X Address %p Offset into ins: %d\n", (*reloc_it).get_rva(), InsInfo ? InsInfo->Original_Address : 0, offset);

					//std::cout << "[+] " << (*reloc_it).get_rva() << " type: " << (*reloc_it).get_type() << std::endl << std::endl;
				}
			}
		}

	}	*/
	return 1;
}

// will try to locate and load all dependencies for a binary into virtual memory
int BinaryLoader::LoadImports(pe_bliss::pe_base *imp_image, VirtualMemory *VMem, CodeAddr ImageBase) {

	printf("LoadImpports ImageBase %X\n", ImageBase);
	
	if (imp_image == NULL || !imp_image->has_imports()) {
		printf("cannot load imports %p %d\n", imp_image, imp_image->has_imports());
		return -1;
	}

    const imported_functions_list imports = get_imported_functions(*imp_image);

    for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it) {
		const import_library& lib = *it;
		/*VirtualMemory::Memory_Section *DLL_code_sect = LoadDLL((char *)lib.get_name().c_str(), imp_image, VMem, 0);
		if (DLL_code_sect) {
			//printf("Loaded DLL fine.. code section %p\n", DLL_code_sect->Address + DLL_code_sect->ImageBase);
		} else {
			printf("Couldn't load DLL %s\n", (char *)lib.get_name().c_str());
		}*/
		uint32_t iat_rva = (*it).get_rva_to_iat();
		section iat_section = imp_image->section_from_rva(iat_rva);
		if (iat_section.empty()) {
			return -1;
		}

		printf("IAT Section %p size %d [%X]\n", iat_section.get_virtual_address() + imp_image->get_image_base_32(), iat_section.get_virtual_size());

		uint32_t IAT_Addr = (uint32_t)(ImageBase + iat_rva);
		uint32_t Original_IAT_Addr = (uint32_t)(OriginalImageBase + iat_rva);

		const import_library::imported_list& functions = lib.get_imported_functions();
		for(import_library::imported_list::const_iterator func_it = functions.begin(); func_it != functions.end(); ++func_it)
		{
			struct timeval start, end;
				//gettimeofday(&start, 0);
				const imported_function& func = *func_it;
				
				uint32_t iat_addr = sizeof(uint32_t) * (500 + iat_count);
				CodeAddr ProcAddr = iat_addr;//GetProcAddress((char *)lib.get_name().c_str(), (char *)func.get_name().c_str());
				// write IAT
				//VMem->MemDataWrite(IAT_Addr, (unsigned char *)&ProcAddr, (int)sizeof(uint32_t));
				printf("GetProcAddress(\"%s\", \"%s\") = %p [ wrote to IAT Address %p ] %d\n", (char *)lib.get_name().c_str(), (char *)func.get_name().c_str(), ProcAddr, IAT_Addr,iat_addr);

				IAT *iatptr = new IAT;
				memset((void *)iatptr, 0, sizeof(IAT));
				iatptr->function = strdup((char *)func.get_name().c_str());
				iatptr->module = strdup((char *)lib.get_name().c_str());
				iatptr->Address = IAT_Addr;
				iatptr->Redirect = ProcAddr;
				
				
				
				//printf("PUTTING AT %X / %X\n", IAT_Addr, Original_IAT_Addr);
				iatptr->Redirect = iat_addr;
				VMem->MemDataWrite(IAT_Addr, (unsigned char *)&iat_addr, (int)sizeof(uint32_t));
				//VMem->MemDataWrite(Original_IAT_Addr, (unsigned char *)&iat_addr, (int)sizeof(uint32_t));
				
				iatptr->next = Imports;
				Imports = iatptr;
				
				iat_count++;
				
				IAT_Addr += sizeof(uint32_t);
				//gettimeofday(&end, 0);
				//int i = end.tv_usec - start.tv_usec;
				//printf("took 0.%3d seconds\n", i/100);
		}

		//std::cout << "Finished processing IAT" << std::endl;
	}
}


int BinaryLoader::WriteFile(int Arch, int FileFormat, char *FileName) {

	return 0;
}


BinaryLoader::IAT *BinaryLoader::FindIAT(uint32_t Address) {
	BinaryLoader::IAT *iptr = NULL;
	
	for (iptr = Imports; iptr != NULL; iptr = iptr->next) {
		if (iptr->Address == Address || iptr->Redirect == Address) {
			break;
		}
	}
	
	return iptr;
}