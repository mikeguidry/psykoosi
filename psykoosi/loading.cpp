#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <inttypes.h>
#include <fstream>
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
	Images_List = NULL;

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


pe_base *BinaryLoader::LoadFile(int Arch, int FileFormat, char *FileName) {
	std::ifstream pe_file(FileName, std::ios::in | std::ios::binary);
	DisassembleTask::CodeAddr Last_Section_Addr = 0;
	LoadedImages *main_image = NULL;

	if (!pe_file) {
		std::cout << "Cannot open " << FileName << std::endl;
		return 0;
	}

	try {
		 image = new pe_base(pe_factory::create_pe(pe_file));

		 std::cout << "Reading PE sections..." << std::hex << std::showbase << std::endl << std::endl;
		 const section_list sections(image->get_image_sections());

		 // calculate entry points virtual address
		 uint32_t EntryPoint = image->get_image_base_32() + image->get_ep();
		 // calculate the highest address of that section
		 uint32_t HighestAddressInEntrySection = image->section_from_rva(image->get_ep()).get_size_of_raw_data() + image->section_from_rva(image->get_ep()).get_virtual_address();//.get_aligned_virtual_size(image->get_section_alignment());
		 printf("\nhighest %p Entry %p\n", HighestAddressInEntrySection, EntryPoint);
		 _DT->SetBinaryLoaderHA(HighestAddressInEntrySection);
		 // queue to disassemble from the entry point to the end of the section.. with priority 100 (top)
		 // this means it should find all code coverage from entry and disassemble correctly.. linear pass later
		 _IA->QueueAddressForDisassembly(EntryPoint, 10, 0, (image->get_image_base_32() + HighestAddressInEntrySection) - EntryPoint, 0);

		 printf("section alignment: %d\n", image->get_section_alignment());
		 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			 const section &s = *it;

			 if (Last_Section_Addr == 0) {
				 Last_Section_Addr = s.get_pointer_to_raw_data() + s.get_virtual_address();
			 } else {
				 int space = (s.get_virtual_address()) - Last_Section_Addr;
				 printf("Space in-between section: %d\n", space);
			 }

			 std::cout << "Section [" << s.get_name() << "]" << std::endl
					 << "RVA " << s.get_pointer_to_raw_data() << std::endl
					 << "Characteristics: " << s.get_characteristics() << std::endl
					 << "Size of raw data: " << s.get_size_of_raw_data() << std::endl
					 << "Virtual address: " << s.get_virtual_address() << std::endl
					 << "Virtual size: " << s.get_virtual_size() << std::endl
					 << "Raw Data Size: " << s.get_size_of_raw_data() << std::endl
					 << "addr: " << (image->get_image_base_32() + s.get_virtual_address()) << std::endl
					 << std::endl;

			 VirtualMemory::Memory_Section *mptr = _VM->Add_Section((VirtualMemory::CodeAddr)s.get_virtual_address(),s.get_size_of_raw_data(),s.get_virtual_size(),s.executable() ? VirtualMemory::SECTION_TYPE_CODE : VirtualMemory::SECTION_TYPE_NONE,s.get_characteristics(),s.get_pointer_to_raw_data(),(char *)s.get_name().c_str(),(unsigned char *) s.raw_data_.data());
			 mptr->ImageBase = image->get_image_base_32();
			 // insert into images loaded list... (used later for getprocaddress, etc maybe hooking of win32 api)


			 // rather than setting the filename.. we'll keep it NULL for easily enumerating the main file's sections
			 //_VM->Section_SetFilename(mptr, FileName);

			//mptr->Section_Type = s.executable() ? VirtualMemory::SECTION_TYPE_CODE : VirtualMemory::SECTION_TYPE_NONE;

			 // write section into virtual memory...
			 _VM->MemDataWrite((image->get_image_base_32() + s.get_virtual_address()),
					 (unsigned char *) s.raw_data_.data(), s.get_size_of_raw_data());

			 // if this is an executable section..
			 if (s.executable()) {
				 // disassemble because this is the code section
				 uint32_t SectionAddress = image->get_image_base_32() + s.get_virtual_address();
				 // queue for analysis after...
				 //int InstructionAnalysis::QueueAddressForDisassembly(CodeAddr Address, int Priority, int Max_Instructions, int Max_Bytes, int Redo) {

				 main_image = AddLoadedImage(NULL, image, (CodeAddr)mptr->ImageBase, NULL);
				 if (main_image) {
					 main_image->CodeSection = mptr;
				 }

				 _IA->QueueAddressForDisassembly(SectionAddress, 1, 0, s.get_size_of_raw_data(), 0);
				 //_DT->RunDisassembleTask((image->get_image_base_32() + s.get_virtual_address()), 1,  s.get_virtual_size(), 0,0);
			 }

		}
		//LoadImports(image, _VM);
	} catch(const pe_exception& e) {
		std::cout << "Error: " << e.what() << std::endl;
		delete image;
		image = NULL;
		return 0;
	}


	_IA->SetPEHandle(image);
	return image;
}

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
	char fname[1024];

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


	 uint32_t ImageBase = CheckImageBase(dll_image->get_image_base_32());
	 if (strstr(fname, "kernel32")) ImageBase = 0x7B810000;

	 dll_image->set_image_base(ImageBase);
	 printf("Loading DLL %s @ PE ImageBase %p has exports %d %d\n", filename, ImageBase, dll_image->has_exports(), dll_image->has_imports());
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

				 BinaryLoader::LoadedImages *lptr = AddLoadedImage(filename, dll_image, ImageBase, NULL);
				 lptr->CodeSection = mptr;
				 if (analyze)
					 _IA->QueueAddressForDisassembly(SectionAddress, 1, 0, s.get_size_of_raw_data(), 0);
				 //_DT->RunDisassembleTask((image->get_image_base_32() + s.get_virtual_address()), 1,  s.get_virtual_size(), 0,0);
			 }
	 }
	 return ret;
}

BinaryLoader::LoadedImages *BinaryLoader::FindLoadedByName(char *filename) {
	for (LoadedImages *lptr = Images_List; lptr != NULL; lptr = lptr->next) {
		if (
				(filename && lptr->filename && (strcasecmp(filename, lptr->filename)==0)) ||
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

	return FunctionAddr;
}

// will try to locate and load all dependencies for a binary into virtual memory
int BinaryLoader::LoadImports(pe_bliss::pe_base *imp_image, VirtualMemory *VMem) {

	if (imp_image == NULL || !imp_image->has_imports()) {
		printf("cannot load imports %p %d\n", imp_image, imp_image->has_imports());
		return -1;
	}

    const imported_functions_list imports = get_imported_functions(*imp_image);

    for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it) {
		const import_library& lib = *it;
		VirtualMemory::Memory_Section *DLL_code_sect = LoadDLL((char *)lib.get_name().c_str(), imp_image, VMem, 0);
		if (DLL_code_sect) {
			//printf("Loaded DLL fine.. code section %p\n", DLL_code_sect->Address + DLL_code_sect->ImageBase);
		} else {
			printf("Couldn't load DLL %s\n", (char *)lib.get_name().c_str());
		}
		uint32_t iat_rva = (*it).get_rva_to_iat();
		section iat_section = imp_image->section_from_rva(iat_rva);
		if (iat_section.empty()) {
			return -1;
		}

		//printf("IAT Section %p size %d [%X]\n", iat_section.get_virtual_address() + imp_image->get_image_base_32(), iat_section.get_virtual_size());

		uint32_t IAT_Addr = (uint32_t)(imp_image->get_image_base_32() + iat_rva);

		const import_library::imported_list& functions = lib.get_imported_functions();
		for(import_library::imported_list::const_iterator func_it = functions.begin(); func_it != functions.end(); ++func_it)
		{
				const imported_function& func = *func_it;
				CodeAddr ProcAddr = GetProcAddress((char *)lib.get_name().c_str(), (char *)func.get_name().c_str());
				// write IAT
				VMem->MemDataWrite(IAT_Addr, (unsigned char *)&ProcAddr, (int)sizeof(uint32_t));
				printf("GetProcAddress(\"%s\", \"%s\") = %p [ wrote to IAT Address %p ]\n", (char *)lib.get_name().c_str(), (char *)func.get_name().c_str(), ProcAddr, IAT_Addr);

				IAT_Addr += sizeof(uint32_t);
		}

		std::cout << std::endl;
	}
}


int BinaryLoader::WriteFile(int Arch, int FileFormat, char *FileName) {

	return 0;
}
