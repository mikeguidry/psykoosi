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

BinaryLoader::BinaryLoader(Disasm *DT, InstructionAnalysis *IA, VirtualMemory *VM) {
	image = NULL;

	_DT = DT;
	_IA = IA;
	_VM = VM;
	code_section = 0;
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


pe_base *BinaryLoader::LoadFile(int Arch, int FileFormat, const char *FileName) {
	std::ifstream pe_file(FileName, std::ios::in | std::ios::binary);
	Disasm::CodeAddr Last_Section_Addr = 0;

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

				 _IA->QueueAddressForDisassembly(SectionAddress, 1, 0, s.get_size_of_raw_data(), 0);
                 //_DT->RunDisasm((image->get_image_base_32() + s.get_virtual_address()), 1,  s.get_virtual_size(), 0,0);
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


int BinaryLoader::WriteFile(int Arch, int FileFormat, char *FileName) {

	return 0;
}
