#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <inttypes.h>
#include <fstream>
#include <udis86.h>
#include <pe_lib/pe_bliss.h>
extern "C" {
#include <capstone/capstone.h>
}
#include "virtualmemory.h"
#include "disassemble.h"
#include "analysis.h"
#include "loading.h"
#include "rebuild.h"
#include "structures.h"
#include "emulation.h"

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


Rebuilder::Rebuilder(DisassembleTask *DT, InstructionAnalysis *IA, VirtualMemory *VM, pe_bliss::pe_base *PE, char *FileName) {
	_DT = DT;
	_IA = IA;
	_VM = VM;
	_PE = PE;

	_BL = 0;
	Modified_Addresses = 0;
	CodeEnd = 0;
	CodeStart = 0;
	CodeSize = 0;
	final_chr = 0;

	final_i = 0;
	warp = 0;
	final_size = 0;
	// if our additional code goes into another section.. we have to rebase the entire thing
	// either move the code section, or move data, or whatever...
	Must_Rebase_Section = 0;

	EntryPointInstruction = NULL;

	// setup output filename.. psykoosi.exe = psykoosi_output.exe
	std::strcpy(FileName_output, FileName);
	char *sptr = std::strrchr(FileName_output, '.');
	if (!sptr++) throw;
	std::strcpy(sptr, "_output.exe");

	std::strcpy(this->FileName, FileName);
	vmem = new VirtualMemory;
}

Rebuilder::~Rebuilder() {

	delete vmem;
}

void Rebuilder::SetBinaryLoader(BinaryLoader *BL) {
	_BL = BL;
}

//free these up later...
void Rebuilder::Add_Modified_Address(DisassembleTask::CodeAddr Original_Address, DisassembleTask::CodeAddr New_Address) {
	ModifiedAddresses *mptr = new ModifiedAddresses;
	std::memset(mptr, 0, sizeof(ModifiedAddresses));

	mptr->Original_Address = Original_Address;
	mptr->New_Address = New_Address;

	mptr->next = Modified_Addresses;
	Modified_Addresses = mptr;
}

DisassembleTask::CodeAddr Rebuilder::CheckForModifiedAddress(DisassembleTask::CodeAddr Lookup) {
	for (ModifiedAddresses *mptr = Modified_Addresses; mptr != NULL; mptr = mptr->next) {
		if (mptr->Original_Address == Lookup)
			return mptr->New_Address;
	}
	return 0;
}

int Rebuilder::RebuildInstructionsSetsModifications() {
	DisassembleTask::CodeAddr CurNewAddr = 0;

	DisassembleTask::CodeAddr GHighestSectionAddr = _BL->HighestAddress(0);

	// loop and create a new instruction set with modifications and new addresses...
	 section_list sections(_PE->get_image_sections());
	 DisassembleTask::InstructionInformation *InsInfo = 0;
	 int increase_raw = 0;
	 for(section_list::iterator it = sections.begin(); it != sections.end(); ++it) {
		 section &s = (section &)*it;


		 DisassembleTask::CodeAddr Section_Virtual_Address = s.get_virtual_address();
		 DisassembleTask::CodeAddr HighestSectionAddr = pe_bliss::pe_utils::align_up(GHighestSectionAddr + s.get_size_of_raw_data() + (1024*30), _PE->get_section_alignment());

		 DisassembleTask::CodeAddr LowestSectionAddr = pe_bliss::pe_utils::align_down(HighestSectionAddr, _PE->get_section_alignment());

		 DisassembleTask::CodeAddr New_Section_High = pe_bliss::pe_utils::align_up(s.get_size_of_raw_data() + (1024*30), _PE->get_section_alignment());
/*
		 LowestSectionAddr = 0x407000;
		 if (increase_raw) {
			 uint32_t ptr = s.get_pointer_to_raw_data();
			 ptr += increase_raw;
			 s.set_pointer_to_raw_data(ptr);
		 } else
			 if (s.executable()) {
				 uint32_t size = s.get_size_of_raw_data();
				 size += (1024*30);
				 increase_raw += 1024*30;
				 s.set_virtual_address(LowestSectionAddr);
			 }

*/
			 DisassembleTask::CodeAddr StartAddr = (uint32_t)(s.get_virtual_address() + _PE->get_image_base_32());
			 DisassembleTask::CodeAddr EndAddr = (uint32_t)(_PE->get_image_base_32() + s.get_virtual_address() + s.get_size_of_raw_data());//+ s.get_aligned_virtual_size(_PE->get_file_alignment());
			 DisassembleTask::CodeAddr CurAddr = (uint32_t)( _PE->get_image_base_32() + s.get_virtual_address());

			 if (CurNewAddr > CurAddr) {
				 printf("Section not big enough\n");
				 //Must_Rebase_Section = 1;
			 }


			 CurNewAddr = CurAddr;

			 for (CurAddr = StartAddr; CurAddr <= EndAddr; ) {

				 /*
				 if ((verify = _DT->GetInstructionInformationByAddress(CurAddr, DisassembleTask::LIST_TYPE_NEXT, 1)) != NULL) {
					 a1++;
					 printf("Address %p already in next! Verify %p\n", CurAddr, verify->Address);
				 }
				 if ((verify = _DT->GetInstructionInformationByAddress(CurAddr, DisassembleTask::LIST_TYPE_INJECTED, 1)) != NULL) {
					 a2++;
					 printf("Address %p already in injected! verify %p\n", CurAddr, verify->Address);
				 }
				 if ((verify = _DT->GetInstructionInformationByAddress(CurNewAddr, DisassembleTask::LIST_TYPE_NEXT, 1)) != NULL) {
					 a3++;
					 printf("NEW Address %p already in next! verify %p\n", CurNewAddr, verify->Address);
				 }
				 if ((verify = _DT->GetInstructionInformationByAddress(CurNewAddr, DisassembleTask::LIST_TYPE_INJECTED, 1)) != NULL) {
					 a4++;
					 printf("NEW Address %p already in injected! Verify %p\n", CurNewAddr, verify->Address);
				 }*/

				 //printf("CHECKING %p\n", CurAddr);
				 InsInfo = _DT->GetInstructionInformationByAddress(CurAddr, DisassembleTask::LIST_TYPE_NEXT, 1, InsInfo);

				 // if we cannot find in instruction database.. push forward
				 if (!InsInfo) {
					 //printf("CANNOT FIND %p in first\n", CurAddr);
					 char data[16];
					 _VM->MemDataRead(CurAddr, (unsigned char *)&data, 1);
					 vmem->MemDataWrite(CurNewAddr, (unsigned char *)&data, 1);

					 final_size++;
					 CurAddr++;
					 CurNewAddr++;

					 continue;
				 }

				 DisassembleTask::InstructionInformation *InjInfo;
				 for (InjInfo = InsInfo->InjectedInstructions; InjInfo != NULL; InjInfo = InjInfo->InjectedInstructions) {

					 DisassembleTask::InstructionInformation *NewIns = new DisassembleTask::InstructionInformation;
					 std::memset(NewIns, 0, sizeof(DisassembleTask::InstructionInformation));

					 NewIns->RawData = new unsigned char[InjInfo->Size + 1];
					 std::memcpy(NewIns->RawData, InjInfo->RawData, InjInfo->Size);

					 NewIns->Size = InjInfo->Size;
					 NewIns->FromInjection = 1;
					 NewIns->Priority = 500;

					 NewIns->Address = CurNewAddr;
					 vmem->MemDataWrite(CurNewAddr, (unsigned char *)NewIns->RawData, NewIns->Size);

					 printf("ADDED %p INJECT\n", CurNewAddr);

					 CurNewAddr += NewIns->Size;
					 final_size += NewIns->Size;

					 NewIns->Lists[DisassembleTask::LIST_TYPE_INJECTED] = _DT->Instructions[DisassembleTask::LIST_TYPE_INJECTED];
					 _DT->Instructions[DisassembleTask::LIST_TYPE_INJECTED] = NewIns;
					 warp += NewIns->Size;
				 }

				 if (!InsInfo->Removed) {
					 DisassembleTask::InstructionInformation *NewIns = new DisassembleTask::InstructionInformation;
					 std::memset(NewIns, 0, sizeof(DisassembleTask::InstructionInformation));

					 NewIns->Address = CurNewAddr;
					 NewIns->Original_Address = InsInfo->Address;
					 NewIns->OriginalInstructionInformation = InsInfo;

					 NewIns->RawData = new unsigned char[InsInfo->Size];
					 std::memcpy(NewIns->RawData, InsInfo->RawData, InsInfo->Size);
					 NewIns->Size = InsInfo->Size;

					 NewIns->FromInjection = 0;
					 NewIns->orig = InsInfo->orig;
					 NewIns->IsEntryPoint = InsInfo->IsEntryPoint;
					 NewIns->Priority = InsInfo->Priority;
					 NewIns->OpDstAddress = InsInfo->OpDstAddress;
					 NewIns->Requires_Realignment = InsInfo->Requires_Realignment;
					 NewIns->InsDetail = InsInfo->InsDetail;
					 NewIns->Displacement_Type = InsInfo->Displacement_Type;
					 NewIns->Displacement_Offset = InsInfo->Displacement_Offset;
					 NewIns->IsPointer = InsInfo->IsPointer;

					 std::memcpy((void *)&NewIns->ud_obj, (void *)&InsInfo->ud_obj, sizeof(ud_t));

					 if (InsInfo->InstructionMnemonicString)
						 NewIns->InstructionMnemonicString = InsInfo->InstructionMnemonicString;

					 vmem->MemDataWrite(CurNewAddr, (unsigned char *)NewIns->RawData, NewIns->Size);

					 //printf("ADDED %p INNJECT\n", CurNewAddr);

					 InsInfo->OpDstAddress_realigned = NewIns;

					 NewIns->Lists[DisassembleTask::LIST_TYPE_INJECTED] = _DT->Instructions[DisassembleTask::LIST_TYPE_INJECTED];
					 _DT->Instructions[DisassembleTask::LIST_TYPE_INJECTED] = NewIns;

					 final_size += NewIns->Size;
					 CurNewAddr += NewIns->Size;
				 }

				 CurAddr += InsInfo->Size;
			 }

	 }


	return 1;
}



// this very similar to the code above although that code has to complete before this one can be called..
// just in case something jumps in the past/future... maybe ill put into one function in the future
// once i fully implement backwards references then i can realign the moment the new instruction structure
// is created
int Rebuilder::RealignInstructions() {
	if (Must_Rebase_Section) return 0;

	Emulation emulator(vmem);

	raw_final.clear();
	final_chr = new unsigned char[final_size + 16];

	// loop and create a new instruction set with modifications and new addresses...
	 const section_list sections(_PE->get_image_sections());
	 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
		 const section &s = *it;

		 // should also modify other areas later.. if we end up moving around data etc
		 if (s.executable()) {
			 DisassembleTask::CodeAddr StartAddr = s.get_virtual_address() + _PE->get_image_base_32();
			 DisassembleTask::CodeAddr EndAddr = _PE->get_image_base_32() + s.get_virtual_address() + s.get_size_of_raw_data() + warp;
			 DisassembleTask::CodeAddr CurAddr = StartAddr;
			 DisassembleTask::InstructionInformation *InsInfo = 0;
			 for (; CurAddr < EndAddr; ) {
				 InsInfo = _DT->GetInstructionInformationByAddress(CurAddr, DisassembleTask::LIST_TYPE_INJECTED, 1, InsInfo);

				 // if we cannot find in instruction database.. push forward
				 if (!InsInfo) {
					 char buf[16];
					 vmem->MemDataRead(CurAddr, (unsigned char *)&buf, 1);
					 final_chr[final_i++] = buf[0];
					 raw_final.append((const char *)buf, 1);
					 CurAddr++;
					 //printf("getting byte for %p from vmem\n", CurAddr);
					 continue;
				 }

				 if (InsInfo->FromInjection) {
					 printf("found from injected\n");
				 }

				 // for now lets rebuild the entire thing again.. i might change this (and also only use one function above)
				 /* else if (!InsInfo->Requires_Realignment) {
					 CurAddr += InsInfo->Size;
					 continue;
				 }*/

				 DisassembleTask::InstructionInformation *NewIns = new DisassembleTask::InstructionInformation;
				 std::memset(NewIns, 0, sizeof(DisassembleTask::InstructionInformation));

				 NewIns->Address = CurAddr;
				 NewIns->Original_Address = InsInfo->Original_Address;
				 NewIns->OriginalInstructionInformation = InsInfo->OriginalInstructionInformation;
				 NewIns->InsDetail = InsInfo->InsDetail;

				 NewIns->RawData = new unsigned char[InsInfo->Size];
				 std::memcpy(NewIns->RawData, InsInfo->RawData, InsInfo->Size);

				 if (InsInfo->InstructionMnemonicString)
					 NewIns->InstructionMnemonicString = InsInfo->InstructionMnemonicString;

				 NewIns->Size = InsInfo->Size;

				 NewIns->FromInjection = InsInfo->FromInjection;
				 if (InsInfo->IsEntryPoint) {
					 NewIns->IsEntryPoint = InsInfo->IsEntryPoint;
					 EntryPointInstruction = NewIns;
				 }
				 NewIns->Priority = InsInfo->Priority;
				 NewIns->OpDstAddress = InsInfo->OpDstAddress;
				 NewIns->Requires_Realignment = InsInfo->Requires_Realignment;
				 NewIns->IsPointer = InsInfo->IsPointer;
				 NewIns->orig = InsInfo->orig;

				 // need to realign here....

				 if (1==1 && NewIns->Requires_Realignment && NewIns->OpDstAddress){// && !NewIns->IsPointer) {
					 signed char dist8 = 0;
					 int32_t dist32 = 0;
					//DisassembleTask::CodeAddr ToAddr = 0;



					//ud_operand_t *udop = (ud_operand_t *)ud_insn_opr(&InsInfo->ud_obj, 0);
				 	int32_t distance = _IA->AddressDistance(InsInfo->Address, InsInfo->Size, InsInfo->OpDstAddress, DisassembleTask::LIST_TYPE_INJECTED);
				 	//printf("Comparing %p to %p ptr? %d %d\n", InsInfo->Address, InsInfo->OpDstAddress, InsInfo->IsPointer, distance);

				 	//if (distance != 0) {
				 	if (distance != 0) {//&& InsInfo->Displacement_Type != 0) {

				 		if (InsInfo->orig != distance) {
				 			printf("Realigning instruction [%p] P %d:\nOriginal: ", InsInfo->Address, InsInfo->IsPointer);
				 			_DT->disasm_str(NewIns->Original_Address, ( char *)NewIns->RawData, NewIns->Size);
				 		}

				 		//printf("%p:%d distance %d disp off %d  dtype %d [%p]\n", InsInfo->Address, InsInfo->Size, distance, InsInfo->Displacement_Offset, InsInfo->Displacement_Type, InsInfo->Original_Address);

				 		int bytes = InsInfo->Size - InsInfo->Displacement_Offset;
				 		switch (bytes) {
				 		case 1:
				 			dist8 = (signed) (distance & 0xff);
				 			if ((dist8 > 128) || (dist8 < -128)) {
				 				printf("FUCK distance %d\n", dist8);
				 			}
				 			std::memcpy(NewIns->RawData+NewIns->Size-1, (void *)&dist8, 1);
				 			break;

				 		case 4:
				 			dist32 = (long)(distance&0xffffffff);
				 			if ((dist8 > 1024) || (dist8 < -1024)) {
				 				printf("FUCK %d\n", distance);
				 			}
							std::memcpy(NewIns->RawData+NewIns->Size-4, (void *)&dist32, 4);
							break;

				 		}
				 		//if (InsInfo->orig != distance) printf("CHANGED\n");

				 		//printf("new (supposed to go to %p) orig %d new %d:", InsInfo->OpDstAddress, InsInfo->orig, distance);
				 		if (InsInfo->orig != distance) {
				 			printf("New: ");
				 			_DT->disasm_str(NewIns->Address, (char *)NewIns->RawData, NewIns->Size);
				 		}


				 	}

				 	// mark as done..
					//NewIns->Requires_Realignment = 0;

				 }
				 // end realignment code


				 // copy it into the final buffer for replacingin the section (maybe use virtual memory for this later)
				 raw_final.append((const char *)NewIns->RawData, (short unsigned int)NewIns->Size);
				 std::memcpy(final_chr+final_i, NewIns->RawData, NewIns->Size);
				 final_i += NewIns->Size;

				 // add some logic for injecting before/after/removing original instruction(s)
				 //if (!InjInfo->InjectInstructionsBefore) {}
				 vmem->MemDataWrite(CurAddr, (unsigned char *)NewIns->RawData, NewIns->Size);

				 // now verify it worked!
				 Emulation::EmulationLog *emu_log = emulator.StepInstruction(CurAddr, 13);
				 printf("Emu Log %p\n", emu_log);
				 if (emu_log == NULL) {
					 //__asm int3

				 } else {
				 if (NewIns->Requires_Realignment && !(emu_log->Monitor & Emulation::REG_EIP)) {
					 printf("didnt modify eip?!? wtf?\n");
					 //throw;
				 } else printf("Did modify EIP %p\n", emu_log->Changes->Result&0xffffffff);
				 }

				 NewIns->Lists[DisassembleTask::LIST_TYPE_REBASED] = _DT->Instructions[DisassembleTask::LIST_TYPE_REBASED];
				 _DT->Instructions[DisassembleTask::LIST_TYPE_REBASED] = NewIns;

				 CurAddr += InsInfo->Size;
			 }
		 } else

		 // data section may have pointers.. might have to modify!
		 if (s.get_characteristics() == 0xc0000040 || (strstr((const char *)s.get_name().c_str(),(const char *) ".data") != NULL)) {
			 unsigned char *data_ptr = (unsigned char *)s.get_raw_data().data();
			 int data_size = s.get_size_of_raw_data();
			 int Total = data_size;// / sizeof(DisassembleTask::CodeAddr);


			 DisassembleTask::CodeAddr *Last = 0;
			 DisassembleTask::CodeAddr LastOrig = 0;


			 DisassembleTask::InstructionInformation *InsInfo = 0;
			 for (int ModCount = 0; ModCount < Total; ModCount += 4) {
				 DisassembleTask::CodeAddr *Addr = (DisassembleTask::CodeAddr *)(data_ptr+ModCount);
				 if (*Addr == 0) continue;
				 InsInfo = _DT->GetInstructionInformationByAddressOriginal(*Addr, DisassembleTask::LIST_TYPE_INJECTED, 1, InsInfo);
				 if (InsInfo != NULL) {
					 LastOrig = *Addr;
					 printf("Data Section [%p]: Replacing %p in data section with %p [name: %s]\n", Addr, *Addr, InsInfo->Address, (char *)s.get_name().c_str());

				  	  *Addr = InsInfo->Address;
				 }
			 }
		 }

	 }

	 return 1;

}

// Ensures all of the relocations are known... this should happen before we add our own and redo the list completely
int Rebuilder::ModifyRelocations() {

	// PE has no relocations
	if (!_PE->has_reloc()) return 0;

	printf("ModifyRelocations\n");

	// iterate through the table lists (they each have a different RVA)
	const relocation_table_list tables(get_relocations(*_PE));
	for(relocation_table_list::const_iterator it = tables.begin(); it != tables.end(); ++it) {
		const relocation_table& table = *it;

		// iterate through each section looping for the section that this table belongs to
		section_list sections(_PE->get_image_sections());
		for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			const section &s = *it;

			if ((table.get_rva() >= s.get_virtual_address()) && (table.get_rva() < (s.get_virtual_address() + s.get_virtual_size()))) {
				// found section of this specific relocation table's RVA
				const relocation_table::relocation_list& relocs = table.get_relocations();
				DisassembleTask::InstructionInformation *InsInfo = 0;
				for(relocation_table::relocation_list::const_iterator reloc_it = relocs.begin(); reloc_it != relocs.end(); ++reloc_it) {
					// calculate the address this relocation entry is pointing to..
					DisassembleTask::CodeAddr CodeAddr = (DisassembleTask::CodeAddr)(_PE->get_image_base_32() + (*reloc_it).get_rva() + table.get_rva());
					// and load that instructions structure using its original address (so we can change the RVA of the relocation entry if
					// it was realigned)

					InsInfo = _DT->GetInstructionInformationByAddressOriginal(CodeAddr, DisassembleTask::LIST_TYPE_INJECTED, 0, InsInfo);
					// offset is how many bytes into the instruction that the actual relocation entry modifies
					int offset = 0;
					if (InsInfo) {
						InsInfo->InRelocationTable = 1;
						InsInfo->RelocationType = (*reloc_it).get_type();
						offset = CodeAddr - InsInfo->Original_Address;

						uint16_t NewReloc = (int16_t)(InsInfo->Address - _PE->get_image_base_32() - table.get_rva() + offset);
						// make sure we modify in place... not a new copy
						relocation_entry &at = (relocation_entry &)(*reloc_it);
						at.set_rva(NewReloc);
					}
					//printf("RVA %X Address %p Offset into ins: %d\n", (*reloc_it).get_rva(), InsInfo ? InsInfo->Original_Address : 0, offset);

					//std::cout << "[+] " << (*reloc_it).get_rva() << " type: " << (*reloc_it).get_type() << std::endl << std::endl;
				}
			}
		}

	}

	// TODO: here we need to add in NEW relocation entries for the code that was inserted


	// find a pointer to the relocation section from the data directory
	section &reloc_sect = _PE->section_from_rva(_PE->get_directory_rva(image_directory_entry_basereloc));
	// use pe bliss to rebuild the relocation data directory from the structures we were just enumerating and modifying
    rebuild_relocations(*_PE, tables, reloc_sect, 0, false, false);

	return 1;
}


int Rebuilder::WriteBinaryPE() {
	// If we have to rebase the section.. then we fail
	if (Must_Rebase_Section) return 0;
	final_size = final_i;

	// load the input file again.. (maybe we should keep it in memory from BinaryLoader)
	std::ifstream pe_file(FileName, std::ios::in | std::ios::binary);
	if (!pe_file) {
		std::cout << "Cannot open input file " << FileName << std::endl;
		return 0;
	}

	try {
		int to_increase = 0;
		int changed = 0;
		 const section_list sections(_PE->get_image_sections());
		 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			 section &s = (section &)*it;

			 printf("%p\n", s.get_virtual_address());

		 // should also modify other areas later.. if we end up moving around data etc
		 if (s.executable()) {
			 std::cout << "size: " << final_size << " i " << final_i << " code size " << s.get_size_of_raw_data() << std::endl;

				//s.raw_data_.resize(final_size);
				//s.raw_data_.assign(blah);
			 //s.unmap_virtual();
				//std::memcpy((void *)(s.get_raw_data().data()),(const void *)"hello", 5);
				//s.set_raw_data(blah);
//s.set_size_of_raw_data(final_size);

				//std::cout << "size: " << final_size << " i " << final_i << " code size " << s.get_size_of_raw_data() << std::endl;
				//std::string ah ( "hello" );
				//s.set_raw_data(ah);
			 to_increase += final_size - s.get_size_of_raw_data();
				std::memcpy((void *)s.raw_data_.data(),(const void *) final_chr , final_size);
				//std::memcpy((void *)s.raw_data_.data()+final_size-32,(const void *) "hello",5);
			 //s.set_raw_data(raw_final);
			 s.set_size_of_raw_data(final_size);
			 //s.get_raw_data().resize(final_size);
			 //std::string raw_1 = s.get_raw_data();
			 //char *shit =(char *) raw_1.c_str();
			 //std::memcpy((void *)shit, (void *)raw_final.c_str(), raw_final.size());
			 //s.set_raw_data(std::string((char *)final_chr));
			 //s.set_size_of_raw_data(raw_final.size());
			 changed++;

		 }
		 if (changed > 1) {
			 //s.set_pointer_to_raw_data(s.get_pointer_to_raw_data()+to_increase);
		 }

	}

	std::stringstream temp_pe(std::ios::out | std::ios::in | std::ios::binary);
	new_image = _PE;

	rebuild_pe(*new_image, temp_pe);

	new_image->set_checksum(calculate_checksum(temp_pe));

	std::string base_file_name(FileName);
	std::string::size_type slash_pos;
	if((slash_pos = base_file_name.find_last_of("/\\")) != std::string::npos)
		base_file_name = base_file_name.substr(slash_pos + 1);

	base_file_name = "new_" + base_file_name;
	std::ofstream new_pe_file(base_file_name.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
	if(!new_pe_file) {
		std::cout << "Cannot create output file " << base_file_name << std::endl;
		return -1;
	}

	//new_image->set_stub_overlay("alalalalala alalalala!!! alalalala alalalalalala!!!!!!");

	rebuild_pe(*new_image, new_pe_file);

	} catch(const pe_exception& e) {
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 1;
}


int Rebuilder::WriteBinaryPE2() {
	// If we have to rebase the section.. then we fail
	if (Must_Rebase_Section) return 0;
	final_size = final_i;

	int to_increase = 0;
	// load the input file again.. (maybe we should keep it in memory from BinaryLoader)
	std::ifstream pe_file(FileName, std::ios::in | std::ios::binary);
	if (!pe_file) {
		std::cout << "Cannot open input file " << FileName << std::endl;
		return 0;
	}
	try {
		// create the new image blank
		std::auto_ptr<pe_base> new_image;

		{
			// load the original file
			pe_base image(pe_factory::create_pe(pe_file));

			//Создаем новый пустой образ

			// setup some information on the new image
			new_image.reset(image.get_pe_type() == pe_type_32
				? static_cast<pe_base*>(new pe_base(pe_properties_32(), image.get_section_alignment()))
				: static_cast<pe_base*>(new pe_base(pe_properties_64(), image.get_section_alignment())));

			new_image->set_characteristics(image.get_characteristics());
			new_image->set_dll_characteristics(image.get_dll_characteristics());
			new_image->set_file_alignment(image.get_file_alignment());
			new_image->set_heap_size_commit(image.get_heap_size_commit_64());
			new_image->set_heap_size_reserve(image.get_heap_size_reserve_64());
			new_image->set_stack_size_commit(image.get_stack_size_commit_64());
			new_image->set_stack_size_reserve(image.get_stack_size_reserve_64());
			new_image->set_image_base(image.get_image_base_32());
			new_image->set_ep(image.get_ep());
			new_image->set_number_of_rvas_and_sizes(image.get_number_of_rvas_and_sizes());
			new_image->set_subsystem(image.get_subsystem());
			new_image->set_stub_overlay(image.get_stub_overlay());
			new_image->set_time_date_stamp(image.get_time_date_stamp());
			new_image->set_machine(image.get_machine());
			new_image->set_base_of_code(image.get_base_of_code());
			new_image->set_os_version(image.get_major_os_version(), image.get_minor_os_version());
 			new_image->set_size_of_initialized_data(image.get_size_of_initialized_data());
			new_image->set_size_of_uninitialized_data(image.get_size_of_uninitialized_data());
			new_image->set_linker_version(image.get_minor_linker_version(), image.get_major_linker_version());
			new_image->set_base_of_data(image.get_base_of_data());


			// add directories.. maybe do relocations a diff way
			for(unsigned long i = 0; i < image.get_number_of_rvas_and_sizes(); ++i) {

				// still have to finish this one
				//if (i != image_directory_entry_basereloc && 1==0) {
					new_image->set_directory_rva(i, image.get_directory_rva(i));
					new_image->set_directory_size(i, image.get_directory_size(i));
				//} else {
					// rebuild relocation from our internal structures
				//}
			}

			// add sections from our list..
			{
				for (VirtualMemory::Memory_Section *sptr = _VM->Section_List; sptr != NULL; sptr = sptr->next) {

					printf("name %s chr %x vaddr %p vsize %d ptr %d size %d\n", sptr->Name, sptr->Characteristics,
							sptr->Address,
							sptr->VirtualSize, sptr->RVA, sptr->RawSize);

					section new_section;
					//std::memset(&new_section, 0, sizeof(section));
					new_section.set_characteristics(sptr->Characteristics);
					new_section.set_name(sptr->Name);
					new_section.set_virtual_address(sptr->Address);
					new_section.set_virtual_size(sptr->VirtualSize);
					printf("setting vsize %X\n", sptr->VirtualSize);
					new_section.set_pointer_to_raw_data(sptr->RVA);
					//new_section.set_size_of_raw_data(sptr->RawSize);
					//new_section.set_size_of_raw_data(final_size);
					new_section.get_raw_data().resize(sptr->RawSize);
					//std::string *blah = new std::string((const char *)final_chr, final_size);
					//new_section.set_raw_data(blah);
					//new_section.raw_data_ = *blah;
					//new_section.raw_data_.resize(final_size);
					if (new_section.executable()) {
						printf("doing exe %s\n", sptr->Name);
						std::memcpy((void *)new_section.get_raw_data().data(),(const void *) final_chr , final_size);
						if (final_size > sptr->RawSize) {
							//to_increase = final_size - sptr->RawSize;
						}
					} else {
						printf("doing %s\n", sptr->Name);
						char buffer[sptr->RawSize+1];
						_VM->MemDataRead(sptr->Address + image.get_image_base_32(), (unsigned char *)buffer, sptr->RawSize);
						std::memcpy((void *)new_section.get_raw_data().data(),(const void *)&buffer, sptr->RawSize);
					}
					new_section.set_size_of_raw_data(sptr->RawSize);

			        section& added_section = new_image->add_section(new_section);
			        added_section.set_characteristics(sptr->Characteristics);
			        added_section.set_name(sptr->Name);
			        added_section.set_virtual_address(sptr->Address);
			        added_section.set_virtual_size(sptr->VirtualSize);
			        new_section.set_pointer_to_raw_data(sptr->RVA + to_increase);
	                new_image->set_section_virtual_size(added_section, sptr->VirtualSize);
				}
				/*const section_list& pe_sections = image.get_image_sections();
				for(section_list::const_iterator it = pe_sections.begin(); it  != pe_sections.end(); ++it) {
					new_image->set_section_virtual_size(new_image->add_section(*it), (*it).get_virtual_size());
				}*/
			}
		}


		std::stringstream temp_pe(std::ios::out | std::ios::in | std::ios::binary);
		rebuild_pe(*new_image, temp_pe);

		new_image->set_checksum(calculate_checksum(temp_pe));

		std::string base_file_name(FileName);
		std::string::size_type slash_pos;
		if((slash_pos = base_file_name.find_last_of("/\\")) != std::string::npos)
			base_file_name = base_file_name.substr(slash_pos + 1);

		base_file_name = "new_" + base_file_name;
		std::ofstream new_pe_file(base_file_name.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
		if(!new_pe_file) {
			std::cout << "Cannot create output file " << base_file_name << std::endl;
			return -1;
		}


		rebuild_pe(*new_image, new_pe_file);

		} catch(const pe_exception& e) {
			std::cout << "Error: " << e.what() << std::endl;
			return -1;
		}

}
