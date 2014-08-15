#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <fstream>
#include <string>
#include <inttypes.h>
#include <udis86.h>
#include <pe_lib/pe_bliss.h>
#include "virtualmemory.h"
extern "C" {
#include <capstone/capstone.h>
}
#include "disassemble.h"

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;

// 64k pages...
#define PAGE_SIZE 4096*2*2*2*2


DisassembleTask::DisassembleTask(VirtualMemory *_VM)
{

	DCount = 0;


	JUMP_SIZE = 1024*1024;

	Loaded_from_Cache = 0;

	Instructions = (InstructionInformation **)new InstructionInformation[LIST_TYPE_MAX];
	for (int i = 0; i < LIST_TYPE_MAX; i++)
		Instructions[i] = NULL;

	Instructions_Jump = (InstructionInformation **)new InstructionInformation[JUMP_SIZE];
	for (int i = 0; i < JUMP_SIZE; i++)
		Instructions_Jump[i] = NULL;

	EngineHandle = NULL;

	HighestCode = 0;
	vmem = _VM;

	// open disassembler handle (later we need to give ability to switch  modes, etc.. or use other disassemblers)
	if (cs_open(CS_ARCH_X86, CS_MODE_32, (csh *)&EngineHandle) != CS_ERR_OK)
	  throw;// exception("Cannot initialize disassembler framework");

	cs_option((csh)EngineHandle, CS_OPT_DETAIL, CS_OPT_ON);
	//cs_option((csh)EngineHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
}

DisassembleTask::~DisassembleTask()
{
	cs_close((csh *)&EngineHandle);
  
	Clear_Instructions();
}

void DisassembleTask::SetPEHandle(pe_base *_PE) {
	PE_Handle = _PE;
}


int DisassembleTask::InstructionsCount(int type) {
	int count = 0;
	DisassembleTask::InstructionInformation *iptr;

	for (iptr = Instructions[type]; iptr != NULL; iptr = iptr->Lists[type]) {
		count++;
	}

	return count;
}


void DisassembleTask::SetBinaryLoaderHA(CodeAddr Addr) {
	HighestCode = Addr;
}


// removes a range of addresses from the instruction list
int DisassembleTask::DeleteAddressRange(CodeAddr Address, int Size, int priority) {
	int CountDeleted = 0;
	CodeAddr CurrentAddress = Address;

	while (CurrentAddress < (Address + Size)) {
		CountDeleted += DeleteInstruction(NULL, CurrentAddress, 0,  priority);
		CurrentAddress++;
	}

	return CountDeleted;
}

// removes an instruction structure by its pointer, or address
int DisassembleTask::DeleteInstruction(InstructionInformation *InsInfoPtr, CodeAddr Address, int strict, int priority) {
	int CurrentList = 0;
	InstructionInformation *InsInfo = NULL;
	InstructionInformation *iptr = NULL, *iptr2 = NULL;

	for (CurrentList = LIST_TYPE_NEXT; CurrentList < LIST_TYPE_MAX; CurrentList++) {
		// if we didnt get a pointer.. find it
		if (!InsInfoPtr && Address) {
			InsInfo = GetInstructionInformationByAddress(Address, CurrentList, strict, InsInfo);
		} else {
			// else we have the pointer.. no need to lookup
			InsInfo = InsInfoPtr;
		}

		if (!InsInfo) continue;

		if (InsInfo->Lists[CurrentList] == NULL) continue;

		if (InsInfo) {
			// free various data in the structures
			if (InsInfo->RawData) {
				delete InsInfo->RawData;
				InsInfo->RawData = NULL;
			}
			if (InsInfo->DisFrameworkIns != NULL) {
				//cs_free(InsInfo->DisFrameworkIns, 1);
				InsInfo->DisFrameworkIns = NULL;
			}
				delete InsInfo->InstructionMnemonicString;
			if (InsInfo->InstructionMnemonicString != NULL) {
				InsInfo->InstructionMnemonicString = NULL;
			}

			// start at top of list
			iptr = Instructions[CurrentList];
			// if it is the beginning.. just set to next
			if (iptr == InsInfo) {
				Instructions[CurrentList] = InsInfo->Lists[CurrentList];
			//	printf("Removed %p from main\n", InsInfo);
			} else {
				// find it by looking through the list
				while (iptr != InsInfo) {
					// make sure to keep the last node (so when we find we push last -> next)
					iptr2 = iptr;
					// move to next node to check for it
					iptr = iptr2->Lists[CurrentList];
				}
				// did we find it?
				if (iptr == InsInfo) {
					// we should always have a last node since it wasnt first!
					if (iptr2 == NULL) throw;
					// make sure the last node goes to the next one from this one we are removing
					iptr2->Lists[CurrentList] = InsInfo->Lists[CurrentList];
					//printf("Removed %p from list iptr2 %p main %p\n", InsInfo, iptr2, InsInfo->Lists[CurrentList]);
					break;
				}
				InsInfo->Lists[CurrentList] = NULL;
			}

		} // end that we have a pointer, or found the pointer for the node to remove

	} // end for loop for each current list

	// did we find the node.. or have it?
	if (InsInfo != NULL) {
		delete InsInfo;
		return 1;
	}

	return 0;
}


int DisassembleTask::SetCurrentListAsListType(int type) {
	int Count = 0;
	InstructionInformation *InsInfoPtr = Instructions[LIST_TYPE_NEXT];

	// ensure we have a list, and they arent using NEXT/PREV (which would memory leak, and makes no sense)
	if (InsInfoPtr == NULL || type == LIST_TYPE_NEXT || type == LIST_TYPE_PREV) return 0;

	InsInfoPtr->Lists[type] = NULL;
	Instructions[type] = NULL;
	do {
		InsInfoPtr->Lists[type] = Instructions[type];
		Instructions[type] = InsInfoPtr;
		InsInfoPtr = InsInfoPtr->Lists[LIST_TYPE_NEXT];
		Count++;
	} while (InsInfoPtr);

	return Count;
}


int DisassembleTask::DisassembleSingleInstruction(CodeAddr Address, InstructionInformation **InsInfo, int priority)
{
		InstructionInformation *InsPtr = this->GetInstructionInformationByAddress(Address, LIST_TYPE_JUMP, 1, NULL);

		// maybe return 0 and have it keep going.. returning 1 so it thinks it worked
		if (InsPtr != NULL) {
			//std::cout << "FOUND Addr" << Address << " old priority " << InsPtr->Priority << " new " << priority << std::endl;
			if (InsPtr->Priority >= priority) {
				*InsInfo = InsPtr;
				return 1;
			}
		}

		char Data[64];
		cs_insn *DisFrameworkIns = 0;
		vmem->MemDataRead(Address, (unsigned char *)&Data, 32);

		//disasm_str(Address, (char *)Data, 13);
		size_t count = cs_disasm_ex((csh)EngineHandle, (const unsigned char *)&Data, 32, Address, 0, &DisFrameworkIns);

		if (!count)
				return 0;


		if (InsPtr) {
			DeleteAddressRange(Address, DisFrameworkIns->size, priority);
			//DeleteInstruction(InsPtr, Address, 1, priority);
		}

		// since we are going to support other disaassemble engines.. lets transfer the information to
		// a particular structure we can use throughout our applications
		InstructionInformation *pInfo = new InstructionInformation;
		std::memset(pInfo, 0, sizeof(InstructionInformation));

		ud_init(&pInfo->ud_obj);
		ud_set_mode(&pInfo->ud_obj, 32);
		ud_set_syntax(&pInfo->ud_obj, UD_SYN_INTEL);
		ud_set_pc(&pInfo->ud_obj, Address);
	    ud_set_input_buffer(&pInfo->ud_obj,(const unsigned char *) &Data, 13);
	    int len = ud_disassemble(&pInfo->ud_obj);



		pInfo->DisFrameworkIns = DisFrameworkIns;


		pInfo->InsDetail = (cs_detail *)&pInfo->_InsDetail;
		std::memcpy((void *)&pInfo->_InsDetail, (void *)DisFrameworkIns->detail, sizeof(cs_detail));


		pInfo->OpDstAddress = pInfo->InsDetail->x86.disp;//Address + DisFrameworkIns->size + pInfo->InsDetail->x86.disp;
		pInfo->Address = DisFrameworkIns[0].address;
		pInfo->Original_Address = pInfo->Address;

		pInfo->Size = DisFrameworkIns[0].size;
		//printf("Added %p Size: %d\n", pInfo->Address, pInfo->Size);
		pInfo->InstructionMnemonicString = new std::string(DisFrameworkIns[0].mnemonic);

		// ensure pinfo has access to the raw data
		pInfo->RawData = new unsigned char[DisFrameworkIns[0].size];
		std::memcpy(pInfo->RawData,(const void *) &Data, DisFrameworkIns[0].size);
		int dtype = 0;
		switch (pInfo->InsDetail->x86.eaDisplacement) {
			case EA_DISP_NONE: dtype = 0; break;
			case EA_DISP_8: dtype = 8; break;
			case EA_DISP_16: dtype = 16; break;
			case EA_DISP_32: dtype = 32; break;
			default: dtype = 100; break;
		}
		pInfo->Displacement_Type = dtype;
		if (pInfo->InsDetail->x86.disp_offset)
			pInfo->Displacement_Offset = pInfo->InsDetail->x86.disp_offset;
		else if (pInfo->InsDetail->x86.imm_offset)
			pInfo->Displacement_Offset = pInfo->InsDetail->x86.imm_offset;

		if (pInfo->Displacement_Offset == 255)
			pInfo->Displacement_Offset = pInfo->InsDetail->x86.imm_offset;

		/*
 printf("Address %X Displacement Offset %d Disp %X Imm Offset %d  disp type %d\n",Address, pInfo->InsDetail->x86.disp_offset,
				 pInfo->InsDetail->x86.disp,
				 (uint8_t)pInfo->InsDetail->x86.imm_offset, dtype);
			for (int i = 0; i < pInfo->InsDetail->x86.op_count;i++) {
				uint32_t disp = pInfo->InsDetail->x86.operands[i].mem.disp;
				uint32_t disp2 = pInfo->InsDetail->x86.operands[i].imm;
				printf("Op %d disp %X disp2 \n", i, disp, disp2);
			}
			printf("hex:");for (int a =0; a < len; a++) { printf("%02X", (unsigned char)Data[a]); }printf("\n");

			disasm_str(Address, (char *)Data, len);
		for (int a = 0; a < pInfo->Size; a++) printf("%02X", (unsigned char)pInfo->RawData[a]);printf("\n");
*/

		cs_free(DisFrameworkIns, 1);
		DCount++;
		*InsInfo = pInfo;
		return 1;
}

std::string DisassembleTask::disasm_str(CodeAddr Address, char *data, int len) {
	    ud_t ud_obj;
	    int i;
	    //char Data[13];

	    //vmem->MemDataRead(Address, (unsigned char *)data, len);

	    ud_init(&ud_obj);

	    ud_set_mode(&ud_obj, 32);
	    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	    ud_set_pc(&ud_obj, Address);

	    // a single instruction has the max length of 13
	    ud_set_input_buffer(&ud_obj, (const unsigned char *)data, len);


	    if ((len = ud_disassemble(&ud_obj)) > 0) {
	        int size = ud_insn_len(&ud_obj);

	        std::cout << "[" << Address << ":" << size << "] " << ud_insn_asm(&ud_obj) << std::endl;

	        if (std::strcmp(ud_insn_asm(&ud_obj), "invalid")==0)
	        	return std::string("");
	        else
	            return std::string(ud_insn_asm(&ud_obj));
	    }

	    return std::string("");
	}

int DisassembleTask::RunDisassembleTask(CodeAddr StartAddress, int priority, int MaxRawSize, int MaxInstructions)
{
	CodeAddr CurAddr = StartAddress;
	int DisassembledInstructionCount = 0;
	int CurrentRawPosition = 0;
	int TaskComplete = 0;
	InstructionInformation *InsInfo  = 0;
	int DisassembleRet = 0;



	std::cout << "Disasm Task: " << StartAddress << "Priority: " << static_cast<int>(priority) << "max raw: " << MaxRawSize << " Max Instructions: " << MaxInstructions << std::endl;
	// loop and disassemble a section of instructions (example: code section)
	do {
		InsInfo = 0;
		DisassembleRet = DisassembleSingleInstruction(CurAddr, &InsInfo, priority);
		//printf("Disasm ret %d CurAddr %p priority %d InsInfo %p\n", DisassembleRet, CurAddr, priority, InsInfo);

//		if (!(CurAddr % 100))
			std::cout << "\r" << CurAddr;

		if (HighestCode > 0 && (CurAddr&0xffffffff) >= (HighestCode&0xffffffff)) {
			std::cout << "\rhigh break: " << CurAddr << " highest " << HighestCode << std::endl;
			break;
		}

		int is_executable = 0;
		 const section_list sections(PE_Handle->get_image_sections());
		 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			 const section &s = *it;

			 if (

					 ((uint32_t)CurAddr >= (uint32_t)((PE_Handle->get_image_base_32() + s.get_virtual_address()) &&
					 ((uint32_t)CurAddr < (uint32_t)((PE_Handle->get_image_base_32() + s.get_virtual_address() + s.get_virtual_size())))))) {

				 if (s.executable())
					 is_executable = 1;

				 break;
			 }
		 }

		 if (!is_executable) break;


		/*
		// If priority.. its not a linear scan.. and this instruction didn't disassemble.. lets stop
		if (!DisassembleRet && priority) {
			CurAddr++;
			continue;
			std::cout << "break" << std::endl;
			break;
		}*/

		// If no priority.. its a linear scan.. we should probably just keep pushing forward to get what we can..
		// we can do some sort of alignment testing later.. and just give it a higher priority..
		if (!InsInfo) {
			CurAddr++;
			CurrentRawPosition++;
		} else {
			DisassembledInstructionCount++;
			CurAddr += InsInfo->Size;
			CurrentRawPosition += InsInfo->Size;

			if (!InsInfo->Priority) {
				InsInfo->Priority = priority;

				//printf("Adding %p [old = %p]\n", InsInfo, Instructions[LIST_TYPE_NEXT]);
				// insert instruction into linked list.. last in, first out system.. we will lookup by
				// addresses later so its irrelevant to be in order... and during rebuild it'll get
				// inserted directly in correct order regardless
				InsInfo->Lists[LIST_TYPE_NEXT] = Instructions[LIST_TYPE_NEXT];
				//Instructions[LIST_TYPE_NEXT]->Lists[LIST_TYPE_PREV] = InsInfo;
				Instructions[LIST_TYPE_NEXT] = InsInfo;

				// jump table to speed up finding it
				InsInfo->Lists[LIST_TYPE_JUMP] = Instructions_Jump[InsInfo->Address % JUMP_SIZE];
				Instructions_Jump[InsInfo->Address % JUMP_SIZE] = InsInfo;
				//printf("Adding %p [old = %p] ins %p\n", InsInfo, InsInfo->Lists[LIST_TYPE_NEXT], Instructions[LIST_TYPE_NEXT]);
			}
		}


		if ((MaxInstructions && (DisassembledInstructionCount > MaxInstructions)) ||
				(CurrentRawPosition > MaxRawSize))
			TaskComplete = 1;
	} while (!TaskComplete);

	std::cout << "\rFinished Disassemble Task" << std::endl;


	return DisassembledInstructionCount;
}


// return the structure relating to a specific address if it exists
DisassembleTask::InstructionInformation *DisassembleTask::GetInstructionInformationByAddress(CodeAddr Address, int type, int strict, InstructionInformation *LastPtr) {

	if (LastPtr && Loaded_from_Cache && LastPtr->Lists[type] != NULL && LastPtr->Lists[type]->Address==Address) return LastPtr->Lists[type];

	if (type == LIST_TYPE_JUMP) {
		for (InstructionInformation *InsInfoPtr = Instructions_Jump[Address % JUMP_SIZE]; InsInfoPtr != NULL; InsInfoPtr = InsInfoPtr->Lists[LIST_TYPE_JUMP]) {
			if (InsInfoPtr->Address == Address ||
				(!strict && ((Address >= InsInfoPtr->Address)
						&& (Address < InsInfoPtr->Address + InsInfoPtr->Size)))) {
				return InsInfoPtr;
			}
		}
		return NULL;
	}


	for (InstructionInformation *InsInfoPtr = Instructions[type]; InsInfoPtr != NULL; InsInfoPtr = InsInfoPtr->Lists[type]) {
		//if (type== LIST_TYPE_INJECTED)printf("InsInfoPtr: Type %d Info Addresss %p [Looking for %p]\n", type, InsInfoPtr->Address, Address);
		// find by address...
		// if we have an injection.. and it wants to takeover all of the calls of the address we injected it at...
		if (InsInfoPtr->Address == Address  && InsInfoPtr->FromInjection && InsInfoPtr->CatchOriginalRelativeDestinations) {
				return InsInfoPtr;
		}

		if (InsInfoPtr->Address == Address ||
			// if not strict.. then we determine if the address lands on this instruction whatsoever
			(!strict && ((Address >= InsInfoPtr->Address)
					&& (Address < InsInfoPtr->Address + InsInfoPtr->Size)))) {
			//if (type==DisassembleTask::LIST_TYPE_INJECTED) printf("Found %p\n", Address);
			// winner winner chicken dinner
			return InsInfoPtr;
		}
	}
/*
	while (InsInfoPtr != NULL) {
		// find by address...
		if (InsInfoPtr->Address == Address ||
			// if not strict.. then we determine if the address lands on this instruction whatsoever
			(!strict && ((Address >= InsInfoPtr->Address)
					&& (Address <= InsInfoPtr->Address + InsInfoPtr->Size)))) {
			// winner winner chicken dinner
			return InsInfoPtr;
		}

		// move to next element of this list type
		//printf("1 %p %p type %d\n", InsInfoPtr, InsInfoPtr->Lists[type], type);
		InsInfoPtr = InsInfoPtr->Lists[type];
	};
*/
	return NULL;
}

// return the structure relating to a specific address if it exists
DisassembleTask::InstructionInformation *DisassembleTask::GetInstructionInformationByAddressOriginal(CodeAddr Address, int type, int strict, InstructionInformation *LastPtr) {

	if (LastPtr && Loaded_from_Cache && LastPtr->Lists[type] != NULL && LastPtr->Lists[type]->Original_Address == Address) return LastPtr->Lists[type];

	if (type == LIST_TYPE_JUMP) {
		for (InstructionInformation *InsInfoPtr = Instructions_Jump[Address % JUMP_SIZE]; InsInfoPtr != NULL; InsInfoPtr = InsInfoPtr->Lists[LIST_TYPE_JUMP]) {
			if (InsInfoPtr->Original_Address == Address ||
				(!strict && ((Address >= InsInfoPtr->Address)
						&& (Address < InsInfoPtr->Original_Address + InsInfoPtr->Size)))) {
				return InsInfoPtr;
			}
		}
		return NULL;
	}

	for (InstructionInformation *InsInfoPtr = Instructions[type]; InsInfoPtr != NULL; InsInfoPtr = InsInfoPtr->Lists[type]) {
		//if (type== LIST_TYPE_INJECTED)printf("InsInfoPtr: Type %d Info Addresss %p [Looking for %p]\n", type, InsInfoPtr->Address, Address);
		// find by address...

		// if we have an injection.. and it wants to takeover all of the calls of the address we injected it at...
		/*if (InsInfoPtr->Address == Address  && InsInfoPtr->FromInjection && InsInfoPtr->CatchOriginalRelativeDestinations) {
				return InsInfoPtr;
		}*/


		if ((InsInfoPtr->Original_Address == Address ||
			// if not strict.. then we determine if the address lands on this instruction whatsoever
			(!strict && ((Address >= InsInfoPtr->Original_Address)
					&& (Address < InsInfoPtr->Original_Address + InsInfoPtr->Size))))) {
			// winner winner chicken dinner
			return InsInfoPtr;
		}
	}

	return NULL;
}

void DisassembleTask::Clear_Instructions() {
	for (int i = 0; i < LIST_TYPE_MAX; i++) {

		if (Instructions[i] != NULL) {
			InstructionInformation *iptr = Instructions[i], *iptr2;
			do {
				iptr2 = iptr->Lists[i];

				delete iptr->InstructionMnemonicString;
				delete iptr->RawData;
				//cs_free(iptr->DisFrameworkIns, 1);
				delete iptr;

				iptr = iptr2;
			} while (iptr);

		}
	}
}



int DisassembleTask::Cache_Save(char *filename) {
	if (Instructions[LIST_TYPE_NEXT] == NULL) return 0;

	std::ofstream qcout(filename, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!qcout) return 0;


	uint32_t header = 0xD15A55;
	qcout.write((char *)&header, sizeof(uint32_t));

	// loop and create a new instruction set with modifications and new addresses...
	 const section_list sections(PE_Handle->get_image_sections());
	 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
		 const section &s = *it;

		 // should also modify other areas later.. if we end up moving around data etc
		 if (s.executable()) {

			 DisassembleTask::CodeAddr StartAddr = s.get_virtual_address() + PE_Handle->get_image_base_32();
			 DisassembleTask::CodeAddr EndAddr = PE_Handle->get_image_base_32() + s.get_virtual_address() + s.get_size_of_raw_data();
			 DisassembleTask::CodeAddr CurAddr = StartAddr;

			 DisassembleTask::InstructionInformation *InsInfo = 0;

			 for (; CurAddr < EndAddr; ) {
				 InsInfo = GetInstructionInformationByAddress(CurAddr, DisassembleTask::LIST_TYPE_JUMP, 1, InsInfo);

				 // if we cannot find in instruction database.. push forward
				 if (!InsInfo) {
					 CurAddr++;
					 continue;
				 }

				 InstructionInformation *qptr = InsInfo;

				 char mnemonic[32];

				if (!qptr->Size) throw;

				qcout.write((char *)qptr, sizeof(InstructionInformation));

				if ( qptr->InstructionMnemonicString->size() > 32) throw;

				std::memcpy((void *)&mnemonic, qptr->InstructionMnemonicString->data(), qptr->InstructionMnemonicString->size() > 32 ? 32 : qptr->InstructionMnemonicString->size());


				qcout.write((char *)&mnemonic, 32);
				if (qptr->Size > 13) throw;

				qcout.write((char *)qptr->RawData, qptr->Size);

				CurAddr += qptr->Size;
			 }
		}
	 }

	qcout.close();


	return 1;
}


int DisassembleTask::Cache_Load(char *filename) {
	int count = 0;
		InstructionInformation *qptr, *last = NULL;

		std::ifstream qcin(filename, std::ios::in | std::ios::binary);
		if (!qcin) return 0;

		uint32_t header = 0xD15A55;
		uint32_t verify = 0;
		qcin.read((char *)&verify, sizeof(uint32_t));
		if (header != verify) {
			//printf("Cache header fail!\n");
			throw;
			return 0;
		}

		Clear_Instructions();

		while (!qcin.eof()) {
			char mnemonic[32];

			qptr = new InstructionInformation;
			qcin.read((char *)qptr, sizeof(InstructionInformation));
			for (int i = 0; i < LIST_TYPE_MAX; i++) qptr->Lists[i] = NULL;

			qcin.read((char *)&mnemonic, 32);
			qptr->InstructionMnemonicString = new std::string(mnemonic);

			qptr->RawData = new unsigned char[qptr->Size];
			qcin.read((char *)qptr->RawData, qptr->Size);
			//std::memcpy((void *)qptr->RawData, ins_raw, qptr->Size);

			if (last == NULL) {

				//qptr->Lists[LIST_TYPE_NEXT] = Instructions[LIST_TYPE_NEXT];

				Instructions[LIST_TYPE_NEXT] = last = qptr;
			} else {
				last->Lists[LIST_TYPE_NEXT] = qptr;
				last = qptr;
			}
			count++;
		}

		if (count) Loaded_from_Cache = 1;
		qcin.close();
		printf("Loaded %d from file\n", count);
}
