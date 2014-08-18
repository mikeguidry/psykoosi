#include <cstddef>
#include <iostream>
#include <cstring>
#include <fstream>
#include <string>
#include <stdio.h>
#include <inttypes.h>
#include <pe_lib/pe_bliss.h>
extern "C" {
#include <capstone/capstone.h>
}
#include "virtualmemory.h"
#include "disassemble.h"
#include "analysis.h"

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


InstructionAnalysis::InstructionAnalysis(DisassembleTask *Dism_Handle) {
	Disassembler_Handle = Dism_Handle;
	Analysis_Queue_List = Analysis_Queue_Last = NULL;
	CallCount = 0;
	PushCount = 0;
	RealignCount = 0;
}

void InstructionAnalysis::SetPEHandle(pe_base *_PE) {
	PE_Handle = _PE;
}

InstructionAnalysis::~InstructionAnalysis() {
	// remove any queue memory
	AnalysisQueue *qptr = Analysis_Queue_List, *qptr2 = NULL;
	while (qptr != NULL) {
		qptr2 = qptr->next;
		delete qptr;
		qptr = qptr2;
	}
}

long InstructionAnalysis::InstructionAddressDistance(DisassembleTask::CodeAddr Address, int Size, DisassembleTask::InstructionInformation *second) {
	long diff = 0;

	if (!Address || !second) return 0;

	// start at the end of the instruction
	diff = Address + Size;

	return second->Address - diff;
}

long InstructionAnalysis::AddressDistance(DisassembleTask::CodeAddr first, int Size, DisassembleTask::CodeAddr second, int type) {
	DisassembleTask::InstructionInformation *FirstPtr;
	DisassembleTask::InstructionInformation *SecondPtr;
	DisassembleTask::InstructionInformation *SecondPtrInj;

	type = 0;


	FirstPtr = Disassembler_Handle->GetInstructionInformationByAddressOriginal((DisassembleTask::CodeAddr)first, type, 1, NULL);
	SecondPtr = Disassembler_Handle->GetInstructionInformationByAddressOriginal((DisassembleTask::CodeAddr)second, type, 1, NULL);
	SecondPtrInj = Disassembler_Handle->GetInstructionInformationByAddress((DisassembleTask::CodeAddr)second, DisassembleTask::LIST_TYPE_REBASED, 1, NULL);

	//std::cout << "FirstPtr: " << static_cast<void *>(FirstPtr) << " " << first << " SecondPtr: " << static_cast<void *>(SecondPtr) << " " << second << std::endl;
	printf("FirstPtr Addr %p Addr2 %p - %p %p cannot find it!\n", first, second, FirstPtr, SecondPtr);
	if (!SecondPtr) {
		//printf("FirstPtr fail 1 %p:%d %p %p\n", first, Size, FirstPtr, SecondPtr);
		return 0;
	}

	if (FirstPtr != NULL)
	  FirstPtr = FirstPtr->OpDstAddress_realigned;

	// if our injected function wants control over what it has taken over!
	if (SecondPtrInj) {
		//printf("Second Ptr %p inj %d catch %d\n",SecondPtrInj->Address, SecondPtrInj->FromInjection, SecondPtrInj->CatchOriginalRelativeDestinations);
		if (SecondPtrInj->FromInjection == 1 && SecondPtrInj->CatchOriginalRelativeDestinations == 1) {
			return InstructionAddressDistance(first, Size, SecondPtrInj);
		}
	}

	SecondPtr = SecondPtr->OpDstAddress_realigned;
	if (!SecondPtr) {
		//printf("FirstPtr fail 2 Address %p:%d - %p %p\n", first, Size,FirstPtr, SecondPtr);
			return 0;
		}

	// if no change...
	//if (SecondPtr->Original_Address == SecondPtr->Address) return 0;

	return InstructionAddressDistance(first, Size, SecondPtr);
}

int InstructionAnalysis::QueueAddressForDisassembly(CodeAddr Address, int Priority, int Max_Instructions, int Max_Bytes, int Redo) {
	AnalysisQueue *qptr = Analysis_Queue_List;
	while (qptr != NULL) {
		if (qptr->Address == Address) break;
		qptr = qptr->next;
	}
	if (qptr != NULL) {
		if (!Redo) return 0;
		qptr->Already_Analyzed = 0;
		return 1;
	}

	qptr = new AnalysisQueue;
	std::memset(qptr, 0, sizeof(AnalysisQueue));
	qptr->Address = Address;
	qptr->Priority = Priority;
	qptr->Max_Instructions = Max_Instructions;
	qptr->Max_Bytes = Max_Bytes;

	if (Analysis_Queue_Last) {
		Analysis_Queue_Last->next = qptr;
		Analysis_Queue_Last = qptr;
	} else {
		Analysis_Queue_List = Analysis_Queue_Last = qptr;
	}
	//qptr->next = Analysis_Queue_List;
	//Analysis_Queue_List = qptr;

	return 1;
}

void InstructionAnalysis::CleanInstructionAnalysis() {
	for (DisassembleTask::InstructionInformation *InsInfo = Disassembler_Handle->Instructions[DisassembleTask::LIST_TYPE_NEXT]; InsInfo != NULL; InsInfo = InsInfo->Lists[DisassembleTask::LIST_TYPE_NEXT]) {
		InsInfo->Requires_Realignment = 0;
		InsInfo->OpDstAddress = 0;
		InsInfo->IsCall = 0;
		InsInfo->IsPush = 0;
		InsInfo->IsEntryPoint = 0;
		InsInfo->AnalysisCount = 0;
		InsInfo->Analyzed = 0;
		InsInfo->IsPointer = 0;
		//InsInfo->Priority = 0;
		InsInfo->InRelocationTable = 0;
		InsInfo->orig = 0;
	}
	AnalysisQueue *qptr = Analysis_Queue_List;
		while (qptr != NULL) {
			qptr->Already_Analyzed = 0;

			qptr = qptr->next;
		}
}
int InstructionAnalysis::AnalyzeInstruction(DisassembleTask::InstructionInformation *InsInfo) {
	// these are the instructions for x86 that have to be realigned...
	// make this modular later to handle other architectures!
	const char *realign[] = { "call","jmp","jz","jnz","jbe","jle","jge","ja","jb","js","jl","jg","jnp","jo","jns","jp","jecxz","push", "jne","je", NULL};
	char *AssemblyCodeString = 0;
	DisassembleTask::CodeAddr DestAddr = 0;

	if (!InsInfo) return 0;

	//printf("Analyze Instruction %p\n", InsInfo->Address);

	// analyzed an instruction and determines properties like where it might jmp, or call...
	// whether it needs to add things into the queue... etc.. anything we need should be handled here

	// obtain ANSI string
	AssemblyCodeString = (char *)InsInfo->InstructionMnemonicString->c_str();
	// first lets check if it should be realigned later...


	if (!InsInfo->Analyzed) {
		InsInfo->Analyzed = 1;

		// change this later so it only executes once!
		uint32_t EntryPoint = PE_Handle->get_image_base_32() + PE_Handle->get_ep();

		//printf("ERROR Analyzing %p\n", InsInfo->Address);

		if (InsInfo->Address == EntryPoint) InsInfo->IsEntryPoint = 1;

		for (int n = 0; realign[n] != NULL; n++) {
			if (strstr(AssemblyCodeString, realign[n]) != NULL || (strstr(ud_insn_asm(&InsInfo->ud_obj), realign[n]))) {
				InsInfo->Requires_Realignment = 1;
				RealignCount++;
				break;
			}
		}

		// we need to add function level analysis here.. to find functions (push ebp, mov ebp, esp, ... ret)
		// also for x64... this will help us figure out any alignment issues later through analysis
	}

	InsInfo->AnalysisCount++;

	if (!InsInfo->Requires_Realignment) {
		return 1;
	}

	/*
	if (ud_insn_opr(&InsInfo->ud_obj, 1) != NULL) {
		InsInfo->Requires_Realignment = 0;
		return 1;
	}*/




	// Here's we we find which instructions need to be aligned.. i started so nice but ended up really sloppy
	// and feeding off of TWO libraries!  Capstone wont give me the offset like udis86 does! I have to either
	// modify capstone or find another solution (brute force?).. need a perm solution for all architectures
	// maybe i can go backwards from the last byte of the instruction and determine from the instruction
	// or i can learn more about ModRM and calulate it properly ;)
	DisassembleTask::CodeAddr ToAddr = 0;
	signed char baby = 0;
	uint16_t boy = 0;
	uint32_t man = 0;

	const ud_operand_t *udop = ud_insn_opr(&InsInfo->ud_obj, 0);
	if (udop) {
		switch (udop->size) {
			case 8:
				baby = (signed char)udop->lval.sbyte;
				ToAddr =  baby;
				break;
			case 16:
				boy = (udop->lval.sword & 0xffff);
				ToAddr = boy;
				break;
			case 32:
				man = (udop->lval.sdword);
				ToAddr = man;
				break;
		}
		if (udop->type == UD_OP_MEM) InsInfo->IsPointer = 1;
		else if (udop->type == UD_OP_IMM) InsInfo->IsImmediate = 1;
	}

	if (InsInfo->_InsDetail.x86.operands[0].type != X86_OP_REG) {
		if (InsInfo->_InsDetail.x86.operands[0].type ==X86_OP_IMM) {
			DestAddr = (uint32_t)InsInfo->_InsDetail.x86.operands[0].imm;
			InsInfo->IsImmediate = 1;

		} else if (InsInfo->_InsDetail.x86.operands[0].type == X86_OP_MEM) {
			DestAddr = (uint32_t)InsInfo->_InsDetail.x86.operands[0].mem.disp;
			InsInfo->IsPointer = 1;

		} else if (InsInfo->_InsDetail.x86.disp) {
			DestAddr = (uint32_t)InsInfo->_InsDetail.x86.disp;
		}
	}

	//printf("[%p] ERROR Addr %p\n", InsInfo->Address, DestAddr);

	// Check if both engines match each other....
	/*if (InsInfo->OpDstAddress && InsInfo->OpDstAddress != ToAddr) {
		//	std::cout << "Error on this instruction: " << InsInfo->Address << std::endl;
		//	std::cout << "InsInfo " << InsInfo->Address << " Capstone " << InsInfo->OpDstAddress <<" ToAddr " << ToAddr << std::endl;
	}*/


		/* // if we found in udis86 and not capstone.. use udis86
		 if (!found && found2) {
			 InsInfo->OpDstAddress = ToAddr;
		 }*/


		 // some various addresses that were giving me trouble probably due to type conversions for sure
		 /*
		 if ((found == 0 && found2 == 0) || InsInfo->OpDstAddress == 0xFFFFFFFF || InsInfo->OpDstAddress < 8196
				 || InsInfo->OpDstAddress > 0xff000000) {
			 //InsInfo->OpDstAddress = 0;
		 }*/

	// Copy the raw destination out in case we want to verify it (match against OpDstAddress or ToAddr)
	signed char dist8 = 0;
	long dist32 = 0;
	long which;
	int bytes = InsInfo->Size - InsInfo->Displacement_Offset;
	switch (bytes) {
		case 1:
			std::memcpy((void *)&dist8, InsInfo->RawData + InsInfo->Size - 1, 1);
			which = dist8;
			break;

		case 4:
			std::memcpy((void *)&dist32, InsInfo->RawData + InsInfo->Size - 4, 4);
			which = dist32;
			break;

	}

	uint32_t newaddr = ((InsInfo->Address + InsInfo->Size) - which) & 0xff;
	uint32_t newaddr2 = ((InsInfo->Address + InsInfo->Size) + ToAddr) & 0xffffffff;


	DestAddr = newaddr2;
	//if (InsInfo->IsPointer)
	//printf("[%p:%d] %d \"%s\" which %X Orig goes to: %p [got %p] %d %ld %d\n", InsInfo->Address, InsInfo->Size,InsInfo->IsPointer, AssemblyCodeString, which, newaddr, InsInfo->OpDstAddress, dist8, dist32, ToAddr);
	//printf("[%p:%d] %d \"%s\" which %X Orig goes to: %p [got %p] [%s] %d\n", InsInfo->Address, InsInfo->Size, InsInfo->IsPointer, AssemblyCodeString, which, newaddr2, InsInfo->OpDstAddress, (char *)Disassembler_Handle->disasm_str(InsInfo->Address,(char *) InsInfo->RawData, InsInfo->Size).c_str(), ToAddr);
	InsInfo->orig = ToAddr;

	int found = 0, found2 = 0;
	// Ensure the address is within one of our sections & executable
	if (DestAddr) {
		 const section_list sections(PE_Handle->get_image_sections());
		 for(section_list::const_iterator it = sections.begin(); it != sections.end(); ++it) {
			 const section &s = *it;
			 DisassembleTask::CodeAddr SecStart = (DisassembleTask::CodeAddr)(PE_Handle->get_image_base_32() + s.get_virtual_address());
			 DisassembleTask::CodeAddr SecEnd = (DisassembleTask::CodeAddr)(PE_Handle->get_image_base_32() + s.get_virtual_address() + s.get_size_of_raw_data());

			 if (((uint32_t)(DestAddr) > (uint32_t)(0x4000)) && ((uint32_t)DestAddr >= SecStart && ((uint32_t)DestAddr < SecEnd))) {
				 if (s.executable()) {
					 InsInfo->OpDstAddress = DestAddr;
					 found = 1;
				 }
			 }

			 if ((which >= SecStart) && (which < SecEnd)) {
				 ToAddr = DestAddr = which;
				 InsInfo->IsImmediate = 1;
				 found2 = 1;
			 } else {
				 if ((ToAddr > 0x4000) && (ToAddr < 0xefff0000) &&
						 ((uint32_t)ToAddr >= SecStart) &&
						 ((uint32_t)ToAddr < SecEnd)) {
					 if (s.executable()) {
						 found2 = 1;
						 break;
					 }
				 }
			 }

			 if (found || found2) break;
		 }
	}

	if (InsInfo->IsImmediate && !found2) {
		InsInfo->IsImmediate = 0;
	}
	if (found || found2) InsInfo->OpDstAddress = DestAddr;


	// various other checks..
	if (strstr((const char *)AssemblyCodeString,(const char *) "push")) {
		PushCount++;
		InsInfo->IsPush = 1;
		if ((ud_insn_opr(&InsInfo->ud_obj, 2) != NULL)) {// || ((ToAddr < 0x4000) || (ToAddr > 0xefffff0000))) {
			//printf("Removing %p toaddr %p point %d %s\n", InsInfo->Original_Address, ToAddr, InsInfo->IsPointer, (char *)Disassembler_Handle->disasm_str(InsInfo->Address,(char *) InsInfo->RawData, InsInfo->Size).c_str());
			//printf("push %p not found %p\n", InsInfo->Address, DestAddr);
			InsInfo->Requires_Realignment = 0;
			InsInfo->OpDstAddress = 0;
			InsInfo->orig = 0;
		} else {
			//printf("ERROR push %p %X found %p - %d %d %p [op count%d]\n", InsInfo->Address, which, ToAddr, DestAddr, found, found2, ud_insn_opr(&InsInfo->ud_obj, 1));
			//InsInfo->OpDstAddress = ((InsInfo->Address + InsInfo->Size) + which) & 0xffffffff;
			//printf("ERROR push %X %p %p found %p - %d %d %p [[%X]]\n", which, InsInfo->Address, ToAddr, DestAddr, found, found2, ud_insn_opr(&InsInfo->ud_obj, 1), InsInfo->OpDstAddress&0xffffffff);
			InsInfo->OpDstAddress = ToAddr;
		}
	}

	if (strstr((const char *)AssemblyCodeString,(const char *) "call")) {
		CallCount++;
		InsInfo->IsCall = 1;
		if ((ud_insn_opr(&InsInfo->ud_obj, 2) != NULL)) {// || ((ToAddr < 0x4000) || (ToAddr > 0xefffff0000))) {
			//printf("Removing %p toaddr %p point %d - %s\n", InsInfo->Original_Address, ToAddr, InsInfo->IsPointer, (char *)Disassembler_Handle->disasm_str(InsInfo->Address,(char *) InsInfo->RawData, InsInfo->Size).c_str());

			InsInfo->Requires_Realignment = 0;
			InsInfo->OpDstAddress = 0;
			InsInfo->orig = 0;
		}
	}

	// If it's in the code section.. and a call or a push.. then we should queue it for analysis
	// just in case it leads us to other branches
	if (found == 1 && ((InsInfo->IsCall || InsInfo->IsPush))) {
		//Queue(Addr Of Ins Dest, Current Priority, 50 instructions max, 0 bytes max, redo?);
		QueueAddressForDisassembly(InsInfo->OpDstAddress, InsInfo->Priority, 500, 0, 0);
	}

	return 1;
}


int InstructionAnalysis::Queue_Clear() {
	AnalysisQueue *qptr = Analysis_Queue_List, *qptr2 = 0;

	while (qptr != NULL) {

		qptr2 = qptr->next;

		delete qptr;

		qptr = qptr2;

	}

	Analysis_Queue_List = NULL;

	return 1;
}

int InstructionAnalysis::QueueCache_Load(char *filename) {
	AnalysisQueue *qptr;
	int n;

	Queue_Clear();

	std::ifstream qcin(filename, std::ios::in | std::ios::binary);
	if (!qcin) return 0;

	qcin.read((char *)&n, sizeof(int));
	CallCount = n;
	qcin.read((char *)&n, sizeof(int));
	PushCount = n;
	qcin.read((char *)&n, sizeof(int));
	RealignCount = n;

	while (!qcin.eof()) {
		qptr = new AnalysisQueue;
		qcin.read((char *)qptr, sizeof(AnalysisQueue));

		qptr->next = Analysis_Queue_List;

		Analysis_Queue_List = qptr;
	}

	qcin.close();

	return 1;
}

int InstructionAnalysis::QueueCache_Save(char *filename) {
	AnalysisQueue *qptr = Analysis_Queue_List;

	if (qptr == NULL) return 0;

	std::ofstream qcout(filename, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!qcout) return 0;

	qcout.write((char *)&CallCount, sizeof(int));
	qcout.write((char *)&PushCount, sizeof(int));
	qcout.write((char *)&RealignCount, sizeof(int));

	while (qptr != NULL) {
		qcout.write((char *)qptr,sizeof(Analysis_Queue_List));

		qptr = qptr->next;
	}

	qcout.close();

	return 1;
}



// loops through queue till it completes...
int InstructionAnalysis::Complete_Analysis_Queue(int redo) {
	int Max_Address_Not_Found = 50;
	int TotalAnalyzedCount = 0;
	int AnalyzedCount = 0;
	do {

		//printf("Complete analysis\n");
		AnalyzedCount = 0;
		AnalysisQueue *qptr = Analysis_Queue_List;

		while (qptr != NULL) {
			std::cout << "Analysis on: " << static_cast<uint32_t>(qptr->Address) << " Max Bytes: " << qptr->Max_Bytes << " " << std::endl;
			if (redo || !qptr->Already_Analyzed) {
				if (qptr->Count++ > 5) break;
				//std::cout << "Analyse first time";

				// run a disassembler task on this address with a max of 20 instructions...
				int CountToAnalyze = Disassembler_Handle->RunDisassembleTask(qptr->Address, qptr->Priority, qptr->Max_Bytes, qptr->Max_Instructions);
				//std::cout << "EROR Count  " + CountToAnalyze << std::endl;
				// then we need to reanalyze the instructions it disassembled
				CodeAddr AnalyzeAddr = qptr->Address;
				while (CountToAnalyze--) {
					// so obtain a pointer to the instruction information
					printf("AnalyzeAddr %p\n", AnalyzeAddr);
					DisassembleTask::InstructionInformation *InsInfo = Disassembler_Handle->GetInstructionInformationByAddress(AnalyzeAddr, DisassembleTask::LIST_TYPE_NEXT, 1, NULL);
					if (!InsInfo) {
						std::cout << "ERROR Address not found: " << AnalyzeAddr << std::endl;
						if (!Max_Address_Not_Found--) {
							std::cout << "We hit the limit of 100 on this queue.. moving on" << std::endl;
							break;
						}
						// this should never happen.. the instruction should exist if it returned the count saying it added it
						AnalyzeAddr++;
						continue;
					} else {
						//std::cout << "ERROR Found in cache " << AnalyzeAddr << std::endl;
					}
					// and analyze it (because it may relate to other previous unknown addresses
					// which also have to be queued...
					AnalyzeInstruction(InsInfo);

					// Increase AnalyzeAddr to the next instruction
					AnalyzeAddr += InsInfo->Size;
				}

				AnalyzedCount++;
				qptr->Already_Analyzed = 1;
			}

			qptr = qptr->next;
		}
		TotalAnalyzedCount += AnalyzedCount;
		if (!AnalyzedCount) break;
	} while (AnalyzedCount);
	std::cout << "Analyzed Total: " << TotalAnalyzedCount << std::endl;
	return TotalAnalyzedCount;
}
