/*
 * polymorph.cpp
 *
 * psykoosi's polymorph engine...
 * The duties of this class is to take an instruction, or several instructions and rewrite them using
 * other instructions which will devise the same output using the x86_emulate function from XEN.
 *
 * This module is a necessity to perform obfuscation on machine code to bypass anti virus, and other
 * engines which are put in place to detect backdoor(s).  This could also be used to obfuscate
 * server side security so that it protects the protocols of the inject3ed security mechanisms.
 *  Created on: Oct 22, 2014
 *      Author: mike
 */


#include <cstddef>
#include <iostream>
#include <cstring>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <pe_lib/pe_bliss.h>
#include <fstream>
#include "virtualmemory.h"
#include "disassemble.h"
#include "analysis.h"
#include "apiproxy_client.h"
#include "loading.h"
#include "rebuild.h"
#include "structures.h"

#include "polymorph.h"
extern "C" {
#include <unistd.h>
}

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


Polymorph::Polymorph() {

}

Polymorph::~Polymorph() {
}

/* stub:
void *Polymorph_Replacement_(void *Original) {
	DisassembleTask::InstructionInformation *InsInfo = (DisassembleTask::InstructionInformation *)Original;
	DisassembleTask::InstructionInformation *ReplaceIns = NULL;
	void *ret = NULL;



	ret = (void *)ReplaceIns;

	return ret;
}
 */

DisassembleTask::InstructionInformation *Polymorph_New_Instruction(DisassembleTask::InstructionInformation *Original, char *AsmCode, int Size) {
	DisassembleTask::InstructionInformation *ReplaceIns = NULL;

	// now build our replacement instruction
	ReplaceIns = new DisassembleTask::InstructionInformation;
	memset(ReplaceIns, 0, sizeof(DisassembleTask::InstructionInformation));

	ReplaceIns->Address = Original->Address;
	ReplaceIns->RawData = (unsigned char *)AsmCode;
	ReplaceIns->Size = Size;
	ReplaceIns->FromInjection = 1;
	ReplaceIns->OriginalInstructionInformation = Original;
	ReplaceIns->Requires_Realignment = Original->Requires_Realignment;

	return ReplaceIns;

}

// takes a push instruction and replaces it with another set of semi-random instructions
DisassembleTask::InstructionInformation *Polymorph_Replacement_Push(DisassembleTask::InstructionInformation *Original) {
	DisassembleTask::InstructionInformation *InsInfo = (DisassembleTask::InstructionInformation *)Original;
	DisassembleTask::InstructionInformation *ReplaceIns = NULL;
	DisassembleTask::InstructionInformation *ret = NULL;
	unsigned char *asmcode = NULL;
	int size = 0;

	// for things that have to be modified due to injections .. dont modify it for now
	// *** later we need to make a log if we want to modify this instruction.. and it should be calculated
	// during the last pass as we are finalizing all of the addresses after injections/modifications`
	if (Original->Requires_Realignment) return NULL;

	// if it uses a register then we dont want to touch..
	// ** we should create a separate function for moving data within registers directly into the stack
	// and decreasing the stack pointer.. this would be the best polymorph for pushing a register or address
	if (InsInfo->_InsDetail.x86.operands[0].type == X86_OP_REG) return NULL;

	// also for now we wont deal with pushing memory addresses (pointers?)
	if (InsInfo->_InsDetail.x86.operands[0].type == X86_OP_MEM) return NULL;

	// lets just do some simple pushes fo rnow
	//if (InsInfo->OpDstAddress > 0x00020000) continue;

	// allocate original bytes * 16 (just in case we do up to 16 new instructions..
	// *** this needs to be calculated for any production release
	asmcode = new unsigned char[Original->Size * 16];

	// verify opdstaddress == push value
	printf("creating a replacement polymorph instruction for %X\n", InsInfo->OpDstAddress);

	int r = rand()%3;

	unsigned long value1 = 0, value2 = 0, value3 = 0, value4 = 0;
	unsigned long r_split = 0;

	switch (r) {
		case 0:
			// split in half
			// split in half.. and take into account that its possible to have a remainder...
			value1 = InsInfo->OpDstAddress / 2;
			value2 = (InsInfo->OpDstAddress / 2) + (InsInfo->OpDstAddress % 2);
			asmcode[0] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+1)) = value1;
			asmcode[5] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+6)) = value2;
			break;
		case 1:
			// spit in quarters
			// split in half
			// split in half.. and take into account that its possible to have a remainder...
			value1 = value2 = value3 = InsInfo->OpDstAddress / 4;
			value4 = value1 + (InsInfo->OpDstAddress % 4);
			asmcode[0] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+1)) = value1;
			asmcode[5] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+6)) = value2;
			asmcode[10] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+13)) = value3;
			asmcode[15] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+16)) = value4;
			break;
		case 2:
			// split randomly between the number of  bytes in two chunks
			r_split = rand() % InsInfo->OpDstAddress;
			value1 = r_split;
			value2 = r_split + (InsInfo->OpDstAddress % r_split);
			asmcode[0] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+1)) = value1;
			asmcode[5] = 0x68;
			*(unsigned int *)((unsigned char *)(asmcode+6)) = value2;
			break;
		case 3:
			// use subtraction and addition randomly to get the final value
			// do this later *** MIKE
			break;

	}

	ReplaceIns = Polymorph_New_Instruction(Original, (char *)asmcode, size);
	ret = ReplaceIns;

	return ret;
}

DisassembleTask::InstructionInformation *Polymorph_Replacement_Add(DisassembleTask::InstructionInformation *Original) {
	return NULL;
	DisassembleTask::InstructionInformation *InsInfo = (DisassembleTask::InstructionInformation *)Original;
	DisassembleTask::InstructionInformation *ReplaceIns = NULL;
	DisassembleTask::InstructionInformation *ret = NULL;

	// find the amount this instruction  is adding to whatever register/memory location


	ret = ReplaceIns;

	return ret;
}

struct _instruction_types {
	char *type_str;
	DisassembleTask::InstructionInformation *(*func)(DisassembleTask::InstructionInformation *);

} InstructionTypes[] = {
		//{ "add", &Polymorph_Replacement_Add },
		{ "push", &Polymorph_Replacement_Push },
		//{ "call", &Polymorph_Call },
		{ NULL, NULL }
};

static int a = 0;

// Analyze an instruction and determine a semi-random replacement.. should call the emulator afterwards to ensure
// throughout the set it actually handles the data the same
DisassembleTask::InstructionInformation *Polymorph::InstructionReplace(DisassembleTask::InstructionInformation *Original) {
	if (!Original || !Original->Size) return NULL;


	printf("checking %s\n", Original->InstructionMnemonicString->c_str());
	DisassembleTask::InstructionInformation *ReplaceIns = NULL;


	// check the type of instruction
	for (int ii = 0; InstructionTypes[ii].type_str != NULL; ii++) {
		if ((Original->InstructionMnemonicString->length()) && strstr((const char *)Original->InstructionMnemonicString->c_str(), (const char *)InstructionTypes[ii].type_str) != NULL) {
			if (++a > 30) return NULL;
			// try to replace the instruction
			ReplaceIns = (DisassembleTask::InstructionInformation *)(*InstructionTypes[ii].func)(Original);
			printf("Polymorph Replace %p\n", ReplaceIns);
			break;
		}
	}

	return ReplaceIns;
}
