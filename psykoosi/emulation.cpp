/*
 * emulation.cpp
 *
 * This will contain code for emulating machine code for various purposes.  We can use it for
 * verification of our own engine.  We can use it later for finding similar code for obfuscation..etc.
 *
 * I will start with using XEN's x86_emulate() code... this will have to be rewrote later if used
 * commercially.
 *
 *  Created on: Aug 11, 2014
 *      Author: mike guidry
 */


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
#include "xen/x86_emulate.h"
}
#include "disassemble.h"
#include "emulation.h"

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


VirtualMemory *_VM2 = NULL;

static int emulated_read(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	 //struct x86_emulate_ctxt *sh_ctxt = ctxt;
//VirtualMemory *_VM = (VirtualMemory *)ctxt;

	    printf("read seg %d offset %X data %X bytes %d ctxt %p\n", seg, offset, p_data, bytes, ctxt);

	    _VM2->MemDataRead(offset,(unsigned char *) p_data, bytes);

	    return X86EMUL_OKAY;

}

static int emulated_write(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
//	VirtualMemory *_VM = (VirtualMemory *)ctxt;
	    printf("write seg %d offset %X data %p bytes %d ctxt %p\n", seg, offset, p_data, bytes, ctxt);

	    _VM2->MemDataWrite(offset,(unsigned char *) p_data, bytes);

	    return X86EMUL_OKAY;

}


Emulation::Emulation(VirtualMemory *_VM) {
	VM = _VM2 = _VM;
	LogList = NULL;

	std::memset((void *)&emulate_ops, 0, sizeof(struct hack_x86_emulate_ops));

	emulate_ops.read = (void *)&emulated_read;
	emulate_ops.insn_fetch = (void *)&emulated_read;
	emulate_ops.write = (void *)&emulated_write;

}


Emulation::~Emulation() {

}

void Emulation::DeleteMemoryAddresses(MemAddresses  *mptr) {
	MemAddresses *mptr2 = NULL;
	for (; mptr != NULL;) {
		mptr2 = mptr->next;
		delete mptr;
		mptr = mptr2;
	}
}

void Emulation::ClearLogEntry(EmulationLog *log) {
	EmulationLog *lptr = LogList, *lptr2 = NULL;
	RegChanges *rptr = NULL, *rptr2 = NULL;


	if (lptr == NULL) return;

	for (rptr = lptr->Changes; rptr != NULL; rptr = rptr->next) {
		delete rptr;
	}

	DeleteMemoryAddresses(lptr->Read);
	DeleteMemoryAddresses(lptr->Wrote);

	if (LogList == log) {
		LogList = log->next;
	} else {
		while (lptr != log) {
			lptr2 = lptr->next;
			lptr = lptr->next;
		}
		if (lptr == NULL)
			// shouldnt ever happen
			throw;

		lptr2->next = log->next;

	}
	delete log;
}

void Emulation::ClearLogs() {
	while (LogList != NULL) {
		ClearLogEntry(LogList);
	}
}

Emulation::EmulationLog *Emulation::StepInstruction(CodeAddr Address, int Max_Size) {
	EmulationLog *ret = NULL;

	// initialize registers and context..
	//if (emulation_ctx.addr_size == 0) {
		emulation_ctx.addr_size = 32;
		emulation_ctx.sp_size = 32;
		emulation_ctx.regs = &registers;

		// copy to last so we know changes!
		std::memcpy(&registers_last, &registers, sizeof(cpu_user_regs_t));
	//}

	registers.eip = Address;


	int r = x86_emulate(&emulation_ctx, (const x86_emulate_ops *)&emulate_ops) == X86EMUL_OKAY;
	if (!r) {
		last_successful = 0;
		return NULL;
	} else
		last_successful = 1;


	ret = CreateLog();
	std::memcpy(&registers_last, &registers, sizeof(cpu_user_regs_t));

	return ret;
}

Emulation::RegChanges *Emulation::CreateChangeEntry(Emulation::RegChanges **changelist, int which, unsigned char *orig,
		unsigned char *cur, int size) {
	RegChanges *change = new RegChanges;

	std::memset(change, 0, sizeof(RegChanges));


	switch (size) {
		case sizeof(uint32_t):
			uint32_t orig_32, new_32;
			std::memcpy(&orig_32, orig, sizeof(uint32_t));
			std::memcpy(&new_32, cur, sizeof(uint32_t));
			std::memcpy(&change->RawResult, cur, sizeof(uint32_t));
			change->Type |= (new_32 > orig_32) ? CHANGE_INCREASE : CHANGE_DECREASE;
			change->Result = new_32;
			break;
		case sizeof(uint16_t):
			uint16_t orig_16, new_16;
			std::memcpy(&orig_16, orig, sizeof(uint16_t));
			std::memcpy(&new_16, cur, sizeof(uint16_t));
			std::memcpy(&change->RawResult, cur, sizeof(uint16_t));
			change->Type |= (new_16 > orig_16) ? CHANGE_INCREASE : CHANGE_DECREASE;
			change->Result = new_16;
			break;
		case sizeof(uint8_t):
			uint8_t orig_8, new_8;
			std::memcpy(&orig_8, orig, sizeof(uint8_t));
			std::memcpy(&new_8, cur, sizeof(uint8_t));
			std::memcpy(&change->RawResult, cur, sizeof(uint8_t));
			change->Type |= (new_8 > orig_8) ? CHANGE_INCREASE : CHANGE_DECREASE;
			change->Result = new_8;
			break;
	}

	change->Register = which;
	change->next = *changelist;
	*changelist = change;

	return change;
}

Emulation::EmulationLog *Emulation::CreateLog() {
	EmulationLog *logptr;
	int Monitor = 0;

	if (!last_successful) return NULL;

	logptr = new EmulationLog;

	std::memset(logptr, 0, sizeof(EmulationLog));


	logptr->Address = registers_last.eip;
	// this might change if it changes EIP jmp,call,etc.. should grab from the database...
	logptr->Size = registers.eip - registers_last.eip;

	if (registers.eip != registers_last.eip) {
		Monitor |= REG_EIP;
		printf("changed eip %d %p -> %p\n", Monitor & REG_EIP, registers_last.eip, registers.eip);
		CreateChangeEntry(&logptr->Changes, REG_EIP, (unsigned char *)&registers_last.eip,  (unsigned char *)&registers.eip, sizeof(uint32_t));
	}
	if (registers.eax != registers_last.eax) {
		Monitor |= REG_EAX;
		printf("changed eax %X %X %d\n", registers_last.eax, registers.eax, Monitor & REG_EAX);
		CreateChangeEntry(&logptr->Changes, REG_EAX,  (unsigned char *)&registers_last.eax, (unsigned char *) &registers.eax, sizeof(uint32_t));
	}
	if (registers.ebx != registers_last.ebx) {
		Monitor |= REG_EBX;
		CreateChangeEntry(&logptr->Changes, REG_EBX, (unsigned char *)&registers_last.ebx, (unsigned char *) &registers.ebx, sizeof(uint32_t));
	}
	if (registers.ecx != registers_last.ecx) {
		Monitor |= REG_ECX;
		CreateChangeEntry(&logptr->Changes, REG_ECX, (unsigned char *) &registers_last.ecx, (unsigned char *) &registers.ecx, sizeof(uint32_t));
	}
	if (registers.edx != registers_last.edx) {
		Monitor |= REG_EDX;
		CreateChangeEntry(&logptr->Changes, REG_EDX, (unsigned char *) &registers_last.edx, (unsigned char *) &registers.edx, sizeof(uint32_t));
	}
	if (registers.esp != registers_last.esp) {
		Monitor |= REG_ESP;
		CreateChangeEntry(&logptr->Changes, REG_ESP,  (unsigned char *)&registers_last.esp,  (unsigned char *)&registers.esp, sizeof(uint32_t));
	}
	if (registers.ebp != registers_last.ebp) {
		Monitor |= REG_EBP;
		CreateChangeEntry(&logptr->Changes, REG_EBP,  (unsigned char *)&registers_last.ebp, (unsigned char *) &registers.ebp, sizeof(uint32_t));
	}
	if (registers.esi != registers_last.esi) {
		Monitor |= REG_ESI;
		CreateChangeEntry(&logptr->Changes, REG_ESI,  (unsigned char *)&registers_last.esi,  (unsigned char *)&registers.esi, sizeof(uint32_t));
	}
	if (registers.edi != registers_last.edi) {
		Monitor |= REG_EDI;
		CreateChangeEntry(&logptr->Changes, REG_EDI,  (unsigned char *)&registers_last.edi, (unsigned char *) &registers.edi, sizeof(uint32_t));
	}
	if (registers.eflags != registers_last.eflags) {
		Monitor |= REG_EFLAGS;
		CreateChangeEntry(&logptr->Changes, REG_EFLAGS, (unsigned char *) &registers_last.eflags,  (unsigned char *)&registers.eflags, sizeof(uint32_t));
	}
	if (registers.cs != registers_last.cs) {
		Monitor |= REG_CS;
		CreateChangeEntry(&logptr->Changes, REG_CS, (unsigned char *) &registers_last.cs, (unsigned char *) &registers.cs, sizeof(uint16_t));
	}
	if (registers.es != registers_last.es) {
		Monitor |= REG_ES;
		CreateChangeEntry(&logptr->Changes, REG_ES, (unsigned char *) &registers_last.es,  (unsigned char *)&registers.es, sizeof(uint16_t));
	}
	if (registers.ds != registers_last.ds) {
		Monitor |= REG_DS;
		CreateChangeEntry(&logptr->Changes, REG_DS,  (unsigned char *)&registers_last.ds,  (unsigned char *)&registers.ds, sizeof(uint16_t));
	}
	if (registers.fs != registers_last.fs) {
		Monitor |= REG_FS;
		CreateChangeEntry(&logptr->Changes, REG_FS, (unsigned char *) &registers_last.fs, (unsigned char *) &registers.fs, sizeof(uint16_t));
	}
	if (registers.gs != registers_last.gs) {
		Monitor |= REG_GS;
		CreateChangeEntry(&logptr->Changes, REG_GS, (unsigned char *) &registers_last.gs, (unsigned char *) &registers.gs, sizeof(uint16_t));
	}
	if (registers.ss != registers_last.ss) {
		Monitor |= REG_SS;
		CreateChangeEntry(&logptr->Changes, REG_SS,  (unsigned char *)&registers_last.ss, (unsigned char *) &registers.ss, sizeof(uint16_t));
	}

	// duh! we need it in our structure!
	logptr->Monitor = Monitor;

	logptr->next = LogList;
	LogList = logptr;

}
