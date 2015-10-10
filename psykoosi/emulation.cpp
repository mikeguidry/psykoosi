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


VirtualMemory *_VM2[MAX_VMS];
Emulation *EmuPtr[MAX_VMS];
Emulation::EmulationThread *EmuThread[MAX_VMS];


static int address_from_seg_offset(enum x86_segment seg, unsigned long offset, struct _x86_emulate_ctxt *ctxt) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];
	Emulation::EmulationThread *emuthread = EmuThread[thread->ID];

	unsigned long _seg = 0;
	uint32_t result = 0;
/*
 * x86_seg_cs,
    x86_seg_ss,
    x86_seg_ds,
    x86_seg_es,
    x86_seg_fs,
    x86_seg_gs,

 */
	switch (seg) {
		case x86_seg_cs:
			_seg = emuthread->registers.cs;
			break;
		case x86_seg_ss:
			_seg = emuthread->registers.ss;
			break;
		case x86_seg_ds:
			_seg = emuthread->registers.ds;
			break;
		case x86_seg_es:
			_seg = emuthread->registers.es;
			break;
		case x86_seg_fs:
			_seg = emuthread->registers.fs;
			break;
		case x86_seg_gs:
			_seg = emuthread->registers.gs;
			break;
		default:
			break;
	}
	result = _seg + offset;

	return result;
}


static int emulated_rep_movs(enum x86_segment src_seg,unsigned long src_offset,enum x86_segment dst_seg, unsigned long dst_offset,unsigned int bytes_per_rep,unsigned long *reps,struct _x86_emulate_ctxt *ctxt) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];
	unsigned long bytes_to_copy = *reps * bytes_per_rep;

    printf("vm %p rep movs src seg %d offset %x dst seg %d offset %d bytes per %d reps %d id %d ctxt %p\n", _VM2[0],
    		src_seg, src_offset, dst_seg, dst_offset, bytes_per_rep, *reps,  ctxt);

    unsigned char *data = new unsigned char [bytes_to_copy];

	pVM->MemDataRead(address_from_seg_offset(src_seg,src_offset,ctxt), (unsigned char *) data, bytes_to_copy);
	pVM->MemDataWrite(address_from_seg_offset(dst_seg, dst_offset,ctxt), (unsigned char *)data, bytes_to_copy);

	delete data;

	return X86EMUL_OKAY;
}



static int emulated_write(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];

	printf("vm %p write seg %d offset %X data %p bytes %d ctxt %p\n", _VM2[0], seg, offset, p_data, bytes, ctxt);

	pVM->MemDataWrite(address_from_seg_offset(seg,offset,ctxt),(unsigned char *) p_data, bytes);

    return X86EMUL_OKAY;
}



static int emulated_cmpxchg(enum x86_segment seg,unsigned long offset,void *p_old,void *p_new,unsigned int bytes,
    struct _x86_emulate_ctxt *ctxt) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];

	printf("vm %p cmpxchg seg %d offset %x old %p new %p bytes %d ctxt %p\n", seg, offset, p_old, p_new, bytes, ctxt);

	pVM->MemDataWrite(address_from_seg_offset(seg,offset,ctxt),(unsigned char *) p_new, bytes);

	return X86EMUL_OKAY;
}


static int emulated_read_helper(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt, int fetch_insn) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];

    printf("vm %p read seg %d offset %X data %X bytes %d ctxt %p id %d ptr %p\n", _VM2[0], seg, offset, p_data, bytes, ctxt,
	    		thread->ID, ctxt);
	pVM->MemDataRead(address_from_seg_offset(seg,offset,ctxt),(unsigned char *) p_data, bytes);

	return X86EMUL_OKAY;
}

static int emulated_read(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	return emulated_read_helper(seg, offset, p_data, bytes, ctxt, 0);
}
static int emulated_read_fetch(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	return emulated_read_helper(seg, offset, p_data, bytes, ctxt, 1);
}


Emulation::Emulation(VirtualMemory *_VM) {
	for (int i = 0; i < MAX_VMS; i++) {
		_VM2[i] = NULL;
		EmuPtr[i] = NULL;
		EmuThread[i] = NULL;
	}

	VM = _VM2[0] = _VM;
	EmuPtr[0] = this;
	EmuThread[0] = &Master;
	Master.LogList = NULL;
	// count of virtual machines and incremental ID
	Current_VM_ID = 0;
	// current VM being executed...
	VM_Exec_ID = 0;

	// default settings for virtual memory logging
	Global_ChangeLog_Read = 0;
	Global_ChangeLog_Write = 0;
	Global_ChangeLog_Verify = 0;

	std::memset((void *)&Master.emulate_ops, 0, sizeof(struct hack_x86_emulate_ops));
	std::memset((void *)&Master.thread_ctx, 0, sizeof(struct _x86_thread));

	Master.emulate_ops.read = (void *)&emulated_read;
	Master.emulate_ops.insn_fetch = (void *)&emulated_read_fetch;
	Master.emulate_ops.write = (void *)&emulated_write;
	Master.emulate_ops.rep_movs = (void *)&emulated_rep_movs;
	Master.emulate_ops.cmpxchg = (void *)&emulated_cmpxchg;

	Master.thread_ctx.ID = 0;
	Master.thread_ctx.emulation_ctx.addr_size = 32;
	Master.thread_ctx.emulation_ctx.sp_size = 32;
	Master.thread_ctx.emulation_ctx.regs = &Master.registers;

	// grabbed these from entry point on an app in IDA pro.. (after dlls+tls etc all loaded
	SetRegister(&Master, REG_EAX, 0);
	SetRegister(&Master, REG_EBX, 0x7FFDE000);
	SetRegister(&Master, REG_ECX, 0x0012FFB0);
	SetRegister(&Master, REG_EDX, 0x7C90E514);
	SetRegister(&Master, REG_ESI, 0);
	SetRegister(&Master, REG_EDI, 0);
	SetRegister(&Master, REG_EBP, 0x0012FFF0);
	SetRegister(&Master, REG_EBP, 0x0012FFC4);

	CopyRegistersToShadow(&Master);


}


Emulation::~Emulation() {

	for (int i = Current_VM_ID; i > 0; i++) {
		//destroy vm one at a time
	}
}

void Emulation::DeleteMemoryAddresses(MemAddresses  *mptr) {
	MemAddresses *mptr2 = NULL;
	for (; mptr != NULL;) {
		mptr2 = mptr->next;
		delete mptr;
		mptr = mptr2;
	}
}

void Emulation::ClearLogEntry(EmulationThread *thread, EmulationLog *log) {
	EmulationLog *lptr = thread->LogList, *lptr2 = NULL;
	RegChanges *rptr = NULL, *rptr2 = NULL;


	if (lptr == NULL) return;

	for (rptr = lptr->Changes; rptr != NULL; rptr = rptr->next) {
		delete rptr;
	}

	DeleteMemoryAddresses(lptr->Read);
	DeleteMemoryAddresses(lptr->Wrote);

	if (thread->LogList == log) {
		thread->LogList = log->next;
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

void Emulation::ClearLogs(EmulationThread *thread) {
	while (thread->LogList != NULL) {
		ClearLogEntry(thread, thread->LogList);
	}
}

Emulation::EmulationLog *Emulation::StepInstruction(EmulationThread *thread, CodeAddr Address) {
	EmulationLog *ret = NULL;

	SetRegister(thread, REG_EIP, Address);
	CopyRegistersToShadow(thread);

	thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_LOGID, ++thread->LogID);
	thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_CPU_CYCLE, ++thread->CPUCycle);

	int r = x86_emulate(&thread->thread_ctx.emulation_ctx, (const x86_emulate_ops *)&thread->emulate_ops) == X86EMUL_OKAY;
	if (!r) {
		thread->last_successful = 0;
		return NULL;
	} else
		thread->last_successful = 1;


	// create change logs of registers that were modified...
	ret = CreateLog(thread);
	if (!ret) throw;
	// retrieve Virtual Memory changes from the VM subsystem...
	ret->VMChangeLog = thread->EmuVMEM->ChangeLog_Retrieve(thread->LogID, &ret->VMChangeLog_Count);
	printf("Change log addr %p\n", ret->VMChangeLog);
	// save registers for this specific execution as well for this exact cpu cycle
	std::memcpy(&ret->registers_shadow, &ret->registers_shadow, sizeof(cpu_user_regs_t));
	std::memcpy(&ret->registers, &ret->registers, sizeof(cpu_user_regs_t));

	// now update shadow registers for our next execution
	CopyRegistersToShadow(thread);

	return ret;
}


Emulation::EmulationThread *Emulation::ExecuteLoop(VirtualMemory *vmem, Emulation::CodeAddr StartAddr, Emulation::CodeAddr EndAddr, struct cpu_user_regs *registers, int new_thread) {
	EmulationLog *logptr = NULL;
	EmulationThread *thread = NULL;
	int done = 0, count = 0;
	CodeAddr EIP = StartAddr;

	if (new_thread) {
		thread = NewVirtualMachine(vmem, EIP, registers);
		if (thread == NULL) {
			return NULL;
		}
	} else thread = &Master;

	if (thread == &Master) {
		std::memcpy((void *)&Master.registers, registers, sizeof(struct cpu_user_regs));
	}

	while (!done) {
		logptr = StepInstruction(thread, EIP);

		if (count++ > 30) break;

		if (thread->registers.eip >= EndAddr)
			done = 1;
	}


	printf("Executed %d instructions\n", count);

	return thread;
}




// this initializes a new virtual machine.. and prepares some information so that the VM has data from its original
// and it will clone on change for any modifications during exec
Emulation::EmulationThread *Emulation::NewVirtualMachine(VirtualMemory *ParentMemory, Emulation::CodeAddr EIP,
		struct cpu_user_regs *registers) {

	EmulationThread *Thread = new EmulationThread;
	std::memset((void *)Thread, 0, sizeof(EmulationThread));

	Thread->ID = ++Current_VM_ID;
	Thread->CPUStart = Thread->CPUCycle = Master.CPUCycle;

	Thread->EmuVMEM->SetParent(ParentMemory);
	Thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_ID, Thread->ID);
	//Thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_LOGID, 0);

}

// this is to destroy a virtual machine (if we have exhausted all instructions through particular branches..
// *** this should queue a new virtual machine for a previously untested branch
void Emulation::DestroyVirtualMachine(Emulation::EmulationThread *Thread) {

	// dont do the initial static
	if (Thread == &Master) return;

	Thread->EmuVMEM->ReleaseParent();
	_VM2[Thread->ID] = NULL;
	EmuThread[Thread->ID] = NULL;

	delete Thread;
}

Emulation::RegChanges *Emulation::CreateChangeEntry(Emulation::RegChanges **changelist, int which, unsigned char *orig,
		unsigned char *cur, int size) {
	RegChanges *change = new RegChanges;

	std::memset(change, 0, sizeof(RegChanges));


	// ** add 64bit support here...
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

void Emulation::CopyRegistersToShadow(EmulationThread *thread) {
	std::memcpy(&thread->registers_shadow, &thread->registers, sizeof(cpu_user_regs_t));
}


void Emulation::SetRegister(EmulationThread *thread, int Monitor, uint32_t value) {
	if (Monitor & REG_EAX) {
		thread->registers.eax = (uint32_t)value;
	}
	if (Monitor & REG_EIP) {
		thread->registers.eip = (uint32_t) value;
	}
	if (Monitor & REG_EBX) {
		thread->registers.ebx = (uint32_t)value;
	}
	if (Monitor & REG_ECX) {
		thread->registers.ecx = (uint32_t)value;
	}
	if (Monitor & REG_EDX) {
		thread->registers.edx = (uint32_t)value;
	}
	if (Monitor & REG_ESI) {
		thread->registers.esi = (uint32_t)value;
	}
	if (Monitor & REG_EDI) {
		thread->registers.edi = (uint32_t)value;
	}
	if (Monitor & REG_ESP) {
		thread->registers.esp = (uint32_t)value;
	}
	if (Monitor & REG_EBP) {
		thread->registers.ebp = (uint32_t)value;
	}
	if (Monitor & REG_EFLAGS) {
		thread->registers.eflags = (uint32_t)value;
	}
	if (Monitor & REG_CS) {
		thread->registers.cs = (uint16_t)value;
	}
	if (Monitor & REG_ES) {
		thread->registers.es = (uint16_t)value;
	}
	if (Monitor & REG_DS) {
		thread->registers.ds = (uint16_t)value;
	}
	if (Monitor & REG_FS) {
		thread->registers.fs = (uint16_t)value;
	}
	if (Monitor & REG_GS) {
		thread->registers.gs = (uint16_t)value;
	}
	if (Monitor & REG_SS) {
		thread->registers.ss = (uint16_t)value;
	}
}


Emulation::EmulationLog *Emulation::CreateLog(EmulationThread *thread) {
	EmulationLog *logptr;
	int Monitor = 0;

	if (!thread->last_successful) return NULL;

	logptr = new EmulationLog;

	std::memset(logptr, 0, sizeof(EmulationLog));


	logptr->LogID = thread->LogID;

	logptr->Address = thread->registers_shadow.eip;
	// this might change if it changes EIP jmp,call,etc.. should grab from the database...
	logptr->Size = thread->registers.eip - thread->registers_shadow.eip;

	if (thread->registers.eip != thread->registers_shadow.eip) {
		Monitor |= REG_EIP;
		printf("changed EIP %d %p -> %p\n", Monitor & REG_EIP, thread->registers_shadow.eip, thread->registers.eip);
		CreateChangeEntry(&logptr->Changes, REG_EIP, (unsigned char *)&thread->registers_shadow.eip,  (unsigned char *)&thread->registers.eip, sizeof(uint32_t));
	}
	if (thread->registers.eax != thread->registers_shadow.eax) {
		Monitor |= REG_EAX;
		CreateChangeEntry(&logptr->Changes, REG_EAX,  (unsigned char *)&thread->registers_shadow.eax, (unsigned char *) &thread->registers.eax, sizeof(uint32_t));
	}
	if (thread->registers.ebx != thread->registers_shadow.ebx) {
		Monitor |= REG_EBX;
		CreateChangeEntry(&logptr->Changes, REG_EBX, (unsigned char *)&thread->registers_shadow.ebx, (unsigned char *) &thread->registers.ebx, sizeof(uint32_t));
	}
	if (thread->registers.ecx != thread->registers_shadow.ecx) {
		Monitor |= REG_ECX;
		CreateChangeEntry(&logptr->Changes, REG_ECX, (unsigned char *) &thread->registers_shadow.ecx, (unsigned char *) &thread->registers.ecx, sizeof(uint32_t));
	}
	if (thread->registers.edx != thread->registers_shadow.edx) {
		Monitor |= REG_EDX;
		CreateChangeEntry(&logptr->Changes, REG_EDX, (unsigned char *) &thread->registers_shadow.edx, (unsigned char *) &thread->registers.edx, sizeof(uint32_t));
	}
	if (thread->registers.esp != thread->registers_shadow.esp) {
		Monitor |= REG_ESP;
		CreateChangeEntry(&logptr->Changes, REG_ESP,  (unsigned char *)&thread->registers_shadow.esp,  (unsigned char *)&thread->registers.esp, sizeof(uint32_t));
	}
	if (thread->registers.ebp != thread->registers_shadow.ebp) {
		Monitor |= REG_EBP;
		CreateChangeEntry(&logptr->Changes, REG_EBP,  (unsigned char *)&thread->registers_shadow.ebp, (unsigned char *) &thread->registers.ebp, sizeof(uint32_t));
	}
	if (thread->registers.esi != thread->registers_shadow.esi) {
		Monitor |= REG_ESI;
		CreateChangeEntry(&logptr->Changes, REG_ESI,  (unsigned char *)&thread->registers_shadow.esi,  (unsigned char *)&thread->registers.esi, sizeof(uint32_t));
	}
	if (thread->registers.edi != thread->registers_shadow.edi) {
		Monitor |= REG_EDI;
		CreateChangeEntry(&logptr->Changes, REG_EDI,  (unsigned char *)&thread->registers_shadow.edi, (unsigned char *) &thread->registers.edi, sizeof(uint32_t));
	}
	if (thread->registers.eflags != thread->registers_shadow.eflags) {
		Monitor |= REG_EFLAGS;
		CreateChangeEntry(&logptr->Changes, REG_EFLAGS, (unsigned char *) &thread->registers_shadow.eflags,  (unsigned char *)&thread->registers.eflags, sizeof(uint32_t));
	}
	if (thread->registers.cs != thread->registers_shadow.cs) {
		Monitor |= REG_CS;
		CreateChangeEntry(&logptr->Changes, REG_CS, (unsigned char *) &thread->registers_shadow.cs, (unsigned char *) &thread->registers.cs, sizeof(uint16_t));
	}
	if (thread->registers.es != thread->registers_shadow.es) {
		Monitor |= REG_ES;
		CreateChangeEntry(&logptr->Changes, REG_ES, (unsigned char *) &thread->registers_shadow.es,  (unsigned char *)&thread->registers.es, sizeof(uint16_t));
	}
	if (thread->registers.ds != thread->registers_shadow.ds) {
		Monitor |= REG_DS;
		CreateChangeEntry(&logptr->Changes, REG_DS,  (unsigned char *)&thread->registers_shadow.ds,  (unsigned char *)&thread->registers.ds, sizeof(uint16_t));
	}
	if (thread->registers.fs != thread->registers_shadow.fs) {
		Monitor |= REG_FS;
		CreateChangeEntry(&logptr->Changes, REG_FS, (unsigned char *) &thread->registers_shadow.fs, (unsigned char *) &thread->registers.fs, sizeof(uint16_t));
	}
	if (thread->registers.gs != thread->registers_shadow.gs) {
		Monitor |= REG_GS;
		CreateChangeEntry(&logptr->Changes, REG_GS, (unsigned char *) &thread->registers_shadow.gs, (unsigned char *) &thread->registers.gs, sizeof(uint16_t));
	}
	if (thread->registers.ss != thread->registers_shadow.ss) {
		Monitor |= REG_SS;
		CreateChangeEntry(&logptr->Changes, REG_SS,  (unsigned char *)&thread->registers_shadow.ss, (unsigned char *) &thread->registers.ss, sizeof(uint16_t));
	}

	// duh! we need it in our structure!
	logptr->Monitor = Monitor;

	logptr->next = thread->LogList;
	thread->LogList = logptr;

	return logptr;
}
