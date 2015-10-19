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
#include "analysis.h"
#include "loading.h"
#include "apiproxy_client.h"
#include "emu_hooks.h"
#include "structures.h"
#include "emulation.h"

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


VirtualMemory *_VM2[MAX_VMS];
Emulation *EmuPtr[MAX_VMS];
Emulation::EmulationThread *EmuThread[MAX_VMS];
BinaryLoader *_BL[MAX_VMS];

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

    printf("!!! vm %p rep movs src seg %d offset %x dst seg %d offset %x bytes per %d reps %d ctxt %p\n",
	 _VM2[0],src_seg, src_offset, dst_seg, dst_offset, bytes_per_rep, *reps, ctxt);

    unsigned char *data = new unsigned char [bytes_to_copy];

	pVM->MemDataRead(
		//address_from_seg_offset(src_seg,src_offset,ctxt)
		src_offset
		, (unsigned char *) data, bytes_to_copy);
		printf("data: %s\n", data);
	pVM->MemDataWrite(
		//address_from_seg_offset(dst_seg, dst_offset,ctxt)
		dst_offset
		, (unsigned char *)data, bytes_to_copy);

	delete data;

	return X86EMUL_OKAY;
}



static int emulated_write(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];
	Emulation::EmulationThread *emuthread = EmuThread[thread->ID];
	uint32_t off = 0;
	
	off = address_from_seg_offset(seg,offset,ctxt);

	printf("vm %p write seg %d offset %X data %p bytes %d ctxt %p\n", _VM2[0], seg, offset, p_data, bytes, ctxt);

	if (seg == x86_seg_fs) {
		off = emuthread->TIB + offset;
	} 
	//printf("final %X\n", off);
	
	// *** FIX for rewind.. maybe put the original in thenext call..
	// read to temporary buffer and push it across.. or allocate here and set on response
	VirtPtr->CreateChangeLogData(&VirtPtr->temp_changes, 65536, off, NULL,(unsigned char *) p_data, bytes); 
	
	pVM->MemDataWrite(off, (unsigned char *) p_data, bytes);

    return X86EMUL_OKAY;
}



static int emulated_cmpxchg(enum x86_segment seg,unsigned long offset,void *p_old,void *p_new,unsigned int bytes,
    struct _x86_emulate_ctxt *ctxt) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];

	//printf("vm %p cmpxchg seg %d offset %x old %p new %p bytes %d ctxt %p\n", seg, offset, p_old, p_new, bytes, ctxt);

	pVM->MemDataWrite(address_from_seg_offset(seg,offset,ctxt),(unsigned char *) p_new, bytes);

	return X86EMUL_OKAY;
}


static int emulated_read_helper(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt, int fetch_insn) {
	struct _x86_thread *thread = (struct _x86_thread *)ctxt;
	Emulation *VirtPtr = EmuPtr[thread->ID];
	VirtualMemory *pVM = _VM2[thread->ID];
	BinaryLoader *Loader = _BL[0];
		Emulation::EmulationThread *emuthread = EmuThread[thread->ID];

	if (Loader->Imports != NULL) {
		BinaryLoader::IAT *iatptr = Loader->Imports;
		while (iatptr != NULL) {
			if (iatptr->Address == offset) break;
			iatptr = iatptr->next;
		}
		if (iatptr != NULL) {
			memcpy((void *)p_data,(void *) &iatptr->Address, sizeof(uint32_t));
		}
	}
	
	uint32_t off = address_from_seg_offset(seg,offset,ctxt);
	
	// allow TIB (we need for SEH for sure... rest should be mirrored)
	if (seg == x86_seg_fs) {
/*		// we must read from the remote TIB until we emulate/implement TIB/PEB locally..
		VirtPtr->Proxy->for_tib = true;
		printf("TIB!! vm %p read seg %d offset %X data %X bytes %d ctxt %p id %d ptr %p\n", _VM2[0], seg, offset, p_data, bytes, ctxt,thread->ID, ctxt);
		uint32_t off = (uint32_t)offset;
		VirtPtr->Proxy->PeekData(off, (char *)p_data, bytes);
		uint32_t *_dat = (uint32_t *)p_data;
		printf("%X\n", *_dat); */
		off = emuthread->TIB + offset; 

	} //else {
	
    	printf("vm %p read seg %d offset %X data %X bytes %d ctxt %p id %d ptr %p\n", _VM2[0], seg, offset, p_data, bytes, ctxt,thread->ID, ctxt);
		pVM->MemDataRead(off,(unsigned char *) p_data, bytes);
		
		VirtPtr->CreateChangeLogData(&VirtPtr->temp_changes, 131072, off, NULL, (unsigned char *)p_data, bytes);
	//}

	return X86EMUL_OKAY;
}

static int emulated_read(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	return emulated_read_helper(seg, offset, p_data, bytes, ctxt, 0);
}
static int emulated_read_fetch(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	return emulated_read_helper(seg, offset, p_data, bytes, ctxt, 1);
}

// -- end of functions to support emulator (x86_emulate)



int Emulation::ConnectToProxy(APIClient *proxy) {
	Proxy = proxy;
	
	printf("EMU Proxy: %p\n", proxy);
	
	// turn off simulation (since we will execute live on the API Proxy)
	simulation = 0;
	
	return proxy != NULL;
}

int Emulation::UsingProxy() {
	printf("UsingProxy: %d\n", Proxy != NULL);
	return Proxy != NULL;
}

int Emulation::SetupThreadStack(EmulationThread *tptr) {
	/*CodeAddr EBP = 0, ESP = 0;
	int Size = 1024 * 1024;
	uint32_t _ESP = 0x0012FD00 + Size;
	
	// check if we are using a real API proxy or not..
	if (!UsingProxy()) {
		// if not.. we put the stack 1 area higher than the last.. its free
		// stacks are generally 1 megabyte..
		if (MasterVM.StackList != NULL) {
			// put it the next 1 megabyte over the last stack..
			ESP = MasterVM.StackList->High + Size;
		} else {
			// loop until we have free space for our stack
			while (!ESP) {
				VirtualMemory::MemPage *pageptr = VM->MemPagePtrIfExists(_ESP);
				if (pageptr == NULL) {
					// ensure the bottom is empty too (1meg lower)
					pageptr = VM->MemPagePtrIfExists(_ESP - Size);
				}
				if (pageptr == NULL) {
					ESP = _ESP;
					break;
				} else {
					_ESP += Size;
				}
			}
		}
	} else {
		// we are using proxy.. so we must allocate locally as well as remotely...
		// and it should come from a bigger region for all threads/stack/heap/code
		
		// lets allocate 64 megabytes if we are using the API proxy...
		// .. tested with 16 locally.. but if we wanna do threaded apps
		// set these variable later for the apps...
		if (!Proxy->Regions) {
			uint32_t DoubleVerified = 0;
			// starting adadress
			uint32_t _RemoteCheck = 0x10000000 + (Size * 64); 
			while (!DoubleVerified) {
				// first we check with our local memory manager...
				uint32_t _Check = _RemoteCheck;
				uint32_t Verified = 0;
				while (!Verified) {
						VirtualMemory::MemPage *pageptr = VM->MemPagePtrIfExists(_ESP);
						if (pageptr == NULL) {
							// ensure the bottom is empty too (1meg lower)
							pageptr = VM->MemPagePtrIfExists(_ESP - (Size * 64));
						}
						if (pageptr == NULL) {
							Verified = _Check;
							break;
						} else {
							_Check += (Size * 64) + 0x00050000;
						}
				}
				// now that we have locally.. we check remotely.. by attempting to allocate
				int Remote_AllocateRet = Proxy->AllocateMemory((uint32_t)Verified, (int)(Size * 64));
				if (Remote_AllocateRet == 1) {
					DoubleVerified = Verified;
					break;
				} else {
					_RemoteCheck = Verified + (Size * 64) + 0x0005000;
				}
			}
			if (!DoubleVerified) {
				printf("Couldnt agree on memory region locally and remotely..\n");
				exit(-1);
			}
		} else {
			// we need to find space inside of the region already allocated on both ends...
			// we could just allocate a fake heap of 1 megabyte and use that for management...
			//APIClient::AllocatedRegion *regionptr = Proxy->Regions;
			
			uint32_t Stack = (uint32_t)HeapAlloc(0, 1024 * 1024);
			if (Stack == 0) {
				printf("couldnt find space for stack in local area\n");
				exit(-1);
			}
			
		}
	}
	*/
	// each thread is default 1meg in win32
	int Size = 1024 * 1024;
	uint32_t ESP = 0, EBP = 0;
	
	ESP = (uint32_t)HeapAlloc(0,Size);

	printf("esp %X\n", ESP);
	if (ESP == 0) {
		printf("couldnt allocate memory for thread stack!\n");
		exit(-1);
		return -1;
	}
	
	// allocate tracking structure
	StackRegions *sptr = new StackRegions;
	if (sptr == NULL) return -1;
	memset((void *)sptr, 0, sizeof(StackRegions));
	
	// keep stack settings for later..
	sptr->High = ESP + Size;
	sptr->Low = ESP;
	sptr->Size = Size;
	MasterVM.StackHigh = ESP + Size;
	MasterVM.StackLow = ESP;
	
	tptr->StackHigh = ESP + Size;
	tptr->StackLow = ESP;
	// add to list
	sptr->next = MasterVM.StackList;
	MasterVM.StackList = sptr;
	
	// we should put a final return address on the stack .. *** FIX
	// put 0xDEADDEAD on top of the stack so we know when the program
	// is complete... (so we dont have to deal with conventions,etc)
	uint32_t end_addr =0xDEADDEAD;
	char *data = (char *)&end_addr;
	uint32_t _where = sptr->High - 32;
	while (_where < sptr->High) {
		MasterVM.Memory->MemDataWrite(_where, (unsigned char *)data, 4);
		_where += sizeof(uint32_t);
	}
	
	ESP = sptr->High - 32;
	EBP = ESP;
	
	// set thread registers..
	SetRegister(tptr, REG_EBP, EBP);
	SetRegister(tptr, REG_ESP, ESP);

	// lets allocate space for the TIB... (SEH etc)
	uint32_t _tib = (uint32_t)HeapAlloc(0,4096);
	tptr->TIB = _tib;
	// set TIB in FS register (for fs:[0x00] (SEH), TIB, PEB pointer, etc)
	SetRegister(tptr, REG_FS, tptr->TIB);
	/* *** FIX
	emulate 
	CS = Code segment
DS = Data segment
ES = Extra segment
SS = Stack Segment

this information needs to come from the loader.. and set accordingly for each new thread

*/

	//SetRegister(tptr, REG_SS, tptr->);
	// put to shadow for when we execute..
	CopyRegistersToShadow(tptr);
}

/*
init isnt in the constructor because we have to give the ability to use the API proxy
if we use the proxy.. then it changes the memory allocation strategies...
*/
uint32_t Emulation::Init(uint32_t ReqAddr) {
	int Size = 1024 * 1024 * 16;
	// lets allocate 16k below the images requested image base..
	// so our custom allocator has some room to play with..
	// + 1 meg for stack..
	//uint32_t Start = (ReqAddr) ? (ReqAddr - ((1024 * 1024) + (1024 * 16))) : 0x00401000;
	printf("Init %X\n", ReqAddr);
	uint32_t Start = (ReqAddr) ? ReqAddr : 0x00401000;
	uint32_t RemAddr = Start;
	if (!UsingProxy()) {
		MasterVM.RegionLow = Start;
		MasterVM.RegionHigh = MasterVM.HeapLow + Size + (1024 * 1024);
		
		MasterVM.HeapLow = MasterVM.RegionLow;
		MasterVM.HeapHigh = MasterVM.RegionHigh - (1024 * 1024);
	} else {
		int count = 0;
		int Verified = 0;
		
		while (!Verified) {
			RemAddr = Proxy->AllocateMemory((uint32_t)Start, Size);
			if (RemAddr != NULL) {
				VirtualMemory::Memory_Section *memptr = VM->Section_FindByAddrandFile(NULL, RemAddr);
				if (memptr == NULL) {
					memptr = VM->Section_FindByAddrandFile(NULL, RemAddr + Size);
				}
				if (memptr == NULL) {
					Verified = 1;
					printf("REMOTE Verified %p\n", RemAddr);
				}
			} else {
				if (ReqAddr != NULL) {
					printf("Couldnt allocate around requesting address %X\n", ReqAddr);
					return 0;
				}
				//printf("failed %X\n", RemAddr);
				Proxy->DeallocateMemory(RemAddr);
				Start += 0x00050000;
				if (count++ > 1000) {
					printf("1000 failures to allocate memory on both ends\n");
					exit(-1);
				} else if (count > 500 && Start < 0x20000000) {
					Start = 0x20000000;
					printf("500 failures.. starting at 0x2...\n"); 
				}
			}
		}
		
		printf("verified %p %d\n", RemAddr, Size);
		
		MasterVM.RegionLow = RemAddr;
		MasterVM.RegionHigh = RemAddr + Size;
		
		MasterVM.HeapLow = MasterVM.RegionLow;
		MasterVM.HeapHigh = MasterVM.RegionHigh - (1024 * 1024) - (1024 * 32);
		MasterVM.HeapLast = 0;
	}
	
	// add section so a new DLL wont overwrite it...
	VM->Add_Section(MasterVM.RegionLow, 1, MasterVM.RegionHigh - MasterVM.RegionLow, (VirtualMemory::SectionType)0, 0, 0, "REGION", (unsigned char *)"\x00");
	
	MasterThread = NewThread(&MasterVM);
	if (MasterThread == NULL) {
		printf("couldnt start thread\n");
		exit(-1);
	}
	EmuThread[0] = MasterThread;
	
	MasterThread->thread_ctx.ID = 0;
	MasterThread->thread_ctx.emulation_ctx.addr_size = 32;
	MasterThread->thread_ctx.emulation_ctx.sp_size = 32;
	MasterThread->thread_ctx.emulation_ctx.regs = &MasterThread->registers;

	// grabbed these from entry point on an app in IDA pro.. (after dlls+tls etc all loaded
	SetRegister(MasterThread, REG_EAX, 0);
	SetRegister(MasterThread, REG_EBX, 1);
	SetRegister(MasterThread, REG_ECX, 2);
	SetRegister(MasterThread, REG_EDX, 3);
	SetRegister(MasterThread, REG_ESI, 4);
	SetRegister(MasterThread, REG_EDI, 5);
	
	VMList = &MasterVM;
	
	printf("end init()\n");
	//SetupThreadStack(MasterThread);
	return RemAddr;
}



Emulation::Emulation(VirtualMemory *_VM) {
	for (int i = 0; i < MAX_VMS; i++) {
		_VM2[i] = NULL;
		EmuPtr[i] = NULL;
		EmuThread[i] = NULL;
	}

	// we start as a simulation until we are connected to the server
	simulation = 1;
	verbose = 1;
	Proxy = NULL;
	VM = _VM2[0] = _VM;
	EmuPtr[0] = this;
	completed = 0;
	std::memset((void *)&MasterVM, 0, sizeof(VirtualMachine));
	//MasterVM.LogList = NULL;
	// count of virtual machines and incremental ID
	Current_VM_ID = 0;
	// current VM being executed...
	VM_Exec_ID = 0;

	// default settings for virtual memory logging
	Global_ChangeLog_Read = 0;
	Global_ChangeLog_Write = 0;
	Global_ChangeLog_Verify = 0;

	MasterVM.Memory = _VM;
	
	std::memset((void *)&MasterVM.emulate_ops, 0, sizeof(struct hack_x86_emulate_ops));
	
	MasterVM.emulate_ops.read = (void *)&emulated_read;
	MasterVM.emulate_ops.insn_fetch = (void *)&emulated_read_fetch;
	MasterVM.emulate_ops.write = (void *)&emulated_write;
	MasterVM.emulate_ops.rep_movs = (void *)&emulated_rep_movs;
	MasterVM.emulate_ops.cmpxchg = (void *)&emulated_cmpxchg;

}

Emulation::EmulationThread *Emulation::NewThread(Emulation::VirtualMachine *VM) {
	EmulationThread *tptr = new EmulationThread;
	if (tptr == NULL) return NULL;
	
	std::memset(tptr, 0, sizeof(EmulationThread));
	
	tptr->thread_ctx.ID = tptr->ID = VM->thread_id++;
	tptr->thread_ctx.emulation_ctx.addr_size = 32;
	tptr->thread_ctx.emulation_ctx.sp_size = 32;
	tptr->thread_ctx.emulation_ctx.regs = &tptr->registers;

	SetRegister(tptr, REG_EAX, 0);
	SetRegister(tptr, REG_EBX, 1);
	SetRegister(tptr, REG_ECX, 2);
	SetRegister(tptr, REG_EDX, 3);
	SetRegister(tptr, REG_ESI, 4);
	SetRegister(tptr, REG_EDI, 5);
	
	tptr->EmuVMEM = (VirtualMemory *)VM->Memory;
	tptr->VM = (VirtualMemory *)VM;
	
	tptr->next = VM->Threads;
	VM->Threads = tptr;
	
	EmuPtr[tptr->ID] = this;
	_VM2[tptr->ID] = tptr->EmuVMEM;
	EmuThread[tptr->ID] = tptr;
	
	SetupThreadStack(tptr);
	
	return tptr;	
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
	Changes *rptr = NULL, *rptr2 = NULL;


	if (lptr == NULL) return;

	for (rptr = lptr->Changes; rptr != NULL; ) {
		Changes *rptr2 = rptr->next;
		// FIX *** MEMORY LEAK.. free the reest of the structure..
		delete rptr;
		rptr = rptr2;
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


/* pre is for simulation
   post is for logging
   
   *** FIX: one problem is we have to load the ret_fix ...
       maybe move this function inside of PreExecute() instead of 
	   as another function so we can accomodate all variables
*/
int Emulation::PostExecute(EmulationThread *thread, uint32_t EIP) {
	int ret = 0;
	// if we are not simulating... we dont care to keep logs of functions because we are filling the data
	// so postexec is irrelevant
	if (!simulation) return 0;
	
	if (Loader->Imports) {
		BinaryLoader::IAT *iatptr = Loader->FindIAT(EIP);
		
		if (iatptr != NULL) {
			Hooks::APIHook *hptr = NULL;
			
			hptr = APIHooks.HookFind(iatptr->module, iatptr->function);
			
			// log the data returned to our user appointed buffer
			// so we can simulate on another execution
			if (hptr) {
				uint32_t buf_addr = FindArgument(thread, hptr->find_buffer);
				uint32_t buf_size = FindArgument(thread, hptr->find_size);
				char *buf = NULL;
				
				if (buf_size) {
					buf = (char *)malloc(buf_size + 1);
				}
				
				if (buf) {
					// read the buffer into our temporary buffer...
					thread->EmuVMEM->MemDataRead(buf_addr, (unsigned char *)buf, buf_size);
				
					// now log it into our protocol exchange list for simulating on another execution
					Hooks::ProtocolExchange *xptr =
 						APIHooks.AddProtocolExchange(hptr->id,
	 						hptr->module_name, hptr->function_name,hptr->side, 
	 						buf, buf_size);
					
					if (xptr != NULL)
						ret = 1;
					
					free(buf); 
				}				 				
			}
		}
	}
	
	return ret;
}


// this will take a current thread context.. and find the buffer for the function thats hooked
// *** Finish this.. and try to remove the constants.. maybe programmatically handle this
uint32_t Emulation::FindArgument(EmulationThread *thread, int arg_information) {
	uint32_t ESP = thread->thread_ctx.emulation_ctx.regs->esp;
	uint32_t ret = 0;
	
	switch (arg_information) {
		case BUF_ESP_p4:
			ret = ESP + 4;
			break;
		case BUF_ESP_p8:
			ret = (ESP + 8);
			break;
		case BUF_ESP_p12:
			ret = (ESP + 12);
			break;
		case BUF_ESP_p16:
			ret = (ESP + 16);
			break;
		case BUF_ESP_p20:
			ret = (ESP + 20);
			break;
		case BUF_ESP_p24:
			ret = (ESP + 24);
			break;
	}
	
	// do we dereference our pointer (ESP at start) once or twice? if we deref again
	// it means we had a pointer to a pointer...
	// !! we always have to deref once because we are pointing to an argument on the stack passed to the function
	// 1: get addr at ESP location (when a char * is pushed)
	// 2: using BUF_DEREF means we pushed &buf when buf was char *
	// which is a pointer to a pointer so it has to be dereferenced..
	int deref = (arg_information & BUF_DEREF) ? 2 : 1;
	
	// read the address at that location for returning to the calling function
	for (int a = 0; a < deref; a++)
		thread->EmuVMEM->MemDataRead(ret, (unsigned char *)&ret, sizeof(uint32_t));
	
	return ret;
}

// catch IAT (called functions in DLLs) and redirect to either
// foreign machine/wine using API proxy.. or simulate from a log
int Emulation::PreExecute(EmulationThread *thread) {
	uint32_t EIP = thread->thread_ctx.emulation_ctx.regs->eip; 
	if ((EIP == 0xDEADDEAD || EIP == 0) || ((EIP > thread->StackLow) && (EIP < thread->StackHigh)) || EIP < 10) {
		printf("Done.. EIP %X\n", EIP);
		thread->completed = 1;
		//completed = 1;
		//exit(-1);
		return 1;
	}
	
	//printf("PRE: %p\n", thread->thread_ctx.emulation_ctx.regs->eip);
	// do some pre-checks on the thread before we execute
	// such as redirects of IAT for API Proxy...
	if (Loader->Imports) {
		BinaryLoader::IAT *iatptr = Loader->FindIAT(EIP);
		if (iatptr != NULL) {
			int proxied = 0;
			uint32_t eax_ret = 0;
			uint32_t ret_fix = 0;
			uint32_t esp = thread->thread_ctx.emulation_ctx.regs->esp;
			uint32_t ret_eip = 0;
			Hooks::APIHook *hptr = NULL;
			
			if (simulation) {
				hptr = APIHooks.HookFind(iatptr->module, iatptr->function);
			}
			
			printf("FUNC \"%s\"\n", iatptr->function);
			if (strcmp(iatptr->function, "ExitThread")==0) {
				thread->completed = 1;
				ret_fix = 0;
				proxied = 0;
			} else if (strcmp(iatptr->function, "HeapAlloc")==0) {
				
				ret_eip = StackPop(thread, &esp);
				
				uint32_t hHeap = StackPop(thread, &esp);
				uint32_t dwFlags = StackPop(thread, &esp);
				uint32_t dwBytes = StackPop(thread, &esp);
				
				eax_ret = HeapAlloc(0, dwBytes);
				
				ret_fix = 0;
				proxied = 0;				
			} else if (strcmp(iatptr->function, "HeapFree")==0) {
				
				ret_eip = StackPop(thread, &esp);
				
				uint32_t hHeap = StackPop(thread, &esp);
				uint32_t dwFlags = StackPop(thread, &esp);
				uint32_t lpMem = StackPop(thread, &esp);

				HeapFree(lpMem);
				
				eax_ret = 1;
				ret_fix = 0;
				
				proxied = 0;
			}/* else if (strcmp(iatptr->function, "CloseHandle")==0) {
				ret_fix = 4;
				eax_ret = 1;
				esp = thread->thread_ctx.emulation_ctx.regs->esp;
				ret_eip = StackPop(thread);
				
			}*/ 
			else if (strcmp(iatptr->function, "GetProcessHeap")==0) {
				
				ret_eip = StackPop(thread, &esp);

				proxied = 0;
				ret_fix = 0;
				eax_ret = 0xBEEFBEEF;				
			}
			else if (strcmp(iatptr->function, "Sleep")==0) {
				
				ret_eip = StackPop(thread, &esp);
				
				thread->sleep_time = StackPop(thread, &esp);
				if (thread->sleep_time > 1000) thread->sleep_time /= 1000;
				
				printf("Sleep time: %d\n", thread->sleep_time);
				thread->sleep_start = time(0);
				thread->state = 1;
				
				ret_fix = 0;
				proxied = 0;
			} else if (strcmp(iatptr->function, "ExitProcess")==0) {
				thread->completed = 1;
				
			} else if (strcmp(iatptr->function, "CreateThread")==0) {
				proxied = 0;
				// hack since we are using StackPop() .. later we should keep stack pop...
				// but it has to get the return address up here rather than down *** FIX
				
				ret_eip = StackPop(thread, &esp);
				eax_ret = CreateThread(thread, &esp);
				ret_fix = 0;
				printf("EIP create %X eax ret %X\n", ret_eip, eax_ret);
				//thread->thread_ctx.emulation_ctx.regs->esp = esp;
			} else {
				proxied = 1;
			}
			
			if (proxied == 1) {
				// we found a redirected function for the API Proxy
				printf("Proxy Func/IAT: %s %s\n", iatptr->module, iatptr->function);
	
				VirtualMachine *_VM = (VirtualMachine *)thread->VM;
				
				if (!simulation || hptr == NULL) {
					// call the function on the proxy server...
					int call_ret = Proxy->CallFunction(iatptr->module, 
					iatptr->function,0,
						thread->thread_ctx.emulation_ctx.regs->esp,
						thread->thread_ctx.emulation_ctx.regs->ebp,
						MasterVM.RegionLow,
						 (MasterVM.RegionHigh - MasterVM.RegionLow),
						  &eax_ret, _VM->StackHigh, &ret_fix);
		
					// *** FIX
					if (call_ret != 1) {	
						printf("ERROR Making call.. fix logic later! (reconnect, etc, etc, local emu)\n");
						exit(-1);
					}
					
	
				} else {
					// we are simulating.. lets load from the database...
					Hooks::ProtocolExchange *xptr = APIHooks.NextProtocolExchange(hptr->id, hptr->side);
					if (xptr == NULL) {
						printf("Missing protocl exchange... hook id %d side %d module %s func %s\n",
							hptr->id, hptr->side, hptr->module_name, hptr->function_name);
							throw;
					}
					
					// how many bytes & whats the return info for this call..
					eax_ret = xptr->call_ret;
					ret_fix = xptr->ret_fix;
					
					// now we have to copy the real data.. this requires differences for each
					// we need to use a strategy (pretty generic way to tell our hooking functions
					// that a particular buffer can be found on the stack, or at an address dereferenced
					// from the stack...
					uint32_t buf_addr = FindArgument(thread, hptr->find_buffer);
					//uint32_t buf_size = FindArgument(thread, hptr, hptr->find_size);
					
					// copy the data in place..
					thread->EmuVMEM->MemDataWrite(buf_addr, (unsigned char *)xptr->buf, xptr->size);
					
					// we are done!
					
				}
			}
				
			printf("Ret fix %d ESP %X proxied %d EAX ret: %X\n", ret_fix,
			thread->thread_ctx.emulation_ctx.regs->esp, proxied, eax_ret);
			
			// return the return value in EAX.. 
			SetRegister(thread, REG_EAX, eax_ret);
			
			if (ret_eip == 0) {
				// find return address from call instruction
				
				// we do this above.. during initialization of esp
				//esp = thread->thread_ctx.emulation_ctx.regs->esp;
				
				VM->MemDataRead(esp, (unsigned char *)&ret_eip, sizeof(uint32_t));
				
				esp += sizeof(uint32_t);
			}
			
			
			//printf("RET EIP from Call: %X [from esp %X]\n", ret_eip, esp);
			
			// accomodate calling convention return fixes (callee cleans up)
			//thread->thread_ctx.emulation_ctx.regs->esp += ret_fix;
			esp += ret_fix;
			// mimic a return from a called function..
			// EIP = *ESP.. add esp, sizeof(DWORD_PTR)
			SetRegister(thread, REG_ESP, esp);
			SetRegister(thread, REG_EIP, ret_eip);
			
			//printf("ESP after ret %X\n",thread->thread_ctx.emulation_ctx.regs->esp );
			
			
			return 1;
		}
	}
	return 0;
}


// emulates a complete cycle on a virtual machine...
// this includes all threads...
int Emulation::StepCycle(VirtualMachine *VirtPtr) {
	int ret = 0;
	EmulationThread *tptr = VirtPtr->Threads;
	EmulationLog *logptr = NULL;
	int count = 0;
	int active = 0;
	
	// loop all threads and perform an instruction...
	// this isnt as efficient as a real task scheduler...
	// for now it wont matter :)
	for (; tptr != NULL; tptr = tptr->next) {
		if (tptr->completed) {
			if (!tptr->dumped) {
				DumpStack(tptr);
			}
			continue;
		}
		count++;
		if (tptr->state == 1) {
			int cur_ts = time(0);
			if ((cur_ts - tptr->sleep_start) >= tptr->sleep_time) {
				tptr->state = 0;
			} else {
				printf("Thread %d asleep\n", tptr->ID);
				continue;
			}
		}
		active++;
		// *** FIX we need to detect a thread crash, overflow.. emulated_read_fetch
		if (verbose) {
			printf("--\n");
			// print registers before execution of the next instruction
			printf("TH %D EIP %x ESP %x EBP %x EAX %x EBX %x ECX %x EDX %x ESI %x EDI %x\n",
			tptr->ID,
			(uint32_t)tptr->registers.eip, (uint32_t)tptr->registers.esp,
			(uint32_t)tptr->registers.ebp,
			(uint32_t)tptr->registers.eax,
			(uint32_t)tptr->registers.ebx, (uint32_t)tptr->registers.ecx,
			(uint32_t)tptr->registers.edx,(uint32_t) tptr->registers.esi,
			(uint32_t)tptr->registers.edi);
		}

		
		if (verbose) {
			Sculpture *op = (Sculpture *)_op;
			// get the 'instruction information' structure for this particular instruction
			// from the disassembly subsystem
			DisassembleTask::InstructionInformation *InsInfo = op->disasm->GetInstructionInformationByAddress(tptr->registers.eip, DisassembleTask::LIST_TYPE_NEXT, 1, NULL);
			if (InsInfo != NULL) {
				//char *ptrbuf = (char *)InsInfo->InstructionMnemonicString;
				std::string ptrbuf = op->disasm->disasm_str(InsInfo->Address, (char *)InsInfo->RawData, InsInfo->Size);
				printf("%p %s\n", tptr->registers.eip,ptrbuf.c_str());
				
			} else {
				// report that we didnt find this.. locate why later...
				printf("[!!!] InsInfo NULL for %X\n", tptr->registers.eip);
			}
		}
		
		logptr = StepInstruction(tptr, 0);

		if (verbose) {
		if (verbose) {
			
			// print registers before execution of the next instruction
			printf("TH %D EIP %x ESP %x EBP %x EAX %x EBX %x ECX %x EDX %x ESI %x EDI %x\n",
			tptr->ID,
			(uint32_t)tptr->registers.eip, (uint32_t)tptr->registers.esp,
			(uint32_t)tptr->registers.ebp,
			(uint32_t)tptr->registers.eax,
			(uint32_t)tptr->registers.ebx, (uint32_t)tptr->registers.ecx,
			(uint32_t)tptr->registers.edx,(uint32_t) tptr->registers.esi,
			(uint32_t)tptr->registers.edi);
		} 
	
			// do some sanity checks on the thread...
			if (!tptr->last_successful) {
				printf("ERROR on thread %d LogID %d [Cpu Start %d Cycle %d Start Addr %X]\n", tptr->ID, tptr->LogID,
				tptr->CPUStart, tptr->CPUCycle, tptr->StartAddress);
			}
		}
	}
	
	if (count == 0) completed = 1;
	if (!active) {
		sleep(1);
	}
	return ret;
}

void Emulation::DumpStack(EmulationThread *thread) {
	return;
	FILE *fd;
	char fname[1024];
	int stack_size = thread->StackHigh - thread->StackLow;
	
	sprintf(fname, "ID.%d.Thread.%d.stack.%X.dat", start_ts/10000, thread->ID,
	thread->StackLow);
	
	printf("Stack Size: %d File: %s\n", stack_size, fname);
	
	if ((fd = fopen(fname, "wb")) == NULL) return;
	char *buf = (char *)malloc(stack_size + 1);
	if (buf == NULL) { fclose(fd); unlink(buf); return; }

	// write memory from virtual memory to the dump file
	thread->EmuVMEM->MemDataRead(thread->StackLow, (unsigned char *)&buf, stack_size);
	fwrite(buf, 1, stack_size, fd);
	
	fclose(fd);
	
	return;	
}

Emulation::EmulationLog *Emulation::StepInstruction(EmulationThread *_thread, CodeAddr Address) {
	EmulationThread *thread = NULL;
	int r = 0, retry_count = 0;
	if (_thread == NULL) thread = MasterThread; else thread = _thread;
	_BL[0] = Loader;
	EmulationLog *ret = NULL;

	// If we are specifically saying to hit a target address... if not use registers
	if (Address != 0)
		SetRegister(thread, REG_EIP, Address);
		
	if (PreExecute(thread) == 1) {
		thread->last_successful = 1;
		return 0;
	}
		
	CopyRegistersToShadow(thread);

	thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_LOGID, ++thread->LogID);
	thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_CPU_CYCLE, ++thread->CPUCycle);

	VirtualMachine *_VM = (VirtualMachine *)(thread->VM);
	EmulationThread *tptr = thread;
emu:
	
	// print registers before execution of the next instruction
			printf("1 TH %D EIP %x ESP %x EBP %x EAX %x EBX %x ECX %x EDX %x ESI %x EDI %x\n",
			tptr->ID,
			(uint32_t)tptr->registers.eip, (uint32_t)tptr->registers.esp,
			(uint32_t)tptr->registers.ebp,
			(uint32_t)tptr->registers.eax,
			(uint32_t)tptr->registers.ebx, (uint32_t)tptr->registers.ecx,
			(uint32_t)tptr->registers.edx,(uint32_t) tptr->registers.esi,
			(uint32_t)tptr->registers.edi);
			
	r = x86_emulate((struct x86_emulate_ctxt *)&thread->thread_ctx.emulation_ctx, (const x86_emulate_ops *)&_VM->emulate_ops) == X86EMUL_OKAY;

		// print registers before execution of the next instruction
			printf("2 TH %D EIP %x ESP %x EBP %x EAX %x EBX %x ECX %x EDX %x ESI %x EDI %x\n",
			tptr->ID,
			(uint32_t)tptr->registers.eip, (uint32_t)tptr->registers.esp,
			(uint32_t)tptr->registers.ebp,
			(uint32_t)tptr->registers.eax,
			(uint32_t)tptr->registers.ebx, (uint32_t)tptr->registers.ecx,
			(uint32_t)tptr->registers.edx,(uint32_t) tptr->registers.esi,
			(uint32_t)tptr->registers.edi);

	// set to 0 since we added more if's below.. maybe rewrite using switch()
	// trying to keep it simple for tons of execs.. might not matter!
	thread->last_successful = 0;
	
	if (r == X86EMUL_OKAY) {
		thread->last_successful = 1;
		printf("emu ok\n");
		char blah[1024];
		VM->MemDataRead(thread->thread_ctx.emulation_ctx.regs->eip, (unsigned char *)&blah, 13);
		uint32_t blahI=0xDEADDEAD;
		uint32_t *_blah = (uint32_t *)blah;
		if (*_blah == blahI) {
			printf("DONE\n");
			exit(0);
		}
		for (int i = 0; i < 13; i++) {
			printf("%02X", (unsigned char)blah[i]);
		}
		printf("\n%X\n", *_blah);
	} else if (r == X86EMUL_UNHANDLEABLE) {
		//printf("UNHANDLEABLE\n");
		// see why things are returning this!! maybe ops are responding
		// incorrectly!
		thread->last_successful = 1;
	} else if (r == X86EMUL_EXCEPTION) {
		printf("Exception\n");
	} else if (r == X86EMUL_RETRY) {
		printf("X86EMUL_RETRY\n");
		// retry.. like it says..
		if (retry_count++ < 4)
			goto emu;
	} else if (r == X86EMUL_CMPXCHG_FAILED) {
		printf("fail\n");
		// maybe just retry this.. not usre what it means about accessor.. we can test soon
		// *** FIX	
	} else {
		printf("bad\n");
	}
	
	if (!thread->last_successful) {
		printf("%X failed! [%d reason]\n", r);
		return NULL;
	}

	// create change logs of registers that were modified...
	if ((ret = CreateLog(thread)) == NULL) {
		printf("error with CreateLog.. probably memory related!\n");
		exit(-1);
	}
	
	// move our 'temporary changes' into the correct posision
	// in case we had some log from READ/WRITE
	if (temp_changes != NULL) {
		if (ret->Changes == NULL) {
			ret->Changes = temp_changes;
		} else {
			Changes *chptr = ret->Changes;
			while (chptr->next != NULL) {
				chptr = chptr->next;	
			}
			chptr->next = temp_changes;
		}
		temp_changes = NULL;
	}
	
	// retrieve Virtual Memory changes from the VM subsystem...
	ret->VMChangeLog = thread->EmuVMEM->ChangeLog_Retrieve(thread->LogID, &ret->VMChangeLog_Count);
	
	// save registers for this specific execution as well for this exact cpu cycle
	//std::memcpy(&ret->registers_shadow, &ret->registers_shadow, sizeof(cpu_user_regs_t));
	//std::memcpy(&ret->registers, &ret->registers, sizeof(cpu_user_regs_t));

	// now update shadow registers for our next execution
	CopyRegistersToShadow(thread);

	if (ret) {
		if (verbose) {
			PrintLog(ret);
		}
	}
	
	if (thread->LogLast == NULL && thread->LogList != NULL) {
		thread->LogLast = thread->LogList;
	}
	
	// return the changelog to teh caller
	return ret;
}

// initialize a virtual machine.. and link to a parent one
// if it exists.. (for deep fuzzing/distribution)
Emulation::VirtualMachine *Emulation::NewVirtualMachine(VirtualMachine *parent) {
	VirtualMachine *vptr = new VirtualMachine;
	std::memset(vptr, 0, sizeof(VirtualMachine));
	if (vptr == NULL) return NULL;
	
	if (parent != NULL) {
		vptr->parent = parent;
		vptr->Memory = parent->Memory;
		vptr->Threads = parent->Threads;
	}
}
/*HANDLE WINAPI CreateThread(
  _In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  _In_      SIZE_T                 dwStackSize,
  _In_      LPTHREAD_START_ROUTINE lpStartAddress,
  _In_opt_  LPVOID                 lpParameter,
  _In_      DWORD                  dwCreationFlags,
  _Out_opt_ LPDWORD                lpThreadId
);*/

uint32_t Emulation::CreateThread(EmulationThread *tptr, uint32_t *esp) {
	// retreive the argments... (ensure we popped the return address in the prior function which handles hooking)
	uint32_t lpThreadAttributes = StackPop(tptr, esp);
	uint32_t dwStackSize = StackPop(tptr, esp);
	uint32_t lpStartAddress = StackPop(tptr, esp);
	uint32_t lpParameter = StackPop(tptr, esp);
	uint32_t dwCreationFlags = StackPop(tptr, esp);
	uint32_t lpThreadID = StackPop(tptr, esp);
	
	printf("CreateThread ID %X flags %X param %X start addr %X stack size %d thread attr %d\n",
	lpThreadID, dwCreationFlags, lpParameter, lpStartAddress, dwStackSize, lpThreadAttributes); 

	EmulationThread *thread = NewThread(&MasterVM);
	if (thread == NULL) {
		printf("Couldnt start new thread\n");
		throw;
		return -1;
	}
	
	//thread->thread_ctx.ID = 0;
	thread->thread_ctx.emulation_ctx.addr_size = 32;
	thread->thread_ctx.emulation_ctx.sp_size = 32;
	thread->thread_ctx.emulation_ctx.regs = &thread->registers;

	// grabbed these from entry point on an app in IDA pro.. (after dlls+tls etc all loaded
	SetRegister(thread, REG_EAX, 0);
	SetRegister(thread, REG_EBX, 1);
	SetRegister(thread, REG_ECX, 2);
	SetRegister(thread, REG_EDX, 3);
	SetRegister(thread, REG_ESI, 4);
	SetRegister(thread, REG_EDI, 5);
	
	SetRegister(thread, REG_EIP, lpStartAddress);
	
	printf("New Thread %X\n", thread);
	EmuThread[thread->ID] = thread;
	if (lpThreadID != NULL) {
		thread->EmuVMEM->MemDataWrite(lpThreadID, (unsigned char *)&thread->ID, sizeof(uint32_t));
	} 
	return thread->ID;
}

void Emulation::StackPush(EmulationThread *thread, uint32_t value) {
	thread->registers.esp -= sizeof(uint32_t);
	
	thread->EmuVMEM->MemDataWrite(thread->registers.esp, (unsigned char *)&value, sizeof(uint32_t));
}

uint32_t Emulation::StackPop(EmulationThread *thread, uint32_t *esp) {
	uint32_t ret = 0;
	
	VM->MemDataRead(*esp, (unsigned char *)&ret, sizeof(uint32_t));
		
	*esp += sizeof(uint32_t);
	
	printf("Popped: %X\n", ret);
	
	return ret;
}

// pulls an argument off of the stack.. however
// it will not destroy/modify ESP
uint32_t Emulation::StackPeek(EmulationThread *thread, int arg) {
	uint32_t ret = 0;
	uint32_t esp = thread->thread_ctx.emulation_ctx.regs->esp;
	
	// skip by however many args
	// we are starting with 1 no matter what.. this will skip the return address
	// since this is expected to happen during a call
	esp += (1+arg) * sizeof(uint32_t);
	
	VM->MemDataRead(esp, (unsigned char *)&ret, sizeof(uint32_t));
	
	return ret;
}

uint32_t Emulation::HeapAlloc(uint32_t ReqAddr, int Size) {
	Emulation::HeapAllocations *ret = NULL;
	//Emulation::HeapAllocations *aptr = new HeapAllocations;
	//memset(aptr, 0, sizeof(HeapAllocations));

	//CustomHeapArea *aptr = NULL;
	Emulation::HeapAllocations *hptr = NULL;

	//for (aptr = (CustomHeapArea *)tinfo->memory_areas; aptr != NULL; aptr = aptr->next) {
		uint32_t SpaceLeft = MasterVM.HeapHigh - MasterVM.HeapLast;

		if (SpaceLeft <= 0) {
			for (hptr = MasterVM.HeapList; hptr != NULL; hptr = hptr->next) {
				// if free'd heap.. can we take this place??
				if (hptr->free && Size <= hptr->size) {

					uint32_t SizeLeft = (hptr->size - Size);
					// if the size left after we give out this block again is more than 16k..
					// lets put it up for grabs..
					if (SizeLeft > (1024 * 16)) {
						Emulation::HeapAllocations *leftover = (Emulation::HeapAllocations *)
						new Emulation::HeapAllocations;
						memset(leftover, 0, sizeof(Emulation::HeapAllocations));

						if (leftover != NULL) {
							leftover->Address = hptr->Address + Size;
							leftover->size = SizeLeft;

							leftover->next = MasterVM.HeapList;
							MasterVM.HeapList = leftover;
						}
					}
					hptr->size = Size;

		
					printf("CustomHeapAlloc [%d] returning %p\r\n", Size, hptr->Address);
					//exit(-1);

					return (uint32_t) hptr->Address;
				}

			}
		}

			

	//aptr = NULL;
	hptr = NULL;

	//for (aptr = (CustomHeapArea *)tinfo->memory_areas; aptr != NULL; aptr = aptr->next) {
		 SpaceLeft = MasterVM.HeapHigh - MasterVM.HeapLast;
		
		//if (SpaceLeft <= 0) continue;

		hptr = (Emulation::HeapAllocations *) new Emulation::HeapAllocations;
		if (hptr == NULL) {
			printf("out of space\n");
			exit(-1);
		}
		
		hptr->size = Size;

		if (MasterVM.HeapLast == 0) {
			hptr->Address = MasterVM.HeapLow;
		} else {
			hptr->Address = MasterVM.HeapLast;
		}

		MasterVM.HeapLast = hptr->Address + Size;

		//// ensure we free the space.. fuzzing = fine.. but backdoors. we dont want that memory getting transferred during shadow copy/sync
		// *** FIX do on vmem
		//ZeroMemory((void *)hptr->Address, Size);

		hptr->next = MasterVM.HeapList;
		MasterVM.HeapList = hptr;
		//break;
	//}

	printf("CustomHeapAlloc [%d] returning %p [aptr %p hptr %p]\r\n", Size, hptr->Address, 0, hptr);
	//OutputDebugString(ebuf);
	
	//asm("int3");

	return (uint32_t)hptr->Address;
	
}

// mark heap block as freed
int Emulation::HeapFree(uint32_t Address) {
	Emulation::HeapAllocations *hptr = MasterVM.HeapList;
	while (hptr != NULL) {
		if (hptr->Address == Address) {
			break;
		}
		hptr = hptr->next;
	}
	
	if (hptr == NULL)
	return -1;
	
	hptr->free = 1;
	
	if (hptr->proxy) {
		// if proxied.. lets clear the memory on the other side.. ***
	}
	
	return 1;
}



Emulation::EmulationThread *Emulation::ExecuteLoop(
	VirtualMemory *vmem, Emulation::CodeAddr StartAddr,
	 Emulation::CodeAddr EndAddr,
	  struct cpu_user_regs *registers,
	  int new_thread) {

	EmulationLog *logptr = NULL;
	EmulationThread *thread = NULL;
	int done = 0, count = 0;
	CodeAddr EIP = StartAddr;

	if (new_thread) {
		thread = NewThread(&MasterVM);//, EIP, registers);
		if (thread == NULL) {
			return NULL;
		}
	} else {
		thread = MasterThread;
	}

	if (thread == MasterThread) {
		std::memcpy((void *)&MasterThread->registers, registers, sizeof(struct cpu_user_regs));
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
Emulation::EmulationThread *Emulation::NewVirtualMachineChild(VirtualMemory *ParentMemory, Emulation::CodeAddr EIP,
		struct cpu_user_regs *registers) {
	return NULL;
/*
	EmulationThread *Thread = new EmulationThread;
	std::memset((void *)Thread, 0, sizeof(EmulationThread));

	Thread->ID = ++Current_VM_ID;
	Thread->CPUStart = Thread->CPUCycle = Master.CPUCycle;

	Thread->EmuVMEM->SetParent(ParentMemory);
	Thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_ID, Thread->ID);
	//Thread->EmuVMEM->Configure(VirtualMemory::SettingType::SETTINGS_VM_LOGID, 0);
*/
}

// this is to destroy a virtual machine (if we have exhausted all instructions through particular branches..
// *** this should queue a new virtual machine for a previously untested branch
void Emulation::DestroyVirtualMachineChild(Emulation::EmulationThread *Thread) {
/*
	// dont do the initial static
	if (Thread == &Master) return;

	Thread->EmuVMEM->ReleaseParent();
	_VM2[Thread->ID] = NULL;
	EmuThread[Thread->ID] = NULL;

	delete Thread;
	*/
	return;
}

// adds log for read/writing of data to virtual memory...
Emulation::Changes *Emulation::CreateChangeLogData(Emulation::Changes **changelist, int which, uint32_t Address, unsigned char *orig,
		unsigned char *cur, int size) {
			
	//printf("CHANGE DATA\n");
	Changes *change = new Changes;

	std::memset(change, 0, sizeof(Changes));

	change->Data_Size = size;
	change->Type = which;
	change->Address = Address;
	
	change->Data = (char *)malloc(size + 1);
	if (change->Data == NULL)
		throw;
		
	memcpy(change->Data, cur, size);

	
/*	change->next = *changelist;
	*changelist = change;
*/
	Emulation::Changes *cptr = *changelist;
	if (cptr != NULL) {
		int c = 0;
		while (cptr->next != NULL) {
			cptr = cptr->next;
			c++;
		}
		
		cptr->next = change;
		
		//printf("Added to next [%d count]\n", c);
	} else {
		*changelist = change;
	}
	
	return change;	
}


Emulation::Changes *Emulation::CreateChangeEntryRegister(Emulation::Changes **changelist, int which, unsigned char *orig,
		unsigned char *cur, int size) {
	Changes *change = new Changes;

	std::memset(change, 0, sizeof(Changes));


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
		CreateChangeEntryRegister(&logptr->Changes, REG_EIP, (unsigned char *)&thread->registers_shadow.eip,  (unsigned char *)&thread->registers.eip, sizeof(uint32_t));
	}
	if (thread->registers.eax != thread->registers_shadow.eax) {
		Monitor |= REG_EAX;
		CreateChangeEntryRegister(&logptr->Changes, REG_EAX,  (unsigned char *)&thread->registers_shadow.eax, (unsigned char *) &thread->registers.eax, sizeof(uint32_t));
	}
	if (thread->registers.ebx != thread->registers_shadow.ebx) {
		Monitor |= REG_EBX;
		CreateChangeEntryRegister(&logptr->Changes, REG_EBX, (unsigned char *)&thread->registers_shadow.ebx, (unsigned char *) &thread->registers.ebx, sizeof(uint32_t));
	}
	if (thread->registers.ecx != thread->registers_shadow.ecx) {
		Monitor |= REG_ECX;
		CreateChangeEntryRegister(&logptr->Changes, REG_ECX, (unsigned char *) &thread->registers_shadow.ecx, (unsigned char *) &thread->registers.ecx, sizeof(uint32_t));
	}
	if (thread->registers.edx != thread->registers_shadow.edx) {
		Monitor |= REG_EDX;
		CreateChangeEntryRegister(&logptr->Changes, REG_EDX, (unsigned char *) &thread->registers_shadow.edx, (unsigned char *) &thread->registers.edx, sizeof(uint32_t));
	}
	if (thread->registers.esp != thread->registers_shadow.esp) {
		Monitor |= REG_ESP;
		printf("ESP changes: %d\n", thread->registers.esp - thread->registers_shadow.esp);
		CreateChangeEntryRegister(&logptr->Changes, REG_ESP,  (unsigned char *)&thread->registers_shadow.esp,  (unsigned char *)&thread->registers.esp, sizeof(uint32_t));
	}
	if (thread->registers.ebp != thread->registers_shadow.ebp) {
		Monitor |= REG_EBP;
		CreateChangeEntryRegister(&logptr->Changes, REG_EBP,  (unsigned char *)&thread->registers_shadow.ebp, (unsigned char *) &thread->registers.ebp, sizeof(uint32_t));
	}
	if (thread->registers.esi != thread->registers_shadow.esi) {
		Monitor |= REG_ESI;
		CreateChangeEntryRegister(&logptr->Changes, REG_ESI,  (unsigned char *)&thread->registers_shadow.esi,  (unsigned char *)&thread->registers.esi, sizeof(uint32_t));
	}
	if (thread->registers.edi != thread->registers_shadow.edi) {
		Monitor |= REG_EDI;
		CreateChangeEntryRegister(&logptr->Changes, REG_EDI,  (unsigned char *)&thread->registers_shadow.edi, (unsigned char *) &thread->registers.edi, sizeof(uint32_t));
	}
	if (thread->registers.eflags != thread->registers_shadow.eflags) {
		Monitor |= REG_EFLAGS;
		CreateChangeEntryRegister(&logptr->Changes, REG_EFLAGS, (unsigned char *) &thread->registers_shadow.eflags,  (unsigned char *)&thread->registers.eflags, sizeof(uint32_t));
	}
	if (thread->registers.cs != thread->registers_shadow.cs) {
		Monitor |= REG_CS;
		CreateChangeEntryRegister(&logptr->Changes, REG_CS, (unsigned char *) &thread->registers_shadow.cs, (unsigned char *) &thread->registers.cs, sizeof(uint16_t));
	}
	if (thread->registers.es != thread->registers_shadow.es) {
		Monitor |= REG_ES;
		CreateChangeEntryRegister(&logptr->Changes, REG_ES, (unsigned char *) &thread->registers_shadow.es,  (unsigned char *)&thread->registers.es, sizeof(uint16_t));
	}
	if (thread->registers.ds != thread->registers_shadow.ds) {
		Monitor |= REG_DS;
		CreateChangeEntryRegister(&logptr->Changes, REG_DS,  (unsigned char *)&thread->registers_shadow.ds,  (unsigned char *)&thread->registers.ds, sizeof(uint16_t));
	}
	if (thread->registers.fs != thread->registers_shadow.fs) {
		Monitor |= REG_FS;
		CreateChangeEntryRegister(&logptr->Changes, REG_FS, (unsigned char *) &thread->registers_shadow.fs, (unsigned char *) &thread->registers.fs, sizeof(uint16_t));
	}
	if (thread->registers.gs != thread->registers_shadow.gs) {
		Monitor |= REG_GS;
		CreateChangeEntryRegister(&logptr->Changes, REG_GS, (unsigned char *) &thread->registers_shadow.gs, (unsigned char *) &thread->registers.gs, sizeof(uint16_t));
	}
	if (thread->registers.ss != thread->registers_shadow.ss) {
		Monitor |= REG_SS;
		CreateChangeEntryRegister(&logptr->Changes, REG_SS,  (unsigned char *)&thread->registers_shadow.ss, (unsigned char *) &thread->registers.ss, sizeof(uint16_t));
	}

	// duh! we need it in our structure!
	logptr->Monitor = Monitor;

	if (thread->LogList == NULL) {
		thread->LogList = thread->LogLast = logptr;
	} else {
		thread->LogLast->next = logptr;
		thread->LogLast = logptr;
	}
	
	return logptr;
}


void Emulation::PrintLog(EmulationLog *logptr) {
	printf("ChangeLog ID: %d Address: %X [%d EIP change]:",
		logptr->LogID, logptr->Address, logptr->Size);

	if (logptr->Monitor & REG_EIP) printf("EIP ");
	if (logptr->Monitor & REG_EAX) printf("EAX ");
	if (logptr->Monitor & REG_EBX) printf("EBX ");
	if (logptr->Monitor & REG_ECX) printf("ECX ");
	if (logptr->Monitor & REG_EDX) printf("EDX ");
	if (logptr->Monitor & REG_ESP) printf("ESP ");
	if (logptr->Monitor & REG_EBP) printf("EBP ");
	if (logptr->Monitor & REG_ESI) printf("ESI ");
	if (logptr->Monitor & REG_EDI) printf("EDI ");
	if (logptr->Monitor & REG_EFLAGS) printf("EFLAGS ");
	if (logptr->Monitor & REG_CS) printf("CS ");
	if (logptr->Monitor & REG_DS) printf("DS ");
	if (logptr->Monitor & REG_ES) printf("ES ");
	if (logptr->Monitor & REG_FS) printf("FS ");
	if (logptr->Monitor & REG_GS) printf("GS ");
	if (logptr->Monitor & REG_SS) printf("SS ");
	
	printf("\n");
}
