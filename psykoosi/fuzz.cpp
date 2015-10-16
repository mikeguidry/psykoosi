/* DO NOT DISTRIBUTE - PRIVATE SOURCE CODE OF MIKE GUIDRY GROUP / UNIFIED DEFENSE TECHNOLOGIES, INC.
 * YOU WILL BE PROSECUTED TO THE FULL EXTENT OF THE LAW IF YOU DISTRIBUTE OR DO NOT DELETE IMMEDIATELY,
 * UNLESS GIVEN PRIOR WRITTEN CONSENT BY MICHAEL GUIDRY, OR BOARD OF UNIFIED DEFENSE TECHNOLOGIES.
 *
 * meszek
 *
 * The intentions of this software is to find bugs solely in your own products.  I take no responsibility for
 * any damages created by anyone who takes and decides to use this software in their own way.
 */

#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <pe_lib/pe_bliss.h>
#include <fstream>
#include "virtualmemory.h"
#include "disassemble.h"
#include "analysis.h"
#include "loading.h"
#include "rebuild.h"
#include "apiproxy_client.h"

#include "emu_hooks.h"
#include "emulation.h"
#include "structures.h"
extern "C" {
#include <unistd.h>
}

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


// was getting  messy
char * Cache_Filename(char *filename, char *type, char *dest) {
	char *tmpb = strrchr(filename, '/');
	if (tmpb == NULL) tmpb = filename; else tmpb++;

	sprintf(dest, "%s.%s.cache", tmpb, type);

	return dest;
}


// our main function... lets try to keep as small as possible (as opposed to how many things were in asmrealign)
int main(int argc, char *argv[]) {
	char filename[1024];
	
	printf("meszek - psykoosi fuzzing platform\n");
	
	// init API Client
	APIClient apicl;
	
	// Connect to server (so we can figure out what memory area we need)
	// for relocations/etc for the executable...
	apicl.Connect("192.168.169.134", 5555);
	//apicl.Connect("127.0.0.1", 5555);

	
	
	if (argc < 2) {
		printf("usage: %s <PE executable file>\n", argv[0]);
		exit(-1);
	}

	// so my linux laptop can still move while testing/developing
	// and soon i would like to add multithreading.. will design that shortly!
	// splitting up disaassembling tasks into pthreads for the amount of cores from /proc/cpuinfo
	// also need to optimzie the engine (maybe use emulator so we dont have to do some much verification
	// and re-passes or ... keep strictly informatin so we know alignment isnt an issue)
	nice(20);

	// Lets initialize our main class....
	Sculpture op;
	// now load emulator before things.. so it can req the aAddress
	
	Emulation emu(&op.vmem);
	// connect the emulator and the sculpture together.. (turns off simulation mode)
	emu.ConnectToProxy(&apicl);
	emu._op = (void *)&op;
	

	// pass classes needed by each other class..
	// this is a MESS.. fix this :)...
	// restructure everything!
	apicl.VM = &op.vmem;
	op.disasm = new DisassembleTask(&op.vmem);
	op.analysis = new InstructionAnalysis(op.disasm);
  	op.loader = new BinaryLoader(op.disasm, op.analysis, &op.vmem);
	op.API = &apicl;
	emu.Loader = op.loader;
	
	int i =  apicl.Ping();
	printf("API Proxy <-> Pong: %d seconds..\n", i);


	// we'll create a system for loading configuration details from a file shortly that can be used
	// to configure every class also from LUA/scripting
	// set the DLL where we will load imports/dll dependencies
	op.loader->SetDLLDirectory("/Users/mike/dlls");

	uint32_t ImageBase = 0;
	uint32_t ImageSize = 0;
	
	// open the file (to get the image base)
	op.pe_image = op.loader->OpenFile(0,0,(char *)argv[1], &ImageBase, &ImageSize );
	
	if (op.pe_image == NULL) {
		printf("Couldnt open file: %s\n", argv[1]);
		exit(0);
	}
	
	// initialize the emulator with the image base..
	// so stack/heap/etc is all linear with this address..
	// to ensure API proxy has no issues..
	if (emu.Init(ImageBase) != ImageBase) {
		printf("Couldnt allocate %X.. trying to get a new (random) one..\n",  ImageBase);
		ImageBase = emu.Init(0);
		printf("afer init\n");
		if (ImageBase == 0) {
			printf("error allocating memory for operations on the remote side!\n");
			exit(-1);
		} else {
			printf("Obtained emulation base memory address: %p\n", ImageBase);
			// if allocation was successful.. lets go 1 megabyte into that address for processing the PE
			// until the new heap allocation is completed (can request sizes in the middle of other allocations)
			// lets just push it straight to heapalloc... and since its the first aAddress
			// due to our modification of Init() then it should load properly..
			// when emulation stops adding sizes to ReqAddr then add this back below *** FIX
			//ImageBase += (1024 * 1024);
		}
	}
	
	// lets try to allocate space surrounding the image base...
	// since our target may not have relocations (fixed:yes in linker)
	if (ImageBase != 0) {
		//* (1024 * 16)); add this back whenever we put the change in Init() from above back
		ImageBase = emu.HeapAlloc(ImageBase, ImageSize );
	} else {
		printf("Zero ImageBase!\n");
		exit(-1);
	}
	
	// now process the PE file (load into virtual memory, process imports/exports,
	// analysis and disassembly of instructions)
	// if we couldnt allocate the real ImageBase .. we can give another one here...
  	op.pe_image = op.loader->ProcessFile(op.pe_image, ImageBase );

	int next_count = 0, inj_count = 0;
	int from_cache = 0;

	next_count = op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_NEXT);
	inj_count = op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_INJECTED);
	printf("next count %d inj %d\n", next_count, inj_count);
	uint32_t highest = op.loader->HighestAddress(1);
	std::cout << "highest address for binary loader: " << highest << std::endl;
	op.disasm->SetBinaryLoaderHA(highest);
	op.disasm->SetPEHandle(op.pe_image);

	printf("Executing assembly analysis\n");

	int start = time(0);
	op.analysis->Complete_Analysis_Queue(0);
	int now = time(0);
	printf("Disassembled first time! [%d seconds]\n", now - start);
/*
	// this is a little better.. will do it differently later in another function
	if (op.disasm->Cache_Load(Cache_Filename(argv[1], "disasm", (char *)&filename)) &&
			op.analysis->QueueCache_Load(Cache_Filename(argv[1], "analysis", (char *)&filename)) &&
			op.vmem.Cache_Load(Cache_Filename(argv[1], "vmem", (char *)&filename))) {
			from_cache = 1;
			int now = time(0);
			printf("Loaded cache! [%d seconds]\n", now - start);
		} else {
			op.disasm->Clear_Instructions();
			//printf("Only loaded instructions.. clearing\n");
		}
*/


/*
	if (!from_cache) {
		//op.disasm->Clear_Instructions();
		//op.analysis->Queue_Clear();
		start = time(0);
		op.analysis->Complete_Analysis_Queue(0);
		int now = time(0);
		printf("Disassembled first time! [%d seconds]\n", now - start);

		start = time(0);
		from_cache = 0;

		op.disasm->Cache_Save(Cache_Filename(argv[1], "disasm", (char *)&filename));
		op.analysis->QueueCache_Save(Cache_Filename(argv[1], "analysis", (char *)&filename));
		op.vmem.Cache_Save(Cache_Filename(argv[1], "vmem", (char *)&filename));
		now = time(0);
		printf("Saved cache in %d seconds\n", now - start);
	}
*/

	printf("%d Instructions after loading\n", op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_NEXT));

	std::cout << "Disasm Count " << op.disasm->DCount << std::endl;
	std::cout << "Call Count " << op.analysis->CallCount << std::endl;
	std::cout << "Push Count " << op.analysis->PushCount << std::endl;
	std::cout << "Realign Count " << op.analysis->RealignCount << std::endl;

	DisassembleTask::CodeAddr InjAddr = op.pe_image->get_image_base_32() + op.pe_image->get_ep();
	printf("INJ ADDR %X\n", InjAddr);
	DisassembleTask::InstructionInformation *InjEntry = NULL;

	
	//Rebuilder master(op.disasm, op.analysis, &op.vmem, op.pe_image, argv[1]);
	//master.SetBinaryLoader(op.loader);
	

	// these are initial register settings after loading.. 
	//http://stackoverflow.com/questions/6028849/windows-initial-execution-context
	emu.SetRegister(emu.MasterThread, Emulation::REG_EIP, op.loader->EntryPoint);
	emu.SetRegister(emu.MasterThread, Emulation::REG_EAX, op.loader->EntryPoint);
	// PEB needs to be initialized *** FIX...
	// for local fs:[18h]... and such reads...
	// for now we can process that memory from remote side if API Proxy
	emu.SetRegister(emu.MasterThread, Emulation::REG_EBX, emu.MasterVM.PEB);
	
	//op.vmem.MemDebug = 1;
	int calls = 40;
	printf("Application Entry Point [%s]: %p\n", argv[1], op.loader->EntryPoint);
	printf("Starting emulation.. [static::%d instructions]\n", calls);
	while (calls-- && !emu.completed) {
		/*
		printf("--\n");
		// print registers before execution of the next instruction
		printf("EIP %x ESP %x EBP %x EAX %x EBX %x ECX %x EDX %x ESI %x EDI %x\n",
		(uint32_t)emu.MasterThread->registers.eip, (uint32_t)emu.MasterThread->registers.esp,
		(uint32_t)emu.MasterThread->registers.ebp,
		(uint32_t)emu.MasterThread->registers.eax,
		(uint32_t)emu.MasterThread->registers.ebx, (uint32_t)emu.MasterThread->registers.ecx,
		(uint32_t)emu.MasterThread->registers.edx,(uint32_t) emu.MasterThread->registers.esi,
		(uint32_t)emu.MasterThread->registers.edi);
		
		// get the 'instruction information' structure for this particular instruction
		// from the disassembly subsystem
		DisassembleTask::InstructionInformation *InsInfo = op.disasm->GetInstructionInformationByAddress(emu.MasterThread->registers.eip, DisassembleTask::LIST_TYPE_NEXT, 1, NULL);
		if (InsInfo != NULL) {
			//char *ptrbuf = (char *)InsInfo->InstructionMnemonicString;
			std::string ptrbuf = op.disasm->disasm_str(InsInfo->Address, (char *)InsInfo->RawData, InsInfo->Size);
			printf("%p %s\n", emu.MasterThread->registers.eip,ptrbuf.c_str()); 
			
		} else {
			// report that we didnt find this.. locate why later...
			printf("[!!!] InsInfo NULL for %X\n", emu.MasterThread->registers.eip);
		}

		// and finally.. handle the execution 
		
		Emulation::EmulationLog *exec_log = emu.StepInstruction(NULL, 0);
		if (exec_log == NULL) {
			printf("ERROR executing that instruction...\n");
		} */
		emu.StepCycle(emu.VMList);
	}
	
	
	printf("Emulation Completed...\n");
	
	printf("Printing resulting logs:\n");
	Emulation::EmulationLog *logptr = emu.MasterThread->LogList;
	
	while (logptr != NULL) {
		printf("LogID: %d EIP Address: %X NextEIP %X ChangeLog Count %d\n",
			logptr->LogID, logptr->Address, logptr->NextEIP, logptr->VMChangeLog_Count);
		
		emu.PrintLog(logptr);
		
		Emulation::Changes *chptr = logptr->Changes;
		
		while (chptr != NULL) {
			printf("\tLogged Changes Type %d Address %X Data Size %d\n", chptr->Type, chptr->Address, chptr->Data_Size);
			
			chptr = chptr->next;
		}
		printf("--\n");
		
		logptr = logptr->next;
	}
	
	
	
}
