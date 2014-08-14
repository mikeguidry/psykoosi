/* DO NOT DISTRIBUTE - PRIVATE SOURCE CODE OF MIKE GUIDRY GROUP / UNIFIED DEFENSE TECHNOLOGIES, INC.
 * YOU WILL BE PROSECUTED TO THE FULL EXTENT OF THE LAW IF YOU DISTRIBUTE OR DO NOT DELETE IMMEDIATELY,
 * UNLESS GIVEN PRIOR WRITTEN CONSENT BY MICHAEL GUIDRY, OR BOARD OF UNIFIED DEFENSE TECHNOLOGIES.
 *
 *
 * README CONTAINS INFORMATION
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
#include "structures.h"
extern "C" {
#include <unistd.h>
}

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;
/*
// Sculpture of our masterpiece....
// Handles some CTORs and allows pointers for other pointers required for class CTORS
// anyways im up for rewriting this later depending on final stage (DLL, Service, EXE, etc)
typedef struct _sculpture_parameters {
  // Virtual Memory is so we can have a snapshot of the binary in memory to work on
  VirtualMemory vmem;
  VirtualMemory *TemporaryVMEM;

  // binary loader handles loading from PE into virtual memory
  BinaryLoader *loader;

  // disassembler (should be easy enough to swap out with another for other architectures not avail)
  DisassembleTask *disasm;
  // analysis class after disassembler has ran its course for the first time anyhow
  InstructionAnalysis *analysis;

  // until later versions and completely modular.. lets make this PE specific
  pe_base *pe_image;
} Sculpture;
*/



// was getting  messy
char * Cache_Filename(char *filename, char *type, char *dest) {
	char *tmpb = strrchr(filename, '/');
	if (tmpb == NULL) tmpb = filename; else tmpb++;

	sprintf(dest, "%s.%s.cache", tmpb, type);

	return dest;
}


DisassembleTask::InstructionInformation *Inj_LoadFile(char *filename) {
	if (!strlen(filename)) return NULL;
	std::ifstream qcin(filename, std::ios::in | std::ios::binary);
	if (!qcin) return 0;

	qcin.seekg( 0, std::ios::end );
	std::streampos fsize = qcin.tellg();
	qcin.seekg( 0, std::ios::beg );
	qcin.clear();

	DisassembleTask::InstructionInformation *ah = new DisassembleTask::InstructionInformation;
	std::memset(ah, 0, sizeof(DisassembleTask::InstructionInformation));

	ah->RawData = new unsigned char [fsize];
	qcin.read((char *)ah->RawData, fsize);
	qcin.close();

	ah->Size = fsize;
	ah->FromInjection = 1;
	ah->CatchOriginalRelativeDestinations = 1;

	return ah;
}

DisassembleTask::InstructionInformation *Inj_Stream(unsigned char *buffer, int size) {
	DisassembleTask::InstructionInformation *ah = new DisassembleTask::InstructionInformation;
	std::memset(ah, 0, sizeof(DisassembleTask::InstructionInformation));

	ah->RawData = new unsigned char [size];
	std::memcpy((char *)ah->RawData, buffer, size);

	ah->Size = size;
	ah->FromInjection = 1;
	ah->CatchOriginalRelativeDestinations = 1;

	return ah;
}

DisassembleTask::InstructionInformation *Inj_NOP(int size) {
	DisassembleTask::InstructionInformation *ah = NULL;
	unsigned char *buf = new unsigned char[size];
	for (int  i = 0; i < size; i++)
		buf[i] = 0x90;

	ah = Inj_Stream(buf, size);

	delete buf;

	return ah;
}



// our main function... lets try to keep as small as possible (as opposed to how many things were in asmrealign)
int main(int argc, char *argv[]) {
	char filename[1024];
	if (argc < 2) {
		printf("psykoosi - binary modification platform\nusage: %s <binary> <module>\n", argv[0]);
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
	op.disasm = new DisassembleTask(&op.vmem);
	op.analysis = new InstructionAnalysis(op.disasm);
  	op.loader = new BinaryLoader(op.disasm, op.analysis, &op.vmem);
	op.pe_image = op.loader->LoadFile(0,0,(char *)argv[1]);

	if (!op.pe_image) {
		printf("Cannot open file: %s\n", argv[1]);
		exit(0);
	}
	int next_count, inj_count;
	int from_cache = 0;

	next_count = op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_NEXT);
	inj_count = op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_INJECTED);
	printf("next count %d inj %d\n", next_count, inj_count);

	uint32_t highest = op.loader->HighestAddress(1);
	std::cout << "highest: " << highest << std::endl;

	op.disasm->SetBinaryLoaderHA(highest);
	op.disasm->SetPEHandle(op.pe_image);
	std::cout << "highest: " << highest << std::endl;


	int start = time(0);

	// this is a little better.. will do it differently later in another function
	if (op.disasm->Cache_Load(Cache_Filename(argv[1], "disasm", (char *)&filename)) &&
			op.analysis->QueueCache_Load(Cache_Filename(argv[1], "analysis", (char *)&filename)) &&
			op.vmem.Cache_Load(Cache_Filename(argv[1], "vmem", (char *)&filename))) {
			from_cache = 1;
			int now = time(0);
			printf("Loaded cache! [%d seconds]\n", now - start);
		} else {
			op.disasm->Clear_Instructions();
			printf("Only loaded instructions.. clearing\n");
		}


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

	printf("%d Instructions after loading\n", op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_NEXT));


	std::cout << "Disasm Count " << op.disasm->DCount << std::endl;
	std::cout << "Call Count " << op.analysis->CallCount << std::endl;
	std::cout << "Push Count " << op.analysis->PushCount << std::endl;
	std::cout << "Realign Count " << op.analysis->RealignCount << std::endl;

	DisassembleTask::CodeAddr InjAddr = op.pe_image->get_image_base_32() + op.pe_image->get_ep();
	DisassembleTask::InstructionInformation *InjEntry = NULL;

	if (argc == 2) { // only have filename to modify
		InjAddr = 0;
	} else {
		if (argc >= 3) // have address after filename for injection
			sscanf(argv[2], "%x", (void *)&InjAddr);
		if (argc >= 4) { // have filename of shellcode
			InjEntry = Inj_LoadFile(argv[3]);
		}
		if (InjEntry == NULL) {
				printf("Inj_LoadFile(\"%s\") failed.. using  2048 NOPs\n", argv[3]);
				InjEntry = Inj_NOP(2048);
		}

	}

	if (InjAddr) {
		printf("Injection Address: %p\n", InjAddr);
		printf("Injection Entry: Size = %d Ptr = %p\n", InjEntry->Size, InjEntry->RawData);

		DisassembleTask::InstructionInformation *InjLoc = op.disasm->GetInstructionInformationByAddress(InjAddr, DisassembleTask::LIST_TYPE_NEXT, 0, NULL);
		if (!InjLoc) {
			printf("We could not find the instruction at location %p for injection\n", InjAddr);
			throw;
		}
		printf("Instruction at Injection Location [%p] - Addr %p Size %d\n", InjLoc, InjLoc->Address, InjLoc->Size);
		InjLoc->InjectedInstructions = InjEntry;
	}




	Rebuilder master(op.disasm, op.analysis, &op.vmem, op.pe_image, argv[1]);
	master.SetBinaryLoader(op.loader);
	master.RebuildInstructionsSetsModifications();
	master.RealignInstructions();
	next_count = op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_NEXT);
		inj_count = op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_INJECTED);
		printf("next count %d inj %d\n", next_count, inj_count);

	master.ModifyRelocations();
	master.WriteBinaryPE2();
}
