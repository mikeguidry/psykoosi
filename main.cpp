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
#include "virtualmemory.h"
#include "disassemble.h"
#include "analysis.h"
#include "loading.h"
#include "rebuild.h"
#include "structures.h"

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

// our main function... lets try to keep as small as possible (as opposed to how many things were in asmrealign)
int main(int argc, char *argv[]) {

	if (argc < 2) {
		printf("psykoosi - binary modification platform\nusage: %s <binary> <module>\n", argv[0]);
		exit(-1);
	}

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
	// try to load cache...
	char cfile[1024];
	sprintf(cfile, "%s.cache.disasm", argv[1]);
	if (op.disasm->Cache_Load(cfile)) {
		sprintf(cfile, "%s.cache.analysis", argv[1]);
		if (op.analysis->QueueCache_Load(cfile)) {
			from_cache = 1;
			int now = time(0);
			printf("Loaded cache! [%d seconds]\n", now - start);
//			op.analysis->CleanInstructionAnalysis();
	//		op.analysis->Complete_Analysis_Queue(1);
		} else {
			op.disasm->Clear_Instructions();
			printf("Only loaded instructions.. clearing\n");
		}
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
		sprintf(cfile, "%s.cache.disasm", argv[1]);
		if (op.disasm->Cache_Save(cfile)) {
			sprintf(cfile, "%s.cache.analysis", argv[1]);
			if (op.analysis->QueueCache_Save(cfile)) {
				from_cache = 1;
			}
		}
		now = time(0);
		printf("Saved cache in %d seconds\n", now - start);
	}

	printf("%d Instructions after loading\n", op.disasm->InstructionsCount(DisassembleTask::LIST_TYPE_NEXT));


	std::cout << "Disasm Count " << op.disasm->DCount << std::endl;
	std::cout << "Call Count " << op.analysis->CallCount << std::endl;
	std::cout << "Push Count " << op.analysis->PushCount << std::endl;
	std::cout << "Realign Count " << op.analysis->RealignCount << std::endl;

	uint32_t entry = op.pe_image->get_image_base_32() + op.pe_image->get_ep();

	DisassembleTask::InstructionInformation *ah = new DisassembleTask::InstructionInformation;
	std::memset(ah, 0, sizeof(DisassembleTask::InstructionInformation));
	ah->RawData = new unsigned char[64];
	ah->Size = (argc == 4) ? atoi(argv[3]) : 1;
	for (int i = 0; i < ah->Size; i++) ah->RawData[i] = 0x90;
	ah->FromInjection = 1;
	DisassembleTask::InstructionInformation *Ientry = op.disasm->GetInstructionInformationByAddress(entry, DisassembleTask::LIST_TYPE_NEXT, 0, NULL);
	if (!Ientry) {
		printf("There was an issue finding the entry point.. maybe the file didnt load, or cache is damaged\n");
		throw;
	}
	printf("Ientry: %p Addr %p size %d\n", Ientry, Ientry->Address, Ientry->Size);

	if (argc > 2)
		Ientry->InjectedInstructions = ah;
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
