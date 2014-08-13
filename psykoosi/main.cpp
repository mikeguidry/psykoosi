/* DO NOT DISTRIBUTE - PRIVATE SOURCE CODE OF MIKE GUIDRY GROUP / UNIFIED DEFENSE TECHNOLOGIES, INC.
 * YOU WILL BE PROSECUTED TO THE FULL EXTENT OF THE LAW IF YOU DISTRIBUTE OR DO NOT DELETE IMMEDIATELY,
 * UNLESS GIVEN PRIOR WRITTEN CONSENT BY MICHAEL GUIDRY, OR BOARD OF UNIFIED DEFENSE TECHNOLOGIES.
 *
 *
 * README CONTAINS INFORMATION
 */
#include <iostream>
#include <string>
#include <stdint.h>
#include <cstring>

#include <psykoosi_lib/psykoosi.h>

#include <unistd.h>

using namespace psykoosi;
using namespace std;

// our main function... lets try to keep as small as possible (as opposed to how many things were in asmrealign)
int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("psykoosi - binary modification platform\nusage: %s <binary> <module>\n", argv[0]);
		exit(-1);
	}

    string fileName = argv[1];
    Psykoosi psy(fileName, ".", true);
	nice(20);

    // loaded

    Disasm::CodeAddr entry = psy.GetEntryPoint();

    Disasm::InstructionInformation *ah = new Disasm::InstructionInformation;
    std::memset(ah, 0, sizeof(Disasm::InstructionInformation));
	int to_add = atoi(argv[3]);
	if (!to_add) to_add = 16;
	ah->RawData = new unsigned char[to_add + 1];
	ah->Size = to_add;
	for (int i = 0; i < to_add; i++) ah->RawData[i] = 0x90;
	ah->FromInjection = 1;
    Disasm::InstructionIterator it = psy.GetInstruction(entry);
    if (it == psy.InstructionsEnd()) {
        throw string("There was an issue finding the entry point.. maybe the file didnt load, or cache is damaged\n");
	}
    printf("Ientry: %p Addr %p size %d\n", it.get(), it->Address, it->Size);

	if (argc > 2)
        it->InjectedInstructions = ah;

    // injected

//    psy.Commit();
    psy.Save(fileName);
}
