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

#include <fstream>

#include <psykoosi_lib/psykoosi.h>

#include <unistd.h>

using namespace psykoosi;
using namespace std;

Disasm::InstructionInformation *Inj_LoadFile(char *filename) {
	if (!strlen(filename)) return NULL;
	std::ifstream qcin(filename, std::ios::in | std::ios::binary);
	if (!qcin) return 0;

	qcin.seekg( 0, std::ios::end );
	std::streampos fsize = qcin.tellg();
	qcin.seekg( 0, std::ios::beg );
	qcin.clear();

    Disasm::InstructionInformation *ah = new Disasm::InstructionInformation;
    std::memset(ah, 0, sizeof(Disasm::InstructionInformation));

	ah->RawData = new unsigned char [fsize];
	qcin.read((char *)ah->RawData, fsize);
	qcin.close();

	ah->Size = fsize;
	ah->FromInjection = 1;
	ah->CatchOriginalRelativeDestinations = 1;

	return ah;
}

Disasm::InstructionInformation *Inj_Stream(unsigned char *buffer, int size) {
    Disasm::InstructionInformation *ah = new Disasm::InstructionInformation;
    std::memset(ah, 0, sizeof(Disasm::InstructionInformation));

	ah->RawData = new unsigned char [size];
	std::memcpy((char *)ah->RawData, buffer, size);

	ah->Size = size;
	ah->FromInjection = 1;
	ah->CatchOriginalRelativeDestinations = 0;

	return ah;
}

Disasm::InstructionInformation *Inj_NOP(int size) {
    Disasm::InstructionInformation *ah = NULL;
	unsigned char *buf = new unsigned char[size];
	for (int  i = 0; i < size; i++)
		buf[i] = 0x90;

	ah = Inj_Stream(buf, size);

	delete buf;

	return ah;
}



// our main function... lets try to keep as small as possible (as opposed to how many things were in asmrealign)
int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("psykoosi - binary modification platform\nusage: %s <binary> <address to inject> <filename of shellcode or blank for NOPs>\n", argv[0]);
		exit(-1);
	}

    string fileName = argv[1];
    Psykoosi psy(fileName, ".", true);
	nice(20);

    // loaded

    Disasm::CodeAddr InjAddr = psy.GetEntryPoint();
    Disasm::InstructionInformation *InjEntry = NULL;

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

        Disasm::InstructionIterator InjLoc = psy.GetInstruction(InjAddr);

        if (InjLoc != psy.InstructionsEnd()) {
			printf("We could not find the instruction at location %p for injection\n", InjAddr);
			throw;
		}
		printf("Instruction at Injection Location [%p] - Addr %p Size %d\n", InjLoc, InjLoc->Address, InjLoc->Size);
		InjLoc->InjectedInstructions = InjEntry;
	}

//    psy.Commit();
    psy.Save(fileName);
}
