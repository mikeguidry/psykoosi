#ifndef STRUCTURES_H
#define STRUCTURES_H

namespace psykoosi {

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;

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



}

#endif
