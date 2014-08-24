#pragma once

#include <string>

#include "disassemble.h"
#include "virtualmemory.h"
#include "analysis.h"
#include "loading.h"
#include "structures.h"

namespace psykoosi {

// High-level api for psykoosi
class Psykoosi {
public:
    Psykoosi(const std::string &fileName, const std::string &dllDir,
             const std::string &cacheDir = std::string(),
             bool debug = false);
    ~Psykoosi();
    Disasm::CodeAddr GetEntryPoint();
    Disasm::InstructionIterator GetInstruction(Disasm::CodeAddr address);
    Disasm::InstructionIterator InstructionsBegin();
    Disasm::InstructionIterator InstructionsEnd();
    void Commit(); // rebuild in-memory image with injected / removed instructions
    void Save(const std::string &fileName);
private:
    void Load(const std::string &fileName, const std::string &dllDir);
    std::string CacheFileName(const std::string& fileName, const std::string& type);
private:
    std::string CacheDir;
    Sculpture op;
    bool Debug;
};

}
