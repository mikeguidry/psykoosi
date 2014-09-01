#pragma once

#include <string>

#include "disassemble.h"
#include "virtualmemory.h"
#include "analysis.h"
#include "loading.h"
#include "structures.h"

namespace psykoosi {

// High-level api for psykoosi

class Disasm;
class Disasm::InstructionInformation;
class InstructionIterator {
public:
    InstructionIterator(Disasm::InstructionInformation* ptr = nullptr);
    InstructionIterator(const InstructionIterator&) = default;
    void Inject(InstructionIterator instruction);
    bool operator==(const InstructionIterator& other);
    bool operator!=(const InstructionIterator& other);
    Disasm::InstructionInformation* operator->();
    void operator++();
    void operator--();
    void jump();
    Disasm::InstructionInformation* get();
    // todo: over operations
private:
    Disasm::InstructionInformation *InstInfoPtr = nullptr;
};

class Psykoosi {
public:
    Psykoosi(const std::string &fileName, const std::string &dllDir,
             const std::string &cacheDir = std::string(),
             bool debug = false);
    Psykoosi();
    ~Psykoosi();
    Disasm::CodeAddr GetEntryPoint();
    InstructionIterator GetInstruction(Disasm::CodeAddr address);
    InstructionIterator InstructionsBegin();
    InstructionIterator InstructionsEnd();
    void Commit(); // rebuild in-memory image with injected / removed instructions
    void Save(std::string fileName);
    void Load(std::string fileName, std::string dllDir);
    void SetDebug(bool debug);
private:
    std::string CacheFileName(const std::string& fileName, const std::string& type);
private:
    std::string CacheDir;
    Sculpture op;
    bool Debug;
};

InstructionIterator Inj_Stream(const unsigned char *buffer, int size);
InstructionIterator Inj_NOP(int size);

}
