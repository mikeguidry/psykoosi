#include "psykoosi.h"
#include "rebuild.h"
#include "disassemble.h"
#include <cstring>

#include <iostream>

namespace psykoosi {

#define dprintf(fmt, ...) if (Debug) { printf(fmt, ##__VA_ARGS__); }

Psykoosi::Psykoosi(const std::string &fileName,
                   const std::string &dllDir,
                   const std::string &cacheDir,
                   bool debug)
    : CacheDir(cacheDir)
    , Debug(debug)
{
    op.disasm = new Disasm(&op.vmem);
    op.analysis = new InstructionAnalysis(op.disasm);
    op.loader = new BinaryLoader(op.disasm, op.analysis, &op.vmem);
    Load(fileName, dllDir);
}

Psykoosi::Psykoosi() {
    op.disasm = new Disasm(&op.vmem);
    op.analysis = new InstructionAnalysis(op.disasm);
    op.loader = new BinaryLoader(op.disasm, op.analysis, &op.vmem);
}

Psykoosi::~Psykoosi() {
    delete op.loader;
    delete op.analysis;
    delete op.disasm;
}

Disasm::CodeAddr Psykoosi::GetEntryPoint() {
    return op.pe_image->get_image_base_32() + op.pe_image->get_ep();
}


InstructionIterator::InstructionIterator(Disasm::InstructionInformation *ptr)
    : InstInfoPtr(ptr)
{
}

void InstructionIterator::Inject(InstructionIterator instruction) {
    InstInfoPtr->InjectedInstructions = instruction.get();
}

bool InstructionIterator::operator==(const InstructionIterator& other) {
    return InstInfoPtr == other.InstInfoPtr;
}

bool InstructionIterator::operator!=(const InstructionIterator& other) {
    return InstInfoPtr != other.InstInfoPtr;
}

Disasm::InstructionInformation* InstructionIterator::operator->() {
    return InstInfoPtr;
}

void InstructionIterator::operator++() {
    InstInfoPtr = InstInfoPtr->Lists[Disasm::LIST_TYPE_NEXT];
}

void InstructionIterator::operator--() {
    InstInfoPtr = InstInfoPtr->Lists[Disasm::LIST_TYPE_PREV];
}

void InstructionIterator::jump() {
    InstInfoPtr = InstInfoPtr->Lists[Disasm::LIST_TYPE_JUMP];
}

Disasm::InstructionInformation *InstructionIterator::get() {
    return InstInfoPtr;
}


InstructionIterator Psykoosi::GetInstruction(Disasm::CodeAddr address) {
    Disasm::InstructionInformation* instInfo =
        op.disasm->GetInstructionInformationByAddress(address, Disasm::LIST_TYPE_NEXT, 0, nullptr);
    return InstructionIterator(instInfo);
}

InstructionIterator Psykoosi::InstructionsBegin() {
    return InstructionIterator(op.disasm->GetInstructionsData(Disasm::LIST_TYPE_NEXT));
}

InstructionIterator Psykoosi::InstructionsEnd() {
    return InstructionIterator(nullptr);
}

void Psykoosi::Commit() {
    throw std::string("unimplemented");
}

void Psykoosi::Save(std::string fileName) {
    // todo: split this stuff into commit and save to be able make several commits before store final binary
    Rebuilder master(op.disasm, op.analysis, &op.vmem, op.pe_image, fileName.c_str());
    master.SetBinaryLoader(op.loader);
    master.RebuildInstructionsSetsModifications();
    master.RealignInstructions();
    int next_count = op.disasm->InstructionsCount(Disasm::LIST_TYPE_NEXT);
    int inj_count = op.disasm->InstructionsCount(Disasm::LIST_TYPE_INJECTED);
    printf("next count %d inj %d\n", next_count, inj_count);

    master.ModifyRelocations();
    master.WriteBinaryPE2();
}

void Psykoosi::Load(std::string fileName, std::string dllDir) {
    op.pe_image = op.loader->LoadFile(0,0,fileName.c_str());
    op.loader->SetDLLDirectory(dllDir.c_str());
    if (!op.pe_image) {
        throw std::string("Can not open file ") + fileName;
    }

    int next_count, inj_count;
    int from_cache = 0;

    next_count = op.disasm->InstructionsCount(Disasm::LIST_TYPE_NEXT);
    inj_count = op.disasm->InstructionsCount(Disasm::LIST_TYPE_INJECTED);
    printf("next count %d inj %d\n", next_count, inj_count);

    uint32_t highest = op.loader->HighestAddress(1);
    std::cout << "highest: " << highest << std::endl;

    op.disasm->SetBinaryLoaderHA(highest);
    op.disasm->SetPEHandle(op.pe_image);
    std::cout << "highest: " << highest << std::endl;


    int start = time(0);

    if (!from_cache) {
        start = time(0);
        op.analysis->Complete_Analysis_Queue(0);
        int now = time(0);
        dprintf("Disassembled first time! [%d seconds]\n", now - start);
        from_cache = 0;


        if (!CacheDir.empty()) {
            start = time(0);
            op.disasm->Cache_Save(CacheFileName(fileName, "disasm").c_str());
            op.analysis->QueueCache_Save(CacheFileName(fileName, "analysis").c_str());
            op.vmem.Cache_Save(CacheFileName(fileName, "vmem").c_str());
            now = time(0);
            dprintf("Saved cache in %d seconds\n", now - start);
        }
    }

    dprintf("%d Instructions after loading\n", op.disasm->InstructionsCount(Disasm::LIST_TYPE_NEXT));

    dprintf("Disasm Count:     %d\n", op.disasm->DCount);
    dprintf("Call Count:       %d\n", op.analysis->CallCount);
    dprintf("Push Count:       %d\n", op.analysis->PushCount);
    dprintf("Realign Count:    %d\n", op.analysis->RealignCount);
}

void Psykoosi::SetDebug(bool debug) {
    Debug = debug;
}

std::string Psykoosi::CacheFileName(const std::string& fileName, const std::string& type) {
    return CacheDir + "/" + fileName + "." + type + ".cache";
}

InstructionIterator Inj_Stream(const unsigned char *buffer, int size) {
    Disasm::InstructionInformation *ah = new Disasm::InstructionInformation;
    memset(ah, 0, sizeof(Disasm::InstructionInformation));

    ah->RawData = new unsigned char [size];
    memcpy((char *)ah->RawData, buffer, size);

    ah->Size = size;
    ah->FromInjection = 1;
    ah->CatchOriginalRelativeDestinations = 0;

    return InstructionIterator(ah);
}

InstructionIterator Inj_NOP(int size) {
    std::string buff((size_t)size, (char)0x90);
    return Inj_Stream((const unsigned char*)buff.data(), buff.size());
}

}
