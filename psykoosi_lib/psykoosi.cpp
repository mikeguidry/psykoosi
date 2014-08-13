#include "psykoosi.h"
#include "rebuild.h"

#include <iostream>

namespace psykoosi {

#define dprintf(fmt, ...) if (Debug) { printf(fmt, ##__VA_ARGS__); }

Psykoosi::Psykoosi(const std::string &fileName,
                   const std::string &cacheDir,
                   bool debug)
    : CacheDir(cacheDir)
    , Debug(debug)
{
    op.disasm = new Disasm(&op.vmem);
    op.analysis = new InstructionAnalysis(op.disasm);
    op.loader = new BinaryLoader(op.disasm, op.analysis, &op.vmem);
    Load(fileName);
}

Psykoosi::~Psykoosi() {
    delete op.loader;
    delete op.analysis;
    delete op.disasm;
}

Disasm::CodeAddr Psykoosi::GetEntryPoint() {
    return op.pe_image->get_image_base_32() + op.pe_image->get_ep();
}

Disasm::InstructionIterator Psykoosi::GetInstruction(Disasm::CodeAddr address) {
    Disasm::InstructionInformation* instInfo =
        op.disasm->GetInstructionInformationByAddress(address, Disasm::LIST_TYPE_NEXT, 0, nullptr);
    return Disasm::InstructionIterator(instInfo);
}

Disasm::InstructionIterator Psykoosi::InstructionsBegin() {
    return Disasm::InstructionIterator(op.disasm->GetInstructionsData(Disasm::LIST_TYPE_NEXT));
}

Disasm::InstructionIterator Psykoosi::InstructionsEnd() {
    return Disasm::InstructionIterator(nullptr);
}

void Psykoosi::Commit() {
    throw std::string("unimplemented");
}

void Psykoosi::Save(const std::string &fileName) {
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

void Psykoosi::Load(const std::string &fileName) {
    op.pe_image = op.loader->LoadFile(0,0,fileName.c_str());
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

    // this is a little better.. will do it differently later in another function
    if (!CacheDir.empty() && op.disasm->Cache_Load(CacheFileName(fileName, "disasm").c_str()) &&
            op.analysis->QueueCache_Load(CacheFileName(fileName, "analysis").c_str()) &&
            op.vmem.Cache_Load(CacheFileName(fileName, "vmem").c_str()))
    {
        from_cache = 1;
        int now = time(0);
        dprintf("Loaded cache! [%d seconds]\n", now - start);
    } else {
        op.disasm->Clear_Instructions();
        dprintf("Only loaded instructions.. clearing\n");
    }


    if (!from_cache) {
        //op.disasm->Clear_Instructions();
        //op.analysis->Queue_Clear();
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

std::string Psykoosi::CacheFileName(const std::string& fileName, const std::string& type) {
    return CacheDir + "/" + fileName + "." + type + ".cache";
}


}
