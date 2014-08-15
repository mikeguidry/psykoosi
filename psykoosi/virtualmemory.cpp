/* This allows us to have 'Virtual Memory' to load images into and modify etc...   */
#include <cstddef>
#include <iostream>
#include <cstring>
#include <inttypes.h>
#include <stdio.h>
#include <fstream>
#include "virtualmemory.h"
// 64k pages...
#define PAGE_SIZE 4096*2*2*2*2*sizeof(unsigned char *)

using namespace psykoosi;


VirtualMemory::VirtualMemory()
{
  Memory_Pages = NULL;
  Section_List = Section_Last = NULL;
  VMParent = NULL;
}

VirtualMemory::~VirtualMemory()
{
  if (Memory_Pages != NULL) {
    MemPage *mptr = (MemPage *)Memory_Pages, *mptr2;
    
    // delete all memory pages we have information at...
    for (mptr = Memory_Pages; mptr; ) {
      mptr2 = mptr->next;
      if (mptr->data)
    	  delete mptr->data;
      delete mptr;
      mptr = mptr2;
    }
  }

}

void VirtualMemory::SetParent(VirtualMemory *Parent) {
	VMParent = Parent;
	VMParent->AddChild();
}

void VirtualMemory::ReleaseParent() {
	VMParent->ReleaseChild();
	VMParent = NULL;
}

void VirtualMemory::AddChild() {
	Children++;
}

void VirtualMemory::ReleaseChild() {
	Children--;
}

unsigned long VirtualMemory::roundupto(unsigned long n, unsigned long block){
	unsigned long ret;
    if(block <= 1) return n;
    block--;

    ret = (n + block) & ~block;

    return ret;
}

VirtualMemory::MemPage *VirtualMemory::MemPagePtrIfExists(unsigned long addr) {
    MemPage *mptr = (MemPage *)Memory_Pages;
    unsigned long round = roundupto(addr, PAGE_SIZE); // round up to 64k pages
    if (mptr != NULL) {
      for (; mptr != NULL; mptr = mptr->next) {
	  if ((unsigned long)round == mptr->round)
	      return mptr;
      }
    }
    return NULL;
}


VirtualMemory::MemPage *VirtualMemory::ClonePage(MemPage *ParentOriginal) {
	MemPage *mptr = NewPage(ParentOriginal->round, ParentOriginal->size);
	if (mptr == NULL) {
		printf("error cloning page!\n");
		throw;
		return NULL;
	}
	std::memcpy(mptr->data, ParentOriginal->data, mptr->size);

	return mptr;
}

int VirtualMemory::IsMyPage(MemPage *mptr) {
	return (mptr->ClassPtr == this);
}

VirtualMemory::MemPage *VirtualMemory::NewPage(unsigned long round, int size) {
    MemPage *mptr = new MemPage;

    std::memset(mptr, 0, sizeof(MemPage));

   // push old back..
   mptr->next = (MemPage *)Memory_Pages;
   // insert in the beginning
   Memory_Pages = mptr;

   // what page range is this for
   mptr->round = round;
   // size of this page
   mptr->size = PAGE_SIZE;
   // lets allocate the data
   mptr->data = new unsigned char[PAGE_SIZE+16];
   std::memset(mptr->data, 0x00, PAGE_SIZE);

   mptr->ClassPtr = this;

   return mptr;

}

// find the specific page
VirtualMemory::MemPage *VirtualMemory::MemPagePtr(unsigned long addr) {
    MemPage *mptr = MemPagePtrIfExists(addr);

    // lets see if we have a parent.. and if it has this data.. if so we borrow the page
    if (VMParent != NULL)
    	mptr = VMParent->MemPagePtrIfExists(addr);

    if (mptr != NULL) return mptr;

    unsigned long round = roundupto(addr, PAGE_SIZE); // round up to 64k pages

    // couldnt find so allocate..
    mptr = NewPage(round, PAGE_SIZE);
    
    return mptr;
}

int VirtualMemory::MemDataIO(int operation, unsigned long addr, unsigned char *data, int len) {
    MemPage *mptr = NULL;
    int i = 0;
    unsigned long pageaddr = 0;
    int count=0;
    
    for (i = 0; i < len; i++) {
        if ((mptr = MemPagePtr(addr+i)) == 0) return 0;

        // determine location on page
        pageaddr = (addr+i) - (mptr->round - PAGE_SIZE);
        // read byte
		switch (operation) {
		  case VMEM_READ:
			data[i] = mptr->data[pageaddr];
			break;
		  case VMEM_WRITE:
			// clone on write.... from parent
			if (!IsMyPage(mptr)) {
				mptr = ClonePage(mptr);
				if (mptr==NULL) throw;
			}
			mptr->data[pageaddr] = data[i];
			break;
		  default:
			break;
		}
		count++;
    }
    return count;
}

//reads data out of the virutal memory
int VirtualMemory::MemDataRead(unsigned long addr, unsigned char *result, int len) {
  return MemDataIO(VMEM_READ, addr, result, len);
}

// writes data into the virtual memory
int VirtualMemory::MemDataWrite(unsigned long addr, unsigned char *data, int len) {
	return MemDataIO(VMEM_WRITE, addr, data, len);
}

VirtualMemory::Memory_Section *VirtualMemory::Add_Section(CodeAddr Address, uint32_t Size,uint32_t VirtualSize, SectionType Type, uint32_t Characteristics, uint32_t RVA, char *Name, unsigned char *Data) {
	Memory_Section *sptr = new Memory_Section;

	std::memset(sptr, 0, sizeof(Memory_Section));

	sptr->Address = Address;
	sptr->VirtualSize = VirtualSize;
	sptr->RawSize = Size;
	sptr->Characteristics = Characteristics;
	sptr->RVA = RVA;
	sptr->Name = new char[std::strlen(Name)+16];
	std::strcpy(sptr->Name, Name);
	sptr->RawData = new unsigned char[sptr->RawSize+16];
	std::memcpy(sptr->RawData, Data, sptr->RawSize);


	if (Section_Last == NULL) {
		Section_List = Section_Last = sptr;
	} else {
		Section_Last->next = sptr;

		Section_Last = sptr;
		printf("ERROR Setting next to %p for %s [%p]\n", sptr->next, sptr->Name, &sptr->next);
		//if (strstr(sptr->Name, ".data")) __asm("int3");
	}

	return sptr;
}

//we now need to cache load/save under virtualmemory class since we are using internal sections..
// must re-evaluate where all of these functions should be later to clean up call graph! :)
int VirtualMemory::Cache_Save(char *filename) {
	if (Section_List == NULL) return 0;
	Memory_Section *sptr = Section_List;

	std::ofstream qcout(filename, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!qcout) return 0;


	uint32_t header = 0x3E3021;
	qcout.write((char *)&header, sizeof(uint32_t));

	for (; sptr != NULL; sptr = sptr->next) {
		// write size first and maybe pull my putint() function from other project... :) to stop duplicate code
		int w_size = (int)strlen(sptr->Name);
		qcout.write((char *)&w_size, sizeof(int));

		qcout.write((char *)sptr, sizeof(Memory_Section));

		qcout.write(sptr->Name, strlen(sptr->Name));
		qcout.write((const char *)sptr->RawData, sptr->RawSize);

	}

	qcout.close();


	return 1;
}


int VirtualMemory::Cache_Load(char *filename) {
	int count = 0;
		Memory_Section *qptr, *last = NULL;

		std::ifstream qcin(filename, std::ios::in | std::ios::binary);
		if (!qcin) return 0;

		uint32_t header = 0x3E3021;
		uint32_t verify = 0;
		qcin.read((char *)&verify, sizeof(uint32_t));
		if (header != verify) {
			printf("Cache header fail!\n");
			throw;
			return 0;
		}

		Section_List = Section_Last = NULL;

		while (!qcin.eof()) {
			int name_size = 0, raw_size = 0;
			qcin.read((char *)&name_size, sizeof(int));

			qptr = new Memory_Section;
			qcin.read((char *)qptr, sizeof(Memory_Section));
			qptr->next = 0; qptr->prev = 0;

			qptr->RawData = new unsigned char[qptr->RawSize];
			qptr->Name = new char[name_size];

			qcin.read((char *)qptr->Name, name_size);
			qcin.read((char *)qptr->RawData, qptr->RawSize);

			if (Section_Last == NULL) {

				Section_List = Section_Last = qptr;
			} else {
				Section_Last->next  = qptr;
				Section_Last = qptr;
			}

			count++;
		}

		//if (count) Loaded_from_Cache = 1;
		qcin.close();
		printf("Loaded %d from file\n", count);
}

