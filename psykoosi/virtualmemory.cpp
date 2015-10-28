/* This allows us to have 'Virtual Memory' to load images into and modify etc...   */
#include <cstddef>
#include <iostream>
#include <cstring>
#include <inttypes.h>
#include <stdio.h>
#include <fstream>
#include <pe_lib/pe_bliss.h>
#include <zlib.h>
#include "virtualmemory.h"

using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


VirtualMemory::VirtualMemory()
{
	int i = 0;
	for (i = 0; i < VMEM_JTABLE; i++)
  		Memory_Pages[i] = NULL;
  Section_List = Section_Last = NULL;
  LogList = LogLast = NULL;
  VMParent = NULL;

  MemDebug = 0;
  for (i = 0; i < SettingType::SETTINGS_MAX; i++) {
	  Settings[i] = 0;
  }

  // lower kb since we'll start cloning, etc...bigger the number = more clones
  Settings[SETTINGS_PAGE_SIZE] = 1024*16;

}

VirtualMemory::~VirtualMemory()
{
	for (int i = 0; i < VMEM_JTABLE; i++)
  if (Memory_Pages[i] != NULL) {
    MemPage *mptr = (MemPage *)Memory_Pages[i], *mptr2;

    // delete all memory pages we have information at...
    for (mptr = Memory_Pages[i]; mptr; ) {
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
/*
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
static inline UINT64 round_down(UINT64 x, UINT64 y) {
	return (x & ~(y - 1));
}
*/
unsigned long VirtualMemory::roundupto(unsigned long n, unsigned long block){
	unsigned long ret;
    if(block <= 1) return n;
    block--;

    ret = (n + block) & ~block;

    return ret;
}

VirtualMemory::MemPage *VirtualMemory::MemPagePtrIfExists(unsigned long addr) {
	unsigned long round = roundupto(addr, Settings[SETTINGS_PAGE_SIZE]); // round up to 64k pages
	int jtable = jtable_algo(round);
    MemPage *mptr = (MemPage *)Memory_Pages[jtable];

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

	mptr->data = new unsigned char[mptr->size+16];
	std::memcpy(mptr->data, ParentOriginal->data, mptr->size);

	mptr->Original_Parent = ParentOriginal->ClassPtr;
	mptr->ClassPtr = this;
	mptr->clone_cycle = Settings[SettingType::SETTINGS_VM_CPU_CYCLE];

	return mptr;
}

int VirtualMemory::IsMyPage(MemPage *mptr) {
	return (mptr->ClassPtr == this);
}

// it loads at 9 seconds.. maybe brute force and find a better timing later
int VirtualMemory::jtable_algo(int round) {
	int hmm = (round & (0xf0f0f00));
	int jtable = hmm + ((round/2) + ((round/6) % (VMEM_JTABLE / 8))); 
	
	int ret = (jtable % VMEM_JTABLE);
	
	if (ret >= VMEM_JTABLE || ret < 0)
		ret = (hmm + ~ret) % VMEM_JTABLE;
	
	return (ret > 0) ? ret : 0;
}

VirtualMemory::MemPage *VirtualMemory::NewPage(unsigned long round, int size) {
    MemPage *mptr = new MemPage;

    std::memset(mptr, 0, sizeof(MemPage));

	int jtable = jtable_algo(round);
   // push old back..
   mptr->next = (MemPage *)Memory_Pages[jtable];
   // insert in the beginning
   Memory_Pages[jtable] = mptr;

   // what page range is this for
   mptr->round = round;

   mptr->addr = round;
   // size of this page
   mptr->size = Settings[SETTINGS_PAGE_SIZE];
   // lets allocate the data
   mptr->data = new unsigned char[Settings[SETTINGS_PAGE_SIZE]+16];
   std::memset(mptr->data, 0x00, Settings[SETTINGS_PAGE_SIZE]);

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

    unsigned long round = roundupto(addr, Settings[SETTINGS_PAGE_SIZE]); // round up to 64k pages

    // couldnt find so allocate..
    mptr = NewPage(round, Settings[SETTINGS_PAGE_SIZE]);

    return mptr;
}

/*
 	changelog should be setup here.. since we will support multi arch using unicorn
	*** FIX
*/

VirtualMemory::ChangeLog *VirtualMemory::ChangeLog_Add(int type, CodeAddr Addr, unsigned char *data, int len) {
	if (type == VMEM_READ && !Settings[SettingType::SETTINGS_CHANGELOG_READS]) return NULL;
	if (type == VMEM_WRITE && !Settings[SettingType::SETTINGS_CHANGELOG_WRITES]) return NULL;

	ChangeLog *logptr = new ChangeLog;
	std::memset(logptr, 0, sizeof(ChangeLog));

	logptr->Address = Addr;
	logptr->Data = new unsigned char[len];
	std::memcpy(logptr->Data, data, len);

	if (LogLast != NULL) {
		logptr->Order = LogLast->Order + 1;
		LogLast->next = logptr;
	} else {
		LogList = LogLast = logptr;
		logptr->Order = 1;
	}

	return logptr;
}


int VirtualMemory::MemDataIO(int operation, unsigned long addr, unsigned char *data, int len) {
    MemPage *mptr = NULL, *mptr_current = NULL;
    unsigned long current_pageaddr_start = 0;
    unsigned long current_vaddr_start = 0;
    unsigned long current_count = 0;
    int i = 0;
    unsigned long pageaddr = 0;
    int count=0;
	unsigned long addy = 0;
	//int z = 0;

	// maybe optimize this later so it knows when it crosses a page..
	// if speed becomes an issue ***
	// we could calculate how many bytes before the end of the current
	// page
    for (i = 0; i < len; i++) {
        if ((mptr = MemPagePtr(addr+i)) == 0) return 0;

		addy = (unsigned long)(addr + i);
/*		if (addy == 0x30EFC28) {
			printf("FOund! 30EFC28\n");
			z = 4;
		}
*/		
        // determine location on page
        pageaddr = (addr+i) - (mptr->round - Settings[SETTINGS_PAGE_SIZE]);
        // read byte
		switch (operation) {
		  case VMEM_READ:
			data[i] = mptr->data[pageaddr];
			//if ((addr < 0x60000000))
			addy = (unsigned long)(addr + i);
			if (MemDebug && (addy < 0x3000)) {
				//__asm("int3");
				printf("(r) %X [%X] = %02X\n", addy, mptr->round, (unsigned char)(data[i]));
			}
		//if (z) { z--; printf("\rz: addy %X:%d %02X\n", addy, z,  (unsigned char)data[i]); }
			break;
		  case VMEM_WRITE:
			// clone on write.... from parent
			if (!IsMyPage(mptr)) {
				mptr = ClonePage(mptr);
				if (mptr == NULL) throw;
			}
			//if ((addr < 0x60000000))
			if (MemDebug)
				printf("(w) %X [%X] = %02X\n", addr + i, mptr->round, (unsigned char)(data[i]));
			mptr->data[pageaddr] = data[i];
			//if (z) { z--; printf("\rz: addy %X:%d %02X\n", addy, z,  (unsigned char)data[i]); }
			break;
		  default:
			  throw;
			break;
		}

		// current is so we only do a changelog at the end, or when a page changes.. so we dont have
		// change logs for single bytes... or if its the last byte...
		/*if (Settings[SettingType::SETTINGS_CHANGELOG]) {
			if (mptr_current != mptr || ((i + 1) == len)) {
				// Logs if our internal page changes...
				current_count++;

				// log the changes...
				ChangeLog *logptr = ChangeLog_Add(operation, current_vaddr_start, (unsigned char *)(&mptr_current->data + pageaddr), current_count);
				if (logptr != NULL) {
					logptr->VM_CPU_Cycle = Settings[SettingType::SETTINGS_VM_CPU_CYCLE];
					logptr->VM_ID = Settings[SettingType::SETTINGS_VM_ID];
					logptr->VM_LogID = Settings[SettingType::SETTINGS_VM_LOGID];
				}


				// restart for the next page...
				mptr_current = mptr;
				current_count = 1; // we just got our first byte from a new page...
				current_pageaddr_start = pageaddr;
				current_vaddr_start = addr + i;
			} else
				// otherwise increases the count.. so we can log later (when completed... or changes)
				current_count++;
		}*/

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
	/*uint32_t Base_Address = Address;
	for (Memory_Section *sect = Section_List; sect != NULL; sect = sect->next) {
		if ((Address >= (sect->Address-(1024*64)) && (Address < (sect->VirtualSize+(1024*64))))) {
			//if its within 64kb of this other section.. it has to be changed...
			Base_Address = sect + sect->VirtualSize + (1024*64);
		}
	}*/
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
		//printf("ERROR Setting next to %p for %s [%p]\n", sptr->next, sptr->Name, &sptr->next);
		//if (strstr(sptr->Name, ".data")) __asm("int3");
	}

	return sptr;
}

//we now need to cache load/save under virtualmemory class since we are using internal sections..
// must re-evaluate where all of these functions should be later to clean up call graph! :)
int VirtualMemory::Cache_Save(char *filename) {
	if (Section_List == NULL) return 0;
	Memory_Section *sptr = Section_List;

	gzFile outfs;

	if ((outfs = gzopen(filename, "wb9")) == NULL) {
		return 0;
	}

	uint32_t header = 0x3E3021;
	gzwrite(outfs, (void *)&header, sizeof(uint32_t));

	for (; sptr != NULL; sptr = sptr->next) {
		// write size first and maybe pull my putint() function from other project... :) to stop duplicate code
		int w_size = (int)strlen(sptr->Name);
		gzwrite(outfs, (void *)&w_size, sizeof(int));
		gzwrite(outfs, (void *)&sptr, sizeof(Memory_Section));
		gzwrite(outfs, (void *)sptr->Name, strlen(sptr->Name));
		gzwrite(outfs, (void *)sptr->RawData, sptr->RawSize);

	}

	gzclose(outfs);


	return 1;
}


int VirtualMemory::Cache_Load(char *filename) {
	int count = 0;
	Memory_Section *qptr, *last = NULL;
	gzFile infs;

	if ((infs = gzopen(filename, "rb9")) == NULL) {
		return 0;
	}

	uint32_t header = 0x3E3021;
	uint32_t verify = 0;
	gzread(infs, (void *)&verify, sizeof(uint32_t));

	if (header != verify) {
		printf("Cache header fail!\n");
		throw;
		return 0;
	}

	Section_List = Section_Last = NULL;

	while (!gzeof(infs)) {
		int name_size = 0, raw_size = 0;
		gzread(infs, (void *)&name_size, sizeof(int));

		qptr = new Memory_Section;

		gzread(infs, (void *)qptr, sizeof(Memory_Section));

		qptr->next = 0; qptr->prev = 0;

		if (!qptr->RawSize) throw;

		qptr->RawData = new unsigned char[qptr->RawSize];
		qptr->Name = new char[name_size];

		gzread(infs, (void *)qptr->Name, name_size);
		gzread(infs, (void *)qptr->RawData, qptr->RawSize);

		if (Section_Last == NULL) {

			Section_List = Section_Last = qptr;
		} else {
			Section_Last->next  = qptr;
			Section_Last = qptr;
		}

		count++;
	}

	//if (count) Loaded_from_Cache = 1;
	gzclose(infs);
	printf("Loaded %d from file\n", count);
}


int VirtualMemory::Configure(SettingType type, int Setting) {
	int Old_Setting = Settings[type];

	int jtable = 0;
	// cannot change page size after there is already data
	if (type == SettingType::SETTINGS_PAGE_SIZE && Memory_Pages[jtable] != NULL && Memory_Pages[jtable]->Original_Parent != this)
		return Old_Setting;

	Settings[type] = Setting;

	return Old_Setting;
}

int VirtualMemory::Configure(SettingType type, unsigned long Setting) {
	int Old_Setting = Settings[type];

	int jtable = 0;
	// cannot change page size after there is already data
	if (type == SettingType::SETTINGS_PAGE_SIZE && Memory_Pages[jtable] != NULL && Memory_Pages[jtable]->Original_Parent != this)
		return Old_Setting;

	Settings[type] = Setting;

	return Old_Setting;
}

// count all change logs.. either total or by a specific log id...
int VirtualMemory::ChangeLog_Count(unsigned long LogID) {
	int Count = 0;
	for (ChangeLog *cptr = LogList; cptr != NULL; cptr = cptr->next) {
		if (LogID && cptr->VM_LogID != LogID) continue;
	}
	return Count;
}


// sort changelog by the order...
int ordersort(const void *log1_ptr, const void *log2_ptr) {
	VirtualMemory::ChangeLog *Log1 = (VirtualMemory::ChangeLog *)log1_ptr;
	VirtualMemory::ChangeLog *Log2 = (VirtualMemory::ChangeLog *)log2_ptr;

	return (Log1->Order > Log2->Order) ? 1 : -1;
}

VirtualMemory::ChangeLog **VirtualMemory::ChangeLog_Retrieve(unsigned long LogID, int *count) {
	int Count = ChangeLog_Count(LogID);
	*count = Count;
	if (!Count) return NULL;
	ChangeLog **ret = new ChangeLog *[Count];
	int i = 0;
	for (ChangeLog *cptr = LogList; cptr != NULL; cptr = cptr->next) {
		if (i >= Count) throw;
		ret[i] = cptr;
	}

	// lets put in order..
	qsort(ret, Count, sizeof(ChangeLog *), ordersort);

	return ret;
}

void VirtualMemory::Section_SetFilename(Memory_Section *sptr, char *filename) {
	if (!sptr) throw;
	int len = strlen(filename);
	sptr->Filename = new char [len+2];
	std::strcpy(sptr->Filename, filename);
	sptr->Filename[len] = 0;
}

// is this section executable?
int VirtualMemory::Section_IsExecutable(Memory_Section *sptr, CodeAddr Addr) {

	if (!sptr)
		sptr = Section_FindByAddrandFile(NULL, Addr);

	if (sptr == NULL) {
		//printf("IsExec: null\n");
		return 0;
	}

	return (sptr->Characteristics & image_scn_mem_execute);
}

// find a section by it's address & filename...
VirtualMemory::Memory_Section *VirtualMemory::Section_FindByAddrandFile(char *filename, CodeAddr Addr) {
	Memory_Section *sptr = NULL;

	// loop through sections finding this address....
	do {
		sptr = Section_EnumByFilename(filename, sptr);
		if (sptr) {
			if ((Addr >= (sptr->Address+sptr->ImageBase)) && (Addr < ((sptr->Address+sptr->ImageBase)+ (sptr->VirtualSize))))
				return sptr;
		}
	} while (sptr);

	return NULL;
}

// loop through sections by its filename.. use NULL for the main PE
VirtualMemory::Memory_Section *VirtualMemory::Section_EnumByFilename(char *filename, Memory_Section *last) {

	for (Memory_Section *sptr = (last ? last->next : Section_List); sptr != NULL; sptr = sptr->next) {

		if ((sptr->Filename != NULL && filename != NULL && strstr(sptr->Filename, filename)) || (sptr->Filename==NULL && filename==NULL)) {
			return sptr;
		}
	}

	return NULL;

}
