/* This allows us to have 'Virtual Memory' to load images into and modify etc...   */
#include <cstddef>
#include <iostream>
#include <cstring>
#include "virtualmemory.h"
// 64k pages...
#define PAGE_SIZE 4096*2*2*2*2*sizeof(unsigned char *)

using namespace psykoosi;


VirtualMemory::VirtualMemory()
{
  Memory_Pages = NULL;
}

VirtualMemory::~VirtualMemory()
{
  if (Memory_Pages != NULL) {
    MemPage *mptr = (MemPage *)Memory_Pages, *mptr2;
    
    // delete all memory pages we have information at...
    do {
      mptr2 = mptr->next;
      delete mptr->data;
      delete mptr;
      mptr = mptr2;
    } while (mptr != NULL);
  }

}

unsigned long VirtualMemory::roundupto(unsigned long n, unsigned long block){
    if(block <= 1) return n;
    block--;
    return (n + block) & ~block;
}

// find the specific page
VirtualMemory::MemPage *VirtualMemory::MemPagePtr(unsigned long addr) {
    MemPage *mptr = (MemPage *)Memory_Pages;
    //MemoryAddr *bptr;
    unsigned long round = roundupto(addr, PAGE_SIZE); // round up to 64k pages
    if (mptr != NULL) {
      for (; mptr != NULL; mptr = mptr->next) {
	  if ((unsigned long)round == mptr->round)
	      return mptr;
      }
    }
    // couldnt find so allocate..
    mptr = new MemPage;
    /*if ((mptr = (MemPage *)malloc(sizeof(MemPage) + 1)) == NULL) {
        printf("MemPagePtr: alloc fail");
        exit(-1);
    }*/
    
    //z c++ero out new memory
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
    mptr->data = new unsigned char[PAGE_SIZE+1];
    std::memset(mptr->data, 0x00, PAGE_SIZE);
    
    return mptr;
}

int VirtualMemory::MemDataIO(int operation, unsigned long addr, unsigned char *data, int len) {
    MemPage *mptr;
    int i;
    unsigned long pageaddr;
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
		 // std::cout << pageaddr << " max " << PAGE_SIZE << "mptr " << mptr << " max " << mptr+mptr->size << std::endl;
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
