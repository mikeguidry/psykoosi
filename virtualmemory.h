namespace psykoosi {

  class VirtualMemory {
    
    enum {
      VMEM_WRITE,
      VMEM_READ,
      VMEM_VERIFY
    };
  public:
    
    /*
    // This is when we want to add in ability to keep history of every change...
    typedef struct memory_block {
	struct memory_block *history;
	unsigned char raw_byte;
	char *name;
	int modified;
    } MemoryAddr;
    */

    typedef struct _memory_page {
	struct _memory_page *next;
	struct _memory_page *prev;
	unsigned long addr;
	unsigned long high_addr;
	unsigned long round;
	int size;
	//MemoryAddr **blocklist;
	unsigned char *data;
    } MemPage;
    
  
  
    public:
      VirtualMemory();
      ~VirtualMemory();
      unsigned long roundupto(unsigned long n, unsigned long block);
      MemPage *MemPagePtr(unsigned long addr);
      int MemDataRead(unsigned long addr, unsigned char *result, int len);
      int MemDataWrite(unsigned long addr, unsigned char *data, int len);
      
    private:
      int MemDataIO(int operation, unsigned long addr, unsigned char *result, int len);
      MemPage *Memory_Pages;
  };

}
