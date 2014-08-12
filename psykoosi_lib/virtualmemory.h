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
	typedef enum {
		SECTION_TYPE_NONE,
		SECTION_TYPE_CODE,
		SECTION_TYPE_DATA,
		SECTION_TYPE_IMPORT,
		SECTION_TYPE_EXPOR,
		SECTION_TYPE_RESOURCE,
		SECTION_TYPE_MAX
	} SectionType;
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
    
    typedef uint32_t CodeAddr;
    // hold information about sections so we can rebuild... (pe bliss didnt allow us to modify the structure in memory easily)
    typedef struct _memory_sections {
    	struct _memory_sections *next;
    	struct _memory_sections *prev;

    	char *Name;
    	unsigned char *RawData;

    	CodeAddr Address;

    	unsigned long VirtualSize;

    	CodeAddr Original_Address;
    	unsigned long Original_RawSize;
    	unsigned long Original_VirtualSize;

    	uint32_t Characteristics;
    	SectionType Section_Type;
    	int Relocated;
    	int RVA;

    	int blah;
    	unsigned long RawSize;
    } Memory_Section;

    public:
      VirtualMemory();
      ~VirtualMemory();
      unsigned long roundupto(unsigned long n, unsigned long block);
      MemPage *MemPagePtr(unsigned long addr);
      int MemDataRead(unsigned long addr, unsigned char *result, int len);
      int MemDataWrite(unsigned long addr, unsigned char *data, int len);
      
      int Cache_Load(char *filename);
      int Cache_Save(char *filename);


      Memory_Section *Add_Section(CodeAddr Address, uint32_t Size, uint32_t VSize,SectionType Type, uint32_t Characteristics, uint32_t RVA, char *name, unsigned char *Data);

      Memory_Section *Section_List;
      Memory_Section *Section_Last;

    private:
      int MemDataIO(int operation, unsigned long addr, unsigned char *result, int len);
      MemPage *Memory_Pages;

  };

}
