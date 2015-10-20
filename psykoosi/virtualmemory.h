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
		SECTION_TYPE_REGION,
		SECTION_TYPE_MAX
	} SectionType;


	typedef enum {
		SETTINGS_PAGE_SIZE,
		SETTINGS_CHANGELOG,
		SETTINGS_VM_ID,
		SETTINGS_VM_CPU_CYCLE,
		SETTINGS_VM_LOGID,
		SETTINGS_CHANGELOG_READS,
		SETTINGS_CHANGELOG_WRITES,
		SETTINGS_CHANGELOG_VERIFY,
		SETTINGS_CHANGELOG_DUMP,
		SETTINGS_REVERSABLE,
		SETTINGS_DUMP,
		SETTINGS_MAX
	} SettingType;

	typedef struct _memory_changelog {
		struct _memory_changelog *next;

		// address of change..
		unsigned long Address;

		// raw data being wrote
		unsigned char *Data;
		unsigned long DataSize;


		// virtual machine ID for threaded emulators...
		unsigned long VM_ID;

		// not sure which of the next two ill use.. but here...
		unsigned long VM_CPU_Cycle;

		// correlating between the virtual machine, and it's ID for the instruction that made the changes..
		unsigned long VM_LogID;

		// so we know the order they happened..
		unsigned long Order;
	} ChangeLog;


    typedef struct _memory_page {
		struct _memory_page *next;
		struct _memory_page *prev;
		unsigned long addr;
		unsigned long high_addr;
		unsigned long round;
		int size;
		//MemoryAddr **blocklist;
		unsigned char *data;
		
		// page protection.. (so we can detect bad read/writes/etc during fuzzing)
		uint32_t protection;

		// what cycle was this cloned at?
		int clone_cycle;
		// parent before a clone...
		VirtualMemory *Original_Parent;

		VirtualMemory *ClassPtr;
    } MemPage;
    
    typedef uint32_t CodeAddr;
    // hold information about sections so we can rebuild... (pe bliss didnt allow us to modify the structure in memory easily)
    typedef struct _memory_sections {
    	struct _memory_sections *next;
    	struct _memory_sections *prev;

    	char *Name;
    	char *Filename;
    	CodeAddr ImageBase;

    	unsigned char *RawData;

    	CodeAddr Address;
    	CodeAddr Address_before_Rebase;

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

    	int IsDLL;

    	pe_bliss::pe_base *PEImage;
		
		int pushed;
		// TS/counter (cycle) of last push
		int last_push;
		// HASH list of the push data.. (in case we want to repush changed data)
		uint32_t *hash_list;
    } Memory_Section;

    public:
      VirtualMemory();
      ~VirtualMemory();

      unsigned long roundupto(unsigned long n, unsigned long block);
      MemPage *MemPagePtr(unsigned long addr);
      MemPage *MemPagePtrIfExists(unsigned long addr);

      int MemDataRead(unsigned long addr, unsigned char *result, int len);
      int MemDataWrite(unsigned long addr, unsigned char *data, int len);
      
      ChangeLog *ChangeLog_Add(int type, CodeAddr Addr, unsigned char *data, int len);
      int ChangeLog_Count(unsigned long LogID);
      ChangeLog **ChangeLog_Retrieve(unsigned long LogID, int *count);


      int Cache_Load(char *filename);
      int Cache_Save(char *filename);

      MemPage *NewPage(unsigned long round, int size);
      MemPage *ClonePage(MemPage *ParentOriginal);
      int IsMyPage(MemPage *mptr);


      void SetParent(VirtualMemory *Parent);
      void ReleaseParent();
      void AddChild();
      void ReleaseChild();

      int Configure(SettingType Setting, int value);
      int Configure(SettingType Setting, unsigned long value);

      Memory_Section *Add_Section(CodeAddr Address, uint32_t Size, uint32_t VSize,SectionType Type, uint32_t Characteristics, uint32_t RVA, char *name, unsigned char *Data);
      void Section_SetFilename(Memory_Section *, char *filename);
      Memory_Section *Section_EnumByFilename(char *filename, Memory_Section *last);
      int Section_IsExecutable(Memory_Section *sptr, CodeAddr Addr);
      Memory_Section *Section_FindByAddrandFile(char *filename, CodeAddr Addr);


      Memory_Section *Section_List;
      Memory_Section *Section_Last;

	  int MemDebug;
	  
	  MemPage *Memory_Pages;
    private:
      int MemDataIO(int operation, unsigned long addr, unsigned char *result, int len);
      
      ChangeLog *LogList, *LogLast;
      VirtualMemory *VMParent;
      int Children;

      int Settings[SETTINGS_MAX];

  };

}
