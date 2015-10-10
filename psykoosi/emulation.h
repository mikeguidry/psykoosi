/*
 * emulation.h
 *
 *  Created on: Aug 11, 2014
 *      Author: mike
 */

#ifndef EMULATION_H_
#define EMULATION_H_

// maximum amount of virtual machines (this is not specific threads for CPU cycles.. this is the maximum
// amount of different branches we would like to emulate during a fuzz, etc...
#define MAX_VMS 1024


extern "C" {
/*#ifdef __x86_64__
#include "xen/xen-x86_64.h"
#else
*/
#include "xen/xen-x86_32.h"
//#endif
#include "xen/x86_emulate.h"

// this is a pointer that contains various information that gets pushed towards our specialty emulated functions
// (ie: mov, cmpxchg, etc) from XEN x86_emulate.c
typedef struct _x86_thread {
		  struct x86_emulate_ctxt emulation_ctx;
		  // this is the VM (main branch, or etc) for this specific emulation cycle
		  int VM;
		  // this is the cycle ID for the CPU so that we can create a log of various information afterwards
		  int ID;
} thread_ctx_t;


}
#include <udis86.h>

namespace psykoosi {

  class Emulation {

  	  public:
	  typedef uint32_t CodeAddr;

	  enum OperationInformation {
		  REG_EAX 		       =      1,
		  REG_EBX	  	       =      2,
		  REG_ECX	 	         =      4,
		  REG_EDX	 	         =      8,
		  REG_ESP	 	         =     16,
		  REG_EBP	 	         =     32,
		  REG_ESI		         =     64,
		  REG_EDI		         =    128,
		  REG_CS		         =    256,
		  REG_EIP            =    512,
		  REG_EFLAGS         =   1024,
		  REG_SS		         =   2048,
		  REG_ES		         =   4096,
		  REG_DS		         =   8192,
		  REG_FS		         =  16384,
		  REG_GS		         =  32768,
		  DATA_WRITE         =  65536,
		  DATA_READ	         = 131072,
		  CHANGE_INCREASE    = 262144,
		  CHANGE_DECREASE    = 524288,
      CAUSES_EXCEPTION   =1048576,
      ACCESSES_HEAP      =2097152,
      UNSUPPORTED_OP     =4194304,
      ACCESSES_STACK     =8388608
	  };

  	  public:
      
      // a heap allocation during emulation
      typedef struct _heap_allocations {
        struct _heap_allocations *next;

          // address of heap block        
          CodeAddr Address;
          
          // size of heap block
          int size;
          
          // what log id were we on when we allocated.. maybe remove this later
          unsigned long LogID;
          
          // what CPU cycle were we on when we allocated this memory?
          unsigned long CpuCycle;
          
          // has this memory been freed? (just in case we keep for now.. and optimize later.. maybe Copy on write etc)
          int freed;
      } HeapAllocations;
      
	  typedef struct _memory_addresses {
		  struct _memory_addresses *next;

		  // log ID pertains to the particular change log ID for a set of data that has been logged...
		  // (this could be reading from one location, and writing to another in a specific order..
		  // although under the same log identifier)
		  unsigned long LogID;

		  // this is the CPU cycle # required to trace back if we want to go backwards and create a particular VM
		  // from a previous branch if we are not satisfied with our code coverage
		  unsigned long CpuCycle;

		  // what was this operation doing?
		  int Operation; // DATA_[READ/WRITE]

		  // the amount of data..
		  int Size;

		  // these contain the addresses for these specific IO operations
		  Emulation::CodeAddr *Source_Address;
		  Emulation::CodeAddr *Dest_Address;

		  // if this is operand based rather than address/pointer based then the registers would go here
		  int Source_Operand;
		  int Dest_Operand;
	  } MemAddresses;

	  // this is a structure for logging register changes during an emulated cycle
	  typedef struct _reg_changes_simple {
		  struct _reg_changes_simple *next;

		  // log ID pertains to the particular change log ID for a set of data that has been logged...
		  // (this could be reading from one location, and writing to another in a specific order..
		  // although under the same log identifier)
		  unsigned long LogID;

		  // this is the CPU cycle # required to trace back if we want to go backwards and create a particular VM
		  // from a previous branch if we are not satisfied with our code coverage
		  unsigned long CpuCycle;

		  // which register was this? the enums are above.. ie: REG_EAX, etc...
		  int Register;

		  // what type of change?? *** i dont remember exactly.. need to document this
		  int Type;

		  // what was the result that was left in this register during this logged change
		  long long Result;

		  // what was the raw data of the register (this is useful if for instance ASCII, or other data
		  // is being pushed into the registers)
		  unsigned char RawResult[8];
	  } RegChanges;

	  // this is the main structure for our emulation logs
	  typedef struct _emulation_log {
		  struct _emulation_log *next;

		  // log ID pertains to the particular change log ID for a set of data that has been logged...
		  // (this could be reading from one location, and writing to another in a specific order..
		  // although under the same log identifier)
		  unsigned long LogID;

		  // what address of execution (EIP from CPU) generated this log?
		  Emulation::CodeAddr Address;

		  // what was the size of this particular instruction?
		  int Size;

		  // what was the bitmask of the different properties to monitor? (IE: registers, etc)
		  int Monitor;

		  // what addresses has this instruction read from?
		  MemAddresses *Read;

		  // what addresses has this instruction wrote to?
		  MemAddresses *Wrote;

		  // this is the linked list of the register changes from this particular instruction
		  RegChanges *Changes;

		  // what is the EIP after this instruction has completed? (usually this+size or if a jmp, then the destination)
		  Emulation::CodeAddr NextEIP;

		  // these are structures that are from x86_emulate (XEN) and are just used as a backup for now..
		  // this should be removed whenever a new CPU emulation engine is used, or all data is verified on
		  // an execution of a sophisticated application such as photoshop
		  struct cpu_user_regs registers;
		  struct cpu_user_regs registers_shadow;

		  // this is a linked list of the change logs for this (change logs are read/writes/registers/etc)
		  // these are create from the Monitor bitmask after the instruction has completed execution
		  VirtualMemory::ChangeLog **VMChangeLog;
		  // how many differen change logs are in this array above
		  int VMChangeLog_Count;
	  } EmulationLog;


	  // these are the 'specialty' instructions that we can control if we wish to log the information that
	  // they read/write/etc
	  struct hack_x86_emulate_ops
	  {
		  void *read;
		  void *insn_fetch;
		  void *write;
		  void *cmpxchg;
		  void *rep_ins;
		  void *rep_outs;
		  void *rep_movs;
		  void *read_segment;
		  void *write_segment;
		  void *read_io;
		  void *write_io;
		  void *read_cr;
		  void *write_cr;
		  void *read_dr;
		  void *write_dr;
		  void *read_msr;
		  void *write_msr;
		  void *wbinvd;
		  void *cpuid;
		  void *inject_hw_exception;
		  void *inject_sw_interrupt;
		  void *get_fpu;
		  void *put_fpu;
		  void *invlpg;
	  };

	  // this is the structure for an emulation 'thread..'
	  // each thread is theoretically the same as a thread in userland...
	  // this could also be a DLL's entry point, or the applications main entry point
	  // or anything from CreateThread() or pthread_create() for Windows, and Linux respectively...
	  typedef struct _emulation_thread {
		  struct _emulation_thread *next;

		  // the identifier for this thread which is used to correlate data within the specialty functions,
		  // and logging operations
		  int ID;

		  // what CPU cycle has this thread started at?
		  // this is useful to determine if this thread has to be cloned during creation of more VMs of specific
		  // points within this application
		  unsigned long CPUStart;

		  // what is the current CPU Cycle # of this thread?
		  unsigned long CPUCycle;

		  // what is the current log identifier for this thread (this is incremented for each instruction)
		  unsigned long LogID;

		  // this is the virtual memory of this particular thread.. the virtual memory gets a bit tricky..
		  // as it can be cloned for different virtual machines.. but overall should be static amongst the same
		  // VM of the same application being executed
		  VirtualMemory *EmuVMEM;
      
      // Heap allocations for this virutal memory
      HeapAllocations *Heap;

		  // this is the structure that contains the functions (specialty) that we redirect from the XEN emulator
		  struct hack_x86_emulate_ops emulate_ops;


		  // was the last instruction execution sucessful?  this could determine whether a thread
		  // has crashed, or whether SEH should be considered.. (exception handling)
		  int last_successful;

		  // thread context is an internal structure used by the XEN x86_emulate.c for execution
		  // it is where our registers/shadow registers are copied/wrote to before/after execution
		  thread_ctx_t thread_ctx;

		  // this is the current registers of this thread
		  struct cpu_user_regs registers;
		  struct cpu_user_regs registers_shadow;

		  // this is the emulation log of this thread.. it should contain all requested logging information for the
		  // lifetime of the thread... maybe later allow to have a maximum limit here.
		  EmulationLog *LogList;

		  // what was the very last log structure? this is so we can easily append a new one for the linked list
		  // without enumerating to the end, or putting it first so things are out of order...
		  EmulationLog *LogLast;

	  } EmulationThread;

    // a virtual machine structure (contains all threads, memory, etc)
    typedef struct _virtual_machine {
      struct _virtual_machine *next;
      
      EmulationThread *Threads;
      
      VirtualMemory Memory;
      
    } VirtualMachine;

  	  public:

	  Emulation(VirtualMemory *_VM);
	  ~Emulation();

  	  public:
	  void ClearLogEntry(EmulationThread *, EmulationLog *lptr);
	  void ClearLogs(EmulationThread *);
	  void DeleteMemoryAddresses(MemAddresses *mptr);
	  void SetRegister(EmulationThread *, int Monitor, uint32_t Value);
	  void CopyRegistersToShadow(EmulationThread *);

	  // this will step a single instruction (during a specific CPU cycle) for a particular thread
	  // at a specific address (if the address is 0 then it should obtain the address from its own
	  // thread structure information
	  EmulationLog *StepInstruction(EmulationThread *, Emulation::CodeAddr Address);

	  // this will execute a series of instructions.. whether its until a final address, a return, or a new branch...
	  // this might not work well whenever we are stepping through a series of threads for a single CPU cycle...
	  // *** maybe rewrite this function
	  Emulation::EmulationThread *ExecuteLoop(VirtualMemory *vmem, Emulation::CodeAddr StartAddr, Emulation::CodeAddr EndAddr, struct cpu_user_regs *registers, int new_thread);

	  // this should be called after an instruction has executed to generate the change log to be inserted
	  // into the threads loggig history
	  EmulationLog *CreateLog(EmulationThread *);


	  Emulation::RegChanges *CreateChangeEntry(Emulation::RegChanges **changelist, int which, unsigned char *orig, unsigned  char *cur, int size);

	  Emulation::EmulationThread *NewVirtualMachine(VirtualMemory *ParentMemory, Emulation::CodeAddr EIP, struct cpu_user_regs *registers);

	  void DestroyVirtualMachine(EmulationThread *);

	  EmulationThread Master;

	  int Global_ChangeLog_Read;
	  int Global_ChangeLog_Write;
	  int Global_ChangeLog_Verify;

	  private:

	  VirtualMemory *VM;
	  int Current_VM_ID;
	  int VM_Exec_ID;

  };


}


#endif /* EMULATION_H_ */
