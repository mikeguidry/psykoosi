/*
 * emulation.h
 *
 *  Created on: Aug 11, 2014
 *      Author: mike
 */

#ifndef EMULATION_H_
#define EMULATION_H_

#define MAX_VMS 1024


extern "C" {
/*#ifdef __x86_64__
#include "xen/xen-x86_64.h"
#else
*/
#include "xen/xen-x86_32.h"
//#endif
#include "xen/x86_emulate.h"

typedef struct _x86_thread {
		  struct x86_emulate_ctxt emulation_ctx;
		  int ID;
} thread_ctx_t;


}
#include <udis86.h>

namespace psykoosi {

  class Emulation {

  	  public:
	  typedef uint32_t CodeAddr;

	  enum OperationInformation {
		  REG_EAX		=   1,
		  REG_EBX		=   2,
		  REG_ECX		=   4,
		  REG_EDX		=   8,
		  REG_ESP		=  16,
		  REG_EBP		=  32,
		  REG_ESI		=  64,
		  REG_EDI		= 128,
		  REG_CS		= 256,
		  REG_EIP		= 512,
		  REG_EFLAGS	=1024,
		  REG_SS		=2048,
		  REG_ES		=4096,
		  REG_DS		=8192,
		  REG_FS		=16384,
		  REG_GS		=32768,
		  DATA_WRITE	=65536,
		  DATA_READ		=131072,
		  CHANGE_INCREASE = 262144,
		  CHANGE_DECREASE = 524288
	  };

  	  public:
	  typedef struct _memory_addresses {
		  struct _memory_addresses *next;

		  int Operation; // DATA_[READ/WRITE]
		  int Size;
		  Emulation::CodeAddr *Source_Address;
		  Emulation::CodeAddr *Dest_Address;

		  int Source_Operand;
		  int Dest_Operand;
	  } MemAddresses;

	  typedef struct _reg_changes_simple {
		  struct _reg_changes_simple *next;

		  int Register;
		  int Type;
		  long long Result;

		  unsigned char RawResult[8];

	  } RegChanges;

	  typedef struct _emulation_log {
		  struct _emulation_log *next;

		  Emulation::CodeAddr Address;
		  int Size;

		  int Monitor;

		  MemAddresses *Read;
		  MemAddresses *Wrote;
		  RegChanges *Changes;

		  Emulation::CodeAddr NextEIP;
	  } EmulationLog;


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

	  typedef struct _emulation_thread {
		  struct _emulation_thread *next;

		  int ID;

		  VirtualMemory EmuVMEM;

		  struct hack_x86_emulate_ops emulate_ops;
		  struct cpu_user_regs registers;
		  struct cpu_user_regs registers_shadow;
		  int last_successful;
		  thread_ctx_t thread_ctx;

		  EmulationLog *LogList;
	  } EmulationThread;


  	  public:

	  Emulation(VirtualMemory *_VM);
	  ~Emulation();

  	  public:
	  void ClearLogEntry(EmulationThread *, EmulationLog *lptr);
	  void ClearLogs(EmulationThread *);
	  void DeleteMemoryAddresses(MemAddresses *mptr);
	  void SetRegister(EmulationThread *, int Monitor, uint32_t Value);
	  void CopyRegistersToShadow(EmulationThread *);

	  EmulationLog *StepInstruction(EmulationThread *, Emulation::CodeAddr Address, int Max_Size);
	  EmulationLog *CreateLog(EmulationThread *);
	  Emulation::RegChanges *CreateChangeEntry(Emulation::RegChanges **changelist, int which, unsigned char *orig, unsigned  char *cur, int size);

	  EmulationThread *NewVirtualMachine(VirtualMemory *ParentMemory, Emulation::CodeAddr EIP, struct cpu_user_regs *registers);
	  void DestroyVirtualMachine(EmulationThread *);

	  EmulationThread Master;

  	  private:

	  VirtualMemory *VM;
	  int Current_VM_ID;

  };


}


#endif /* EMULATION_H_ */
