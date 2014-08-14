/*
 * emulation.h
 *
 *  Created on: Aug 11, 2014
 *      Author: mike
 */

#ifndef EMULATION_H_
#define EMULATION_H_

extern "C" {
/*#ifdef __x86_64__
#include "xen/xen-x86_64.h"
#else
*/
#include "xen/xen-x86_32.h"
//#endif
#include "xen/x86_emulate.h"
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



  	  public:
	   //int emulated_read(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt);
	   //int emulated_write(enum x86_segment seg, unsigned long offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt);

	  struct hack_x86_emulate_ops emulate_ops;
	  struct x86_emulate_ctxt emulation_ctx;
	  struct cpu_user_regs registers;

	  Emulation(VirtualMemory *_VM);
	  ~Emulation();

  	  public:
	  void ClearLogEntry(EmulationLog *lptr);
	  void ClearLogs();
	  void DeleteMemoryAddresses(MemAddresses  *mptr);
	  void SetRegister(int Monitor, uint32_t Value);


	  EmulationLog *StepInstruction(Emulation::CodeAddr Address, int Max_Size);
	  EmulationLog *CreateLog();
	  Emulation::RegChanges *CreateChangeEntry(Emulation::RegChanges **changelist, int which, unsigned char *orig, unsigned  char *cur, int size);



	  EmulationLog *LogList;

  	  private:

	  int last_successful;
	  VirtualMemory *VM;
	  struct cpu_user_regs registers_last;

  };


}


#endif /* EMULATION_H_ */
