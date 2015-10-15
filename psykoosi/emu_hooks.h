/*
 * apiproxy_client.h
 *
 *  Created on: Oct 10, 2015
 *      Author: mike
 */

#ifndef HOOKS_H_
#define HOOKS_H_

namespace psykoosi {

  class Hooks {
	  public:


		typedef struct _protocol_exchanges {
			struct _protocol_exchanges *next;
			// second linked list for the specific functions..
			struct _protocol_exchanges *hook_next;
		
			// if its a hook we setup...
			int hook_id;
			
			// or if its an IAT DLL Call
			char *module;
			char *function;
			
			// pkt id.. incremental
			int id;
		
			// how many bytes to fix on the stack for the arguments?
			int ret_fix;
			int call_ret;
		  

			// ordered = 0, sends without awaiting a response.. or 1 ensures the ID before it
			// has been received.
			int ordered;
		
			// 0 read, 1 write (reading or writing to/from data)
			int side;
			
			int size;
			char *buf;
		} ProtocolExchange;
		

	  typedef struct _call_context {
		  struct _call_context *next;
		  
	  } HookContext;
	  
	  typedef struct _api_hook {
		  struct _api_hook *next;
		  
		  // internal identifier if necessary.. or remove and use context
		  int id;
		  
		  // address of the hooked function
		  void *func;
		  
		  // side? read/write
		  int side;
		  
		  // enum of way to find the buffer for this function
		  int find_buffer;
		  
		  // DLL / function hooked
		  char *function_name;
		  char *module_name;
		  
		  // how many times has this function been called
		  int call_count;
		  
		  // protocol communications for this hook
		  ProtocolExchange *protocol;

		  // hook context if necessary		  
		  HookContext ctx;
	  }	APIHook;
	  
	  typedef struct _save_structure {
		  int id;
		  int hook_id;
		  int side;
		  int ordered;
		  int ret_fix;
		  int call_ret;
		  // these sizes are of the data appended after the end of the structure
		  int module_size;
		  int function_size;
		  // now is the data
		  int size;
	  } SaveStructure;
	  
	  Hooks();
	  ~Hooks();
	  int Init();
	  
	  APIHook *HookFunction(void *func, char *module, char *function, int side, int id, int logging);
	  APIHook *HookFind(char *module, char *function);
	  int HookFree(APIHook *);
	  int HookRead(int, char *dst, int size);
	  int HookWrite(int, char *src, int size);
	  
	  ProtocolExchange *AddProtocolExchange(int id, int hook_id, char *module, char *function, int side, char *data, int size);
	  ProtocolExchange *NextProtocolExchange(int hook_id, int side);
	  int FreeExchange(ProtocolExchange **_eptr, ProtocolExchange *eptr);
	  
	  int Save(char *file);
	  int Load(char *file);
	  
	  // linked list of hooks
	  APIHook *hooks;
	  // all protocol communications (of hooked functions),
	  // including IAT DLL calls
	  ProtocolExchange *exchange;
	  ProtocolExchange *exchange_last;
	  
	  // identifier of the current hook id (to ensure each are different) 
	  int hook_id;
	  int count_id;
	  
	  // are we logging (real execution, or simulating)
	  int simulation;
  };
}

#endif