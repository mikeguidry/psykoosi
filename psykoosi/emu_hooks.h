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
		enum {
			BUF_ESP_p4=1,
			BUF_ESP_p8=2,
			BUF_ESP_p12=4,
			BUF_ESP_p16=8,
			BUF_ESP_p20=16,
			BUF_ESP_p24=32,
			// EBP is usually locals since the caller’s function began.. so its usually plus.. but we could add some minus in case the buffer is originating easier that far up…
			BUF_EBP_m4=64,
			BUF_EBP_m8=128,
			BUF_EBP_m12=256,
			BUF_EBP_m16=512,
			BUF_EBP_m20=1024,
			BUF_EBP_p4=2048,
			BUF_EBP_p8=4096,
			BUF_EBP_p16=8192,
			BUF_EBP_p20=16384,
			BUF_EAX=32768,
			BUF_EBX=65536,
			BUF_ECX=131072,
			BUF_EDX=262144,
      // do we dereference this location?
      BUF_DEREF=524288,
		};
		
		typedef int (Hooks::*tHookRead)(int hook_id, char *dst, int size, uint32_t *);
		typedef int (Hooks::*tHookWrite)(int, char *src, int size, uint32_t *);

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
			// count id during creation of this exchange
			int current_count_id;
			
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
		  // now the same information for finding the size..
		  int find_size;
		  
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
	  
	  
	  typedef struct _fuzzy_addresses {
			struct _fuzzy_addresses *next;
			// address this begins..
			uint32_t Address;
			// original address information
			struct _fuzzy_addresses *OriginalFuzzy;
			// how many read/writes of the original memory till this structure? (like a rover tap)
			int FuzzyRelations;
			// the raw data we responded with (which should be used to fuzz)
			char *Data;
			// Size of the data
			int Size;
			// side (0 read 1 write)
			int Side;
			// which protocol exchange was this crewated at
			ProtocolExchange *exchange;
			// which API hook did this happen at?
			APIHook *hook;
	  } FuzzyAddresses;

	  
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
	  int HookRead(int, char *dst, int size, uint32_t *rw_count);
	  int HookWrite(int, char *src, int size, uint32_t *rw_count);
	  
	  ProtocolExchange *AddProtocolExchange(int hook_id, char *module, char *function, int side, char *data, int size);
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
	  int read_count_id;
	  int write_count_id;
	  
	  // are we logging (real execution, or simulating)
	  int simulation;
  };
}

#endif