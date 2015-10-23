/*
 * apiproxy_client.h
 *
 *  Created on: Oct 10, 2015
 *      Author: mike
 */

#ifndef APIPROXY_CLIENT_H_
#define APIPROXY_CLIENT_H_

namespace psykoosi {

  class APIClient {

	public:
		typedef uint32_t CodeAddr;
		
		typedef struct _api_queue {
			struct _api_queue *next;
		
			CodeAddr Address;
			CodeAddr ESP;
			CodeAddr EBP;
			CodeAddr Region;
			CodeAddr Region_Size;
		
			char *module_name;
			char *function_name;
		
			unsigned char *args;
			int arg_len;
			
			VirtualMemory *VMEM;
		} ApiQueue;
		
		typedef struct _allocated_regions {
			struct _allocated_regions *next;
			
			CodeAddr Address;
			int Size;
			
		} AllocatedRegion;
		
		typedef struct _api_thread {
			struct _api_thread *next;
			// id to identify the thread during fuzzing..
			int id;
			
			// remote id
			int remote_id;
		} APIThreads;
	
		int SendPkt(int type, char *data, int size, char **response, int *response_size);
	
		// connect to our api proxy server (windows/wine)
		int Connect(char *ip, int port);
		int Disconnect();
		
		// allocate memory on the remote side.. so our local
		// addresses match
		uint32_t AllocateMemory(uint32_t Addresss, int Size);
		int DeallocateMemory(uint32_t Address);
		// zero memory on remote side
		int ZeroMemory(uint32_t Address, int Size);
		int PushData(uint32_t Address, char *Source, int Size);
		int PeekData(uint32_t Address, char *Destination, int Size);
		int PushSections();
		
		uint32_t GetDLLAddress(char *filename);
		uint32_t LoadDLL(char *filename);
		char *GetDLLPath(char *filename);
		
		char *FileDownload(char *filepath, int *);
		int FileUpload(char *filepath, char *data, int size);
		int FileDelete(char *);
		
		int Ping();
		
		// create a new thread and return an id
		int NewThread();
		// destroy a thread we created on the remote side
		int DestroyThread(int id);
		
		int CallFunction(char *module, char *function, CodeAddr Address, CodeAddr ESP, CodeAddr EBP,
			CodeAddr Region, CodeAddr Region_Size, uint32_t *eax_ret, CodeAddr ESP_High, uint32_t *ret_fix);
			
		void SetVirtualMemory(VirtualMemory *);
		
		APIClient();
		~APIClient();
		
		ApiQueue *queue;
		
		AllocatedRegion *Regions;
		
		VirtualMemory *VM;
		
		// flag we turn on to make the next write or peek access the tib
		bool for_tib;
	private:
	
		// identifier of this execution.. if we reconnect
		int run_id;
		
		int connected;
		
		// socket for connection to server
		int proxy_socket;
		
		// are we threaded off (queues)? or doing instant responses...
		int threaded;
		
		int thread_id;
		
		//virtual memory we are using for this execution...
		
		
		APIThreads *Threads;
		
  };
}


#endif /* APIPROXY_CLIENT_H_ */