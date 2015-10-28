#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <fstream>
#include <string>
#include <inttypes.h>
#include <udis86.h>
#include <zlib.h>
#include <pe_lib/pe_bliss.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include "virtualmemory.h"
#include "apiproxy_client.h"
extern "C" {
#include <capstone/capstone.h>
}

#include "disassemble.h"
#include "analysis.h"
#include "loading.h"
#include "emu_hooks.h"
#include "emulation.h"


extern "C" {
	// command IDs for proxy
// command IDs for proxy
enum {
	CMD_START,		// place holder showing start of commands..
	PROC_EXIT,		// *exitprocess() on proxy.. maybe shutdown and let logging file know? or respond back with soem random information.. we'll see
	
	THREAD_START,	// *CreateThread to a stub that starts a new zeromq socket so we can control it
					// maybe use a linked list as a queue for instructions for a thread.. having the thread respond with results (slower than zeromq)
						// but will for doing a small tcp/ip stub or backdoor
	THREAD_END,		// *kill a particular thread
	
	FILE_WRITE,		// *write a complete file
	FILE_READ,		// *read a complete file
	FILE_DELETE,	// *delete a file

	//FILE_EXEC,		// maybe allow executing a program and then injecting a DLL for proxying data backwards

	LOAD_DLL,		// *load a DLL (loadlibrary) support loading into memory using our own memory laoder later for further manipulations if necessary
	UNLOAD_DLL,		// *freeloadlib
	CALL_FUNC,		// *call a particular function (requires its arguments to be behind it)
					// *each argument needs ability to give memory as an argument if its a pointer..


	MEM_PUSH,		// *write to memory a range of data
	MEM_PEEK,		// *read from the memory
	MEM_ALLOC,		// *allocate on heap
	MEM_DEALLOC,	// *free heap
	MEM_ZERO,

	// do these later
	//TLS_READ,		// maybe just respond with the entire TLS instead of wasting time disasembling or knowing the particular address/length
	//TLS_WRITE,		// write a value to tls -- maybe add segment selection to normal memory functions

	//LOG_ON,			// turn on logging (writing all requests/responses to a data file)
	//LOG_OFF,		// turn logging off
	
	//REDIRECT_BACKWARDS_FUNC,
					// maybe allow proxying backwards for specific API that is called from OTHER API
	//EXCEPTION_SET,	// set a particular thing to happen on exception

	//LASTERROR_MODE, // mode to determine if we need to report backwards GetLastError every call so the client can have it ready
	PING,
	GET_DLL_HANDLE,
	GET_MODULE_FILENAME,
	CMD_DONE		// just placeholder for the end
	
};


#pragma pack(push)
#pragma pack(1)
typedef struct _zero_pkt {
    int32_t type;
    int32_t len;
} ZmqHdr;

typedef struct _file_info {
	int32_t cmd;
	int32_t name_len;
	int32_t data_len;
	int32_t overwrite;
	int32_t perms;
} FileInfo;

typedef struct _zmq_pkt {
	uint32_t crc;
	int32_t thread_id; // 0 for global
	int32_t cmd;
	int32_t len; // len of cmd after pkt
} ZmqPkt;

// our response packet
typedef struct _zmq_ret {
	int32_t response;		// return code
	int32_t extra_len;		// how much data after packet header...
} ZmqRet;

// transfer of memory
typedef struct _mem_info {
	int32_t len;			// len of data after packet
	int32_t _virtual;
	int32_t cmd;  // MEM_PUSH, or MEM_PEEK
	int32_t addr;			// address
	
} MemTransfer;

// information given when needing to call API
typedef struct call_info {
	int32_t addr;
	int32_t module_len;
	int32_t func_len;

	uint32_t ESP;
	uint32_t EBP;
	uint32_t Region;
	uint32_t Region_Size;
	// how many TransferParams come next..
	int32_t arg_len;
	uint32_t ThreadID;
} CallInfo;

#define REGION_BLOCK (sizeof(uint32_t)*2)

#pragma pack(pop)
}


using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


APIClient::APIClient() {
	connected = false;
	VM = NULL;
	Regions = NULL;
	queue = NULL;
	Threads = NULL;
	run_id = connected = thread_id = threaded = 0;
}

APIClient::~APIClient() {
	if (connected) {
		Disconnect();
	}
	// *** FREE MEMORY
}

void APIClient::SetVirtualMemory(VirtualMemory *mptr) {
	VM = mptr;
}

int APIClient::SendPkt(int type, char *data, int size, char **response, int *response_size) {
	int i = 0;
	int sret = -1;
	int final_size = sizeof(ZmqPkt) + sizeof(ZmqHdr) + size;
	//FILE *fd = fopen("/tmp/pkt.dat","wb");
/*
	printf("type: %d data %p size %d resp %p resp size %d [sizeof %d %d %d]\n",
		type, data, size, response, response_size,
		sizeof(ZmqPkt), sizeof(ZmqHdr), size);
*/
	char *final = (char *)malloc(final_size + 1);
	char *ptr = (char *)final;
	if (final == NULL) return -1;
	memset(final, 0, final_size);
	
	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ptr += sizeof(ZmqHdr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr);
	ptr += sizeof(ZmqPkt);

	// what command? (or type)
	hdr->type = type;
	pkt->cmd = type;
	
	// set lengths..
	hdr->len = size + sizeof(ZmqPkt);
	pkt->len = size + sizeof(ZmqPkt);
	
	// copy the extra data for the packet
	if (size > 0) {
		memcpy(ptr, data, size);
		//memcpy((void *)((char *)final + sizeof(ZmqHdr) + sizeof(ZmqPkt)),
		//	 data, size);
	}

	//fwrite(final, final_size, 1, fd);
	//fclose(fd);
	i = write(proxy_socket, final, final_size);
	if (i <= 0) {
		if (errno == ENOTCONN) {
			printf("not conn\n");
			close(proxy_socket);
			connected = 0;
		}
	}
	/*
	int s=0;
	while (i < final_size) {
		s = write(proxy_socket, final+i, final_size-i);
		if (s == -1) {
			i = -1;
			break;
		}
		i += s;
	}
	if (i <= 0) {
		if (errno == ENOTCONN) {
			close(proxy_socket);
			connected = 0;
			return -1;
		}
	}*/
	if (i == final_size) {
		int r = read(proxy_socket, final, sizeof(ZmqRet));
		if (r >= sizeof(ZmqRet)) {
			ZmqRet *ret = (ZmqRet *)(final);
			printf("call type %d extra len %d resp %d\n", type, ret->extra_len, ret->response);
			if (ret->extra_len && ret->response == 1) {
				if ((ret->extra_len+sizeof(ZmqRet)) > final_size) {
					printf("too big. replace\n");
					char *replace_buf = (char *)realloc(final, ret->extra_len + sizeof(ZmqRet) + 1);
					if (replace_buf == NULL) {
						printf("couldnt allocate replace buf\n");
						free(final);
						close(proxy_socket);
						connected = 0;
						return -1;
					}
					final = replace_buf;
					final_size = ret->extra_len + sizeof(ZmqRet);
				}
				int _read = 0;
				while (_read < ret->extra_len) {
					r = read(proxy_socket, (char *)((char *)final + sizeof(ZmqRet) + _read), (int)(ret->extra_len - _read));
					if (r <= 0) {
						printf("couldnt read socket\n");
						if (errno == ENOTCONN) {
							close(proxy_socket);
							connected = 0;
							break;
						}
					}
					_read += r;
				}
			} else if (ret->response == 0) {
				printf("bad response\n");
				sret = 0;
			}
			
			if (response != NULL && ret->extra_len) {
				char *rbuf = (char *)malloc(ret->extra_len + 1);
				if (rbuf != NULL) {
					memcpy(rbuf, (void *)((char *)final + sizeof(ZmqRet)), ret->extra_len);
					*response_size = ret->extra_len;
					*response = rbuf;
					
					sret = 1;
				}
			}
		}
	}
	
	free(final);
	
	return sret;
}


// push sections across (at least once) so the software data is intact on the other side
// later we can emulate and change semantics for linear...
int APIClient::PushSections() {
	int count = 0;
	VirtualMemory::Memory_Section *sptr = NULL;

	for (sptr = VM->Section_EnumByFilename(NULL, sptr); sptr != NULL; sptr = VM->Section_EnumByFilename(NULL, sptr)) {
		// if we already pushed this across...
		if (sptr->pushed) continue;
		// if its a DLL
		if (sptr->IsDLL) continue;
		
		// push data of this section across
		PushData(sptr->ImageBase + sptr->Address, NULL, sptr->RawSize);
		
		// ensure we know its pushed later.. to not replicate the data on seq. calls
		sptr->pushed++;
		// we need to link this to the cycle of the virtual machine structure...
		sptr->last_push = time(0);
		
		count++;
	}

	// how many sections have we replicated across this API Proxy
	return count;
}

// write data to remote address
int APIClient::PushData(uint32_t Address, char *Source, int Size) {
	int ret = 0;
	printf("pushing data %X %d src %p\n", Address, Size, Source);
	if (Size < 0) {
		printf("Size < 0\n");
		return -1;
	}
	// if Source == NULL we push from VMEM
	int pkt_size = sizeof(MemTransfer) + Size;
	char *ptr = (char *)malloc(pkt_size + 1);
	if (ptr == NULL) return -1;
	memset(ptr, 0, pkt_size);
	
	if (Source != NULL) {
		memcpy((void *)((char *)ptr + sizeof(MemTransfer)), Source, Size);
	} else {
		VM->MemDataRead(Address, (unsigned char *)((char *)ptr + sizeof(MemTransfer)), Size);
	}
	
	MemTransfer *minfo = (MemTransfer *)ptr;
	minfo->len = Size;
	minfo->cmd = MEM_PUSH;
	minfo->addr = (int32_t)Address;
	if (for_tib) {
		for_tib = false;
		minfo->_virtual = 1;
	}
	
	char *resp = NULL;
	int resp_size = 0;
	ret = SendPkt(MEM_PUSH, ptr, pkt_size, &resp, &resp_size);
	
	free(ptr);
	
	printf("PushData ret: %d\n", ret);
	
	return ret;	
}

// read data from remote address
int APIClient::PeekData(uint32_t Address, char *Destination, int Size) {
	int ret = 0;
	printf("pulling data %X %d src %p\n", Address, Size, Destination);
	if (Size < 0) {
		printf("Size < 0\n");
		return -1;
	}
	// if Source == NULL we push from VMEM
	int pkt_size = sizeof(MemTransfer) + Size;
	char *ptr = (char *)malloc(pkt_size + 1);
	if (ptr == NULL) return -1;
	memset(ptr, 0, pkt_size);
	
	/*if (Destination != NULL) {
		memcpy(Destination, (void *)((char *)ptr + sizeof(MemTransfer)), Size);
	} else {
		VM->MemDataRead(Address, (unsigned char *)((char *)ptr + sizeof(MemTransfer)), Size);
	}*/
	
	MemTransfer *minfo = (MemTransfer *)ptr;
	minfo->len = Size;
	minfo->cmd = MEM_PEEK;
	minfo->addr = (int32_t)Address;
	if (for_tib) {
		for_tib = false;
		minfo->_virtual = 1;
	}
	
	char *resp = NULL;
	int resp_size = 0;
	ret = SendPkt(MEM_PUSH, ptr, pkt_size, &resp, &resp_size);
	if (ret == 1 && resp != NULL) {
		if (resp_size != Size) {
			printf("ERROR READING REMOTE DATA!\n");
			exit(-1);
		}
		
		if (Destination != NULL) {
			memcpy(Destination, resp, resp_size);
		} else {
			VM->MemDataWrite(Address, (unsigned char *)resp, resp_size);
		}
		
		free(resp);
	}
	
	free(ptr);
	
	return ret;	
}



// send a ping to the server (to verify connection)
int APIClient::Ping() {
	if (!connected)
		return -1;
	int start = time(0);
	int cur = 0;
	int i = APIClient::SendPkt(PING, NULL, 0, NULL, 0);
	
	if (i == 1) {
		cur = time(0);
		
		return cur - start;
	}
	
	return 0;
}



int APIClient::Connect(char *ip, int port) {
	int ret = 0;
	char _hdr[]="APIPSY0";
	char hdr[7];

	printf("API connect: %s %d\n", ip, port);
	
	if (connected) {
		// if weare already connected.. lets try to ping
		if (APIClient::Ping())
			return 1;
	}
	
    struct sockaddr_in proxy_addr;

	if ((proxy_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;
	proxy_addr.sin_family = AF_INET;                
    proxy_addr.sin_addr.s_addr = inet_addr(ip);
	//proxy_addr.sin_addr.s_addr = inet_addr("192.168.1.160");
    proxy_addr.sin_port = htons(port);

	if (connect(proxy_socket, (const struct sockaddr *) &proxy_addr, sizeof(struct sockaddr_in)) != 0) {
		close(proxy_socket);
		return -1;
	}

/*
	int i = 0;
	if ((i = read(proxy_socket, (char *)&hdr, 7)) < 7) {
		printf("error reading api proxy\n");
		exit(-1);
	}
	if (memcmp(_hdr,hdr,6)==0) {
		printf("connected successfully\n");
	}
#define VERSION 1
	int remote_ver = (int)(hdr[7]);
	if (remote_ver > (VERSION + '0')) {
		printf("protocol error version %d vs %d\n", remote_ver, VERSION);
	}
	
	unsigned short magic = 0xAFDE;
	if (write(proxy_socket, (char *)&magic, 2) < 2) {
		printf("error writing magic\n");
		exit(-1);
	}
	printf("Remote API Proxy: %d socket %d\n", remote_ver - '0', proxy_socket);
	*/
	
	printf("Connected\n");
		
	connected = 1;
	return ret;
}

int APIClient::Disconnect() {
	if (!connected) return -1;
	
	APIClient::AllocatedRegion *rptr = Regions;
	
	while (rptr != NULL) {
		DeallocateMemory(rptr->Address);
		rptr= rptr->next;
	}
	
	close(proxy_socket);
	
	connected = 0;
	
	return 1;
}

uint32_t APIClient::AllocateMemory(uint32_t Address, int Size) {
	uint32_t ret = 0;
	int r = 0;
	int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer);
	char *ptr = (char *)malloc(pkt_len + 1);
	
	if (ptr == NULL) {
		// same as above.. out of memory!
		return 0;
	}

	memset(ptr, 0, pkt_len);
	
	// setup our command structure for the remote side...
	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr+sizeof(ZmqHdr));
	MemTransfer *minfo = (MemTransfer *)((char *)ptr+sizeof(ZmqHdr)+sizeof(ZmqPkt));

	hdr->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
	pkt->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
	hdr->type = MEM_ALLOC;
	pkt->cmd = MEM_ALLOC;

	//printf("Allocate asking for %p [%d]\n", Address, Size);
	// memory information required to allocate remotely..
	minfo->addr = (int32_t)Address;
	
	// we are allocating memory..
	minfo->cmd = MEM_ALLOC;
	// this tells it to use VirtualAlloc...
	minfo->_virtual = 1;
	minfo->len = Size;

	if ((r = write(proxy_socket, ptr, pkt_len)) < pkt_len) {
		connected = false;
		close(proxy_socket);
		free(ptr);
		
		return 0;
	}

	if ((r = read(proxy_socket, ptr, pkt_len)) < sizeof(ZmqRet)) {
		connected = false;
		close(proxy_socket);
		free(ptr);
		
		return 0;
	}

	ZmqRet *retpkt = (ZmqRet *)ptr;
	if (retpkt->response == 1) {
		uint32_t *_addr = (uint32_t *)((char *)ptr + sizeof(ZmqRet));
		ret = *_addr;
		
		AllocatedRegion *regptr = new AllocatedRegion;
		memset((void *)regptr, 0, sizeof(AllocatedRegion));
		regptr->Size = Size;
		regptr->Address = Address;
		
		// add to list
		regptr->next = Regions;
		Regions = regptr;
	}

	free(ptr);
	
	return ret;
}


int APIClient::DeallocateMemory(uint32_t Address) {
	int ret = 0;
	int i = 0;
	int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer);

	char *ptr = (char *)malloc(pkt_len + 1);
	if (ptr == NULL) return -1;
	memset(ptr, 0, pkt_len);

	char *retptr = (char *)malloc(sizeof(ZmqRet) + 1);
	if (retptr == NULL) return -1;

	// setup our command structure for the remote side...
	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr+sizeof(ZmqHdr));
	MemTransfer *minfo = (MemTransfer *)((char *)ptr+sizeof(ZmqHdr)+sizeof(ZmqPkt));

	hdr->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
	pkt->len = sizeof(ZmqPkt) + sizeof(MemTransfer);

	pkt->cmd = MEM_DEALLOC;
	hdr->type = MEM_DEALLOC;
	minfo->cmd = MEM_DEALLOC;
	
	minfo->_virtual = 1;
	minfo->addr = (int32_t)Address;
	
	if ((i = write(proxy_socket, ptr, pkt_len)) < pkt_len) {
			connected = false;
			close(proxy_socket);
			free(ptr);
			return -1;
	}

	if ((i = read(proxy_socket, retptr, sizeof(ZmqRet))) < sizeof(ZmqRet)) {
			connected = false;
			close(proxy_socket);
			free(ptr);
			
			return -1;
	}
	
	ZmqRet *rethdr = (ZmqRet *)retptr;
	if (rethdr->response == 1) ret = 1;
	
	return ret;
}



int APIClient::NewThread() {
	int ret = 0;
	int i = 0;
	int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt);

	char *ptr = (char *)malloc(pkt_len + 1);
	if (ptr == NULL) {
		return -1;
	}

	char *retptr = (char *)malloc(sizeof(ZmqRet) + sizeof(uint32_t) + 1);
	if (retptr == NULL) {
		free(ptr);
		return -1;
	}

	// setup our command structure for the remote side...
	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr+sizeof(ZmqHdr));
	
	hdr->len = sizeof(ZmqPkt);
	pkt->len = sizeof(ZmqPkt);
	pkt->cmd = THREAD_START;
	hdr->type = THREAD_START;
	
	if ((i = write(proxy_socket, ptr, pkt_len)) < pkt_len) {
			connected = false;
			close(proxy_socket);
			free(ptr);
			free(retptr);
			return -1;
	}

	if ((i = read(proxy_socket, retptr, sizeof(ZmqRet))) < sizeof(ZmqRet)) {
			connected = false;
			close(proxy_socket);
			free(ptr);
			free(retptr);
			return -1;
	}
	
	ZmqRet *rethdr = (ZmqRet *)retptr;
	if (rethdr->response != 1) {
		ret = 0;
	} else {
		uint32_t *tid = (uint32_t *)((char *)retptr + sizeof(ZmqRet));
		
		APIThreads *aptr = new APIThreads;
		std::memset((void *)aptr, 0, sizeof(APIThreads));
		aptr->id = thread_id++;
		aptr->remote_id = *tid;
		
		ret = aptr->id;
	}
		
	free(retptr);
	free(ptr);
	
	return ret;
}

int APIClient::DestroyThread(int id) {
	int ret = 0;
	APIThreads *aptr = Threads;
	while (aptr != NULL) {
		if (id == aptr->id) break;
	}
	
	if (aptr != NULL) {
		// remove thread on remote side..
		int i = 0;
		int pkt_len = sizeof(ZmqHdr) + sizeof(uint32_t);
		//int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt);
	
		char *ptr = (char *)malloc(pkt_len + 1);
		if (ptr == NULL) {
			return -1;
		}
	
		char *retptr = (char *)ptr;
		
		// setup our command structure for the remote side...
		ZmqHdr *hdr = (ZmqHdr *)(ptr);
		
		// FIX THIS LATER.. WE WILL NEED PKT .. but for now it just looks for the number
		hdr->len = sizeof(ZmqPkt);
		//pkt->len = sizeof(ZmqPkt);
		//pkt->cmd = THREAD_END;
		hdr->type = THREAD_END;

		uint32_t *_id = (uint32_t *)((char *)ptr + sizeof(ZmqHdr));
		*_id = aptr->remote_id;
		
		if ((i = write(proxy_socket, ptr, pkt_len)) < pkt_len) {
				connected = false;
				close(proxy_socket);
				free(ptr);
				return -1;
		}
	
		if ((i = read(proxy_socket, retptr, sizeof(ZmqRet))) < sizeof(ZmqRet)) {
				connected = false;
				close(proxy_socket);
				free(ptr);
				return -1;
		}
		
		ZmqRet *rethdr = (ZmqRet *)retptr;
		if (rethdr->response != 1) {
			ret = 0;
		} else {
			ret = 1;
		}
		
		// remote thread locally
		// remove fro linked list
		if (Threads == aptr)
			Threads = aptr->next;
		else {
			APIThreads *aptr2 = Threads;
			while (aptr2->next != aptr) {
				aptr2 = aptr2->next;
			}
			aptr2->next = aptr->next;
		}
		
		free(aptr);	
	}
	
	return ret;
}


/*
this function has to push over all data required for a particular function call
as well as local variables and stack information...

since we are emulating we need to track all local variables (ESP areas) since the entrance of the ffunction
or emulate the function locally to determine what data will be required until it reaches a syscall, or high enough DLL (kernel/ntdll/winsock/IO)

return packet:
0x00  call return
0x04  return fix (conventions)
0x08+ region changes returns as dword addr, dword data

*/
int APIClient::CallFunction(char *module, char *function, CodeAddr Address,
 CodeAddr ESP, CodeAddr EBP,
CodeAddr Region, CodeAddr Region_Size, uint32_t *eax_ret, CodeAddr ESP_High,
 uint32_t *ret_fix, uint32_t ThreadID) {
	struct _ret_pkt {
		uint32_t eax_ret;
		uint32_t ret_fix;
	} *RetPkt = NULL;
	int module_len = strlen(module) + 1;
	int function_len = strlen(function) + 1;
	
	printf("API Proxy: Call %s[%s]\n", function, module);
	
	int arg_len = 0;
	// adding 2 for each 00 after the strings..
	int pkt_len = sizeof(CallInfo) + module_len + function_len + arg_len;
	char *ptr = (char *)malloc(pkt_len + 1);
	if (ptr == NULL) return -1;
	memset(ptr, 0, pkt_len);
	
	CallInfo *cinfo = (CallInfo *)(ptr);
	cinfo->module_len = (int32_t)module_len;
	cinfo->func_len = (int32_t)function_len;

	char *_module = (char *)((char *)ptr + sizeof(CallInfo));
	memcpy(_module, module, module_len);
	char *_function = (char *)((char *)ptr + sizeof(CallInfo) + module_len);
	memcpy(_function, function, function_len);
	char *_arg = (char *)((char *)ptr + sizeof(CallInfo) + module_len + function_len);
	
	
	
	/*  NOT MATCHING UP TO WIN32 CLIENT... manually fixing ESP
	// lets decrease ESP (simulating a normal call)
	// later fix to do the size of (DWORD_PTR) *** FIX
	ESP -= sizeof(uint32_t);
	
	// put return address there (fake... irrelevant)
	unsigned char retaddr[] = "\xFF\xFF\xFF\xFF";
	VM->MemDataWrite(ESP, (unsigned char *)&retaddr, (int)sizeof(uint32_t));
	*/
	
	// i dont think the remote side is expecting ESP to be setup for the call
	//ESP += (sizeof(uint32_t) * 2);
	uint32_t StartESP = ESP;// + sizeof(uint32_t);
	
	//ESP += (sizeof(uint32_t) * 2);

	char adata[64];
	if (arg_len > 0) {
		
		VM->MemDataRead(StartESP, (unsigned char *)&adata, arg_len);
		memcpy(_arg, adata, arg_len);
	}
	//VM->MemDataWrite(ESP, (unsigned char *)&adata, arg_len);
	
	
	cinfo->addr = (uint32_t)Address;
	cinfo->ESP = ESP;
	cinfo->EBP = EBP;
	cinfo->Region = Region;
	cinfo->Region_Size = Region_Size;
	cinfo->arg_len = arg_len;
	cinfo->ThreadID = ThreadID;
	
	printf("Pushing call to remote side [%s %s] %d %d / %d %d\n", _module, _function,
	module_len, function_len, cinfo->module_len, cinfo->func_len);
	//printf("Region %X size %d\n", Region, Region_Size);

	char *resp = NULL;
	int resp_size = 0;

	// push the data regions of the executable, and code across to the remote side
	// for chance of pointers going back into these regions	
	//PushData(Region, 0, Region_Size);
	PushSections();
	
	// push all stack over..
	int push_size = (int)(EBP - ESP);
	printf("push size %d\n", push_size);
	if (push_size < 0)
		push_size = 64;
		 
	PushData(ESP, NULL, push_size);
	
	// should also shadow copy like the windows vversion
	// using a hashing algorithm to verify changes.. *** FIX
	int remote_ret = SendPkt(CALL_FUNC, ptr, pkt_len, &resp, &resp_size);

	//ESP += sizeof(uint32_t);
	
	// pull it back down in case some local variables were modified
	PeekData(ESP, NULL, (int)push_size);
		
	// later fix to do the size of (DWORD_PTR) *** FIX
	//ESP -= (sizeof(uint32_t) * 2);
	
	if (remote_ret == -1 && !resp) return -1;
	
	ZmqRet *ret = (ZmqRet *)(resp);
	
	// process the response of this function call
	if (resp && resp_size) {//ret->response == 1 && ret->extra_len >= sizeof(uint32_t)) {
		//printf("have response %X size %d [%d]\n", resp, resp_size, resp_size - sizeof(struct _ret_pkt));
		RetPkt = (struct _ret_pkt *)(resp);
		//uint32_t *_eax_ret = (uint32_t *)resp;
		
		if (eax_ret != NULL)
			*eax_ret = RetPkt->eax_ret;
			
		// we need to accomodate ESP using the ret fix
		*ret_fix = RetPkt->ret_fix;
		
		//printf("eax %d ret %d\n", RetPkt->eax_ret, RetPkt->ret_fix);
		
		// now we may be interested in regions of memory that have changed due to the call
		int memory_change_count = (resp_size - sizeof(RetPkt)) / (REGION_BLOCK);
		char *memptr = (char *)(resp + sizeof(RetPkt));
		//printf("memory change %d\n", memory_change_count);
		// ignore memory changes for now.. buggy
		//memory_change_count = 0;
		for (int a = 0; a < memory_change_count; a++) {
			// get the data address of our changed memory
			uint32_t *MemAddr = (uint32_t *)memptr;
			memptr += sizeof(uint32_t);
			uint32_t *MemData = (uint32_t *)memptr;
			memptr += sizeof(uint32_t);
			uint32_t *_MData = (uint32_t *)*MemData;
			
			
			// write the returned data into the virtual memory
			//printf("Writing memory to %X changed from region [%X]\n", MemAddr, _MData);
			VM->MemDataWrite(*MemAddr, (unsigned char *)&_MData, sizeof(uint32_t));
			
			
		}   
	} else {
		printf("no RESPONSE resp %p resp %d extra %d\n",resp, ret->response, ret->extra_len);
		throw;
	}
	
	free(resp);
	
	
	return 1;
}

char *APIClient::GetDLLPath(char *dll) {
	int sret = 0;
	char *ret = NULL;
	
	int pkt_size = strlen(dll) + sizeof(ZmqPkt) + 1;
	char *pkt = (char *)malloc(pkt_size + 1);
	if (pkt == NULL) return 0;
	
	char *resp = NULL;
	int resp_size = 0;
	sret = SendPkt(LOAD_DLL, pkt, pkt_size, &resp, &resp_size);
	
	if (sret == 1 && resp != NULL && resp_size) {
		
		ret = (char *)malloc(resp_size + 2);
		if (ret != NULL)
			memcpy(ret, resp, resp_size);

		free(resp);
	}
	
	free(pkt);
	
	printf("Get DLL Path: %d\n", ret);

	return ret;	
}


uint32_t APIClient::LoadDLL(char *dll) {
	int sret = 0;
	uint32_t ret = 0;
	
	int pkt_size = strlen(dll) + sizeof(ZmqPkt) + 1;
	char *pkt = (char *)malloc(pkt_size + 1);
	if (pkt == NULL) return 0;
	
	char *resp = NULL;
	int resp_size = 0;
	sret = SendPkt(LOAD_DLL, pkt, pkt_size, &resp, &resp_size);
	
	if (sret == 1 && resp != NULL && resp_size) {
		
		memcpy(&ret, resp, sizeof(uint32_t));

		free(resp);
	}
	
	free(pkt);
	
	printf("LoadDLL: %d\n", ret);

	return ret;	
}

uint32_t APIClient::GetDLLAddress(char *dll) {
	int sret = 0;
	uint32_t ret = 0;
	
	int pkt_size = strlen(dll) + sizeof(ZmqPkt) + 1;
	char *pkt = (char *)malloc(pkt_size + 1);
	if (pkt == NULL) return 0;
	
	char *resp = NULL;
	int resp_size = 0;
	sret = SendPkt(GET_DLL_HANDLE, pkt, pkt_size, &resp, &resp_size);
	
	if (sret == 1 && resp != NULL && resp_size) {
		
		memcpy(&ret, resp, sizeof(uint32_t));

		free(resp);
	}
	
	free(pkt);
	
	printf("Get DLL Handle: %d\n", ret);

	return ret;	
}


char *APIClient::FileDownload(char *filepath, int *size) {
	int sret = 0;
	char *ret = NULL;
	
	int pkt_size = sizeof(FileInfo) + strlen(filepath) + 1;
	char *pkt = (char *)malloc(pkt_size + 1);
	if (pkt == NULL) return 0;
	
	FileInfo *finfo = (FileInfo *)pkt;
	finfo->cmd = FILE_READ;
	finfo->name_len = strlen(filepath) + 1;
	
	char *fname = (char *)(pkt + sizeof(FileInfo));
	strcpy(fname, filepath);
	
	char *resp = NULL;
	int resp_size = 0;
	sret = SendPkt(FILE_READ, pkt, pkt_size, &resp, &resp_size);
	
	if (sret == 1 && resp != NULL && resp_size) {
		ret = resp;
		*size = resp_size;
	}
	
	free(pkt);
	
	printf("FileDownload: %s ret addr %X / %d bytes\n", filepath, ret, resp_size);

	return ret;		
}


int APIClient::FileUpload(char *filepath, char *data, int size) {
	int sret = 0;
	int ret = 0;
	
	int pkt_size = sizeof(FileInfo) + (strlen(filepath) + 1) + size;
	char *pkt = (char *)malloc(pkt_size + 1);
	if (pkt == NULL) return 0;
	
	FileInfo *finfo = (FileInfo *)pkt;
	finfo->cmd = FILE_WRITE;
	finfo->name_len = strlen(filepath) + 1;
	
	char *fname = (char *)(pkt + sizeof(FileInfo));
	memcpy(fname, filepath, strlen(filepath));
		
	char *data_ptr = (char *)(pkt + sizeof(FileInfo) + finfo->name_len);
	memcpy(data_ptr, data, size);
	

	char *resp = NULL;
	int resp_size = 0;
	sret = SendPkt(FILE_WRITE, pkt, pkt_size, &resp, &resp_size);
	
	if (sret == 1) {
		ret = 1;
	}
	
	free(pkt);
	
	printf("FileUpload: %s wrote? %d\n", filepath, ret);

	return ret;			
}

int APIClient::FileDelete(char *filepath) {
	int sret = 0;
	int ret = 0;
	
	int pkt_size = sizeof(FileInfo) + (strlen(filepath) + 1);
	char *pkt = (char *)malloc(pkt_size + 1);
	if (pkt == NULL) return 0;
	
	FileInfo *finfo = (FileInfo *)pkt;
	finfo->cmd = FILE_DELETE;
	finfo->name_len = strlen(filepath) + 1;
	
	char *fname = (char *)(pkt + sizeof(FileInfo));
	memcpy(fname, filepath, strlen(filepath));
	
	char *resp = NULL;
	int resp_size = 0;
	sret = SendPkt(FILE_DELETE, pkt, pkt_size, &resp, &resp_size);
	
	if (sret == 1) {
		ret = 1;
	}
	
	free(pkt);
	
	printf("FileDelete: %s deleted? %d\n", filepath, ret);

	return ret;			
}