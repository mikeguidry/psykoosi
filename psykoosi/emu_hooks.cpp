/*
emulation of functions (aka hooks) for replaying logged calls or manipulating IO for fuzzing

the communications protocol logging/replay needs to be done in a way where
it can be used on TCP, FILE, UDP, or even internal protocols within a particular application
this means we need prototypes to convert it for use in each... it should be as simple as
write(buf, size)
read(buf, size)
the rest is irrelevant unless its a state machine where we can hope the application
handles its own internal buffering so we can merge logs together for replays, or
do higher level analysis (ie: where its reading/writing to)

*/
#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <fstream>
#include <string>
#include <stdio.h>
#include <inttypes.h>
#include <udis86.h>
#include <zlib.h>
#include <pe_lib/pe_bliss.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virtualmemory.h"
#include "apiproxy_client.h"
extern "C" {
#include <capstone/capstone.h>
}

#include "disassemble.h"
#include "analysis.h"
#include "loading.h"
#include "structures.h"
#include "emu_hooks.h"
#include "emulation.h"


using namespace psykoosi;
using namespace pe_bliss;
using namespace pe_win;


Hooks::Hooks() {
	exchange = exchange_last = NULL;
	hooks = NULL;
	hook_id = 0;
}

Hooks::~Hooks() {
	while (hooks != NULL) {
		HookFree(hooks);
	}
	
	while (exchange != NULL) {
		FreeExchange(&exchange, exchange);
	}
}

// initialize our compiled in hooks..
// change this to a scripting language.. or a list of functions in 
// a file
int Hooks::Init() {
//HookFunction(void *func, char *module, char *function, int side, int id, int logging) {
	//HookFunction()
	return 1;	
}

Hooks::APIHook *Hooks::HookFunction(void *func, char *module, char *function, int side, int id, int logging) {
	APIHook *aptr = new APIHook;
	if (aptr == NULL) throw;
	memset(aptr, 0, sizeof(APIHook));
	
	aptr->func = func;
	aptr->side = side;
	aptr->id = id;
	
	aptr->function_name = strdup(function);
	aptr->module_name = strdup(module);
	
	return aptr;
}

int Hooks::HookFree(Hooks::APIHook *aptr) {
	
	free(aptr->function_name);
	free(aptr->module_name);
	
	if (hooks == aptr) {
		hooks = aptr->next;
	} else {
		APIHook *aptr2 = hooks;
		while (aptr2->next != aptr) {
			aptr2 = aptr2->next;
		}
		aptr2->next = aptr->next;
	}
	
	free(aptr);

	return 1;	
}

int Hooks::HookRead(int hook_id, char *dst, int size) {
	Hooks::ProtocolExchange *eptr = NULL;
	if (simulation) {
		eptr = NextProtocolExchange(hook_id, 0);
		if (eptr == NULL) {
			printf("Cannot find next read protocol exchange for %d [cur count id %d]\n",
			hook_id, count_id);
			throw;
			return -1;
		}
		memcpy(dst, eptr->buf, eptr->size);
	} else {
		eptr = AddProtocolExchange(hook_id, NULL, NULL, 0, dst, size);
	}
	return (eptr != NULL);
}

int Hooks::HookWrite(int hook_id, char *src, int size) {
	Hooks::ProtocolExchange *eptr = NULL;
	if (simulation) {
		eptr = NextProtocolExchange(hook_id, 1);
		if (eptr == NULL) {
			printf("Cannot find next write protocol exchange for %d [cur count id %d]\n",
			hook_id, count_id);
			throw;
			return -1;
		}
		memcpy(src, eptr->buf, eptr->size);
		
	} else {
		eptr = AddProtocolExchange(hook_id, NULL, NULL, 1, src, size);
	}
	return (eptr != NULL);
}


Hooks::ProtocolExchange *Hooks::NextProtocolExchange(int hook_id, int side) {
	ProtocolExchange *eptr = exchange;
	while (eptr != NULL) {
		if (eptr->hook_id == hook_id && eptr->side == side) {
			if (eptr->id == count_id) {
				count_id++;
				break;
			}
		}
	}
	
	return eptr;
}

Hooks::ProtocolExchange *Hooks::AddProtocolExchange(int hook_id, char *module, char *function, int side, char *data, int size) {
	ProtocolExchange *eptr = new ProtocolExchange;
	if (eptr == NULL) {
		return NULL;
	}
	memset(eptr, 0, sizeof(ProtocolExchange));
	
	if (module != NULL)
		eptr->module = strdup(module);
	if (function != NULL)
		eptr->function = strdup(function);
	
	eptr->hook_id = hook_id;
	eptr->id = ++count_id;
	eptr->side = side;
	eptr->ordered = 1;
	eptr->size = size;
	
	if (data != NULL) {
		eptr->buf = (char *)malloc(size + 1);
		if (eptr->buf == NULL) {
			throw;
			return NULL;
		}
		
		memcpy(eptr->buf, data, size);
	}
	
	// add to the exchange list...
	eptr->next = exchange;
	exchange = eptr;
	
	return NULL;
}

int Hooks::FreeExchange(ProtocolExchange **_eptr, ProtocolExchange *eptr) {
	free(eptr->buf);
	if (eptr->function != NULL) free(eptr->function);
	if (eptr->module != NULL) free(eptr->module);
	free(eptr);
	
	if (*_eptr == eptr) {
		*_eptr = eptr->next;
	} else {
		ProtocolExchange *eptr2 = *_eptr;
		while (eptr2->next != eptr) {
			eptr2 = eptr2->next;
		}
		eptr2->next = eptr->next;
	}
	
	return 1;
}

int Hooks::Load(char *file) {
	FILE *fd;
	struct stat stv;
	int count = 0;
	int i = 0;
	
	if ((fd = fopen(file, "rb")) == NULL) {
		return -1;
	}
	
	fstat(fileno(fd), &stv);
	SaveStructure save;
	
	while (!feof(fd)) {
		i = fread(fd, 1, sizeof(SaveStructure), fd);
		if (i < sizeof(SaveStructure)) {
			// incomplete file..
			break;
		}
		
		if ((ftell(fd) + save.size + save.module_size + save.function_size) > stv.st_size) {
			// incomplete file..
			break;
		}
		
		// copy module name from saved data..
		char *module = (char *)malloc(save.module_size + 2);
		fread(module, 1, save.module_size, fd);
		module[save.module_size] = 0;
		// copy the function from saved data..
		char *function = (char *)malloc(save.function_size + 2);
		fread(function, 1, save.function_size, fd);
		function[save.function_size] = 0;
		
		char *data = (char *)malloc(save.size + 1);
		fread(data, 1, save.size, fd);
		
		// create the exchange protocol
		ProtocolExchange *eptr = AddProtocolExchange(save.hook_id,NULL, NULL, save.side, NULL, 0);
		if (eptr == NULL) {
			printf("Couldnt add the protocol exchange\n");
			throw;
			return -1;
		}
		
		// put the information we read from the file..
		eptr->module = module;
		eptr->function = function;
		eptr->buf = data;
		eptr->size = save.size;
		
		if (count_id < eptr->id)
			count_id = eptr->id + 1;
			
		count++;
	}

	return count;
}

int Hooks::Save(char *file) {
	FILE *fd;
	int count = 0;
	if ((fd = fopen(file, "wb")) == NULL) {
		return -1;
	}

	SaveStructure save;
	memset(&save, 0, sizeof(SaveStructure));
	
	for (ProtocolExchange *eptr = exchange; eptr != NULL; eptr = eptr->next) {
		save.id = eptr->id;
		save.hook_id = eptr->hook_id;
		save.side = eptr->side;
		save.ordered = eptr->ordered;
		save.module_size = strlen(eptr->module);
		save.function_size = strlen(eptr->function);
		save.size = eptr->size;
		
		
		// write the data
		fwrite((void *)&save, sizeof(SaveStructure), 1, fd);
		fwrite(eptr->module, 1, strlen(eptr->module), fd);
		fwrite(eptr->function, 1, strlen(eptr->function), fd);
		fwrite((void *)eptr->buf, eptr->size, 1, fd);
		
		count++;	
	}
	
	fclose(fd);

	return count;
}

Hooks::APIHook *Hooks::HookFind(char *module, char *function) {
	APIHook *aptr = hooks;
	while (aptr != NULL) {
		if (aptr->module_name && aptr->function_name) {
			if ((strcmp(aptr->module_name, module)==0) &&
				(strcmp(aptr->function_name, function)==0)) {
					break;
			}
		}
	}
	return aptr;
}