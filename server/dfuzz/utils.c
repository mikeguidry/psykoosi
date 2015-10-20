#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread.h>
#include <ngx_event.h>
#include <GeoIP.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
//#include <libmemcached/memcached.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <string.h>
#include <nanomsg/nn.h>
#include <nanomsg/ipc.h>
#include <nanomsg/pair.h>
#include <nanomsg/reqrep.h>
#include <stdarg.h>

#ifndef CDBHASH
#define CDBHASH

// cdb hashing.. for other unrelated project.. but useful if you need some kinda hashing here..
unsigned int cdb_hashadd(unsigned int h,unsigned char c) {
    h += (h << 5);
    return h ^ c;
}

unsigned int cdb_hash(const char *buf,unsigned int len) {sup with
    unsigned int h;
    
    h = 5381;
    while (len) {
        h = cdb_hashadd(h,*buf++);
        --len;
    }
    return h;
}
// end cdb
#endif



#ifndef NANOMSG
#define NANOMSG

char *nanoreq(char *fmt, ...) {
    char *ret = NULL;
    int msg_sock = 0;
    va_list vptr;
    int len = 0;
    char msg[16384];
    
    va_start(vptr, fmt);
    len = vsprintf(msg, fmt, vptr);
    va_end(vptr);
    
    if ((msg_sock = nn_socket(AF_SP, NN_REQ)) < 0) goto end;
    if (nn_connect(msg_sock, "ipc:///tmp/blah.ipc") < 0) goto end;
    
    if (nn_send(msg_sock, msg, strlen(msg), 0) < 0) goto end;
    
    memset(msg, 0, sizeof(msg));
    len = nn_recv(msg_sock, msg, sizeof(msg), 0);
    
    if (len) return strdup(msg);
end:;
    if (msg_sock) nn_close(msg_sock);
}


char *nanoreqlen(int *_len, char *fmt, ...) {
    char *ret = NULL;
    int msg_sock = 0;
    va_list vptr;
    int len = 0;
    char msg[16384];
    void *data = NULL;
    
    va_start(vptr, fmt);
    len = vsprintf(msg, fmt, vptr);
    va_end(vptr);
    
    if ((msg_sock = nn_socket(AF_SP, NN_REQ)) < 0) goto end;
    if (nn_connect(msg_sock, "ipc:///tmp/curl.ipc") < 0) goto end;
    
    if (nn_send(msg_sock, msg, strlen(msg), 0) < 0) goto end;
    
    len = nn_recv(msg_sock, &data, NN_MSG, 0);
    
       
    *_len = len;
    
    if (len) {
        ret = malloc(len + 1);
        if (ret == NULL) return NULL; // fatal should exit...
        memcpy(ret, data, len);
        nn_freemsg(data);
        
    }
end:;
    if (msg_sock) nn_close(msg_sock);
    return ret;
}
#endif


#ifndef BASE64
#define BASE64
// base64 stuff.. i thikn nginx has it built in but i didnt feel like going through the API/documention/source

static const unsigned char pr2six[256] =
{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54,
    55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

char *
base64_decode(char *bufcoded, int* len)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufplain;
    register unsigned char *bufout;
    register int nprbytes;
    
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;
    bufplain = (char *)malloc(nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;
    
    while (nprbytes > 0) {
        *(bufout++) = (unsigned char) (pr2six[bufin[0]] << 2 | pr2six[bufin[1]] >> 4);
        if (nprbytes == 2) break;
        *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        if (nprbytes == 3) break;
        *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }
    *bufout = 0;
    *len=(bufout - bufplain);
    return bufplain;
}

static const char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(unsigned char *s, int len) {
    register int i;
    register char *p, *e;
    
    p = e = (char *) malloc((((len + 2) / 3 * 4)) + 1);
    
    for (i = 0; i < len; i += 3) {
        *p++ = basis_64[s[i] >> 2];
        if (i == len) break;
        if ((i + 1) == len) {
            *p++ = basis_64[((s[i] & 0x03) << 4)];
            break;
        } else {
            *p++ = basis_64[((s[i] & 0x03) << 4) | ((int) (s[i+1] & 0xF0) >> 4)];
        }
        if ((i + 2) == len) {
            *p++ = basis_64[((s[i+1] & 0x0F) << 2)];
            break;
        } else {
            *p++ = basis_64[((s[i+1] & 0x0F) << 2) | ((int) (s[i+2] & 0xC0) >> 6)];
        }
        *p++ = basis_64[  s[i+2] & 0x3F];
    }
    *p = '\0';
    return e;
} 
// end base64
#endif


#ifndef LINKEDLIST
#define LINKEDLIST

// some generic linked list.. i think i removed use for most of this since i wanted to manually add to optimize speed.. it always calls l_last every add and enumerates
// through the entire structure.. bad for big structures.. good for small list.. easier to set the list variable to the new one and push the list to ->next.. LIFO (last in first out)
typedef struct _link { struct _link *next; struct _link *prev; } LINK;



LINK *l_last(LINK *start) {
	LINK *lptr = start;
    
	while ((lptr != NULL) && (lptr->next != NULL))
		lptr = lptr->next;
    
	return lptr;
    
}





LINK *l_link(LINK **list, LINK *obj) {
	LINK *lptr;
    
	if (*list != NULL) {
		lptr = (LINK *)l_last(*list);
		lptr->next = obj;
	} else
		*list = obj;
    
	return obj;
}





LINK *l_add(LINK **list, int size) {
	LINK *newptr;
    
	if ((newptr = (LINK *)malloc(size + 1)) == NULL)
		return NULL;
    
	memset(newptr, 0, size);
	return l_link(list, newptr);
}





void l_unlink(LINK **l_ptr, LINK *rem) {
	LINK *cur = *l_ptr, *last = rem;
    
	if (*l_ptr == rem) {
		if (cur->next != NULL)
			*l_ptr = cur->next;
		else
			*l_ptr = NULL;
        
	} else {
		while ((cur != NULL) && (cur != rem)) {
            last = cur;
            
            cur = cur->next;
		}
        
		if (cur == NULL) {
			return;
		}
        
		if (cur->next != NULL)
			last->next = cur->next;
		else
			last->next = NULL;
	}
}

void l_del(LINK **l_ptr, LINK *rem) {
	l_unlink(l_ptr, rem);
    
	free(rem);
}

int l_count(LINK *l_ptr) {
	int i = 0;
    
	while (l_ptr != NULL) {
		i++;
        
		l_ptr = l_ptr->next;
	}
    
	return i;
}
// end generic link stuff

#endif

