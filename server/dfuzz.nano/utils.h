#ifndef CDBHASH
#define CDBHASH
unsigned int cdb_hashadd(unsigned int h,unsigned char c);
unsigned int cdb_hash(const char *buf,unsigned int len);
#endif

#ifndef NANOMSG
#define NANOMSG
char *nanoreq(char *fmt, ...);
char *nanoreqlen(int *_len, char *fmt, ...);
#endif
#ifndef BASE64
#define BASE64
char *base64_decode(char *bufcoded, int* len);
char *base64_encode(unsigned char *s, int len);
#endif

#ifndef LINKEDLIST
#define LINKEDLIST
typedef struct _link { struct _link *next; struct _link *prev; } LINK;

LINK *l_last(LINK *start);
LINK *l_link(LINK **list, LINK *obj);
LINK *l_add(LINK **list, int size);
void l_unlink(LINK **l_ptr, LINK *rem);
void l_del(LINK **l_ptr, LINK *rem);
int l_count(LINK *l_ptr);
#endif