/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "SStream.h"
#include "cs_priv.h"

#ifdef _MSC_VER
#pragma warning(disable: 4996) // disable MSVC's warning on strcpy()
#endif

void SStream_Init(SStream *ss)
{
	ss->index = 0;
	ss->buffer[0] = '\0';
}

void SStream_concat0(SStream *ss, char *s)
{
#ifndef CAPSTONE_DIET
	strcpy(ss->buffer + ss->index, s);
	ss->index += strlen(s);
#endif
}

void SStream_concat(SStream *ss, const char *fmt, ...)
{
#ifndef CAPSTONE_DIET
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = cs_vsnprintf(ss->buffer + ss->index, sizeof(ss->buffer) - (ss->index + 1), fmt, ap);
	va_end(ap);
	ss->index += ret;
#endif
}

/*
   int main()
   {
   SStream ss;
   int64_t i;

   SStream_Init(&ss);

   SStream_concat(&ss, "hello ");
   SStream_concat(&ss, "%d - 0x%x", 200, 16);

   i = 123;
   SStream_concat(&ss, " + %ld", i);
   SStream_concat(&ss, "%s", "haaaaa");

   printf("%s\n", ss.buffer);

   return 0;
   }
 */
