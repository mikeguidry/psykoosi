#include <cstddef>
#include <iostream>
#include <cstring>
#include <stdio.h>
#include <inttypes.h>
#include <fstream>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include "logging.h"

using namespace psykoosi;


Logging::Logging() {
	char buf[1024];

	srand(time(0));
	sprintf(buf, "/tmp/%d.%d.txt", getpid(), rand()%65535);

	logging_fd = fopen(buf, "a");
	filename = strdup(buf);

}

Logging::~Logging() {
	if (logging_fd != NULL)
		fclose(logging_fd);
	if (filename != NULL)
		free(filename);
}

void Logging::LogMsg(char *fmt, ...) {
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end (args);

	if (logging_fd) {
		fputs(buf, logging_fd);
		fputs("\n", logging_fd);
	}
}
