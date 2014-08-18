#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

HMODULE blah = LoadLibrary(argv[1]);

printf("LoadLibrary(\"%s\") = %p\n", argv[1], blah);

Sleep(1000 * 5);
ExitProcess(0);
}