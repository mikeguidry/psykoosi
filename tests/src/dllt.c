#define WIN32_LEAN_AND_MEAN
//#pragma comment(linker, "/FILEALIGN:16")
#include <stdio.h>
#include <windows.h>

void doit(void *parm) {
MessageBoxA(0,"hello","hi",0);

}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
//int main(int argc, char **argv)
	if (dwReason != DLL_PROCESS_ATTACH) return TRUE;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) doit, NULL, 0, NULL);

	return TRUE;
}
