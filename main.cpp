
/***
 *                                                                                                                                                                                    
 *        ,o888888o.     8 8888      88 8 8888888888     d888888o. 8888888 8888888888  8 8888     ,o888888o.     b.             8     ,o888888o.    8 8888      88 `8.`8888.      ,8' 
 *     . 8888     `88.   8 8888      88 8 8888         .`8888:' `88.     8 8888        8 8888  . 8888     `88.   888o.          8    8888     `88.  8 8888      88  `8.`8888.    ,8'  
 *    ,8 8888       `8b  8 8888      88 8 8888         8.`8888.   Y8     8 8888        8 8888 ,8 8888       `8b  Y88888o.       8 ,8 8888       `8. 8 8888      88   `8.`8888.  ,8'   
 *    88 8888        `8b 8 8888      88 8 8888         `8.`8888.         8 8888        8 8888 88 8888        `8b .`Y888888o.    8 88 8888           8 8888      88    `8.`8888.,8'    
 *    88 8888         88 8 8888      88 8 888888888888  `8.`8888.        8 8888        8 8888 88 8888         88 8o. `Y888888o. 8 88 8888           8 8888      88     `8.`88888'     
 *    88 8888     `8. 88 8 8888      88 8 8888           `8.`8888.       8 8888        8 8888 88 8888         88 8`Y8o. `Y88888o8 88 8888           8 8888      88      `8. 8888      
 *    88 8888      `8,8P 8 8888      88 8 8888            `8.`8888.      8 8888        8 8888 88 8888        ,8P 8   `Y8o. `Y8888 88 8888   8888888 8 8888      88       `8 8888      
 *    `8 8888       ;8P  ` 8888     ,8P 8 8888        8b   `8.`8888.     8 8888        8 8888 `8 8888       ,8P  8      `Y8o. `Y8 `8 8888       .8' ` 8888     ,8P        8 8888      
 *     ` 8888     ,88'8.   8888   ,d8P  8 8888        `8b.  ;8.`8888     8 8888        8 8888  ` 8888     ,88'   8         `Y8o.`    8888     ,88'    8888   ,d8P         8 8888      
 *        `8888888P'  `8.   `Y88888P'   8 888888888888 `Y8888P ,88P'     8 8888        8 8888     `8888888P'     8            `Yo     `8888888P'       `Y88888P'          8 8888      
 */

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

#define TARGET_MODULE "chrome.dll"
#define DONT_KILL_INTEL 2

#define SIG "\x48\x8B\xC4\x48\x89\x58\x10\x48\x89\x68\x18\x48\x89\x70\x20\x57\x41\x56\x41\x57\x48\x00\x00\x00\x00\x00\x00\x48\x8B\xE9\x4C\x8D\x05\x43\x36\xC2\x01"
#define MASK "xxxxxxxxxxxxxxxxxxxxx??????xxxxxxxxxx"

// finds the module within the chrome process
MODULEINFO FindModule(HANDLE hProcess);
// finds the pattern within the chrome process
uintptr_t findPattern(char* base, unsigned int size, char* pattern, char *mask);
// attaches the debugger
int AttachDebugger(int pid);
// debugger loop
void DebugLoop(char * ptrToFunc, int pid);

int stop = 0;

int main() {
	int temp = -1;
	char * tempChromeBuf = NULL;
	MODULEINFO chromeDllModule;
	ZeroMemory(&chromeDllModule, sizeof(MODULEINFO));

	printf("pointer size: %d\n", sizeof(char*));

	int pid;
	do {
		Sleep(DONT_KILL_INTEL);
		printf("enter pid: ");
		scanf("%d", &pid);
		HANDLE chromeProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (chromeProcess == NULL) {
			int lasterror = GetLastError();
			printf("unable to open process (%d)\n", lasterror);
		}
		else {
			printf("trying to locate chrome.exe...\n");
			chromeDllModule = FindModule(chromeProcess);
			CloseHandle(chromeProcess);
		}
	} while (!chromeDllModule.EntryPoint);

	printf("base of dll: %x, size: %x\n", chromeDllModule.lpBaseOfDll, chromeDllModule.SizeOfImage);
	HANDLE chromeDllProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!chromeDllProcess) {
		printf("unable to find process\n");
		return 1;
	}

	tempChromeBuf = new char[chromeDllModule.SizeOfImage];
	SIZE_T bytesRead = 0;
	ZeroMemory(tempChromeBuf, chromeDllModule.SizeOfImage);
	if (!ReadProcessMemory(chromeDllProcess, chromeDllModule.lpBaseOfDll, tempChromeBuf, chromeDllModule.SizeOfImage, &bytesRead)) {
		CloseHandle(chromeDllProcess);
		delete[] tempChromeBuf;
		printf("unable to read memory\n");
		return 1;
	}

	printf("bytes : %x\n", bytesRead);

	char* relPtrToFunc = (char*)findPattern(tempChromeBuf, chromeDllModule.SizeOfImage, SIG, MASK);

	char *absPtrToSuspectFunc = (char*)((char*)chromeDllModule.lpBaseOfDll + (uintptr_t)relPtrToFunc - (uintptr_t)tempChromeBuf);
	if (relPtrToFunc == NULL) {
		printf("unable to locate function\n");
	}
	else {
		printf("ptrFunc: %llx\n", absPtrToSuspectFunc);
	}

	if (AttachDebugger(pid)) {
		DebugLoop(absPtrToSuspectFunc, pid);
	}
	else {
		stop = 1;
	}

	char ans;
	printf("do you want to stop?");
	scanf("%c", &ans);
	stop = 1;

	if (!DebugActiveProcessStop(pid)) {
		printf("unable to detach\n");
	}

	if (tempChromeBuf != NULL) {
		free(tempChromeBuf);
		tempChromeBuf = NULL;
	}
	if (chromeDllProcess) {
		CloseHandle(chromeDllProcess);
		chromeDllProcess = NULL;
	}
	printf("press enter to continue\n");
	scanf("%c", &temp);
	return 0;
}

int AttachDebugger(int pid) {
	if (!DebugActiveProcess(pid) && !DebugSetProcessKillOnExit(false)) {
		printf("unable to attach to process");
		return 0;
	}
	return 1;
}

void WriteBreakpoint(HANDLE pHandle, char * address, char buf[]) {
	SIZE_T bytesWritten = 0;
	if (!WriteProcessMemory(pHandle, address, buf, sizeof(char) * 1, &bytesWritten)) {
		printf("unable to write memory\n");
	}
}

void DebugLoop(char * ptrToFunc, int pid) {
	char int3 = { '\xCC' };
	char restore = { '\x48' };
	DEBUG_EVENT dbgEvent;
	HANDLE processHandle;
	HANDLE threadHandle = NULL;

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!processHandle) {
		printf("unable to open process");
		return;
	}


	ZeroMemory(&dbgEvent, sizeof(DEBUG_EVENT));
	WriteBreakpoint(processHandle, ptrToFunc, &int3);
	while (!stop) {
		if (WaitForDebugEvent(&dbgEvent, INFINITE) == 0)
			break;

		if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
			dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
			printf("breakpoint debug event -> %x \n", dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress);
			if (dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == ptrToFunc) {
				CONTEXT threadContext = { 0 };
				threadContext.ContextFlags = CONTEXT_FULL;
				if (!threadHandle) {
					threadHandle = OpenThread(THREAD_ALL_ACCESS, false, dbgEvent.dwThreadId);
				}
				SuspendThread(threadHandle);

				if (!GetThreadContext(threadHandle, &threadContext)) {
					printf("unable to get thread context\n");
					ResumeThread(threadHandle);
					continue;
				}




				// can't be dealing with pointer math shit so just cast it to a uintptr_t
				char * addressOfBody = (char*)((uintptr_t)threadContext.Rdx + 0x10);
				unsigned __int64 httpData = NULL;
				unsigned __int64 length = threadContext.Rdi;
				char * tempBuffer = new char[length + 1];
				SIZE_T bytesRead = 0;
				ZeroMemory(tempBuffer, length + 1);

				if (ReadProcessMemory(processHandle, addressOfBody, &httpData, sizeof(char*), &bytesRead)) {
					if (ReadProcessMemory(processHandle, (LPCVOID)httpData, tempBuffer, length, &bytesRead)) {
						puts("req:");
						for (size_t i = 0; i < length; i++)
						{
							printf("%c", tempBuffer[i]);
						}

						puts("req done");
					}
					else {
						printf("unable to read inner buffer\n");
					}
				}
				else {
					printf("unable to read outer buffer\n");
				}
				delete[] tempBuffer;
				printf("len of request : %d\n", length);

				// WriteBreakpoint(processHandle, ptrToFunc, &restore);
				threadContext.Rip = threadContext.Rip + 2;
				threadContext.Rax = threadContext.Rsp;
				if (!SetThreadContext(threadHandle, &threadContext)) {
					printf("unable to rewind rip, there's nothing to do :(\n");
				}
				ResumeThread(threadHandle);
			}
		}


		if (!ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE)) {
			printf("unable to continue debug event\n");
		}
		// WriteBreakpoint(processHandle, ptrToFunc, &int3);
	}
	WriteBreakpoint(processHandle, ptrToFunc, &restore);

	CloseHandle(processHandle);
	CloseHandle(threadHandle);
	threadHandle = NULL;
}



MODULEINFO FindModule(HANDLE hProcess)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	MODULEINFO result;
	unsigned int i;

	if (NULL == hProcess) {
		ZeroMemory(&result, sizeof(MODULEINFO));
		return result;
	}

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

			MODULEINFO moduleInfo;
			if (!GetModuleInformation(hProcess, hMods[i], &moduleInfo, sizeof(MODULEINFO))) {
				printf("unable to get module info for module (%d)\n", GetLastError());
				continue;
			}
			result = moduleInfo;
			break;
		}
	}

	return result;
}

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
				break;
			}
		}

		if (found)
		{
			return (uintptr_t)base + i;
		}
	}
	return 0;
}

/*some notes
rdx+10 is the pointer to an array of chars containing head/body
looking for length rdi is the immediate suspect #Confirmed!
*/
