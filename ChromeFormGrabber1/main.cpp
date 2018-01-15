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

void testFailure();
MODULEINFO FindModule(HANDLE hProcess);
uintptr_t findPattern(char* base, unsigned int size, char* pattern, char *mask);

int main() {
	int temp = -1;
	char * tempChromeBuf = NULL;
	MODULEINFO chromeDllModule;
	ZeroMemory(&chromeDllModule, sizeof(MODULEINFO));
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
		printf("unable to locate function");
	}
	else {
		printf("ptrFunc: %llx", absPtrToSuspectFunc);
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

	// Release the handle to the process.

	// CloseHandle(hProcess);

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