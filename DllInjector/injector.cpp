#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include<string>


bool Inject(DWORD pId, char *dllName);

#define BUF_SIZE 1024

using namespace std;

int main( int argc,char * argv[])
{
	char strDLL[BUF_SIZE];
	system("title Dll Injector");
	cout << endl;
	cout << "                     Dll Injector\n\n";
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xC);
	cout << "                                        |\n";
	cout << "                  ,------------=--------|___________|\n";
	cout << "--=============%%%|         |  |______|_|___________|\n";
	cout << "                  | | | | | | ||| | | | |___________|\n";
	cout << "pb                `------------=--------|           |\n";
	cout << "                                        |\n";
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
	cout << "\n-------------------------------------------------------\n\n";
	int pid;
	TCHAR full_path[MAX_PATH];
	if (argc != 3) {
		cout << "Enter target PID: ";
		cin >> pid;
		fflush(stdin);
		cout << "Enter target DLL: ";
		cin >> strDLL;
	}
	else {
		size_t size;
		pid = stoi(argv[1], &size);
		strcpy(strDLL, argv[2]);
	}
	GetFullPathName(strDLL, MAX_PATH, full_path, NULL);
	Inject(pid, full_path);
	system("pause");
	return 0;
}

bool Inject(DWORD pId, char *dllName)
{
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
	if (h)
	{
		LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		cout << "[!] Initialized Library\n";
		LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		cout << "[!] Initialized memory allocation\n";
		WriteProcessMemory(h, dereercomp, dllName, strlen(dllName), NULL);
		cout << "[!] Wrote dll name to memory: " << strlen(dllName) << " byte(s)\n";
		HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
		if (asdc == NULL) {
			int lastError = GetLastError();
			printf("last error %d\n", lastError);
			VirtualFreeEx(h, dereercomp, strlen(dllName), MEM_RELEASE);
			CloseHandle(h);
			return false;
		}
		cout << "[!] Created remote thread: " << asdc << endl;
		cout << "[!] Waiting for Dll exit...\n";
		WaitForSingleObject(asdc, INFINITE);
		VirtualFreeEx(h, dereercomp, strlen(dllName), MEM_RELEASE);
		cout << "[!] Freeing memory\n";
		CloseHandle(asdc);
		CloseHandle(h);
		cout << "[!] Closed all handles\n";
		return true;
		cout << "[!] Complete!\n";
	}
	cout << "[!] That process does not exist\n";
	return false;
}