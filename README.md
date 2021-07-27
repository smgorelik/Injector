## Day 2 - Jektor Toolkit v1.0

**Context:** This is an older tool I once wrote during an offensive, malware development competition. It was supposed to demonstrate various shellcode injection/execution methods in user-mode. This tool is in an **archived** state, I won't be providing any updates.

This challenge focused on shellcode injection techniques to demonstrate methods that malware may use to execute shellcode on a victim system

- [x] Dynamically resolves API functions to evade IAT inclusion
- [x] Includes usage of undocumented NT Windows API functions
- [x] Supports local shellcode execution via CreateThread
- [x] Supports remote shellcode execution via CreateRemoteThread
- [x] Supports local shellcode injection via QueueUserAPC
- [x] Supports local shellcode injection via EnumTimeFormatsEx
- [x] Supports local shellcode injection via CreateFiber

![9ada2d9a23bb4fe7a91b5089a262b44d](https://user-images.githubusercontent.com/70239991/124507514-71a30a80-ddbd-11eb-8c54-5755c596e8ed.png)

**Anti-virus detection?:**

Pre-pending a set of NOPs to a Msfvenom XOR encrypted shellcode payload while using dynamic function address resolutions seems to bypass Windows Defender.

### IAT Import Evasion

Jektor makes use of dynamic function address resolutions using LoadLibrary and GetProcessAddress to make static analysis more difficult.

Important functions such as VirtualAlloc are not directly called which makes debugging and dumping the shellcode through breakpoints more difficult.

### Local shellcode execution via CreateThread

On Windows when you want to create a new thread for the current process you can call the CreateThread function, this is the most basic technique for executing malicious code or shellcode within a process. You can simply allocate a region of memory for your shellcode, move your shellcode into the allocated region, and then call CreateThread with a pointer to the address of the allocated region. When you call CreateThread you pass the lpStartAddress
parameter which is a pointer to the application-defined function that will be executed by the newly created thread. 

![f78e209597194051a4ebb74d3f519c5a](https://user-images.githubusercontent.com/70239991/124507531-7a93dc00-ddbd-11eb-8e07-350720a94f3f.png)

1.  Allocate a region of memory big enough for the shellcode using VirtualAlloc
2.  Move the globally defined shellcode buffer into the newly allocated memory region with memcpy/RtlCopyMemory
3.  Create a new thread that includes the base address of the allocated memory region with CreateThread
4.  Wait for the new thread to be created/executed with WaitForSingleObject to ensure the payload detonates

After the memory region for the shellcode payload is allocated as RWX and the payload is moved into it, you can easily discover this region of memory by looking for any region of memory in the process that is marked as RWX, then if you inspect it you can seen the shellcode payload was moved into it, highlighted below are the first five bytes of the shellcode payload that executes a calculator on the victim system.

![image](https://user-images.githubusercontent.com/70239991/126000980-f0e774cf-ede3-469c-a2d0-cc4c416f4392.png)

Hunting for RWX regions of memory is a quick way to identify potentially malicious activity on your system.

![image](https://user-images.githubusercontent.com/70239991/126001037-6916ec4f-456c-4f47-922b-dc77fde403af.png)

### Remote shellcode execution via CreateRemoteThread

Another technique to create threads for shellcode execution is to call the CreateRemoteThread function, this will allow you to create threads remotely in another process. But the catch is that you will also want to allocate and write the shellcode payload into the remote process as well, since you’ll create a thread remotely that executes the payloads address that’s allocated within that process. In order to allocate the payload remotely, you’ll need to use the VirtualAllocEx function, this function is different from VirtualAlloc in that it can allocate memory regions remotely and in other processes. To do this, Jektor creates a new process with the CREATE_NO_WINDOW flag set using CreateProcessW, this is used to spawn a new hidden notepad process. One the new process is spawn it remotely allocated memory in it using VirtualAllocEx and then uses WriteProcessMemory to write the shellcode payload into the remote buffer in the remote payload. After this it calls CreateRemoteThread to execute the shellcode payload.

1.  Spawn a new process using CreateProcessW with CREATE\_NO\_WINDOW set
2.  Open a HANDLE to the newly spawed process by PID with OpenProcess and dwProcessId from PROCESS_INFORMATION
3.  Allocate memory remotely in the spawned process for the shellcode with VirtualAllocEx
4.  Write the shellcode payload into the allocated memory region with WriteProcessMemory
5.  Detonate the remotely created shellcode payload with CreateRemoteThread and the HANDLE from OpenProcess

![48dda89e4b0a4102b0a57dc115d9e2ee](https://user-images.githubusercontent.com/70239991/124507544-8089bd00-ddbd-11eb-8ddc-5f117dd1159a.png)

### Local shellcode execution via EnumTimeFormatsEx

1.  Allocate memory locally for the shellcode payload with VirtualAlloc
2.  Move the shellcode payload into the newly allocated region with memcpy/RtlCopyMemory
3.  Detonate the shellcode by passing it as the lpTimeFmtEnumProcEx parameter for EnumTimeFormatsEx

![9875383125f74cc090c749fd95aef4f8](https://user-images.githubusercontent.com/70239991/124507573-913a3300-ddbd-11eb-8bcc-e95f861e1607.png)

### Local shellcode execution via CreateFiber

1. Get a HANDLE to the current thread using GetCurrentThread
2. Convert the main thread to a Fiber using ConvertThreadToFiber
3. Allocate memory for the shellcode payload with VirtualAlloc
4. Copy the shellcode buffer into the newly allocated memory region with memcpy
5. Create a new fiber with the base address of the allocated memory region as the lpStartAddress parameter for CreateFiber
6. Detonate the shellcode by scheduling the fiber with SwitchToFiber
7. Perform cleanup by deleting the created fiber with DeleteFiber

![6e69f015c6df47a9a63393400be44309](https://user-images.githubusercontent.com/70239991/124507585-9bf4c800-ddbd-11eb-8a06-2c48da041a17.png)

### Local shellcode execution via QueueUserAPC

1. Allocate memory for the shellcode buffer with VirtualAlloc
2. Get a handle to the current process with GetCurrentProcess
3. Write the shellcode payload into the newly allocated memory region with WriteProcessMemory
4. Get a handle to the current thread with GetCurrentThread
5. Queue a new APC routine pass the address of the allocated memory region as the pfnAPC parameter to QueueUserAPC 
6. Trigger the shellcode payload by calling the undocumented NtTestAlert function which clears the APC queue for the current thread
7. Perform cleanup by closing the handles to the current thread and current process

![116365f5725f46e09e7c37ca14bfe78d](https://user-images.githubusercontent.com/70239991/124507598-a1521280-ddbd-11eb-95d1-ea3867e77f41.png)
