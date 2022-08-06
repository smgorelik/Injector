## Original version is credited to https://github.com/FULLSHADE/Jektor  

This utility focuses on shellcode injection techniques to demonstrate methods that malware may use to execute shellcode on a victim system

- [x] Dynamically resolves API functions to evade IAT inclusion
- [x] Includes usage of undocumented NT Windows API functions
- [x] Supports local shellcode execution via CreateThread
- [x] Supports remote shellcode execution via CreateRemoteThread
- [x] Supports local shellcode injection via QueueUserAPC
- [x] Supports local shellcode injection via EnumTimeFormatsEx
- [x] Supports local shellcode injection via CreateFiber
- [x] Supports local shellcode injection via ModuleStomping (using amsi module)
