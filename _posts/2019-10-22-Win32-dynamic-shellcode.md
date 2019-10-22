---
title: Win32 Dynamic Shellcode
date: 2019-10-22
layout: single
classes: wide
header:
  teaser: /assets/images/winXP.png
tags:
  - Shell
  - Assembly
  - Code
  - win32
  - windows
  - x86
  - Shellcode
--- 
![](/assets/images/winXP.png)
## Enviornment Setup
+ [See this post to setup your windows xp enviornment](/_posts/2019-10-20-Win32-Env.md)

## kernel32.dll
+ [See Skape's paper for full details.](http://www.hick.org/code/skape/papers/win32-shellcode.pdf)
+ Unlike Linux System-Calls, Window's System-Calls do not support networking.
+ In Window's, DLL's are used instead of System-Calls for shellcode.
  - Dynamically-Linking-Librarie's are mapped into the process's memory at runtime.
+ The only DLL that is guaranteed to exist in the process is `kernel32.dll`.

### Dynamically Finding kernel32.dll in Process Memory
```nasm
    xor ecx, ecx            ; clear ecx register
    mov eax, [fs:ecx+0x30]  ; save PEB address in eax register
    mov eax, [eax+0xc]      ; pointer to the loader data structure (Ldr)
    mov esi, [eax+0x1c]     ; first entry in the init order module list
    lodsd                   ; grab next entry which points to kernel32.dll
    mov eax, [eax+0x8]      ; store module base address in eax
    ret                     ; return to caller
```
+ After executing this code, the program should have the base address of `kernel32.dll` stored in the `eax` register.




### Compiling + Extracting the Shellcode Hex
```console
root@kali# nasm -f win32 findKernel32.asm -o win32.o
root@kali# for i in $(objdump -D findKernel32.o | grep "^ " | cut -f2); do echo -n '\x'$i;done;echo
\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x40\x08\xc3
```
+ Compiled on kali linux x64 host.


### Shellcode Test Program
```c
char code[] = "\xcc\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x40\x08\xc3";
int main(int argc, char **argv)
{
    int (*func)();
    func = (int(*)()) code;
    (int)(*func)();
}
```
+ Added '\xcc' to start of `code[]` array to set a software breakpoint.
+ The breakpoint allows us to step through our test code as it executes; using a debugger like Immunity.
+ Compiled on Windows XP SP3 Pro x86 (32-bit), wil lcc-win32 program.
![](/assets/images/kernel32winCompile.png)

### Testing the Shellcode Execution
+ Open the compiled program with Immunity Debugger.
+ When pressing the play button, the code should break at our software breakpoint.

![](/assets/images/foundKernel32.png)
+ We see that we successfully found our `kernel32.dll` base address within the host process's memory.
![](/assets/images/kernel32eax.png)
+ Our shellcode successfully stores the base address of `kernel32.dll` in the `eax` register.
![](/assets/images/kernel32altM.png)
+ In Immunity we verify kernel32's base address by pressing `Alt+M` to go to view the memory map, and then find our `kernel32.dll` base address.



; successfully loaded kernel32.7C800000 into the eax register
; used Immunity to check. Break point stopped the program at the start of the SC execution.
; used <alt+M> to check that kernel32.dll was at 0x7c800000. Great success




### LoadLibraryA() -- within kernel32.dll
+ A function/symbol within the `kernel32.dll` that can load other DLL's into the process's memory.
+ [LoadLibraryA() Microsoft Documentation.](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
```c
HMODULE LoadLibraryA(LPCSTR lpLibFileName);
```
lpLibFileName
: The name of the module/DLL to load.
### 



