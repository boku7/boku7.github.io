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
## Find GetProcAddress
#### Goal
Find the address for the symbol(function) `GetProcAddress`, within `kernel32.dll`.
  - `GetProcAddress` can then be used to retrieve the adress of other symbols within Dynamically Linked Libraries (DLL's).
#### Requirement to Finding GetProcAddress
First you must find the base address of `kernel32.dll`. 
  - Reference my previous post to understand this.
#### Technique 
Export Directory Table
  - As detailed in [Skapes Windows 32 Shellcoding paper](http://www.hick.org/code/skape/papers/win32-shellcode.pdf)
#### Tools
  - PEview
  - OllyDbg
  - Windows Vista Home SP1 x86
  - nasm (kali)
  - Immunity Debugger

1. Get the base address of `kernel32.dll`
2. Find offset to New EXE Header within the `Image_dos_Header` of `kernel32.dll`
```
  (BaseAddr of kernel32.dll) + 0x3c = (PTR to New Exe Header)
```
    - This RVA holds a pointer to 0xe0 (RVA of New Exe Header)
    - For windows Vista SP1
  ![](/assets/images/exeHeaderBegin.png)
3. Find Offset for the Export Table within `Image_optional_header` 
```
  (RVA of New Exe Header) + 0x78 = (PTR to RVA of Export table)
  0xe0                    + 0x78 = 0x158
```
  - This RVA holds a pointer to 0x00C009C
  ![](/assets/images/exportTableRVA.png)
4. Find Offsets for Address Table, Name Pointer Table and Ordinal Table from Export Table
```
  (Addr of Export Table) + 0x14 = Number of Functions/Symbols within the Tables
  (Addr of Export Table) + 0x1c = (PTR to RVA of Address Table)
  (Addr of Export Table) + 0x20 = (PTR to RVA of Name Pointer Table)
  (Addr of Export Table) + 0x24 = (PTR to RVA of Ordinal Table)
```
  ![](/assets/images/RVAsTables.png)
5. Loop through Name Pointer Table comparing each string with "GetProcAddress"
  - Make sure to keep count of placement
  ![](/assets/images/NamePtrTbl_GetProcAddr.png)
6. Find GetProcAddress Ordinal number from Ordinal Table
```
  (Addr of Ordinal Table) + (Position of "GetProcAddress") * 2 = GetProcAddress Ordinal Number
```
    - Each entry in the Ordinal Table is 2 bytes.
  ![](/assets/images/Ordinal_GetProcAddr.png)
7. Find GetProcAddress RVA from the Address Table
```
  (Addr of Address Table) + (Ordinal Number) * 4 = RVA GetProcAddress
```
8. Get full address of GetProcAddress
```
  (kernel32.dll base addr) + (GetProcAddress RVA) = Full Address of GetProcAddress
```
  ![](/assets/images/AddrTble_GetProcAddr.png)


























## References
+ `http://sh3llc0d3r.com/windows-reverse-shell-shellcode-i/`
+ `https://0xdarkvortex.dev/index.php/2019/04/01/windows-shellcoding-x86-calling-functions-in-kernel32-dll-part-2/`
+ `https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html`
+ `http://www.hick.org/code/skape/papers/win32-shellcode.pdf`
+ `https://www.corelan.be/index.php/`
