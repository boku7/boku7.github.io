---
title: Creating the "Where Am I" Cobalt Strike BOF
date: 2021-8-19
layout: single
classes: wide
tags:
  - CobaltStrike
  - BeaconObjectFile
  - BOF
  - Windows
  - Internals
  - RedTeam
--- 

## Overview
This post covers a walkthrough of creating the Cobalt Strike Beacon Object File (BOF), "Where Am I?".

### Our BOF Flow to get the Environment Variables Dynamically in Memory
TEB (GS Register) --> PEB --> PEB.ProcessParamters --> ProcessParamters --> Environment

```
# TEB Address
0:000> !teb
TEB at 00000000002ae000
# PEB Address from TEB
0:000> dt !_TEB 2ae000
   +0x060 ProcessEnvironmentBlock : 0x00000000`002ad000 _PEB
# ProcessParamters Address from PEB
0:000> dt !_PEB 2ad000
   +0x020 ProcessParameters : 0x00000000`007423b0 _RTL_USER_PROCESS_PARAMETERS
# Environment Address & Size from ProcessParameters
0:000> dt !_RTL_USER_PROCESS_PARAMETERS 7423b0
   +0x080 Environment      : 0x00000000`00741130 Void
   +0x3f0 EnvironmentSize  : 0x124e
```

### Initial Setup
+ Boot up a windows box
+ Download and Install x96DBG
+ Download and install WinDBG 
+ Make sure WinDBG symbols are setup
+ Open any executable PE file

## From TEB to PEB
The address of the Thread Environment Block (TEB) can be discovered from anywhere in memory by referencing the GS register for 64 bit, and the FS register for 32 bit. The TEB includes within it the address of the Process Environment Block (PEB). Therefor once we get the TEB using the FS register, we can find the PEB.

### Viewing the TEB in WinDBG
To see the TEB for our current thread in WinDBG, just use the `!teb` command. This displays the TEB for us nicely.

```
0:000> !teb
TEB at 00000000002ae000
    ExceptionList:        0000000000000000
    StackBase:            0000000000650000
    StackLimit:           000000000064d000
    SubSystemTib:         0000000000000000
    FiberData:            0000000000001e00
    ArbitraryUserPointer: 0000000000000000
    Self:                 00000000002ae000
    EnvironmentPointer:   0000000000000000
    ClientId:             00000000000008f0 . 0000000000001f30
    RpcHandle:            0000000000000000
    Tls Storage:          0000000000743340
    PEB Address:          00000000002ad000
```
+ We can see that the PEB Address is `0x2ad000` for our process.
+ Although we can see the PEB address here, we need to know the offset to the PEB Address pointer within the TEB, so we can do this programatically in our BOF.

### Parsing the TEB Structure in Memory
Using the TEB address we discovered by using the `!teb` command, we will feed that into the `dt` command and parse the memory at the TEB Address `0x2ae000` so we can discover the offset of the PEB Address.

```
0:000> dt !_TEB 2ae000
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x038 EnvironmentPointer : (null) 
   +0x040 ClientId         : _CLIENT_ID
   +0x050 ActiveRpcHandle  : (null) 
   +0x058 ThreadLocalStoragePointer : 0x00000000`00743340 Void
   +0x060 ProcessEnvironmentBlock : 0x00000000`002ad000 _PEB
...
```
+ We can see that the PEB Address is at an offset of `+0x060` within the TEB.

### Creating TEB to PEB Shellcode
Our goal is to do this in a Cobalt Strike Beacon Object File, so we will need to create the Assembly code to discover the PEB from the TEB programatically. We will make sure this is Position Independant Code (PIC) by using the GS register to discover the TEB.  

+ To test that this works, we will open our PE file in x96DBG.
+ X96DBG has advantages over WinDBG, and WinDBG has advantages over x96DBG. I switch between them allot depending on what i'm trying to do.
+ Set a break point anywhere. Then select the current line that RIP is on.
+ Press the spacebar and edit the assembly.

### Editing Opcodes in memory with x64dbg

![](/assets/images/whereAmIBof/x64EditAssembly.png)   

+ We will put 0x60 into the RAX register, because we know that the PEB Address is at `TEB+0x60`.
+ For the next instruction put in `mov rbx, gs:[rax]`.
  + We are referencing the TEB address using the GS register. This is a Windows internals operating system functionality.
  + We are telling the processor to move the 8 byte value at `TEB+0x60` into the `RBX` register.
  + Our PEB Adress is at `TEB+0x60`.
+ Now that we have our 2 instruction in, we press `F7` to step forward and execute our instructions.
![](/assets/images/whereAmIBof/pebAddress.png)     
+ The address of the PEB is in `RBX` and is `0x31E000`.

### Confirming PEB Address
To confirm that our assembly code resolves the correct address of the PEB dynamically in memory we can confirm using the Memory Map tab.

![](/assets/images/whereAmIBof/memMapPEB.png)  

### Our Assembly Code so Far

```asm
mov rax, 0x60     // RAX = 0x60 = Offset of PEB Address within the TEB
mov rbx, gs:[rax] // RBX = PEB Address
```

## From PEB to ProcessParameters

### Get the Address of the Process Environment Block (PEB)
+ in WinDBG enter the `!peb` command in the console to get the address of the PEB in memory

```
0:000> !peb
PEB at 00000000002ad000
```

![](/assets/images/whereAmIBof/bangPeb.png)

  + We can see that `!peb` command parses out the PEB, the Loader (Ldr), the Process Parameters, as well as the Environment information we are targeting.

### Walk the PEB Struct to find ProcessParameters Struct
The Process Enviroment Block (PEB) contains allot of information. Right now, we are discovering where the `ProcessParamters` struct exists within the PEB. We will note the offset: `+0x020 ProcessParameters`.
```
0:000> dt !_PEB 00000000002ad000
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
...
   +0x010 ImageBaseAddress : 0x00000000`00400000 Void
   +0x018 Ldr              : 0x00007ffb`01f9a4c0 _PEB_LDR_DATA
   +0x020 ProcessParameters : 0x00000000`007423b0 _RTL_USER_PROCESS_PARAMETERS
   +0x028 SubSystemData    : (null) 
   +0x030 ProcessHeap      : 0x00000000`00740000 Void
   +0x038 FastPebLock      : 0x00007ffb`01f9a0e0 _RTL_CRITICAL_SECTION
...
   +0x7c0 Reserved         : 0y0000000000000000000000000000000 (0)
   +0x7c4 NtGlobalFlag2    : 0
```

## From ProcessParameters to Environment

### Walk the ProcessParameters Struct to find our Environment
From the ProcessParamters Struct we will want to note the pointer to the `Environment` and the `EnvironmentSize`.

```
0:000> dx -r1 ((ntdll!_RTL_USER_PROCESS_PARAMETERS *)0x7423b0)
((ntdll!_RTL_USER_PROCESS_PARAMETERS *)0x7423b0)                 : 0x7423b0 [Type: _RTL_USER_PROCESS_PARAMETERS *]
    [+0x000] MaximumLength    : 0x748 [Type: unsigned long]
    [+0x004] Length           : 0x748 [Type: unsigned long]
    [+0x008] Flags            : 0x1 [Type: unsigned long]
    [+0x00c] DebugFlags       : 0x0 [Type: unsigned long]
    [+0x010] ConsoleHandle    : 0x0 [Type: void *]
    [+0x018] ConsoleFlags     : 0x0 [Type: unsigned long]
    [+0x020] StandardInput    : 0x0 [Type: void *]
    [+0x028] StandardOutput   : 0x0 [Type: void *]
    [+0x030] StandardError    : 0x0 [Type: void *]
    [+0x038] CurrentDirectory [Type: _CURDIR]
    [+0x050] DllPath          [Type: _UNICODE_STRING]
    [+0x060] ImagePathName    [Type: _UNICODE_STRING]
    [+0x070] CommandLine      [Type: _UNICODE_STRING]
    [+0x080] Environment      : 0x741130 [Type: void *]
...
    [+0x3f0] EnvironmentSize  : 0x124e [Type: unsigned __int64]
```

+ Now we know that the `Environment` is at address `0x741130`.
+ The size of the Environment is `0x124e` (4686 bytes)

### Viewing the Environment Unicode Strings
Now that we know the address and size of the Environment, we can view the memory at that address to confirm

```
0:000> db 0x741130 0x741130+0x124e
00000000`00741130  3d 00 3a 00 3a 00 3d 00-3a 00 3a 00 5c 00 00 00  =.:.:.=.:.:.\...
00000000`00741140  41 00 4c 00 4c 00 55 00-53 00 45 00 52 00 53 00  A.L.L.U.S.E.R.S.
00000000`00741150  50 00 52 00 4f 00 46 00-49 00 4c 00 45 00 3d 00  P.R.O.F.I.L.E.=.
00000000`00741160  43 00 3a 00 5c 00 50 00-72 00 6f 00 67 00 72 00  C.:.\.P.r.o.g.r.
00000000`00741170  61 00 6d 00 44 00 61 00-74 00 61 00 00 00 41 00  a.m.D.a.t.a...A.
00000000`00741180  50 00 50 00 44 00 41 00-54 00 41 00 3d 00 43 00  P.P.D.A.T.A.=.C.
00000000`00741190  3a 00 5c 00 55 00 73 00-65 00 72 00 73 00 5c 00  :.\.U.s.e.r.s.\.
00000000`007411a0  62 00 6f 00 6b 00 75 00-5c 00 41 00 70 00 70 00  b.o.k.u.\.A.p.p.
00000000`007411b0  44 00 61 00 74 00 61 00-5c 00 52 00 6f 00 61 00  D.a.t.a.\.R.o.a.
00000000`007411c0  6d 00 69 00 6e 00 67 00-00 00 43 00 68 00 6f 00  m.i.n.g...C.h.o.
00000000`007411d0  63 00 6f 00 6c 00 61 00-74 00 65 00 79 00 49 00  c.o.l.a.t.e.y.I.
```
+ We see that the strings are there as Unicode. You can tell because of the `00` after everything.
  + Windows Unicode strings are 2 bytes (4 hex characters).
+ We can see that the Unicode strings end with a `00 00` unicode byte.
 
## Assembly Shellcode to get to Enviroment from Anywhere in Memory

TEB (GS Register) --> PEB --> PEB.ProcessParamters --> ProcessParamters --> Environment
```asm
xor r10, r10         // R10 = 0x0 - Null out some registers
mul r10              // RAX&RDX = 0x0
add al, 0x60         // RAX = 0x60 = Offset of PEB Address within the TEB
mov rbx, gs:[rax]    // RBX = PEB Address
mov rax, [rbx+0x20]  // RAX = ProcessParamters Address
mov rbx, [rax+0x3f0] // RBX = Environment Address
mov rax, [rax+0x80]  // RAX = Environment Size
```

#### Testing That our Code Works
We enter in the above Assembly code into a process using x64dbg to test it out. We step through it and see that it resolves the Environment Address & Environment Size.

![](/assets/images/whereAmIBof/testingASM.png)

+ We see that the Environment Address is in the `RAX` register.
+ The Environment Size is in the `RBX` register.

### Confirming the Evironment Address
Just to make sure, we right-click the RAX value in x64dbg and click 'View in Dump'. We can confirm that our Environment Unicode strings are at that address.

![](/assets/images/whereAmIBof/confirmEnvAddr.png)
