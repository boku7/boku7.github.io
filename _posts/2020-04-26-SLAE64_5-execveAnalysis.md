---
title: SLAE64 Assignment 5 - MSFVenom Execve Analysis
date: 2020-4-26
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE64.png
tags:
  - Assembly
  - Code
  - SLAE
  - Linux
  - x64
  - Shellcode
--- 
![](/assets/images/SLAE64.png)

# Overview
For the fifth assignment of the SLAE64, I analyzed three payloads from msfvenom. This is the first payload, `linux/x64/exec`.

# Execve Anaylsis
We will be analyzing the msfvenom execve payload. This payload has a customizable command that execve will execute. To simplify the analysis, the command 'whoami' was chosen.
## Generating the MSFVenom Payload
Here we generate the payload on Kali Linux and output it to the C format. This allows us to easy add it to our host shellcode.c program.
```bash
root# msfvenom -p linux/x64/exec -f c -v shellcode CMD='whoami'
Payload size: 46 bytes
unsigned char shellcode[] =
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x07\x00"
"\x00\x00\x77\x68\x6f\x61\x6d\x69\x00\x56\x57\x48\x89\xe6\x0f"
"\x05";
```

## Shellcode.c Host Program
Here we add our shellcode to our C host program. We will compile our host program, and then use GDB for analysis of the execve payload.
```c
// Shellcode Title:  Linux/x64 - ROL Encoded Execve Shellcode (57 bytes)
// Shellcode Author: Bobby Cooke
// Date:             2020-04-26
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] =
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x07\x00"
"\x00\x00\x77\x68\x6f\x61\x6d\x69\x00\x56\x57\x48\x89\xe6\x0f"
"\x05";
int main()
{
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

### Compile & Test Shellcode.c
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# ./shellcode
root
```

## GDB Analysis
### Setup
Here we will start our shellcode with the Gnu Debugger and set a breakpoint on the main function. After the breakpoint is set, we will run the program. 
```bash
root# gdb ./shellcode
GNU gdb (Debian 8.3.1-1) 8.3.1
gdb-peda$ b main
Breakpoint 1 at 0x1129
gdb-peda$ r
```

### Finding shellcode[]
We will use the GDB step-into (`s`) command to move through our program until we reach the point where execution is passed to the shellcode[] array (our execve shellcode from msfvenom).
```bash
=> 0x555555555141 <main+28>:    call   rdx
gdb-peda$ s
```
+ Step into rdx (shellcode[]).

## Dumping MSFVenom Execve Assembly Instructions
With the instruction pointer (RIP) on the first instruction of `shellcode`, dump the instructions of the entire payload.
```bash
=> 0x555555558040 <shellcode>:  push   0x3b
   0x555555558042 <shellcode+2>:        pop    rax
   0x555555558043 <shellcode+3>:        cdq
   0x555555558044 <shellcode+4>:        movabs rbx,0x68732f6e69622f
   0x55555555804e <shellcode+14>:       push   rbx
   0x55555555804f <shellcode+15>:       mov    rdi,rsp
   0x555555558052 <shellcode+18>:       push   0x632d
   0x555555558057 <shellcode+23>:       mov    rsi,rsp
   0x55555555805a <shellcode+26>:       push   rdx
   0x55555555805b <shellcode+27>:       call   0x555555558067 <shellcode+39>
   0x555555558060 <shellcode+32>:       ja     0x5555555580ca
   0x555555558062 <shellcode+34>:       outs   dx,DWORD PTR ds:[rsi]
   0x555555558063 <shellcode+35>:       (bad)
   0x555555558064 <shellcode+36>:       ins    DWORD PTR es:[rdi],dx
   0x555555558065 <shellcode+37>:       imul   eax,DWORD PTR [rax],0x89485756
   0x55555555806b <shellcode+43>:       out    0xf,al
   0x55555555806d <shellcode+45>:       add    eax,0x0
gdb-peda$ x/17i $rip
```

## Push-Pop-cdq
```bash
<shellcode>:  push   0x3b
<shellcode+2>:        pop    rax
<shellcode+3>:        cdq
```
+ In the first 3 commands we can see that rax is set to 0x3b. 
  - This is the system call number for `execve`.
+ `cdq` is used to clear out the `rdx` register 
  - set it to `0x0` aka `NULL`


## String to Stack
```bash
RDI: 0x7fffffffe100 --> 0x68732f6e69622f ('/bin/sh')

<shellcode+4>:        movabs rbx,0x68732f6e69622f
<shellcode+14>:       push   rbx
<shellcode+15>:       mov    rdi,rsp
```
+ Here we see the string `/bin/sh` being moved into the `rbx` register.
+ The string is then pushed to the top of the stack.
+ Once on the stack, the `rdi` register is set to point to the address of the string.
+ For the execve system call, `rdi` holds a pointer to the command that will be executed.

## Shell Flag
```
RSI: 0x7fffffffe0f8 --> 0x632d ('-c')

<shellcode+18>:       push   0x632d
<shellcode+23>:       mov    rsi,rsp
<shellcode+26>:       push   rdx
```
+ Here we see that `rdi` points to the string `-c`
+ The `push rdx` null terminates the string.

## Sneaky System Call
```bash
<shellcode+27>:       call   0x555555558067 <shellcode+39>
...
<shellcode+39>:       push   rsi
<shellcode+40>:       push   rdi
<shellcode+41>:       mov    rsi,rsp
<shellcode+44>:       syscall
```
+ Here we see a sneaky system call. 
+ At first look, GDB did not even show us a system call, but as we step through the shellcode we see that it was being obfuscated by the call instruction.

## The Command String
When the shellcode performs the call instruction, this pushes the memory address of the instruction after call onto the top of the stack. In this case the next instruction after the call is actually the string "whoami". 
```bash 
0x55555555805b <shellcode+27>:       call   0x555555558067 <shellcode+39>
0x555555558060 <shellcode+32>:       ja     0x5555555580ca
0x555555558062 <shellcode+34>:       outs   dx,DWORD PTR ds:[rsi]
0x555555558063 <shellcode+35>:       (bad)
0x555555558064 <shellcode+36>:       ins    DWORD PTR es:[rdi],dx

gdb-peda$ x/s 0x555555558060
0x555555558060 <shellcode+32>:  "whoami"
```

## The System Call
Here we see everything setup perfectly to execute the command `/bin/sh -c whoami` with the `execve` system call.
```bash
[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RDX: 0x0
RSI: 0x7fffffffe0d8 --> 0x7fffffffe100 --> 0x68732f6e69622f ('/bin/sh')
RDI: 0x7fffffffe100 --> 0x68732f6e69622f ('/bin/sh')
RSP: 0x7fffffffe0d8 --> 0x7fffffffe100 --> 0x68732f6e69622f ('/bin/sh')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe0d8 --> 0x7fffffffe100 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe0e0 --> 0x7fffffffe0f8 --> 0x632d ('-c')
0016| 0x7fffffffe0e8 --> 0x555555558060 --> 0x5600696d616f6877 ('whoami')
0024| 0x7fffffffe0f0 --> 0x0
```
