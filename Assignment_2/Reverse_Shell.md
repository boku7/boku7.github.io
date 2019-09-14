## 1. Clear the registers.
```nasm 
	xor eax, eax	; Clear EAX Register. EAX = 0x00000000
	xor ebx, ebx	; Clear EBX Register. EBX = 0x00000000
	xor ecx, ecx	; Clear ECX Register. ECX = 0x00000000
	xor edx, edx	; Clear EDX Register. EDX = 0x00000000
```  

## 2. Create the Socket.
Create Socket C Function: `int socket(int domain, int type, int protocol);`  
Our C Function:
```c
            socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
EAX=0x66     EBX    ECX[0]     ECX[1]      ECX[2]
```  

```console
cat /usr/src/linux-headers-$(uname -r)/include/linux/net.h
    SOCK_STREAM     = 1
cat /usr/include/i386-linux-gnu/bits/socket.h
		#define AF_INET         PF_INET    // We see that AF_INET is mapped to PF_INET	
		#define PF_INET         2          // IP protocol family.
```  

```nasm
  mov al, 0x66     ; EAX = 0x66 = 102. SYSCAL 102 = socketcall
  mov bl, 0x1      ; EBX = 0x1 = socket() // Create a socket
  push ecx         ; ECX[2] = int protocol = 0. Pushes 0x0 onto the stack
  push ebx         ; ECX[1] - int type = SOCK_STREAM = 0x1. Pushes 0x1 onto the stack
  push 0x2         ; ECX[0] - int domain = AF_INET = PF_INET = 0x2. Pushes 0x2 onto the stack
  mov ecx, esp     ; Point the ECX Register to the Top of the stack
  int 0x80         ; Execute the socket() System Call
  mov esi, eax     ; save the "sockfd" generated from the socket above 
```
