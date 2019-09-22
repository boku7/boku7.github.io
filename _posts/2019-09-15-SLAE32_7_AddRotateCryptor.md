---
title: SLAE32 Assignment 7 -- Add + Rotate Cryptor 
date: 2019-9-22
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE32.jpg
tags:
  - Cryptor
  - Crypto
  - Cesaer
  - modulus
  - Bind
  - Assembly
  - Code
  - SLAE
  - Linux
  - x86
--- 
![](/assets/images/SLAE32.png)
## Overview
For the seventh assignment of the SLAE32 course we were required to create a custom cryptor and decryptor. 

Online I found many examples for RC4, AES, DES and other common encryptors, so I decided to do something different.  
### Creating a Custom Cryptor
For my cryptor I decided to create somewhat of a Cesaer Chipher. The cryptor takes a key, and for every byte of the shellcode adds to it the corresponding byte of the key. 
+ When the key length is exceeded, the key repeats itself.  
+ the example key is `key = "HelloFriend"`

In the example, the strength of this cryptor is quite terrible. Although it can be used in a way that makes it good. If the key is the same length of the shellcode, then this works as a One-Time Pad (OTP). 
### Using the Cryptor Smartly
+ The key or "pad" should not be words, or even letters, of the english language. 
+ Each byte of the key should be a randomly generated hex value, ranging from `\x00` to `\xff`.   

This encryption method is not typically seen in production because the key lengths are huge, non-memerable strings, and the key is needed both at the cryptor and decryptor sides.   

+ Instead of XOR'ing I chose to use the bitwise AND operation, since I have used XOR quite a bit in the SLAE32 course.  

Obviously adding a byte from the shellcode and the key together is likely to exceed the maximum value of the result space. If this happens, the cryptor will subtract 256 (one byte) from the result, and store the remainder in the encrypted byte.  

When decrypting, it will simply check to see if a byte was subtracted, and add a byte back.  

Since my example uses a small, repeated key, I added that the byte be rotated to the left once when encrypting. Then rotate the byte to the right once when decrypting.  

## ADD Rotate-Left Cryptor
```python
#!/usr/bin/python
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
shellcode += "\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
key = "HelloFriend"
encrypted = ""
keyArray = bytearray(key)
keyLength = len(bytearray(key))
# count will be used to make the key the same length as the shellcode
count = 0				
for x in bytearray(shellcode) : 
	# If their are no more letters in the key, reuse the key from the start
	if count == keyLength :		
		count = 0
	# Add the first byte of shellcode and key together
	x = x + keyArray[count]		
	if x > 255 :
		# if the key is greater than a byte value, remove the extra byte
		x -= 256		
	if x > 127:
        	x = x - 128             # Remove the left-most bit
        	x = x << 1              # Shift to the left 1
        	x += 1                  # Add 1, to complete the rotate
        	encrypted += '\\x'
        	encrypted += '%02x' %x	# Add the rotated left hex to string 
	else:
        	encrypted += '\\x'       # No leftmost bit, just rotate
        	encrypted += '%02x' %(x << 1)
	count += 1

print encrypted
```

## SUB Rotate-Right Decryptor
```python
#!/usr/bin/python
encrypted = "\xf2\x4a\x79\xa9\x3d\xea\xcb\xa3\x9b\x3b\x8d\x63\xa7"
encrypted += "\xeb\x9e\x7f\x9f\xa8\x79\xdd\x9e\x28\xa6\x64\xd9"
key = "HelloFriend"
decrypted = ""

keyArray = bytearray(key)
keyLength = len(bytearray(key))
count = 0
for x in bytearray(encrypted) : 
	if count == keyLength :
		count = 0
	oddEven = x % 2
	if oddEven == 1:
		x = x >> 1
		x = x + 128
	else:
		x = x >> 1
	x = x - keyArray[count]
	if x < 0 :
		x += 256
	decrypted += '\\x'
	decrypted += '%02x' %x	# Add the rotated left hex to string 
	count += 1

print decrypted

#if decrypted + key > 255
#	encrypted = decrypted + key - 256
#else 
#	encrypted = decrypted + key

#if encrypted - key < 0
#	decrypted = encrypted - key + 256
#else
#	decrypted = encrypted - key
```

