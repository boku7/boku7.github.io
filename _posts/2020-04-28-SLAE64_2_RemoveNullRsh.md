---
title: SLAE64 Assignment 2 - Remove Nulls TCP Reverse Shell
date: 2020-4-28
layout: single
classes: wide
header:
  teaser: /assets/images/SLAE64.png
tags:
  - Shell
  - Assembly
  - Code
  - SLAE
  - Linux
  - x64
  - Shellcode
--- 
![](/assets/images/SLAE64.png)

## Overview
The second part of the second assignment of SLAE64 was to remove the nulls from the reverse-shell provided by Pentester Academy.

## Compiling & Testing Original - With GCC in C Host Program
```bash
```
+ We can see here that these nulls truncate our shellcode when executed in a host program.
+ This is because `\x00` will terminate a string in the host program.
+ Most of the time shellcode is injected into the host program by overflowing the string of a buffer, therefor truncating the shellcode.

## Compiling & Testing Original - With NASM & LD
The shellcode works great if it is compiled and ran as its own program. This means the shellcode logic is good. 

#### Terminal 1
```bash

```

#### Terminal 2

```bash
```

## Removing Nulls
To make this shellcode injectable into most host programs, we will need to remove the `0x00` aka `Nulls`.

To determine which assembly instructions are producing the nulls, we will use `objdump` on the object file.

```bash
```

+ After investigating the shellcode, we can see that the Nulls exist due to the mov instructions used.

## Modified Null-Free Shellcode

```nasm
syscall
```

## Assemble the new shellcode

```bash
```

## Add the Modified Shellcode to the C Host Program

```c
```


#### Terminal 1
```bash

```

#### Terminal 2

```bash
```



