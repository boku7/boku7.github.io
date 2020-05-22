---
title: WebApp PHP - File Upload Bypass
date: 2020-5-21
layout: single
classes: wide
tags:
  - PHP
  - WebApp
  - File
  - Upload
  - Bypass
--- 

## Overview
Techniques gathered to bypass PHP file upload filters.

### PHP Null Byte

```
photo.php%00.jpg
```
+ Only usable with older PHP versions ~<5.4

### Apache Dual Extentions

```
photo.php.png
```
+ Apache has a setting were a file can have 2 extensions
+ Apache will process the file as either type based on the extensions


### Alternate PHP Extentions

```
.phtml  .php3   .php4   .php5   .phps
```
+ There are many different file extensions for PHP.
+ Developers may blacklist `*.php` but forget `*.php3`

### Case Sensitive Bypass

+ Developers may blacklist `*.php` using case sensitive regex
+ This can be bypassed with `file.PhP`



## External References 
[PentesterLab.blog - Bypassing File Upload Restrictions](https://pentestlab.blog/2012/11/29/bypassing-file-upload-restrictions/)

