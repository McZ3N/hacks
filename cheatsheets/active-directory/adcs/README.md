---
description: Active Directory Certificate Services (ADCS)
---

# ADCS

### <mark style="color:yellow;">Public Key Infrastucture</mark>

PKI uses digital certificates and public key cryptography. A digital certificate binds public key to a person, organization, device or service.&#x20;

> A certificate is is issued and signed by a trusted `Certificate Authority (CA)`

### <mark style="color:yellow;">What is ADCS</mark>

Active Directory Certificate Services is a Window server role to establish and manage a PKI. Its used for securing SSL/TLS, VPN, RDS and WLAN. Also issue certficates for smart cards and physical tokens tot authenticate user to a network.

<table><thead><tr><th width="203">Terminoloy</th><th>Description</th></tr></thead><tbody><tr><td>Certificate Templates</td><td>Used to define what certificate can be used for like web server for https, code signing or a custom like VPN.</td></tr><tr><td>Certificate Authority</td><td>Issues certifates to users, computers, and services.</td></tr></tbody></table>

### <mark style="color:yellow;">Certificate Authorities</mark>

CAs issue certifcates and a root CA creates it own self-signed certificate using it private key. ADCS sets the certificate's name and marks it as a CA. Once trusted by devices the certificate allows the CA to be recognized as a trusted source.&#x20;

{% hint style="info" %}
**Trusting the CA = trusting all the certificates it issues**, making secure communication seamless across your network or organization.
{% endhint %}

### <mark style="color:yellow;">Certificate Templates</mark>

Enterprise CAs in AD CS use certificate templates to define how certificates are issued and used. These templates include settings like usage, validity, subject info and who can request them. They are stored in   AD as `pKICertificateTemplate` objects. The `pKIExtendedKeyUsage` attribute lists OIDs that define what the certificate can be used for—like code signing, smart card logon, or client authentication.

### <mark style="color:yellow;">Misconfigurations</mark>

<table><thead><tr><th width="245"></th><th></th></tr></thead><tbody><tr><td>Abusing Certifcate Templates</td><td>ESC1, ESC2, ESC3, ESC9, and ESC10:, focusing on misconfiguration within certificate templates.</td></tr><tr><td>Abusing CA Configuration</td><td>ESC6: Exploiting weaknesses within the Certificate Authority configuration</td></tr><tr><td>Abusing Access Control</td><td>ESC4, ESC5, ESC7: Misconfigurationwith Access Control</td></tr><tr><td>NTLM Relay</td><td>ESC8, ESC11: NTLM relay misconfiguration</td></tr><tr><td>MIscellaneous</td><td>Cetrified, PKINIT</td></tr></tbody></table>
