---
description: >-
  Active Directory Certificate Services (ADCS) | PKI | Certificate Authority
  (CA)
---

# ADCS

{% embed url="https://www.youtube.com/watch?ab_channel=EvalianLimited&t=2s&v=KaDj-yboKYc" %}

## ADCS in short

Active Directory Certificate Services (AD CS) is a Windows server feature that helps organizations create and manage their own Public Key Infrastructure (PKI). Where **Public Key Infrastructure (PKI)** is a system that uses digital certificates and public key cryptography to secure communication over unsafe networks, like the Internet.

<details>

<summary>A <strong>certificate</strong> is a digitally signed document in X.509 format that can be used for encryption, message signing, or authentication. Certificates contain key information, such as:</summary>

* **Subject**: The identity of the certificate owner.
* **Public Key**: Links the subject to their private key.
* **Validity Dates**: Shows when the certificate starts and ends being valid.
* **Serial Number**: A unique ID given by the issuing authority.
* **Issuer**: The entity that issued the certificate (usually a Certificate Authority or CA).
* **Subject Alternative Name**: Other names associated with the subject.
* **Basic Constraints**: Defines if the certificate is for a CA or end-user, and its allowed uses.
* **Extended Key Usages (EKUs)**: Describes specific uses for the certificate, like code signing, securing emails, or smart card logins.
* **Signature Algorithm and Signature**: Shows the algorithm and signature used by the issuer to sign the certificate.

</details>

{% hint style="warning" %}
**Certificate Authorities (CAs)** are trusted entities that issue certificates. Certificate templates are used to define certificate settings, such as usage policies, validity periods, subject details, and who can request them\
\
Certificates can extend Kerberos authentication using PKINIT (Public Key Cryptography for Initial Authentication).
{% endhint %}

### <mark style="color:yellow;">Public Key Infrastructure (PKI)</mark>

`Public Key Infrastructure (PKI)` is a system that uses digital certificates and public key cryptography. This is done to provide secure communication over unsecured network like the internet. PKI enables signatures, ecnryption and authentication of documents, email.

{% hint style="info" %}
A certificate is a document that binds a public key to a person, organization, device or service. It is issued and signed by a trusted Certificate Authority (CA). The CS verifies identity of certificate holder and integrity of public key.&#x20;
{% endhint %}

The certificate includes:

* Public key
* Name of subject
* Name of issuer
* Validity period

### <mark style="color:yellow;">What is ADCS?</mark>

`Active Directory Certificate Services (AD CS)` is a Windows server role that enables organizations to establish and manage their own Public Key Infrastructure (PKI). It is used to secure network services like SSL/TLS, VPN, Remote Desktop Services, WLAN.&#x20;

Active Directory Certificate Services includes:

* Digital certificates
* Certificate Authority
* Certificate Templates
* Key Pair generation
* Certificate Revocation
* Secure communication
* Digital Signatures
* Encryption and Decryption
* Enhanced Security and Identity Managemen

### <mark style="color:yellow;">ADCS Terminology</mark>

ADCS serves as a pivotal player working with trust and encryption and at its core lies the Ceritifcate Authority (CA).&#x20;

<details>

<summary>Terminologies in ADCS</summary>

* `Certificate Templates` are preset configurations in Active Directory Certificate Services (AD CS) that define how certificates are used and issued. They include settings like purpose, key size, validity period, and policies. AD CS provides default templates like Web Server and Code Signing, and administrators can also create custom templates to meet specific needs.

- Pu`blic Key Infrastructure (PKI)` is a system that combines hardware, software, policies, and procedures to manage digital certificates. It handles creating, distributing, and revoking certificates and includes Certification Authorities (CAs) and registration authorities to verify entities in electronic transactions using public key cryptography.

* `Certificate Authority (CA)`: This component issues certificates to users, computers, and services while overseeing certificate validity management.

- `Certificate Enrollment`: Entities request certificates from CAs, where verification of the requester's identity precedes certificate issuance.

* `Certificate Manager`: Responsible for certificate issuance, management, and authorization of enrollment and revocation requests.

- `Digital Certificate`: An electronic document containing identity information, such as a user or organization's name, along with a public key. These certificates are used for authentication to verify the identity of a person or device.

* `Certificate Revocation:` ADCS allows the revocation of certificates if they are compromised or become invalid. This is managed using Certificate Revocation Lists (CRLs) or the Online Certificate Status Protocol (OCSP).

- `Key Management`: ADCS provides mechanisms to manage private keys, ensuring their security and proper usage.

* `Backup Operator`: A backup operator is responsible for backing up and restoring files and directories. They are assigned through Active Directory Users and Computers or Computer Management. Their tasks include backing up and restoring the system state (including CA information), starting and stopping the AD CS service, using the system backup user right, and accessing records and configuration details in the CA database.

- `Standalone CA & Enterprise CA`: `Standalone CAs` Standalone CAs work independently of Active Directory, handling manual or web-based certificate requests. Enterprise CAs, integrated with Active Directory, issue certificates to users, devices, and servers within an organization, automating processes through Group Policy or Certificate Enrollment Web Services.&#x20;

* `Certificate Signing Requests`: `Certificate Signing Requests (CSRs)` are requests sent by users or devices to an ADCS CA to get a certificate. A CSR includes the public key and identifying details like the subject name and intended use of the certificate. The CA verifies the requester's identity and checks the CSR for validity. If approved, the CA issues a digital certificate linking the public key to the requester's identity and intended purpose.

- `Certificate Revocation List`: A digitally signed inventory issued by a CA cataloging revoked certificates. The CRL includes details of certificates invalidated by the CA, ensuring entities can verify the revoked status of specific certificates.

* `Extended/Enhanced Key Usages (EKUs)`: Certificate extensions that define the allowed uses of a certificate. EKUs let administrators limit certificates to specific applications or tasks, such as code signing, email encryption, or smart card logon. AD CS provides built-in EKUs like Server Authentication, Client Authentication, and Code Signing, and also allows administrators to create custom EKUs for specific business needs.

</details>

### <mark style="color:yellow;">Certificates</mark>

A certificate is an `X.509-formatted digitally signed document` serves purposes like encryption, message signing, and authentication. It consists of multiple key fields:

* Subject: Certificate owner's identity.
* Public key: Links subjects to a private key.
* NotBefore and NotAfter dates: Certificate's validity duration
* Serial Number: Unique identifier assigned by issuing CA.
* Issuer: Identifies the certifcate issuer
* SubjectAlternativeName: Alternative names associated with subject.
* Basic Constraints: Defines if certificate is a CA or entity.
* Extende Key Usages (EKUs): Object identifiers describing usage over code signing, ecrypting file sytems, secuer email, client and server authentication.

### <mark style="color:yellow;">Certificate Authorities</mark>

`Certificate Authorities (CAs)` serve as pivotal entities responsible for the issuance of certificates, which play a crucial role in validating digital identities, enabling secure communications, and establishing trust within networks.

| Container/AD Object                | Description                                                                                                     | Purpose                                                                                                          |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Certification Authorities          | Defines root CA certificates that establish the trust foundation in AD CS environments.                         | Trusted Root Certification Authorities store on Windows machines, enabling certificate trust verification.       |
| Enrollment Services                | Hosts Enterprise CA objects enabled in AD CS, managing attributes like certificate templates and DNS hostnames. | Supports client certificate requests and deployment to Intermediate Certification Authorities store.             |
| NTAuthCertificates                 | Defines CA certificates required for authentication to Active Directory.                                        | Ensures client certificates used for AD authentication are signed by trusted CAs.                                |
| AIA (Authority Information Access) | Contains intermediate and cross-CA objects for validating certificate chains.                                   | Aids in certificate chain validation, with intermediate CAs in the Intermediate Certification Authorities store. |

### <mark style="color:yellow;">Certificate Templates</mark>

AD CS Enterprise `CAs` use `certificate templates`. Template are managed through the Certificate Template feature and are stored as AD object as `objectClass pKICertificateTemplate`. Settings are defined through attributes security descriptors enroll permisions and template edits.

The **`pKIExtendedKeyUsage`** attribute in an Active Directory (AD) certificate template defines which specific **Extended Key Usage (EKU)** functionalities are allowed for certificates issued using that template.

{% hint style="info" %}
EKUs are represented by unique identifiers called **Object Identifiers (OIDs)**, and they determine what the certificate can be used for, such as client authentication, code signing, or smart card logon.

[SpecterOps research](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) focused on `EKUs` that enable authentication to AD when present in a certificate.
{% endhint %}

### <mark style="color:yellow;">Enrollment Process</mark>

{% stepper %}
{% step %}
#### Find an Enterprise CA

Client finds an Enterprise CA. Based on objects in enrollment services container.
{% endstep %}

{% step %}
#### Generate a public-private key pair and create a CSR

Client generates a public-private key par, CSR message or certificate signing request.
{% endstep %}

{% step %}
#### Sign the CSR with private key and send to Enterprise CA server

Clients signs CRS with private key and sends it to CA server.
{% endstep %}

{% step %}
#### CA check if the client is authorized to request certificates

CA server check if client is authorized to request certificates. CA check if certificate template AD objects permissions allow it to obtain a certificate.
{% endstep %}

{% step %}
#### CA generate the certificate, sign it and if allowed, send it to the client

CA generates a certificate with settings defined by the certificate template like the EKUs.&#x20;
{% endstep %}

{% step %}
#### The Client Receive the certificate:

Client stores certifcate in Windows Certificate store to use EKU.
{% endstep %}
{% endstepper %}

## ADCS Enumeration

When Active Directory Certificate Services (AD CS) is present and doing a security check find out what server is running the ADCS, which can be the DC but usually its own server.

### <mark style="color:yellow;">Enumeration From Windows</mark>

On factor indicating ADCS is present is the built-in Cert Publishers group which authorizes Certificate Authorities to publish certificates to the directory indicating a ADCS server.&#x20;

```powershell
# Query Cert Publishers group
net localgroup "Cert Publishers"
```

{% hint style="info" %}
Certify can be used to find and exploit ADCS misconfigurations, find binaries here. [https://github.com/Flangvik/SharpCollection/blob/master/NetFramework\_4.7\_x64/Certify.exe](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_x64/Certify.exe)
{% endhint %}

#### **Enumerate ESC9 from Windows**

```powershell
.\Certify.exe find
```

### <mark style="color:yellow;">Enumeration from Linux</mark>

```
netexec ldap 10.129.205.199 -u "blwasp" -p "Password123!" -M adcs
```

#### Or with Certipy

```bash
certipy find -u 'BlWasp@lab.local' -p 'Password123!' -dc-ip 10.129.205.199 -stdout
```

### <mark style="color:yellow;">Certificate Mapping</mark>

Certificate mapping is relevant for ESC6, ESC9 and ESC10 attacks. Certificate mapping connects a certificate to the specific user or machine it belongs to. This ensures that when a certificate is used, it can only be associated with its rightful owner in Active Directory.

#### **Types of Certificate Mapping**

* **Explicit mapping**: The account's **altSecurityIdentities** attribute contains the certificate’s identifier and certificate must match this value and be issued by a trusted CA.
* **Implicit mapping:** Information in the certificate's **Subject Alternative Name (SAN)** field is used to map it to the account, such as: UPN or DNS.

#### Kerberos Certificate Mapping

When certificates are used for Kerberos authentication, the **`StrongCertificateBindingEnforcement`** registry key determines how the mapping is handled:

* Disabled mode: If certificat contains a UPN, kerberos tries to match with UPN, else sAMAccountName.
* Compatibility mode: Default, explicit mapping exists (altSecurityIdentities), authentication is allowed.
* Full Enforcement mode: Strong mapping is required (either explicit mapping or validation of the security extension). If neither is present, authentication fails.
