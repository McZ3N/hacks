---
description: Powerview - SharpView
---

# Powerview/Sharpview

SID conversion

```powershell
# Convert to sid
.\SharpView.exe ConvertTo-SID -Name zen.doe

# Covert to username
.\SharpView.exe Convert-ADName -ObjectName S-1-5-21-2974783224-3764228556-2640795941-1724
```

#### Domain enumeration

```powershell
# Get Domain name
.\SharpView.exe Get-Domain
Get-Domain

# Return OUs or Organizational Units
.\SharpView.exe Get-DomainOU | findstr /b "name"

# Get users with PreauthNotRequired
.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired

# Information about hosts
Get-DomainComputer | select dnshostname, useraccountcontrol

# Check for open share
.\SharpView.exe Get-NetShare -ComputerName DC01

# Check where users are logged in
Find-DomainUserLocation

# Domain trusts
Get-DomainTrust
```

#### GPO - Group Policy Objects

```powershell
# Get all GPOs
.\SharpView.exe Get-DomainGPO | findstr displayname

# Map GPOs to host
Get-DomainGPO -ComputerIdentity WS01 | select displayname
```

#### AD Users enumeration

```powershell
# Count users
(Get-DomainUser).count

# Get Users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName

# Retrieve properties
Get-DomainUser -Identity zen.doe -Domain zencorp.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol

# Get all users and export to CSV file
Get-DomainUser * -Domain zencorp.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol | Export-Csv .\zencorp_users.csv -NoTypeInformation

# Check for ASREPRoastable users
.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired -Properties samaccountname,useraccountcontrol,memberof

# Kerberos constrained delegation
.\SharpView.exe Get-DomainUser -TrustedToAuth -Properties samaccountname,useraccountcontrol,memberof 

# Look for users with unconstrained delegation
.\SharpView.exe Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# Check for sensitive data
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}

# Check for users with SPNs for Kerberoasting
.\SharpView.exe Get-DomainUser -SPN -Properties samaccountname,memberof,serviceprincipalname

# Users from foreign domains
Find-ForeignGroup
```

#### AD Groups enumeration

```powershell
# Check all groups
Get-DomainGroup -Properties Name

# More info on group
.\SharpView.exe Get-DomainGroupMember -Identity 'Help Desk'

# Check manager of group
Get-ADGroup -Identity "Help Desk" -Properties ManagedBy | Select-Object Name, ManagedBy

# Look for protected groups
.\SharpView.exe Get-DomainGroup -AdminCount

# Look for managed security groups
Find-ManagedSecurityGroups | select GroupName

# Check Security Operations
Get-DomainManagedSecurityGroup

# Check local group memberships
Get-NetLocalGroup -ComputerName WS01 | select GroupName

# Check local group membership input host
.\SharpView.exe Get-NetLocalGroupMember -ComputerName WS01

# Check local group on host
Find-DomainLocalGroupMember -ComputerName WS01 -GroupName "Remote Management Users"

```

#### AD Computers enumeration

```powershell
# Domain computers
Get-DomainComputer

# Gather info
.\SharpView.exe Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol

# Save to CSV
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol | Export-Csv .\inlanefreight_computers.csv -NoTypeInformation

# Check for unconstrained delegation
.\SharpView.exe Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol

# Check for constrained delegation
Get-DomainComputer -TrustedToAuth | select -Property dnshostname,useraccountcontrol 
```

#### Domain ACLs enumeration

```powershell
# Check ACL
(Get-ACL "AD:$((Get-ADUser doe.zen).distinguishedname)").access  | ? {$_.IdentityReference -eq "ZENCORP\zen.doe"}

# Find users with WriteProperty or GenericAll
(Get-ACL "AD:$((Get-ADUser zen.doe).distinguishedname)").access  | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -Unique | ft -W

# Use powerview to check ACLs
Get-DomainObjectAcl -Identity zen.doe -Domain zencorp.ocal -ResolveGUIDs

# Search objects
Find-InterestingDomainAcl -Domain zencorp.local -ResolveGUIDs

# Check ACLs on file shares
Get-NetShare -ComputerName SQL01
Get-PathAcl "\\SQL01\backups"

# Check for DCSync rights
Get-ObjectACL "DC=zencorp,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object SecurityIdentifier | Sort-Object -Property SecurityIdentifier -Unique

# DCSync rights and users
$dcsync = Get-ObjectACL "DC=zencorp,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
Convert-SidToName $dcsync
```

#### AD GPO enumeration

```powershell
# GPO names
Get-DomainGPO | select displayname

# Check which GPO applies to system
Get-DomainGPO -ComputerName WS01 | select displayname

# Check GUID of GPO
Get-DomainGPO -Identity "Audit Policy" | select displayname,objectguid

# Use gpresult
gpresult /r /user:zen.doe
gpresult /r /S WS01

# Check SID and group permissions
Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq 'S-1-5-21-2974783224-3764228556-2640795941-513'}

# Confirm GPO
Get-GPO -Guid 831DE3ED-40B1-4703-ABA7-8EA13B2EB118
```

#### AD Trusts enumeration

```powershell
# Check trusts
Get-DomainTrust

# Enum all trusts for current domain and reachable
Get-DomainTrustMapping
```

